#define GLOG_NO_ABBREVIATED_SEVERITIES
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <WinSock2.h>
#include <WS2spi.h>
#include <MSWSock.h>
#include <iostream>
#include <mutex>
#include <atomic>
#include "config.h"
#include "hook.h"
#include "winsock_hook.h"

#pragma comment(lib, "Ws2_32.lib")

#define NEXON_IP_NA		L"23.98.21"  /* Nexon's North America IP pattern to search for upon hook */
#define NEXON_IP_SA		L"52.171.48" /* Nexon's South America IP pattern to search for upon hook */
#define NEXON_IP_EU		L"13.65.17"  /* Nexon's Europe IP pattern to search for upon hook */
#define NULL_IP         L"0.0.0.0"   /* An uninitialized IP argument presents a "null" IP of zero */

namespace winsock {
    namespace {
        // State tracking
        WSPPROC_TABLE g_ProcTable;
        ULONG g_HostAddress;
        ULONG g_RouteAddress;
        std::atomic<bool> g_HookInitialized{ false };
        std::atomic<bool> g_WSPStartupCalled{ false };
        std::atomic<bool> g_WS2HooksInstalled{ false };
        std::mutex g_HookMutex;

        // Define the WSPStartup signature
        using WSPStartup_t = int (WINAPI*)(WORD, LPWSPDATA, LPWSAPROTOCOL_INFOW, WSPUPCALLTABLE, LPWSPPROC_TABLE);
        static WSPStartup_t WSPStartupAddr = nullptr;

        // WS2_32 function pointers for direct API hooking (fallback layer)
        using connect_t = int (WINAPI*)(SOCKET, const sockaddr*, int);
        using WSAConnect_t = int (WINAPI*)(SOCKET, const sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
        using getpeername_t = int (WINAPI*)(SOCKET, sockaddr*, int*);

        static connect_t Original_connect = nullptr;
        static WSAConnect_t Original_WSAConnect = nullptr;
        static getpeername_t Original_getpeername = nullptr;

        // Helper: Check if address matches Nexon patterns and should be redirected
        bool ShouldRedirectAddress(const sockaddr* addr, int addrlen, WCHAR* outAddr, DWORD outAddrLen) {
            if (!addr || addrlen < sizeof(sockaddr_in)) return false;

            const sockaddr_in* service = (const sockaddr_in*)addr;
            if (service->sin_family != AF_INET) {
                std::cout << "[Winsock] Non-IPv4 connection (AF=" << service->sin_family << "), skipping redirect" << std::endl;
                return false;
            }

            // Get string representation
            DWORD dwLen = outAddrLen;
            if (WSAAddressToStringW((sockaddr*)addr, addrlen, NULL, outAddr, &dwLen) != 0) {
                // Fallback: build string manually
                swprintf_s(outAddr, outAddrLen, L"%d.%d.%d.%d:%d",
                    service->sin_addr.S_un.S_un_b.s_b1,
                    service->sin_addr.S_un.S_un_b.s_b2,
                    service->sin_addr.S_un.S_un_b.s_b3,
                    service->sin_addr.S_un.S_un_b.s_b4,
                    htons(service->sin_port));
            }

            return (wcsstr(outAddr, NEXON_IP_NA) || wcsstr(outAddr, NEXON_IP_SA) ||
                    wcsstr(outAddr, NEXON_IP_EU) || wcsstr(outAddr, NULL_IP));
        }

        // Helper: Perform the actual redirect
        bool PerformRedirect(sockaddr_in* service, const char* caller) {
            std::cout << "[" << caller << "] Resolving hostname: " << config::HostName << std::endl;

            hostent* he = gethostbyname(config::HostName.c_str());
            if (!he || !he->h_addr_list || !he->h_addr_list[0]) {
                int err = WSAGetLastError();
                std::cerr << "[" << caller << "] ERROR: DNS resolution failed for " << config::HostName << " (error: " << err << ")" << std::endl;
                return false;
            }

            auto routeAddr = (struct in_addr*)he->h_addr_list[0];
            std::cout << "[" << caller << "] " << config::HostName << " resolved to " << inet_ntoa(*routeAddr) << std::endl;

            g_RouteAddress = routeAddr->S_un.S_addr;
            g_HostAddress = service->sin_addr.S_un.S_addr;
            service->sin_addr.S_un.S_addr = g_RouteAddress;
            return true;
        }

        /* Hooks the Winsock Service Provider's Connect function to redirect the host to a new socket */
        int WINAPI WSPConnect_Hook(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS, LPINT lpErrno) {
            std::cout << "[WSPConnect] Hook called - Socket: " << s << ", namelen: " << namelen << std::endl;

            if (!name) {
                std::cerr << "[WSPConnect] ERROR: sockaddr is NULL!" << std::endl;
                return g_ProcTable.lpWSPConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);
            }

            if (namelen < sizeof(sockaddr_in)) {
                std::cerr << "[WSPConnect] ERROR: namelen too small (" << namelen << " < " << sizeof(sockaddr_in) << ")" << std::endl;
                return g_ProcTable.lpWSPConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);
            }

            sockaddr_in* service = (sockaddr_in*)name;
            unsigned short pPort = htons(service->sin_port);

            std::cout << "[WSPConnect] Address family: " << service->sin_family << ", Port: " << pPort << std::endl;
            std::cout << "[WSPConnect] Raw IP bytes: "
                      << (int)service->sin_addr.S_un.S_un_b.s_b1 << "."
                      << (int)service->sin_addr.S_un.S_un_b.s_b2 << "."
                      << (int)service->sin_addr.S_un.S_un_b.s_b3 << "."
                      << (int)service->sin_addr.S_un.S_un_b.s_b4 << std::endl;

            // Retrieve a string buffer of the current socket address (IP)
            WCHAR szAddr[50] = { 0 };
            DWORD dwLen = 50;
            int nRet = WSAAddressToStringW((sockaddr*)name, namelen, NULL, szAddr, &dwLen);
            if (nRet) {
                int wsaError = WSAGetLastError();
                std::cerr << "[WSPConnect] WSAAddressToStringW failed with error: " << wsaError << std::endl;

                if (!pPort) {
                    std::cerr << "[WSPConnect] No port specified, returning error" << std::endl;
                    return nRet;
                }

                std::cout << "[WSPConnect] Socket redirection falling back to " << config::HostName << std::endl;
            } else {
                std::wcout << L"[WSPConnect] Parsed address: " << szAddr << std::endl;
            }

            bool matchNA = wcsstr(szAddr, NEXON_IP_NA) != nullptr;
            bool matchSA = wcsstr(szAddr, NEXON_IP_SA) != nullptr;
            bool matchEU = wcsstr(szAddr, NEXON_IP_EU) != nullptr;
            bool matchNull = wcsstr(szAddr, NULL_IP) != nullptr;

            std::cout << "[WSPConnect] Pattern match - NA: " << matchNA << ", SA: " << matchSA
                      << ", EU: " << matchEU << ", NULL: " << matchNull << std::endl;

            if (matchNA || matchSA || matchEU || matchNull) {
                std::wcout << L"[WSPConnect] Redirecting from: " << szAddr << std::endl;
                std::cout << "[WSPConnect] Resolving hostname: " << config::HostName << std::endl;

                hostent* he = gethostbyname(config::HostName.c_str()); // Resolve DNS
                if (!he) {
                    int nRet = WSAGetLastError();
                    std::cerr << "[WSPConnect] ERROR: Unable to resolve " << config::HostName << " with error: " << nRet << std::endl;
                    return nRet;
                }

                if (!he->h_addr_list || !he->h_addr_list[0]) {
                    std::cerr << "[WSPConnect] ERROR: DNS resolved but no addresses returned!" << std::endl;
                    return WSAHOST_NOT_FOUND;
                }

                auto routeAddr = (struct in_addr*)he->h_addr_list[0];
                std::cout << "[WSPConnect] " << config::HostName << " resolved to " << inet_ntoa(*routeAddr) << std::endl;
                g_RouteAddress = routeAddr->S_un.S_addr;
                g_HostAddress = service->sin_addr.S_un.S_addr;
                service->sin_addr.S_un.S_addr = g_RouteAddress;
            } else {
                std::wcout << L"[WSPConnect] No pattern match for address: " << szAddr << L" - passing through without redirect" << std::endl;
            }

            std::cout << "[WSPConnect] Connecting to " << inet_ntoa(service->sin_addr) << ":" << pPort << std::endl;

            int result = g_ProcTable.lpWSPConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);
            if (result == SOCKET_ERROR && lpErrno) {
                std::cerr << "[WSPConnect] Connection failed with error: " << *lpErrno << std::endl;
            } else {
                std::cout << "[WSPConnect] Connection initiated successfully" << std::endl;
            }

            return result;
        }

        /* Hooks the Winsock Service Provider's GetPeerName function to pretend to be connected to the host */
        int WINAPI WSPGetPeerName_Hook(SOCKET s, sockaddr* name, LPINT namelen, LPINT lpErrno) {
            std::cout << "[WSPGetPeerName] Hook called - Socket: " << s << std::endl;

            int nRet = g_ProcTable.lpWSPGetPeerName(s, name, namelen, lpErrno);
            if (nRet == SOCKET_ERROR) {
                std::cerr << "[WSPGetPeerName] Failed with error: " << (lpErrno ? *lpErrno : -1) << std::endl;
                return nRet;
            }

            sockaddr_in* service = reinterpret_cast<sockaddr_in*>(name);
            std::cout << "[WSPGetPeerName] Peer address: " << inet_ntoa(service->sin_addr) << std::endl;

            // Check if the returned address is the routed address
            if (service->sin_addr.S_un.S_addr == g_HostAddress) {
                std::cout << "[WSPGetPeerName] Swapping host address to route address" << std::endl;
                // Return the socket address back to the host address
                service->sin_addr.S_un.S_addr = g_RouteAddress;
            }

            return 0;
        }
    }

    // ============================================================================
    // WS2_32 Direct API Hooks (Fallback Layer)
    // These hooks catch connections that bypass the WSP layer
    // ============================================================================
    namespace ws2_fallback {

        int WINAPI connect_Hook(SOCKET s, const sockaddr* name, int namelen) {
            std::cout << "[WS2_connect] Hook called - Socket: " << s << std::endl;

            if (name && namelen >= sizeof(sockaddr_in)) {
                WCHAR szAddr[50] = { 0 };
                sockaddr_in* service = (sockaddr_in*)name;
                unsigned short port = htons(service->sin_port);

                std::cout << "[WS2_connect] Attempting connection to "
                          << inet_ntoa(service->sin_addr) << ":" << port << std::endl;

                if (ShouldRedirectAddress(name, namelen, szAddr, 50)) {
                    std::wcout << L"[WS2_connect] Redirecting from: " << szAddr << std::endl;
                    if (PerformRedirect(service, "WS2_connect")) {
                        std::cout << "[WS2_connect] Redirected to " << inet_ntoa(service->sin_addr) << ":" << port << std::endl;
                    }
                }
            }

            return Original_connect(s, name, namelen);
        }

        int WINAPI WSAConnect_Hook(SOCKET s, const sockaddr* name, int namelen,
                                   LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
                                   LPQOS lpSQOS, LPQOS lpGQOS) {
            std::cout << "[WS2_WSAConnect] Hook called - Socket: " << s << std::endl;

            if (name && namelen >= sizeof(sockaddr_in)) {
                WCHAR szAddr[50] = { 0 };
                sockaddr_in* service = (sockaddr_in*)name;
                unsigned short port = htons(service->sin_port);

                std::cout << "[WS2_WSAConnect] Attempting connection to "
                          << inet_ntoa(service->sin_addr) << ":" << port << std::endl;

                if (ShouldRedirectAddress(name, namelen, szAddr, 50)) {
                    std::wcout << L"[WS2_WSAConnect] Redirecting from: " << szAddr << std::endl;
                    if (PerformRedirect(service, "WS2_WSAConnect")) {
                        std::cout << "[WS2_WSAConnect] Redirected to " << inet_ntoa(service->sin_addr) << ":" << port << std::endl;
                    }
                }
            }

            return Original_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
        }

        int WINAPI getpeername_Hook(SOCKET s, sockaddr* name, int* namelen) {
            int result = Original_getpeername(s, name, namelen);

            if (result == 0 && name && namelen && *namelen >= sizeof(sockaddr_in)) {
                sockaddr_in* service = (sockaddr_in*)name;
                if (service->sin_addr.S_un.S_addr == g_HostAddress) {
                    std::cout << "[WS2_getpeername] Swapping host address to route address" << std::endl;
                    service->sin_addr.S_un.S_addr = g_RouteAddress;
                }
            }

            return result;
        }

        BOOL InstallWS2Hooks() {
            std::lock_guard<std::mutex> lock(g_HookMutex);

            if (g_WS2HooksInstalled.load()) {
                std::cout << "[WS2Hooks] Already installed, skipping" << std::endl;
                return TRUE;
            }

            std::cout << "[WS2Hooks] Installing WS2_32 direct API hooks..." << std::endl;

            HMODULE hWs2 = GetModuleHandleA("WS2_32.dll");
            if (!hWs2) {
                hWs2 = LoadLibraryA("WS2_32.dll");
            }

            if (!hWs2) {
                std::cerr << "[WS2Hooks] ERROR: Failed to get WS2_32.dll handle" << std::endl;
                return FALSE;
            }

            FARPROC pConnect = GetProcAddress(hWs2, "connect");
            FARPROC pWSAConnect = GetProcAddress(hWs2, "WSAConnect");
            FARPROC pGetpeername = GetProcAddress(hWs2, "getpeername");

            std::cout << "[WS2Hooks] connect: " << (void*)pConnect
                      << ", WSAConnect: " << (void*)pWSAConnect
                      << ", getpeername: " << (void*)pGetpeername << std::endl;

            bool success = true;

            if (pConnect) {
                MH_STATUS status = MH_CreateHook(pConnect, connect_Hook, (void**)&Original_connect);
                if (status == MH_OK) {
                    MH_EnableHook(pConnect);
                    std::cout << "[WS2Hooks] connect hook installed" << std::endl;
                } else {
                    std::cerr << "[WS2Hooks] Failed to hook connect: " << status << std::endl;
                    success = false;
                }
            }

            if (pWSAConnect) {
                MH_STATUS status = MH_CreateHook(pWSAConnect, WSAConnect_Hook, (void**)&Original_WSAConnect);
                if (status == MH_OK) {
                    MH_EnableHook(pWSAConnect);
                    std::cout << "[WS2Hooks] WSAConnect hook installed" << std::endl;
                } else {
                    std::cerr << "[WS2Hooks] Failed to hook WSAConnect: " << status << std::endl;
                    success = false;
                }
            }

            if (pGetpeername) {
                MH_STATUS status = MH_CreateHook(pGetpeername, getpeername_Hook, (void**)&Original_getpeername);
                if (status == MH_OK) {
                    MH_EnableHook(pGetpeername);
                    std::cout << "[WS2Hooks] getpeername hook installed" << std::endl;
                } else {
                    std::cerr << "[WS2Hooks] Failed to hook getpeername: " << status << std::endl;
                    success = false;
                }
            }

            g_WS2HooksInstalled.store(success);
            std::cout << "[WS2Hooks] WS2_32 hooks installation " << (success ? "complete" : "partial") << std::endl;
            return success ? TRUE : FALSE;
        }
    }

    BOOL Hook() {
        std::cout << "[WinsockHook] ============================================" << std::endl;
        std::cout << "[WinsockHook] Initializing multi-layer winsock hook..." << std::endl;
        std::cout << "[WinsockHook] Target hostname: " << config::HostName << std::endl;
        std::cout << "[WinsockHook] ============================================" << std::endl;

        // First, check if Winsock is already initialized (timing issue detection)
        WSADATA wsaData;
        int wsaInitResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (wsaInitResult == 0) {
            std::cout << "[WinsockHook] WARNING: Winsock already initialized or just initialized now" << std::endl;
            std::cout << "[WinsockHook] This may indicate WSPStartup was already called before our hook!" << std::endl;
            WSACleanup();
        } else {
            std::cout << "[WinsockHook] Winsock not yet initialized (good for WSP hook)" << std::endl;
        }

        // ====================================================================
        // Layer 1: WS2_32 Direct API Hooks (Primary - Most Reliable)
        // ====================================================================
        std::cout << "[WinsockHook] Installing Layer 1: WS2_32 direct API hooks..." << std::endl;
        BOOL ws2Result = ws2_fallback::InstallWS2Hooks();
        if (!ws2Result) {
            std::cerr << "[WinsockHook] WARNING: WS2_32 hooks partially failed" << std::endl;
        }

        // ====================================================================
        // Layer 2: WSP Hook (Secondary - May not trigger if already initialized)
        // ====================================================================
        std::cout << "[WinsockHook] Installing Layer 2: WSP hooks..." << std::endl;

        static decltype(&WSPStartup) _WSPStartup = decltype(&WSPStartup)(hook::GetFuncAddress("MSWSOCK", "WSPStartup"));

        if (!_WSPStartup) {
            std::cerr << "[WinsockHook] WARNING: Failed to get WSPStartup address from MSWSOCK.dll" << std::endl;
            std::cerr << "[WinsockHook] WSP layer hook will not be installed, relying on WS2_32 hooks only" << std::endl;
            // Don't fail - we have WS2_32 hooks as fallback
            g_HookInitialized.store(true);
            return TRUE;
        }
        std::cout << "[WinsockHook] Found WSPStartup at: " << (void*)_WSPStartup << std::endl;

        WSPStartupAddr = (WSPStartup_t)hook::GetFuncAddress("MSWSOCK", "WSPStartup");
        if (!WSPStartupAddr) {
            std::cerr << "[WinsockHook] WARNING: Failed to get WSPStartup address (second call)" << std::endl;
            g_HookInitialized.store(true);
            return TRUE;  // WS2_32 hooks should work
        }
        std::cout << "[WinsockHook] WSPStartupAddr: " << (void*)WSPStartupAddr << std::endl;

        decltype(&WSPStartup) Hook = [](WORD wVersionRequested, LPWSPDATA lpWSPData, LPWSAPROTOCOL_INFOW lpProtocolInfo, WSPUPCALLTABLE UpcallTable, LPWSPPROC_TABLE lpProcTable) -> int {
            std::cout << "[WinsockHook] *** WSPStartup hook triggered! ***" << std::endl;
            std::cout << "[WinsockHook] Version requested: " << LOBYTE(wVersionRequested) << "." << HIBYTE(wVersionRequested) << std::endl;

            if (lpProtocolInfo) {
                std::wcout << L"[WinsockHook] Protocol: " << lpProtocolInfo->szProtocol << std::endl;
                std::cout << "[WinsockHook] Address Family: " << lpProtocolInfo->iAddressFamily
                          << ", Socket Type: " << lpProtocolInfo->iSocketType
                          << ", Protocol: " << lpProtocolInfo->iProtocol << std::endl;
            }

            g_WSPStartupCalled.store(true);

            int ret = _WSPStartup(wVersionRequested, lpWSPData, lpProtocolInfo, UpcallTable, lpProcTable);
            if (ret != 0) {
                std::cerr << "[WinsockHook] ERROR: Original WSPStartup failed with: " << ret << std::endl;
                return ret;
            }

            std::cout << "[WinsockHook] Original WSPStartup succeeded, installing WSP Connect/GetPeerName hooks" << std::endl;
            g_ProcTable = *lpProcTable;

            lpProcTable->lpWSPConnect = WSPConnect_Hook;
            lpProcTable->lpWSPGetPeerName = WSPGetPeerName_Hook;

            std::cout << "[WinsockHook] WSP hooks installed successfully" << std::endl;
            return ret;
        };

        MH_STATUS createStatus = MH_CreateHook(WSPStartupAddr, Hook, reinterpret_cast<void**>(&_WSPStartup));
        if (createStatus != MH_OK) {
            std::cerr << "[WinsockHook] WARNING: MH_CreateHook for WSPStartup failed with status: " << createStatus << std::endl;
            std::cerr << "[WinsockHook] Relying on WS2_32 hooks only" << std::endl;
            g_HookInitialized.store(true);
            return TRUE;
        }
        std::cout << "[WinsockHook] MH_CreateHook for WSPStartup succeeded" << std::endl;

        MH_STATUS enableStatus = MH_EnableHook(WSPStartupAddr);
        if (enableStatus != MH_OK) {
            std::cerr << "[WinsockHook] WARNING: MH_EnableHook for WSPStartup failed with status: " << enableStatus << std::endl;
            std::cerr << "[WinsockHook] Relying on WS2_32 hooks only" << std::endl;
            g_HookInitialized.store(true);
            return TRUE;
        }
        std::cout << "[WinsockHook] MH_EnableHook for WSPStartup succeeded" << std::endl;

        g_HookInitialized.store(true);
        std::cout << "[WinsockHook] ============================================" << std::endl;
        std::cout << "[WinsockHook] Multi-layer hook initialization complete!" << std::endl;
        std::cout << "[WinsockHook] Layer 1 (WS2_32): " << (g_WS2HooksInstalled.load() ? "ACTIVE" : "PARTIAL") << std::endl;
        std::cout << "[WinsockHook] Layer 2 (WSP): READY (will activate on first Winsock call)" << std::endl;
        std::cout << "[WinsockHook] ============================================" << std::endl;
        return TRUE;
    }
}
