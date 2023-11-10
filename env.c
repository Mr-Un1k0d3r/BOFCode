#include <windows.h>
#include <processenv.h>
#include <stdio.h>
#include "beacon.h"

#define printf(format, args...) { BeaconPrintf(CALLBACK_OUTPUT, format, ## args); }
DECLSPEC_IMPORT FARPROC WINAPI kernel32$GetProcAddress(HANDLE, CHAR*);
DECLSPEC_IMPORT HANDLE WINAPI kernel32$LoadLibraryA(CHAR*);

FARPROC Resolver(CHAR *lib, CHAR *func) {
	FARPROC ptr = kernel32$GetProcAddress(kernel32$LoadLibraryA(lib), func);
	return ptr;
}

VOID go() {
	FARPROC GetEnvironmentStrings = Resolver("kernel32.dll", "GetEnvironmentStrings");
	FARPROC strlen = Resolver("msvcrt.dll", "strlen");
	FARPROC FreeEnvironmentStrings = Resolver("kernel32.dll", "FreeEnvironmentStringsA");
	LPCH env = GetEnvironmentStrings();
	LPCH start = env;
	while(env[0] != 0x00) {
		printf("%s\n", env);
		env += strlen(env) + 1;
	}
	
	FreeEnvironmentStrings(start);
}
