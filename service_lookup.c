// Compile BOF: gcc service_lookup.c -c -o service_lookup.x64.o -DCOMPILE_BOF
// Compile EXE: gcc service_lookup.c -o service_lookup.exe
#include <windows.h>
#include <stdio.h>

#ifdef COMPILE_BOF

#warning "Compiling the BOF version of the code"

#include "beacon.h"

#define printf(format, args...) { BeaconPrintf(CALLBACK_OUTPUT, format, ## args); }

DECLSPEC_IMPORT FARPROC WINAPI kernel32$GetProcAddress(HANDLE, CHAR*);
DECLSPEC_IMPORT HANDLE WINAPI kernel32$LoadLibraryA(CHAR*);

FARPROC Resolver(CHAR *lib, CHAR *func) {
    FARPROC ptr = kernel32$GetProcAddress(kernel32$LoadLibraryA(lib), func);
    printf("%s!%s at 0x%p\n", lib, func, ptr);
    return ptr;
}

#define IMPORT_RESOLVE FARPROC snprintf = Resolver("msvcrt", "_snprintf"); \
    FARPROC strcmp = Resolver("msvcrt", "strcmp"); \
    FARPROC LogonUserA = Resolver("advapi32", "LogonUserA"); \
    FARPROC GetLastError = Resolver("kernel32", "GetLastError");  \
    FARPROC ImpersonateLoggedOnUser = Resolver("advapi32", "ImpersonateLoggedOnUser"); \
    FARPROC LookupAccountNameA = Resolver("advapi32", "LookupAccountNameA"); \
    FARPROC CloseHandle = Resolver("kernel32", "CloseHandle"); \

#else

#warning "Compiling the EXE version of the code"
#define IMPORT_RESOLVE ""

#endif

// this is designed to "bypass" the gcc main being renamed to __main
int real_main(int argc, char **argv) {
    IMPORT_RESOLVE;

    if(argc < 3) {
        printf("Usage: %s host(. for local) servicename domain(optional) username(optional) password(optional)\n", argv[0]);
        return 0;
    }

    BOOL bResult = FALSE;
    CHAR *hostname = argv[1];
    CHAR *userService = argv[2];
    CHAR serviceName[256];
    snprintf(serviceName, 255, "Nt Service\\%s", argv[2]);

    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD dwSid = sizeof(sid);
    CHAR domainName[256];
    DWORD dwDomainName = sizeof(domainName);
    SID_NAME_USE snu;

    if(strcmp(hostname, ".") == 0) {
        hostname = NULL;
    }

    if(argc == 6) {
        CHAR* domain = argv[3];
        CHAR* username = argv[4];
        CHAR* password = argv[5];

        HANDLE hToken = NULL;
        printf("Username was provided attempting to call LogonUserA.\n");
        bResult = LogonUserA(username, domain, password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &hToken);
        if(!bResult) {
            printf("LogonUserA failed %ld\n", GetLastError());
            return 0;
        }

        bResult = FALSE;
        bResult = ImpersonateLoggedOnUser(hToken);
        if(!bResult) {
            printf("ImpersonateLoggedOnUser failed %ld\n", GetLastError());
            return 0;
        }
        CloseHandle(hToken);

    }

    if(LookupAccountNameA(hostname, serviceName, sid, &dwSid, domainName, &dwDomainName, &snu)) {  
        if(hostname == NULL) {
            printf("%s was found on the local system.\n", userService);
        } else {
            printf("%s was found on the remote host (%s).\n", userService, hostname);
        }
    }

    return 0;
}

#ifdef COMPILE_BOF

int go(char* args, int length) {
    datap p;
    BeaconDataParse(&p, args, length);
    CHAR *argv[6];
    argv[0] = NULL;
    DWORD i = 1;
    for(i; i < 6; i++) {
        argv[i] = BeaconDataExtract(&p, NULL);
    }

    printf("Running against %s searching for %s\n", argv[1], argv[2]);

    if(strcmp(argv[3], "") == 0) {
        real_main(3, argv);
    } else {
        real_main(6, argv);
    }
    
    return 0;
}

#else

int main(int argc, char **argv) {
    real_main(argc, argv);
    return 0;
}

#endif
