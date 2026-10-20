#ifndef ADAWAY_LISTENER_STARTUP_WIN32_H
#define ADAWAY_LISTENER_STARTUP_WIN32_H
#include "managed_listener_address_win32.h"
#include "listener_pair.h"
#include <shellapi.h>
#include <stdbool.h>

/* A pair is prepared as one transaction. Roll back only addresses added by
 * this attempt; pre-existing addresses and all physical interfaces are kept. */
static inline DWORD ms_prepare(const char *ipv4,const char *ipv6,int http,int https) {
    const char *targets[2]={ipv4,ipv6}; bool added[2]={false,false};
    DWORD status=NO_ERROR;
    for (int i=0;i<2;i++) {
        if (!*targets[i]) continue;
        char normalized[64];
        if (la_normalize(targets[i],normalized)!=(i ? 6 : 4)) { status=ERROR_INVALID_PARAMETER; break; }
        int error=0,h=la_probe(targets[i],http,&error),s=la_probe(targets[i],https,&error);
        if (h==2 && s==2) {
            status=ma_add(targets[i]);
            if (status==NO_ERROR) added[i]=true;
            else if (status==ERROR_OBJECT_ALREADY_EXISTS) status=NO_ERROR;
            if (status!=NO_ERROR) break;
            h=la_probe(targets[i],http,&error); s=la_probe(targets[i],https,&error);
        }
        if (h || s) { status=MA_PORT_CONFLICT; break; }
    }
    if (status) for (int i=1;i>=0;i--) if (added[i] && ma_remove(targets[i])!=NO_ERROR) status=MA_CLEANUP_FAILED;
    return status;
}

static inline int ms_cli(int argc,char **argv) {
    if (argc<2 || strcmp(argv[1],"--ensure-listener-addresses")) return -1;
    if (argc!=6) return ERROR_INVALID_PARAMETER;
    int http=la_port(argv[4]),https=la_port(argv[5]);
    if (!http || !https || http==https) return ERROR_INVALID_PARAMETER;
    lp_pair pair={0};
    if (!lp_set(&pair,"--listen-ipv4",argv[2]) || !lp_set(&pair,"--listen-ipv6",argv[3])
            || (!*pair.ipv4 && !*pair.ipv6)) return ERROR_INVALID_PARAMETER;
    WSADATA data; if (WSAStartup(MAKEWORD(2,2),&data)) return ERROR_NOT_SUPPORTED;
    DWORD status=ms_prepare(pair.ipv4,pair.ipv6,http,https);
    WSACleanup(); return (int)status;
}

/* Called once per real server startup, never by diagnostics or editing.
 * Fixed arguments, no paths/commands from settings. Normal server stays at
 * its original privilege level. UAC is needed only while addresses are absent. */
static inline DWORD ms_startup(const lp_pair *saved,const char *legacy,bool all,int http,int https) {
    lp_pair pair=*saved;
    if (!pair.explicit_pair) {
        char normalized[64]; int family=la_normalize(legacy,normalized);
        snprintf(pair.ipv4,64,"%s",family ? family==4 ? normalized : "" : all ? "0.0.0.0" : "127.0.0.1");
        snprintf(pair.ipv6,64,"%s",family ? family==6 ? normalized : "" : all ? "::" : "::1");
    }
    WSADATA data; if (WSAStartup(MAKEWORD(2,2),&data)) return ERROR_NOT_SUPPORTED;
    const char *targets[2]={pair.ipv4,pair.ipv6}; bool missing=false;
    DWORD status=NO_ERROR;
    for (int i=0;i<2;i++) if (*targets[i]) {
        int error=0,h=la_probe(targets[i],http,&error),s=la_probe(targets[i],https,&error);
        if (h==2 && s==2) {
            SOCKADDR_INET address;
            if (!ma_address(targets[i],&address)) { status=ERROR_INVALID_ADDRESS; break; }
            missing=true;
        } else if (h || s) { status=MA_PORT_CONFLICT; break; }
    }
    WSACleanup();
    if (status || !missing) return status;
    wchar_t exe[32768],args[256]; DWORD length=GetModuleFileNameW(NULL,exe,32768);
    if (!length || length>=32768) return ERROR_FILENAME_EXCED_RANGE;
    swprintf(args,256,L"--ensure-listener-addresses %hs %hs %d %d",
            *pair.ipv4 ? pair.ipv4 : "-",*pair.ipv6 ? pair.ipv6 : "-",http,https);
    SHELLEXECUTEINFOW request; memset(&request,0,sizeof(request)); request.cbSize=sizeof(request);
    request.fMask=SEE_MASK_NOCLOSEPROCESS|SEE_MASK_NOASYNC|SEE_MASK_FLAG_NO_UI;
    request.lpVerb=L"runas"; request.lpFile=exe; request.lpParameters=args; request.nShow=SW_HIDE;
    if (!ShellExecuteExW(&request)) return GetLastError();
    if (!request.hProcess) return ERROR_INVALID_HANDLE;
    /* Do not time out and leave an elevated helper creating addresses later. */
    DWORD wait=WaitForSingleObject(request.hProcess,INFINITE);
    if (wait!=WAIT_OBJECT_0 || !GetExitCodeProcess(request.hProcess,&status)) status=GetLastError();
    CloseHandle(request.hProcess); return status;
}
#endif
