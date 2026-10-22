#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <windows.h>
#include "listener_arrival_win32.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(int argc,char **argv) {
    WSADATA data; assert(WSAStartup(MAKEWORD(2,2),&data)==0);
    const char *nonce="0123456789abcdef0123456789abcdef";
    char response[256]; snprintf(response,sizeof(response),"HTTP/1.1 200 OK\r\nX-AdAway-Listener-Probe: %s\r\n\r\nadaway-listener:%s",nonce,nonce);
    assert(arrival_valid_receipt(response,nonce));
    const char *lower="HTTP/1.1 200 OK\r\nx-adaway-listener-probe: 0123456789abcdef0123456789abcdef\r\n\r\nadaway-listener:0123456789abcdef0123456789abcdef";
    assert(arrival_valid_receipt(lower,nonce));
    assert(!arrival_valid_receipt(response,"ffffffffffffffffffffffffffffffff"));
    assert(!arrival_valid_receipt("HTTP/1.1 200 OK\r\n\r\ngeneric block",nonce));
    response[9]='3'; assert(!arrival_valid_receipt(response,nonce));
    assert(arrival_domain_valid("ad.doubleclick.net")); assert(arrival_domain_valid("ADS.example.com."));
    const char *invalid[]={"localhost","127.0.0.1","https://ads.example.com","ads.example.com/path","ads.example.com:80","ads.example.com\r\nHost: evil","-ads.example.com"};
    for (size_t i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++) assert(!arrival_domain_valid(invalid[i]));
    /* No listener targets and invalid management port: report semantics can be
       checked without opening sockets, changing DNS or importing a CA. */
    struct arrival_config scope={0}; scope.pair=true; scope.http=28080; scope.https=28443;
    wchar_t scope_report[6144]; arrival_report(&scope,"","",scope_report,6144);
    assert(wcsstr(scope_report,L"HTTP/28080、HTTPS/28443"));
    assert(wcsstr(scope_report,L"HTTP/28080 回执不证明默认 HTTP/80 可达"));
    assert(wcsstr(scope_report,L"HTTPS/28443 回执不证明默认 HTTPS/443 可达"));
    scope.http=80; scope.https=443; arrival_report(&scope,"","",scope_report,6144);
    assert(!wcsstr(scope_report,L"回执不证明默认"));
    if (argc==5 && !strcmp(argv[1],"--tls")) {
        struct arrival_tls_result result=arrival_tls(argv[2],atoi(argv[3]),argv[4]);
        printf("tls_state=%d protocol=%s verify=%ld\n",result.state,result.protocol,result.verify_error);
        WSACleanup(); return result.state==ARRIVAL_TLS_RECEIPT ? 0 : 20+(int)result.state;
    }
    if (argc==6 && !strcmp(argv[1],"--report")) {
        struct arrival_config config={0}; snprintf(config.ip,sizeof(config.ip),"%s",argv[2]); config.http=atoi(argv[3]); config.stats=atoi(argv[4]);
        wchar_t report[6144]; char utf8[24576]; arrival_report(&config,argv[5],"",report,6144);
        if (!WideCharToMultiByte(CP_UTF8,0,report,-1,utf8,sizeof(utf8),NULL,NULL)) return 5;
        puts(utf8); WSACleanup(); return 0;
    }
    if (argc==3) { int received=arrival_receipt(argv[1],atoi(argv[2])); WSACleanup(); return received ? 0 : 4; }
    puts("Windows arrival: nonce, generic-page/redirect rejection and DNS input policy passed");
    WSACleanup(); return 0;
}
