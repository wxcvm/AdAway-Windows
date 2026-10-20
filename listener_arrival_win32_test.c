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
    assert(!arrival_valid_receipt(response,"ffffffffffffffffffffffffffffffff"));
    assert(!arrival_valid_receipt("HTTP/1.1 200 OK\r\n\r\ngeneric block",nonce));
    response[9]='3'; assert(!arrival_valid_receipt(response,nonce));
    assert(arrival_domain_valid("ad.doubleclick.net")); assert(arrival_domain_valid("ADS.example.com."));
    const char *invalid[]={"localhost","127.0.0.1","https://ads.example.com","ads.example.com/path","ads.example.com:80","ads.example.com\r\nHost: evil","-ads.example.com"};
    for (size_t i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++) assert(!arrival_domain_valid(invalid[i]));
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
