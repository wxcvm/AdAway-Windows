/* The complete production report/DNS/HTTP code, with only the system resolver
   and unavailable TLS replaced. No Hosts, trust-store or network configuration. */
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "listener_arrival_win32.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while (0)
static ADDRINFOW records[140];
static SOCKADDR_STORAGE addresses[140];
static unsigned record_count;
static volatile LONG resolver_calls,http4,http6;
static wchar_t expected_name[256]=L"answers.fixture.invalid.";
static int fixture_resolve(PCWSTR name,PCWSTR service,const ADDRINFOW *hints,PADDRINFOW *answers) {
    CHECK(!wcscmp(name,expected_name)); CHECK(!service && hints->ai_family==AF_UNSPEC);
    InterlockedIncrement(&resolver_calls); *answers=record_count ? records : NULL; return 0;
}
static void fixture_free(ADDRINFOW *answers) { CHECK(!answers || answers==records); }
#define GetAddrInfoW fixture_resolve
#define FreeAddrInfoW fixture_free
#include "listener_arrival_win32.c"
#undef GetAddrInfoW
#undef FreeAddrInfoW
struct arrival_tls_result arrival_tls_cancel(const char *ip,int port,const char *host,const struct arrival_cancel *cancel) {
    (void)ip; (void)port; (void)host; (void)cancel;
    struct arrival_tls_result result={0}; return result;
}
struct arrival_tls_result arrival_tls(const char *ip,int port,const char *host) { return arrival_tls_cancel(ip,port,host,NULL); }
static void add(const char *ip) {
    CHECK(record_count<140); unsigned i=record_count++;
    ADDRINFOW *row=&records[i]; memset(row,0,sizeof(*row)); memset(&addresses[i],0,sizeof(addresses[i]));
    row->ai_family=strchr(ip,':') ? AF_INET6 : AF_INET; row->ai_socktype=SOCK_STREAM;
    row->ai_addr=(struct sockaddr *)&addresses[i]; row->ai_addr->sa_family=(ADDRESS_FAMILY)row->ai_family;
    row->ai_addrlen=row->ai_family==AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    void *raw=row->ai_family==AF_INET ? (void *)&((struct sockaddr_in *)row->ai_addr)->sin_addr : (void *)&((struct sockaddr_in6 *)row->ai_addr)->sin6_addr;
    CHECK(inet_pton(row->ai_family,ip,raw)==1);
    if (i) records[i-1].ai_next=row;
}
static SOCKET listeners[2]; static HANDLE stop;
static DWORD WINAPI serve(void *unused) {
    (void)unused;
    while (WaitForSingleObject(stop,0)!=WAIT_OBJECT_0) {
        fd_set ready; FD_ZERO(&ready); FD_SET(listeners[0],&ready); FD_SET(listeners[1],&ready);
        struct timeval budget={0,50000}; int status=select(0,&ready,NULL,NULL,&budget); CHECK(status!=SOCKET_ERROR);
        for (int i=0;i<2;i++) if (FD_ISSET(listeners[i],&ready)) {
            SOCKET client=accept(listeners[i],NULL,NULL); CHECK(client!=INVALID_SOCKET);
            DWORD timeout=1000; CHECK(!setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(timeout)));
            char request[1024]={0}; int used=0;
            while (used<(int)sizeof(request)-1 && !strstr(request,"\r\n\r\n")) {
                int got=recv(client,request+used,(int)sizeof(request)-1-used,0); CHECK(got>0); used+=got; request[used]=0;
            }
            const char *prefix="GET /adaway-listener-probe/"; CHECK(!strncmp(request,prefix,strlen(prefix)));
            char nonce[33]; memcpy(nonce,request+strlen(prefix),32); nonce[32]=0;
            if (strstr(request,"Host: answers.fixture.invalid\r\n")) InterlockedIncrement(i ? &http6 : &http4);
            char response[256]; int length=snprintf(response,sizeof(response),"HTTP/1.1 200 OK\r\nX-AdAway-Listener-Probe: %s\r\nConnection: close\r\n\r\nadaway-listener:%s",nonce,nonce);
            CHECK(send(client,response,length,0)==length); closesocket(client);
        }
    }
    return 0;
}
static int listen_pair(void) {
    int port=0;
    for (int i=0;i<2;i++) {
        int family=i ? AF_INET6 : AF_INET; listeners[i]=socket(family,SOCK_STREAM,IPPROTO_TCP); CHECK(listeners[i]!=INVALID_SOCKET);
        if (i) { DWORD only=1; CHECK(!setsockopt(listeners[i],IPPROTO_IPV6,IPV6_V6ONLY,(char *)&only,sizeof(only))); }
        SOCKADDR_INET address; CHECK(ac_parse(i ? "::1" : "127.0.0.1",&address));
        if (i) address.Ipv6.sin6_port=htons((u_short)port);
        int size=i ? sizeof(address.Ipv6) : sizeof(address.Ipv4);
        CHECK(!bind(listeners[i],(struct sockaddr *)&address,size)); CHECK(!listen(listeners[i],8));
        CHECK(!getsockname(listeners[i],(struct sockaddr *)&address,&size));
        if (!i) port=ntohs(address.Ipv4.sin_port);
    }
    return port;
}
static wchar_t report[6144];
static void run(struct arrival_config *config) {
    InterlockedExchange(&http4,0); InterlockedExchange(&http6,0);
    LONG before=resolver_calls;
    CHECK(arrival_report_cancel(config,"answers.fixture.invalid","",report,6144,NULL));
    CHECK(resolver_calls==before+1); CHECK(wcsstr(report,L"本次检测完成"));
    CHECK(wcsstr(report,L"UTC ") && wcsstr(report,L"非待重启设置；不等于服务就绪"));
}
int main(void) {
    WSADATA winsock; CHECK(!WSAStartup(MAKEWORD(2,2),&winsock));
    struct arrival_config config={0}; config.pair=true; config.http=listen_pair();
    strcpy(config.ip,"127.0.0.1"); strcpy(config.ipv6,"::1");
    stop=CreateEventW(NULL,TRUE,FALSE,NULL); CHECK(stop);
    HANDLE server=CreateThread(NULL,0,serve,NULL,0,NULL); CHECK(server);
    /* More than the old row limit of duplicate A records cannot hide AAAA. */
    for (int i=0;i<20;i++) add("127.0.0.1");
    add("0:0:0:0:0:0:0:1"); add("::1");
    run(&config); CHECK(http4==1 && http6==1);
    CHECK(wcsstr(report,L"已检查 2 个不同地址，2 个匹配本机监听；跳过 20 个重复"));
    CHECK(wcsstr(report,L"应答检查完成"));
    record_count=0;
    for (int i=1;i<=16;i++) { char ip[64]; snprintf(ip,sizeof(ip),"198.51.100.%d",i); add(ip); }
    add("::1"); run(&config); CHECK(!http4 && http6==1);
    CHECK(wcsstr(report,L"仍有结果未检查"));
    record_count=0; add("127.0.0.1"); add("::1");
    config.ipv6[0]=0; run(&config); CHECK(http4==1 && !http6);
    CHECK(wcsstr(report,L"未启用 IPv6 监听，未连接")); CHECK(wcsstr(report,L"IPv6=disabled"));
    record_count=0; add("::ffff:127.0.0.1"); add("127.0.0.1"); run(&config);
    CHECK(http4==1 && !http6);
    CHECK(wcsstr(report,L"1 个 IPv4-mapped IPv6 记录已归一为 IPv4 路径；不代表 IPv6 验证"));
    CHECK(wcsstr(report,L"已检查 1 个不同地址，1 个匹配本机监听；跳过 1 个重复"));
    record_count=0; add("127.0.0.2"); add("198.51.100.10"); run(&config); CHECK(!http4 && !http6);
    CHECK(wcsstr(report,L"未匹配本次启动监听地址，未连接"));
    strcpy(config.ip,"0.0.0.0"); record_count=0; add("198.51.100.10"); run(&config);
    CHECK(!http4 && !http6 && wcsstr(report,L"地址不属于本机，未连接"));
    record_count=0; add("127.0.0.1"); records[0].ai_addrlen=1; run(&config);
    CHECK(!http4 && wcsstr(report,L"1 个无效记录") && wcsstr(report,L"没有可用的 A/AAAA 地址"));
    record_count=0; run(&config); CHECK(!http4 && !http6 && wcsstr(report,L"没有可用的 A/AAAA 地址"));
    record_count=0;
    for (int i=1;i<=17;i++) { char ip[64]; snprintf(ip,sizeof(ip),"198.51.100.%d",i); add(ip); }
    run(&config); CHECK(wcsstr(report,L"已检查 16 个不同地址") && wcsstr(report,L"仍有结果未检查"));
    CHECK(!http4 && !http6);
    record_count=0; for (int i=0;i<130;i++) add("127.0.0.1");
    run(&config); CHECK(http4==1 && !http6);
    CHECK(wcsstr(report,L"127 个重复") && wcsstr(report,L"仍有结果未检查"));
    /* Same production report entry and capacity policy: metadata fits, later
       stages overflow, and an unqualified completion must never be visible. */
    wchar_t short_report[320];
    CHECK(arrival_report_cancel(&config,"answers.fixture.invalid","",short_report,320,NULL));
    CHECK(wcsstr(short_report,L"结果已截断")); CHECK(!wcsstr(short_report,L"本次检测完成"));
    CHECK(wcslen(short_report)<320);
    char long_domain[254]; memset(long_domain,'a',253); long_domain[253]=0;
    long_domain[63]='.'; long_domain[127]='.'; long_domain[191]='.';
    CHECK(arrival_domain_valid(long_domain));
    CHECK(MultiByteToWideChar(CP_UTF8,0,long_domain,-1,expected_name,256)); expected_name[253]=L'.'; expected_name[254]=0;
    record_count=0;
    for (int i=1;i<=17;i++) { char ip[64]; snprintf(ip,sizeof(ip),"198.51.100.%d",i); add(ip); }
    CHECK(arrival_report_cancel(&config,long_domain,long_domain,report,6144,NULL));
    CHECK(wcsstr(report,L"结果已截断") && !wcsstr(report,L"本次检测完成") && wcslen(report)<6144);
    CHECK(SetEvent(stop)); CHECK(WaitForSingleObject(server,2000)==WAIT_OBJECT_0);
    CloseHandle(server); CloseHandle(stop); closesocket(listeners[0]); closesocket(listeners[1]); WSACleanup();
    FILE *evidence=fopen("arrival-answers-results.json","wb"); CHECK(evidence);
    CHECK(fputs("{\"passed\":true,\"productionReportEntry\":true,\"systemResolverInjected\":true,\"realDualStackHttpReceipts\":true,\"duplicateDoesNotHideAAAA\":true,\"mappedDeduplicatedAsIPv4\":true,\"familyDisabledNotProbed\":true,\"remoteNotConnected\":true,\"malformedAndEmptyAnswers\":true,\"uniqueLimit\":16,\"scanLimit\":128,\"budgetOmissionReported\":true,\"appliedSnapshotMetadata\":true,\"longReportTruncationMarked\":true,\"tlsNotExercised\":true,\"hostNetworkChanges\":false}\n",evidence)>=0); CHECK(!fclose(evidence));
    puts("PASS: actual report entry, injected DNS answers, real dual-stack HTTP receipts, deduplication, family/address gating, bounded omissions and snapshot metadata");
    return 0;
}
