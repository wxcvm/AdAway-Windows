#define _WIN32_WINNT 0x0A00
#define UNICODE
#define _UNICODE
#include "managed_listener_address_win32.h"
#include "listener_arrival_win32.h"
#include "traffic_observer_win32.h"
#include <bcrypt.h>
#include <stdarg.h>
#include <ctype.h>

bool arrival_domain_valid(const char *domain) {
    if (!domain || !*domain) return false;
    size_t length=strlen(domain); if (length>254) return false;
    if (domain[length-1]=='.') length--;
    if (!length || length>253) return false;
    char ip[64],literal[254]; memcpy(literal,domain,length); literal[length]=0;
    if (la_normalize(literal,ip)) return false;
    size_t label=0; int dots=0;
    for (size_t i=0;i<length;i++) {
        unsigned char ch=(unsigned char)domain[i];
        if (ch=='.') { if (!label || domain[i-1]=='-') return false; label=0; dots++; }
        else {
            if (!(ch>='a' && ch<='z') && !(ch>='A' && ch<='Z') && !(ch>='0' && ch<='9') && ch!='-') return false;
            if ((!label && ch=='-') || ++label>63) return false;
        }
    }
    return dots && label && domain[length-1]!='-';
}

bool arrival_valid_receipt(const char *response,const char *nonce) {
    if (!response || !nonce || strlen(nonce)!=32 || strspn(nonce,"0123456789abcdef")!=32) return false;
    const char *body=strstr(response,"\r\n\r\n"); if (!body || strncmp(response,"HTTP/1.1 200 ",13)) return false;
    char expected[64]; snprintf(expected,sizeof(expected),"adaway-listener:%s",nonce);
    if (strcmp(body+4,expected)) return false;
    static const char prefix[]="X-AdAway-Listener-Probe: ";
    const char *line=strstr(response,"\r\n");
    while (line && line<body) {
        line+=2; const char *end=strstr(line,"\r\n");
        if (!end || end>body) break;
        if ((size_t)(end-line)==sizeof(prefix)-1+32 && !_strnicmp(line,prefix,sizeof(prefix)-1)
                && !memcmp(line+sizeof(prefix)-1,nonce,32)) return true;
        line=end;
    }
    return false;
}

static bool ac_parse(const char *ip,SOCKADDR_INET *address) {
    char normalized[64]; int version=la_normalize(ip,normalized); if (!version) return false;
    memset(address,0,sizeof(*address)); address->si_family=version==4 ? AF_INET : AF_INET6;
    return inet_pton(address->si_family,normalized,version==4 ? (void *)&address->Ipv4.sin_addr : (void *)&address->Ipv6.sin6_addr)==1;
}

bool arrival_local_address(const char *ip) {
    SOCKADDR_INET address; if (!ac_parse(ip,&address)) return false;
    if (address.si_family==AF_INET && ((const unsigned char *)&address.Ipv4.sin_addr)[0]==127) return true;
    static const unsigned char loop[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if (address.si_family==AF_INET6 && !memcmp(&address.Ipv6.sin6_addr,loop,16)) return true;
    MIB_UNICASTIPADDRESS_ROW row; return ma_find(&address,&row)==NO_ERROR;
}

static bool ac_wait(SOCKET client,bool writing,ULONGLONG deadline,const struct arrival_cancel *cancel) {
    while (!arrival_cancel_requested(cancel)) {
        ULONGLONG now=GetTickCount64(); if (now>=deadline) return false;
        ULONGLONG remaining=deadline-now; if (remaining>50) remaining=50;
        fd_set ready,errors; FD_ZERO(&ready); FD_ZERO(&errors); FD_SET(client,&ready); FD_SET(client,&errors);
        struct timeval budget={0,(long)remaining*1000};
        int status=select(0,writing ? NULL : &ready,writing ? &ready : NULL,&errors,&budget);
        if (status==SOCKET_ERROR || FD_ISSET(client,&errors)) return false;
        if (status>0) return !arrival_cancel_requested(cancel);
    }
    return false;
}

static bool ac_receipt_host(const char *ip,int port,const char *host,const struct arrival_cancel *cancel) {
    if (arrival_cancel_requested(cancel)) return false;
    SOCKADDR_INET address; if (!ac_parse(ip,&address) || !arrival_local_address(ip) || port<1 || port>65535) return false;
    if (strcmp(host,"localhost") && !arrival_domain_valid(host)) return false;
    unsigned char random[16]; if (BCryptGenRandom(NULL,random,sizeof(random),BCRYPT_USE_SYSTEM_PREFERRED_RNG)!=0) return false;
    char nonce[33]; for (int i=0;i<16;i++) snprintf(nonce+i*2,3,"%02x",random[i]);
    SOCKET client=socket(address.si_family,SOCK_STREAM,IPPROTO_TCP); if (client==INVALID_SOCKET) return false;
    u_long nonblocking=1;
    if (ioctlsocket(client,FIONBIO,&nonblocking)) { closesocket(client); return false; }
    if (address.si_family==AF_INET) address.Ipv4.sin_port=htons((u_short)port);
    else address.Ipv6.sin6_port=htons((u_short)port);
    ULONGLONG deadline=GetTickCount64()+2000; bool valid=false;
    int result=connect(client,(struct sockaddr *)&address,address.si_family==AF_INET ? sizeof(address.Ipv4) : sizeof(address.Ipv6));
    if (result==SOCKET_ERROR && WSAGetLastError()!=WSAEWOULDBLOCK) goto done;
    ULONGLONG connect_deadline=GetTickCount64()+800;
    if (!ac_wait(client,true,connect_deadline,cancel)) goto done;
    int error=0,size=sizeof(error); if (getsockopt(client,SOL_SOCKET,SO_ERROR,(char *)&error,&size) || error) goto done;
    char request[512]; int length=snprintf(request,sizeof(request),"GET /adaway-listener-probe/%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",nonce,host);
    int sent=0;
    while (sent<length && !arrival_cancel_requested(cancel) && GetTickCount64()<deadline) {
        if (!ac_wait(client,true,deadline,cancel)) goto done;
        int count=send(client,request+sent,length-sent,0);
        if (count==SOCKET_ERROR && WSAGetLastError()==WSAEWOULDBLOCK) continue;
        if (count<=0) goto done;
        sent+=count;
    }
    if (sent!=length) goto done;
    char response[4097]; size_t used=0;
    while (used<sizeof(response)-1 && !arrival_cancel_requested(cancel) && GetTickCount64()<deadline) {
        if (!ac_wait(client,false,deadline,cancel)) goto done;
        int count=recv(client,response+used,(int)(sizeof(response)-1-used),0);
        if (count==SOCKET_ERROR && WSAGetLastError()==WSAEWOULDBLOCK) continue;
        if (count<=0) break;
        used+=(size_t)count; response[used]=0;
        if (arrival_valid_receipt(response,nonce)) { valid=true; break; }
    }
done:
    closesocket(client); return valid && !arrival_cancel_requested(cancel);
}

bool arrival_receipt_cancel(const char *ip,int port,const struct arrival_cancel *cancel) {
    return ac_receipt_host(ip,port,"localhost",cancel);
}
bool arrival_receipt(const char *ip,int port) { return arrival_receipt_cancel(ip,port,NULL); }

static void ac_append(wchar_t *out,size_t cap,const wchar_t *format,...) {
    size_t used=wcslen(out); if (used+1>=cap) return;
    va_list args; va_start(args,format); vswprintf(out+used,cap-used,format,args); va_end(args); out[cap-1]=0;
}

static bool ac_match(const struct arrival_config *config,const char *ip) {
    if (config->pair) {
        const char *selected=strchr(ip,':') ? config->ipv6 : config->ip;
        if (!*selected) return false;
        if (!strcmp(selected,strchr(ip,':') ? "::" : "0.0.0.0")) return true;
        SOCKADDR_INET left,right;
        return ac_parse(selected,&left) && ac_parse(ip,&right) && ma_equal(&left,&right);
    }
    if (!*config->ip) return config->all || !strcmp(ip,"::1") || !strcmp(ip,"127.0.0.1");
    if (!strcmp(config->ip,"0.0.0.0")) return !strchr(ip,':');
    if (!strcmp(config->ip,"::")) return strchr(ip,':')!=NULL;
    SOCKADDR_INET left,right;
    return ac_parse(config->ip,&left) && ac_parse(ip,&right) && ma_equal(&left,&right);
}

static void ac_tls(const char *ip,int port,const char *host,wchar_t *out,size_t cap,const struct arrival_cancel *cancel) {
    if (arrival_cancel_requested(cancel)) return;
    arrival_progress(cancel,ARRIVAL_STAGE_HTTPS,ip,port);
    if (port<1 || port>65535) { ac_append(out,cap,L"HTTPS：未配置检测端口。\r\n"); return; }
    struct arrival_tls_result result=arrival_tls_cancel(ip,port,host,cancel);
    if (arrival_cancel_requested(cancel)) return;
    if (result.state==ARRIVAL_TLS_RECEIPT)
        ac_append(out,cap,L"HTTPS [%hs]:%d（%hs）：%hs 握手、离线证书链/名称校验与加密回执通过。\r\n",ip,port,host,result.protocol);
    else if (result.state==ARRIVAL_TLS_NO_RECEIPT)
        ac_append(out,cap,L"HTTPS [%hs]:%d（%hs）：%hs 与证书校验通过，但无 AdAway 加密回执。\r\n",ip,port,host,result.protocol);
    else if (result.state==ARRIVAL_TLS_CERTIFICATE_REJECTED)
        ac_append(out,cap,L"HTTPS [%hs]:%d（%hs）：证书链或名称/策略拒绝（%ld）；未跳过验证，未发送加密 HTTP。\r\n",ip,port,host,result.verify_error);
    else ac_append(out,cap,L"HTTPS [%hs]:%d（%hs）：连接或 TLS 未完成，不能确认 HTTPS 到达。\r\n",ip,port,host);
}

/* UDP endpoint ownership is an observation, never QUIC support evidence. */
static void ac_udp(int port,wchar_t *out,size_t cap,const struct arrival_cancel *cancel) {
    for (int family=0;family<2 && !arrival_cancel_requested(cancel);family++) {
        arrival_progress(cancel,ARRIVAL_STAGE_UDP,family ? "IPv6" : "IPv4",port);
        ULONG af=family ? AF_INET6 : AF_INET; DWORD bytes=0;
        DWORD status=GetExtendedUdpTable(NULL,&bytes,FALSE,af,UDP_TABLE_OWNER_PID,0);
        bool found=false;
        void *buffer=status==ERROR_INSUFFICIENT_BUFFER ? malloc(bytes) : NULL;
        if (buffer && GetExtendedUdpTable(buffer,&bytes,FALSE,af,UDP_TABLE_OWNER_PID,0)==NO_ERROR) {
            DWORD rows=family ? ((MIB_UDP6TABLE_OWNER_PID *)buffer)->dwNumEntries : ((MIB_UDPTABLE_OWNER_PID *)buffer)->dwNumEntries;
            for (DWORD i=0;i<rows;i++) {
                DWORD local_port=family ? ((MIB_UDP6TABLE_OWNER_PID *)buffer)->table[i].dwLocalPort : ((MIB_UDPTABLE_OWNER_PID *)buffer)->table[i].dwLocalPort;
                DWORD pid=family ? ((MIB_UDP6TABLE_OWNER_PID *)buffer)->table[i].dwOwningPid : ((MIB_UDPTABLE_OWNER_PID *)buffer)->table[i].dwOwningPid;
                if (ntohs((u_short)local_port)==port) { ac_append(out,cap,L"IPv%d UDP/%d 有绑定 PID %lu（未识别协议）。\r\n",family ? 6 : 4,port,(unsigned long)pid); found=true; }
            }
            if (!found) ac_append(out,cap,L"IPv%d UDP/%d：未发现绑定。\r\n",family ? 6 : 4,port);
        } else ac_append(out,cap,L"IPv%d UDP/%d：无法读取占用。\r\n",family ? 6 : 4,port);
        free(buffer);
    }
}

struct ac_dns_work {
    LONG references;
    HANDLE done;
    wchar_t name[256];
    ADDRINFOW hints,*answers;
    int status;
};
static volatile LONG ac_dns_active;

static void ac_dns_release(struct ac_dns_work *work) {
    if (InterlockedDecrement(&work->references)!=0) return;
    if (work->answers) FreeAddrInfoW(work->answers);
    CloseHandle(work->done); free(work);
}

static DWORD WINAPI ac_dns_worker(void *opaque) {
    struct ac_dns_work *work=(struct ac_dns_work *)opaque;
    work->status=GetAddrInfoW(work->name,NULL,&work->hints,&work->answers);
    InterlockedExchange(&ac_dns_active,0);
    SetEvent(work->done);
    ac_dns_release(work);
    return 0;
}

/* Winsock synchronous GetAddrInfoEx rejects a timeout on real Windows.
 * A single outstanding resolver mirrors Android's bounded DNS worker. A timed
 * out query retains its heap context until completion, without dangling callbacks
 * or unbounded thread creation. The UI wait remains at most two seconds. */
static int ac_resolve(const char *domain,ADDRINFOW **answers,const struct arrival_cancel *cancel) {
    *answers=NULL;
    if (arrival_cancel_requested(cancel)) return WSA_OPERATION_ABORTED;
    if (InterlockedCompareExchange(&ac_dns_active,1,0)!=0) return WSAEINPROGRESS;
    struct ac_dns_work *work=(struct ac_dns_work *)calloc(1,sizeof(*work));
    if (!work) { InterlockedExchange(&ac_dns_active,0); return WSA_NOT_ENOUGH_MEMORY; }
    work->done=CreateEventW(NULL,TRUE,FALSE,NULL);
    if (!work->done) { free(work); InterlockedExchange(&ac_dns_active,0); return WSA_NOT_ENOUGH_MEMORY; }
    work->references=2; work->hints.ai_family=AF_UNSPEC; work->hints.ai_socktype=SOCK_STREAM;
    MultiByteToWideChar(CP_UTF8,0,domain,-1,work->name,255);
    size_t length=wcslen(work->name);
    if (work->name[length-1]!=L'.') { work->name[length]=L'.'; work->name[length+1]=0; }
    HANDLE thread=CreateThread(NULL,0,ac_dns_worker,work,0,NULL);
    if (!thread) { InterlockedExchange(&ac_dns_active,0); work->references=1; ac_dns_release(work); return WSA_NOT_ENOUGH_MEMORY; }
    CloseHandle(thread);
    ULONGLONG deadline=GetTickCount64()+2000;
    int status=WSAETIMEDOUT;
    while (!arrival_cancel_requested(cancel) && GetTickCount64()<deadline) {
        ULONGLONG now=GetTickCount64();
        if (now>=deadline) break;
        ULONGLONG remaining=deadline-now;
        DWORD wait=WaitForSingleObject(work->done,(DWORD)(remaining>50 ? 50 : remaining));
        if (wait==WAIT_OBJECT_0) { status=work->status; break; }
        if (wait==WAIT_FAILED) { status=WSAEINVAL; break; }
    }
    if (arrival_cancel_requested(cancel)) status=WSA_OPERATION_ABORTED;
    if (status==0) { *answers=work->answers; work->answers=NULL; }
    ac_dns_release(work); return status;
}

static void ac_domain(const struct arrival_config *config,const char *domain,wchar_t *out,size_t cap,const struct arrival_cancel *cancel) {
    if (!domain || !*domain || arrival_cancel_requested(cancel)) return;
    if (!arrival_domain_valid(domain)) { ac_append(out,cap,L"请输入完整 ASCII / xn-- 测试域名，不含 URL、IP 或路径。\r\n"); return; }
    ADDRINFOW *answers=NULL;
    arrival_progress(cancel,ARRIVAL_STAGE_DNS,domain,0);
    int status=ac_resolve(domain,&answers,cancel);
    if (arrival_cancel_requested(cancel)) { if (answers) FreeAddrInfoW(answers); return; }
    if (status==WSAEINPROGRESS) { ac_append(out,cap,L"%hs：上次系统 DNS 查询尚未结束，请稍后重试；没有连接。\r\n",domain); return; }
    if (status) { ac_append(out,cap,L"%hs：系统 DNS 未完成或无 A/AAAA 应答（%d），没有连接。\r\n",domain,status); if (answers) FreeAddrInfoW(answers); return; }
    ULONGLONG deadline=GetTickCount64()+5000; unsigned count=0;
    for (ADDRINFOW *row=answers;row && count++<16 && !arrival_cancel_requested(cancel) && GetTickCount64()<deadline;row=row->ai_next) {
        char ip[64]; void *raw=row->ai_family==AF_INET ? (void *)&((struct sockaddr_in *)row->ai_addr)->sin_addr
                : row->ai_family==AF_INET6 ? (void *)&((struct sockaddr_in6 *)row->ai_addr)->sin6_addr : NULL;
        if (!raw || !inet_ntop(row->ai_family,raw,ip,sizeof(ip))) continue;
        if (!ac_match(config,ip) || !arrival_local_address(ip)) ac_append(out,cap,L"%hs → %hs：未指向当前本机监听，未连接。\r\n",domain,ip);
        else {
            arrival_progress(cancel,ARRIVAL_STAGE_HTTP,ip,config->http);
            ac_append(out,cap,L"%hs → %hs：DNS 已指向；HTTP/%d %ls。\r\n",domain,ip,config->http,
                ac_receipt_host(ip,config->http,domain,cancel) ? L"请求已到达 AdAway" : L"未收到 AdAway 回执");
            ac_tls(ip,config->https,domain,out,cap,cancel);
        }
    }
    FreeAddrInfoW(answers);
}

bool arrival_report_cancel(const struct arrival_config *config,const char *adblock,const char *hosts,wchar_t *out,size_t cap,const struct arrival_cancel *cancel) {
    if (!out || !cap) return true;
    out[0]=0;
    if (arrival_cancel_requested(cancel)) goto cancelled;
    arrival_progress(cancel,ARRIVAL_STAGE_START,"",0);
    if ((*adblock && !arrival_domain_valid(adblock)) || (*hosts && !arrival_domain_valid(hosts))) {
        ac_append(out,cap,L"请输入完整 ASCII / xn-- 测试域名，不含 URL、路径、IP 或空白。"); return true;
    }
    ac_append(out,cap,L"本次检测 HTTP/%d、HTTPS/%d；DNS 只返回地址，不指定端口。\r\n",config->http,config->https);
    if (config->http!=80)
        ac_append(out,cap,L"HTTP/%d 回执不证明默认 HTTP/80 可达；默认端口需另行验证。\r\n",config->http);
    if (config->https!=443)
        ac_append(out,cap,L"HTTPS/%d 回执不证明默认 HTTPS/443 可达；默认端口需另行验证。\r\n",config->https);
    enum adguard_process_signal process=adguard_process_probe();
    ac_append(out,cap,L"AdGuard 进程：%ls。进程存在不等于正在接管流量。\r\n",process==ADGUARD_PROCESS_PRESENT ? L"检测到运行" : process==ADGUARD_PROCESS_ABSENT ? L"未发现" : L"未知");
    if (arrival_cancel_requested(cancel)) goto cancelled;
    arrival_progress(cancel,ARRIVAL_STAGE_MANAGEMENT,"::1",config->stats);
    bool management=arrival_receipt_cancel("::1",config->stats,cancel);
    if (!management && !arrival_cancel_requested(cancel)) {
        arrival_progress(cancel,ARRIVAL_STAGE_MANAGEMENT,"127.0.0.1",config->stats);
        management=arrival_receipt_cancel("127.0.0.1",config->stats,cancel);
    }
    if (arrival_cancel_requested(cancel)) goto cancelled;
    ac_append(out,cap,L"管理端口 %d：%ls。\r\n",config->stats,management ? L"AdAway 回执已确认" : L"无回执；旧版本、服务未就绪或路径受影响");
    const char *targets[2]={config->pair ? (*config->ip ? config->ip : NULL) : *config->ip ? config->ip : "127.0.0.1",
        config->pair ? (*config->ipv6 ? config->ipv6 : NULL) : *config->ip ? NULL : "::1"};
    for (int i=0;i<2 && !arrival_cancel_requested(cancel);i++) if (targets[i]) {
        if (!strcmp(targets[i],"0.0.0.0")) targets[i]="127.0.0.1";
        if (!strcmp(targets[i],"::")) targets[i]="::1";
        arrival_progress(cancel,ARRIVAL_STAGE_HTTP,targets[i],config->http);
        ac_append(out,cap,L"[%hs]:%d：%ls。\r\n",targets[i],config->http,
                arrival_receipt_cancel(targets[i],config->http,cancel) ? L"HTTP 请求已到达 AdAway" : L"无 AdAway 回执，不能用端口连通代替实际到达");
        ac_tls(targets[i],config->https,"localhost",out,cap,cancel);
    }
    if (arrival_cancel_requested(cancel)) goto cancelled;
    ac_domain(config,adblock,out,cap,cancel); ac_domain(config,hosts,out,cap,cancel);
    if (arrival_cancel_requested(cancel)) goto cancelled;
    ac_append(out,cap,L"\r\nQUIC / HTTP/3：本版本未实现 UDP 服务；TCP/443 与 HTTPS 成功不代表 QUIC 成功。\r\n");
    ac_udp(443,out,cap,cancel);
    if (config->https!=443 && config->https>0) ac_udp(config->https,out,cap,cancel);
    if (arrival_cancel_requested(cancel)) goto cancelled;
    ac_append(out,cap,L"\r\n系统 DNS 可能来自缓存或 Hosts；规则类别以 AdGuard 日志为准。HTTPS 使用 Windows ROOT 信任锚做离线链/名称校验，不下载吊销信息，不代表其他应用的证书固定/信任策略。未修改网络、AdGuard 或证书。");
    arrival_progress(cancel,ARRIVAL_STAGE_DONE,"",0);
    return true;
cancelled:
    ac_append(out,cap,L"\r\n检测已取消，未开始后续探测。可以重试。\r\n");
    arrival_progress(cancel,ARRIVAL_STAGE_CANCELLED,"",0);
    return false;
}

void arrival_report(const struct arrival_config *config,const char *adblock,const char *hosts,wchar_t *out,size_t cap) {
    (void)arrival_report_cancel(config,adblock,hosts,out,cap,NULL);
}
