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

static bool ac_local(const char *ip) {
    SOCKADDR_INET address; if (!ac_parse(ip,&address)) return false;
    if (address.si_family==AF_INET && ((const unsigned char *)&address.Ipv4.sin_addr)[0]==127) return true;
    static const unsigned char loop[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if (address.si_family==AF_INET6 && !memcmp(&address.Ipv6.sin6_addr,loop,16)) return true;
    MIB_UNICASTIPADDRESS_ROW row; return ma_find(&address,&row)==NO_ERROR;
}

static bool ac_receipt_host(const char *ip,int port,const char *host) {
    SOCKADDR_INET address; if (!ac_parse(ip,&address) || !ac_local(ip) || port<1 || port>65535) return false;
    if (strcmp(host,"localhost") && !arrival_domain_valid(host)) return false;
    unsigned char random[16]; if (BCryptGenRandom(NULL,random,sizeof(random),BCRYPT_USE_SYSTEM_PREFERRED_RNG)!=0) return false;
    char nonce[33]; for (int i=0;i<16;i++) snprintf(nonce+i*2,3,"%02x",random[i]);
    SOCKET client=socket(address.si_family,SOCK_STREAM,IPPROTO_TCP); if (client==INVALID_SOCKET) return false;
    u_long nonblocking=1; ioctlsocket(client,FIONBIO,&nonblocking);
    if (address.si_family==AF_INET) address.Ipv4.sin_port=htons((u_short)port);
    else address.Ipv6.sin6_port=htons((u_short)port);
    ULONGLONG deadline=GetTickCount64()+2000; bool valid=false;
    int result=connect(client,(struct sockaddr *)&address,address.si_family==AF_INET ? sizeof(address.Ipv4) : sizeof(address.Ipv6));
    if (result==SOCKET_ERROR && WSAGetLastError()!=WSAEWOULDBLOCK) goto done;
    fd_set ready; FD_ZERO(&ready); FD_SET(client,&ready); struct timeval budget={0,800000};
    if (select(0,NULL,&ready,NULL,&budget)<=0) goto done;
    int error=0,size=sizeof(error); if (getsockopt(client,SOL_SOCKET,SO_ERROR,(char *)&error,&size) || error) goto done;
    char request[512]; int length=snprintf(request,sizeof(request),"GET /adaway-listener-probe/%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",nonce,host);
    int sent=0;
    while (sent<length && GetTickCount64()<deadline) {
        FD_ZERO(&ready); FD_SET(client,&ready); budget.tv_sec=0; budget.tv_usec=100000;
        if (select(0,NULL,&ready,NULL,&budget)<=0) continue;
        int count=send(client,request+sent,length-sent,0); if (count<=0) goto done; sent+=count;
    }
    if (sent!=length) goto done;
    char response[4097]; size_t used=0;
    while (used<sizeof(response)-1 && GetTickCount64()<deadline) {
        FD_ZERO(&ready); FD_SET(client,&ready); budget.tv_sec=0; budget.tv_usec=100000;
        if (select(0,&ready,NULL,NULL,&budget)<=0) continue;
        int count=recv(client,response+used,(int)(sizeof(response)-1-used),0);
        if (count<=0) break;
        used+=(size_t)count; response[used]=0;
        if (arrival_valid_receipt(response,nonce)) { valid=true; break; }
    }
done:
    closesocket(client); return valid;
}

bool arrival_receipt(const char *ip,int port) { return ac_receipt_host(ip,port,"localhost"); }

static void ac_append(wchar_t *out,size_t cap,const wchar_t *format,...) {
    size_t used=wcslen(out); if (used+1>=cap) return;
    va_list args; va_start(args,format); vswprintf(out+used,cap-used,format,args); va_end(args); out[cap-1]=0;
}

static bool ac_match(const struct arrival_config *config,const char *ip) {
    if (!*config->ip) return config->all || !strcmp(ip,"::1") || !strcmp(ip,"127.0.0.1");
    if (!strcmp(config->ip,"0.0.0.0")) return !strchr(ip,':');
    if (!strcmp(config->ip,"::")) return strchr(ip,':')!=NULL;
    SOCKADDR_INET left,right;
    return ac_parse(config->ip,&left) && ac_parse(ip,&right) && ma_equal(&left,&right);
}

static void ac_domain(const struct arrival_config *config,const char *domain,wchar_t *out,size_t cap) {
    if (!domain || !*domain) return;
    if (!arrival_domain_valid(domain)) { ac_append(out,cap,L"请输入完整 ASCII / xn-- 测试域名，不含 URL、IP 或路径。\r\n"); return; }
    wchar_t name[256]; MultiByteToWideChar(CP_UTF8,0,domain,-1,name,255);
    size_t n=wcslen(name); if (name[n-1]!=L'.') { name[n]=L'.'; name[n+1]=0; }
    ADDRINFOEXW hints,*answers=NULL; memset(&hints,0,sizeof(hints)); hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    struct timeval timeout={2,0};
    int status=GetAddrInfoExW(name,NULL,NS_DNS,NULL,&hints,&answers,&timeout,NULL,NULL,NULL);
    if (status) { ac_append(out,cap,L"%hs：系统 DNS 未完成或无 A/AAAA 应答（%d），没有连接。\r\n",domain,status); if (answers) FreeAddrInfoExW(answers); return; }
    ULONGLONG deadline=GetTickCount64()+5000; unsigned count=0;
    for (ADDRINFOEXW *row=answers;row && count++<16 && GetTickCount64()<deadline;row=row->ai_next) {
        char ip[64]; void *raw=row->ai_family==AF_INET ? (void *)&((struct sockaddr_in *)row->ai_addr)->sin_addr
                : row->ai_family==AF_INET6 ? (void *)&((struct sockaddr_in6 *)row->ai_addr)->sin6_addr : NULL;
        if (!raw || !inet_ntop(row->ai_family,raw,ip,sizeof(ip))) continue;
        if (!ac_match(config,ip) || !ac_local(ip)) ac_append(out,cap,L"%hs → %hs：未指向当前本机监听，未连接。\r\n",domain,ip);
        else ac_append(out,cap,L"%hs → %hs：DNS 已指向；%ls。\r\n",domain,ip,ac_receipt_host(ip,config->http,domain) ? L"HTTP 请求已到达 AdAway" : L"未收到 AdAway 回执");
    }
    FreeAddrInfoExW(answers);
}

void arrival_report(const struct arrival_config *config,const char *adblock,const char *hosts,wchar_t *out,size_t cap) {
    if (!out || !cap) return;
    out[0]=0;
    if ((*adblock && !arrival_domain_valid(adblock)) || (*hosts && !arrival_domain_valid(hosts))) {
        ac_append(out,cap,L"请输入完整 ASCII / xn-- 测试域名，不含 URL、路径、IP 或空白。"); return;
    }
    enum adguard_process_signal process=adguard_process_probe();
    ac_append(out,cap,L"AdGuard 进程：%ls。进程存在不等于正在接管流量。\r\n",process==ADGUARD_PROCESS_PRESENT ? L"检测到运行" : process==ADGUARD_PROCESS_ABSENT ? L"未发现" : L"未知");
    bool management=arrival_receipt("::1",config->stats) || arrival_receipt("127.0.0.1",config->stats);
    ac_append(out,cap,L"管理端口：%ls。\r\n",management ? L"AdAway 回执已确认" : L"无回执；旧版本、服务未就绪或路径受影响");
    const char *targets[2]={*config->ip ? config->ip : "127.0.0.1",*config->ip ? NULL : "::1"};
    if (!strcmp(targets[0],"0.0.0.0")) targets[0]="127.0.0.1";
    if (!strcmp(targets[0],"::")) targets[0]="::1";
    for (int i=0;i<2;i++) if (targets[i]) ac_append(out,cap,L"%hs:%d：%ls。\r\n",targets[i],config->http,
            arrival_receipt(targets[i],config->http) ? L"HTTP 请求已到达 AdAway" : L"无 AdAway 回执，不能用端口连通代替实际到达");
    ac_domain(config,adblock,out,cap); ac_domain(config,hosts,out,cap);
    ac_append(out,cap,L"\r\n系统 DNS 结果可能来自缓存或 Hosts；命中规则类型以 AdGuard 日志为准。未验证 HTTPS 证书信任或其他应用路径；未修改 WFP、DNS、代理、AdGuard 配置或证书。");
}
