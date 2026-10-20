#include "isolated_transport_win32.h"
#include "diagnostic_udp_packet.h"
#include <ws2tcpip.h>
#include <bcrypt.h>

struct it_session {
    SOCKET sockets[4];
    struct sockaddr_storage addresses[4];
    int length;
    ULONGLONG deadline;
    const struct it_options *options;
    struct it_result *result;
};
static int it_cancelled(const struct it_options *options) {
    return options->cancel && WaitForSingleObject(options->cancel,0)==WAIT_OBJECT_0;
}
static int it_wait(struct it_session *session,SOCKET socket,bool writing) {
    for (;;) {
        if (it_cancelled(session->options)) { session->result->status=IT_CANCELLED; return 0; }
        ULONGLONG now=GetTickCount64();
        if (now>=session->deadline) { session->result->status=IT_TIMEOUT; return 0; }
        fd_set set; FD_ZERO(&set); FD_SET(socket,&set);
        ULONGLONG left=session->deadline-now;
        struct timeval timeout={0,(long)((left<20?left:20)*1000)};
        int rc=select(0,writing?NULL:&set,writing?&set:NULL,NULL,&timeout);
        if (rc>0) return 1;
        if (rc==SOCKET_ERROR) { session->result->status=IT_SYSTEM_ERROR; return 0; }
    }
}
static int it_open(struct it_session *s,unsigned index) {
    int family=s->options->family==4?AF_INET:AF_INET6;
    SOCKET socket_value=socket(family,SOCK_DGRAM,IPPROTO_UDP);
    if (socket_value==INVALID_SOCKET) return 0;
    s->sockets[index]=socket_value; s->result->sockets_opened++;
    u_long nonblocking=1;
    if (ioctlsocket(socket_value,FIONBIO,&nonblocking)) return 0;
    if (family==AF_INET) {
        struct sockaddr_in *address=(struct sockaddr_in *)&s->addresses[index];
        address->sin_family=AF_INET; address->sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    } else {
        DWORD only=1;
        if (setsockopt(socket_value,IPPROTO_IPV6,IPV6_V6ONLY,(const char *)&only,sizeof(only))) return 0;
        struct sockaddr_in6 *address=(struct sockaddr_in6 *)&s->addresses[index];
        address->sin6_family=AF_INET6; address->sin6_addr=in6addr_loopback;
    }
    if (bind(socket_value,(const struct sockaddr *)&s->addresses[index],s->length)) return 0;
    int length=s->length;
    return getsockname(socket_value,(struct sockaddr *)&s->addresses[index],&length)==0;
}
static int it_pair(struct it_session *s,unsigned a,unsigned b) {
    return connect(s->sockets[a],(struct sockaddr *)&s->addresses[b],s->length)==0
        && connect(s->sockets[b],(struct sockaddr *)&s->addresses[a],s->length)==0;
}
static int it_send(struct it_session *s,unsigned index,const uint8_t *bytes,size_t count) {
    while (it_wait(s,s->sockets[index],true)) {
        int sent=send(s->sockets[index],(const char *)bytes,(int)count,0);
        if (sent==(int)count) return 1;
        int error=WSAGetLastError();
        if (sent<0 && error==WSAEWOULDBLOCK) continue;
        s->result->status=IT_SYSTEM_ERROR;s->result->error=(unsigned)error;return 0;
    }
    return 0;
}
static int it_receive(struct it_session *s,unsigned index,uint8_t *bytes,size_t capacity) {
    while (it_wait(s,s->sockets[index],false)) {
        int count=recv(s->sockets[index],(char *)bytes,(int)capacity,0);
        if (count>=0) return count;
        int error=WSAGetLastError();
        if (error==WSAEWOULDBLOCK) continue;
        s->result->status=IT_SYSTEM_ERROR;s->result->error=(unsigned)error;return -1;
    }
    return -1;
}
static void it_exchange(struct it_session *s) {
    s->result->stage=4;
    uint8_t nonce[32],request[DUDP_MAX_PACKET],received[DUDP_MAX_PACKET],response[DUDP_MAX_PACKET],backend[DUDP_PAYLOAD+1];
    NTSTATUS random_status=BCryptGenRandom(NULL,nonce,sizeof(nonce),BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (random_status!=0) { s->result->error=(unsigned)random_status;return; }
    size_t request_size=dudp_request(s->options->family,12345,nonce,sizeof(nonce),request,sizeof(request));
    if (s->options->fixture==IT_BAD_PACKET) request[request_size-1]^=1;
    // Datagram pair 0/1 stands in for the caller-owned TUN packet source/sink.
    if (!it_send(s,0,request,request_size)) return;
    int n=it_receive(s,1,received,sizeof(received)); if (n<0) return;
    s->result->stage=5;
    struct dudp_packet parsed;
    if (!dudp_parse(received,(size_t)n,&parsed)) { s->result->status=IT_INVALID; return; }
    if (!it_send(s,2,received+parsed.header+8,parsed.payload)) return;
    int count=it_receive(s,3,backend,sizeof(backend)); if (count<0) return;
    s->result->stage=6;
    if (s->options->ready) SetEvent(s->options->ready);
    // Fixed private responder, not an arbitrary destination or a network proxy.
    if (s->options->fixture!=IT_SILENT) {
        if (count!=(int)sizeof(nonce)) { s->result->status=IT_INVALID; return; }
        backend[0]^=0x5a;
        if (s->options->fixture==IT_STALE_REPLY) backend[1]^=1;
        if (!it_send(s,3,backend,(size_t)count)) return;
    }
    count=it_receive(s,2,backend,sizeof(backend)); if (count<0) return;
    s->result->stage=7;
    uint8_t expected[sizeof(nonce)]; memcpy(expected,nonce,sizeof(nonce)); expected[0]^=0x5a;
    if (count!=(int)sizeof(nonce) || memcmp(backend,expected,sizeof(expected))) { s->result->status=IT_INVALID; return; }
    size_t size=dudp_reply(received,(size_t)n,backend,(size_t)count,response,sizeof(response));
    if (!size || !it_send(s,1,response,size)) return;
    count=it_receive(s,0,received,sizeof(received)); if (count<0) return;
    // Compare complete IP/UDP envelope, endpoint, payload and checksums.
    if ((size_t)count!=size || memcmp(received,response,size)) { s->result->status=IT_INVALID; return; }
    s->result->status=IT_OK;
}
void isolated_transport_run(const struct it_options *options,struct it_result *result) {
    if (!result) return;
    memset(result,0,sizeof(*result)); result->status=IT_SYSTEM_ERROR;
    if (!options || (options->family!=4 && options->family!=6) || options->budget_ms<1 || options->budget_ms>1200) {
        result->status=IT_INVALID; result->cleanup_ok=true; return;
    }
    result->family=options->family;
    struct it_session session; memset(&session,0,sizeof(session)); session.options=options; session.result=result;
    for (unsigned i=0;i<4;i++) session.sockets[i]=INVALID_SOCKET;
    session.length=options->family==4?sizeof(struct sockaddr_in):sizeof(struct sockaddr_in6);
    ULONGLONG started=GetTickCount64(); session.deadline=started+options->budget_ms;
    result->stage=1;
    WSADATA data; bool startup=WSAStartup(MAKEWORD(2,2),&data)==0;
    if (startup && !it_cancelled(options)) {
        bool opened=true;
        result->stage=2;
        for (unsigned i=0;i<4;i++) if (!it_open(&session,i)) { opened=false; break; }
        if (opened) {
            result->stage=3;
            if (it_pair(&session,0,1) && it_pair(&session,2,3)) it_exchange(&session);
        }
    } else if (it_cancelled(options)) result->status=IT_CANCELLED;
    result->cleanup_ok=true;
    if (result->status==IT_SYSTEM_ERROR && !result->error) result->error=(unsigned)WSAGetLastError();
    for (unsigned i=0;i<4;i++) if (session.sockets[i]!=INVALID_SOCKET) {
        if (closesocket(session.sockets[i])==0) result->sockets_closed++;
        else result->cleanup_ok=false;
    }
    if (startup && WSACleanup()!=0) result->cleanup_ok=false;
    if (!result->cleanup_ok) result->status=IT_CLEANUP_FAILED;
    result->elapsed_ms=(unsigned)(GetTickCount64()-started);
}
const wchar_t *isolated_transport_status(enum it_status status) {
    switch (status) {
        case IT_OK:return L"转发回执通过";
        case IT_CANCELLED:return L"已取消";
        case IT_TIMEOUT:return L"超时";
        case IT_INVALID:return L"报文或响应被拒绝";
        case IT_CLEANUP_FAILED:return L"资源清理失败";
        default:return L"系统或套接字错误";
    }
}
