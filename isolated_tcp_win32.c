#define _WIN32_WINNT 0x0A00
#include "isolated_tcp_win32.h"
#include "diagnostic_socks5.h"
#include <ws2tcpip.h>
#include <bcrypt.h>
#include <string.h>

struct tcp_session {
    const struct tcp_options *options;
    struct it_result *result;
    ULONGLONG deadline;
    SOCKET owned[6];
    unsigned count;
};
static bool tcp_tick(struct tcp_session *s) {
    if (s->options->cancel && WaitForSingleObject(s->options->cancel,0)==WAIT_OBJECT_0) {
        s->result->status=IT_CANCELLED;return false;
    }
    if (GetTickCount64()>=s->deadline) { s->result->status=IT_TIMEOUT;return false; }
    return true;
}
static bool tcp_error(struct tcp_session *s,int error) {
    s->result->error=(unsigned)error;s->result->status=IT_SYSTEM_ERROR;return false;
}
static bool tcp_reject(struct tcp_session *s) { s->result->status=IT_INVALID;return false; }
static bool tcp_wait(struct tcp_session *s,SOCKET socket,bool writing) {
    while(tcp_tick(s)) {
        fd_set set;FD_ZERO(&set);FD_SET(socket,&set);
        struct timeval timeout={0,20000};
        int ready=select(0,writing?NULL:&set,writing?&set:NULL,NULL,&timeout);
        if (ready==SOCKET_ERROR) return tcp_error(s,WSAGetLastError());
        if (ready>0) return tcp_tick(s);
    }
    return false;
}
static SOCKET tcp_own(struct tcp_session *s,SOCKET socket) {
    if(socket==INVALID_SOCKET) { tcp_error(s,WSAGetLastError());return INVALID_SOCKET; }
    if(s->count>=6) { closesocket(socket);tcp_reject(s);return INVALID_SOCKET; }
    s->owned[s->count++]=socket;s->result->sockets_opened++;
    u_long nonblocking=1;
    if(ioctlsocket(socket,FIONBIO,&nonblocking)!=0) { tcp_error(s,WSAGetLastError());return INVALID_SOCKET; }
    return socket;
}
static SOCKET tcp_listener(struct tcp_session *s,struct sockaddr_storage *address,int *length) {
    SOCKET socket=tcp_own(s,WSASocketW(s->options->family==6?AF_INET6:AF_INET,SOCK_STREAM,IPPROTO_TCP,NULL,0,WSA_FLAG_NO_HANDLE_INHERIT));
    if(socket==INVALID_SOCKET)return socket;
    BOOL exclusive=TRUE;
    if(setsockopt(socket,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,(const char *)&exclusive,sizeof(exclusive))!=0) {
        tcp_error(s,WSAGetLastError());return INVALID_SOCKET;
    }
    memset(address,0,sizeof(*address));
    if(s->options->family==6) {
        struct sockaddr_in6 *v6=(struct sockaddr_in6 *)address;
        v6->sin6_family=AF_INET6;v6->sin6_addr=in6addr_loopback;*length=sizeof(*v6);
        DWORD only=1;
        if(setsockopt(socket,IPPROTO_IPV6,IPV6_V6ONLY,(const char *)&only,sizeof(only))!=0) {
            tcp_error(s,WSAGetLastError());return INVALID_SOCKET;
        }
    } else {
        struct sockaddr_in *v4=(struct sockaddr_in *)address;
        v4->sin_family=AF_INET;v4->sin_addr.s_addr=htonl(INADDR_LOOPBACK);*length=sizeof(*v4);
    }
    if(bind(socket,(struct sockaddr *)address,*length)!=0 || listen(socket,1)!=0 ||
       getsockname(socket,(struct sockaddr *)address,length)!=0) {
        tcp_error(s,WSAGetLastError());return INVALID_SOCKET;
    }
    return socket;
}
static bool tcp_pair(struct tcp_session *s,SOCKET listener,const struct sockaddr_storage *address,int length,SOCKET *outbound,SOCKET *accepted) {
    *outbound=tcp_own(s,WSASocketW(s->options->family==6?AF_INET6:AF_INET,SOCK_STREAM,IPPROTO_TCP,NULL,0,WSA_FLAG_NO_HANDLE_INHERIT));
    if(*outbound==INVALID_SOCKET)return false;
    if(connect(*outbound,(const struct sockaddr *)address,length)!=0) {
        int error=WSAGetLastError();
        if(error!=WSAEWOULDBLOCK)return tcp_error(s,error);
        if(!tcp_wait(s,*outbound,true))return false;
        int failure=0;int size=sizeof(failure);
        if(getsockopt(*outbound,SOL_SOCKET,SO_ERROR,(char *)&failure,&size)!=0)return tcp_error(s,WSAGetLastError());
        if(failure)return tcp_error(s,failure);
    }
    if(!tcp_wait(s,listener,false))return false;
    *accepted=tcp_own(s,accept(listener,NULL,NULL));
    if(*accepted==INVALID_SOCKET)return false;
    BOOL enabled=TRUE;
    if(setsockopt(*outbound,IPPROTO_TCP,TCP_NODELAY,(const char *)&enabled,sizeof(enabled))!=0 ||
       setsockopt(*accepted,IPPROTO_TCP,TCP_NODELAY,(const char *)&enabled,sizeof(enabled))!=0)return tcp_error(s,WSAGetLastError());
    return tcp_tick(s);
}
static bool tcp_write(struct tcp_session *s,SOCKET socket,const uint8_t *bytes,size_t size) {
    size_t at=0;
    while(at<size && tcp_tick(s)) {
        int length=(int)(size-at>3?3:size-at);
        int count=send(socket,(const char *)bytes+at,length,0);
        if(count==SOCKET_ERROR) {
            int error=WSAGetLastError();
            if(error!=WSAEWOULDBLOCK)return tcp_error(s,error);
            if(!tcp_wait(s,socket,true))return false;
        } else if(count==0)return tcp_reject(s);
        else at+=(size_t)count;
    }
    return at==size && tcp_tick(s);
}
static bool tcp_read(struct tcp_session *s,SOCKET socket,uint8_t *bytes,size_t capacity,bool eof,size_t *used) {
    *used=0;
    while(tcp_tick(s)) {
        uint8_t scratch[7];
        size_t available=capacity-*used;
        int length=(int)(available>sizeof(scratch)?sizeof(scratch):available);
        if(!eof && available==0)return true;
        /* An extra bounded read detects oversized streams rather than accepting a prefix. */
        int count=recv(socket,(char *)scratch,length?length:1,0);
        if(count==0)return eof?true:tcp_reject(s);
        if(count==SOCKET_ERROR) {
            int error=WSAGetLastError();
            if(error!=WSAEWOULDBLOCK)return tcp_error(s,error);
            if(!tcp_wait(s,socket,false))return false;
        } else {
            if((size_t)count>available)return tcp_reject(s);
            memcpy(bytes+*used,scratch,(size_t)count);*used+=(size_t)count;
        }
    }
    return false;
}
static bool tcp_frame(struct tcp_session *s,SOCKET from,SOCKET to,const uint8_t *sent,size_t length,uint8_t *received) {
    size_t count;
    return tcp_write(s,from,sent,length) && tcp_read(s,to,received,length,false,&count) && count==length;
}
static bool tcp_shutdown(struct tcp_session *s,SOCKET socket) {
    return shutdown(socket,SD_SEND)==0?true:tcp_error(s,WSAGetLastError());
}
static bool tcp_exchange(struct tcp_session *s) {
    struct sockaddr_storage backend_address,proxy_address;
    int backend_length,proxy_length;
    SOCKET backend_listener=tcp_listener(s,&backend_address,&backend_length);
    if(backend_listener==INVALID_SOCKET)return false;
    SOCKET proxy_listener=tcp_listener(s,&proxy_address,&proxy_length);
    if(proxy_listener==INVALID_SOCKET)return false;
    SOCKET client,proxy,upstream,backend;
    if(!tcp_pair(s,proxy_listener,&proxy_address,proxy_length,&client,&proxy))return false;
    uint8_t token[16],sent[DS_LIMIT+1],received[DS_LIMIT+1];size_t count;
    if(BCryptGenRandom(NULL,token,sizeof(token),BCRYPT_USE_SYSTEM_PREFERRED_RNG)!=0)return tcp_error(s,ERROR_GEN_FAILURE);
    s->result->stage=1;
    const uint8_t greeting[]={5,1,2};
    if(!tcp_frame(s,client,proxy,greeting,sizeof(greeting),received))return false;
    if(ds_greeting(received,sizeof(greeting))!=0)return tcp_reject(s);
    const uint8_t method[]={5,2};
    if(!tcp_frame(s,proxy,client,method,sizeof(method),received))return false;
    if(memcmp(method,received,sizeof(method))!=0)return tcp_reject(s);
    s->result->stage=2;
    ds_auth_frame(token,sent);size_t length=25;
    if(s->options->fixture==TCP_BAD_AUTH)sent[length-1]^=1;
    if(!tcp_frame(s,client,proxy,sent,length,received))return false;
    unsigned code=ds_auth(received,length,token);
    uint8_t auth_reply[]={1,(uint8_t)code};
    if(!tcp_frame(s,proxy,client,auth_reply,sizeof(auth_reply),received))return false;
    if(code || received[0]!=1 || received[1]!=0)return tcp_reject(s);
    s->result->stage=3;
    length=ds_request(s->options->family,sent);
    if(s->options->fixture==TCP_BAD_TARGET)sent[length-1]^=1;
    if(!tcp_frame(s,client,proxy,sent,length,received))return false;
    code=ds_connect(received,length,s->options->family);
    if(code) {
        length=ds_reply(s->options->family,code,0,sent);
        if(!tcp_frame(s,proxy,client,sent,length,received))return false;
        return tcp_reject(s);
    }
    /* Upstream sockets are created only after both credential and fixed-target checks. */
    if(!tcp_pair(s,backend_listener,&backend_address,backend_length,&upstream,&backend))return false;
    struct sockaddr_storage bound;int bound_length=sizeof(bound);
    if(getsockname(upstream,(struct sockaddr *)&bound,&bound_length)!=0)return tcp_error(s,WSAGetLastError());
    unsigned port=s->options->family==6?ntohs(((struct sockaddr_in6 *)&bound)->sin6_port):ntohs(((struct sockaddr_in *)&bound)->sin_port);
    length=ds_reply(s->options->family,0,port,sent);
    if(!tcp_frame(s,proxy,client,sent,length,received))return false;
    if(ds_reply_code(received,length,s->options->family)!=0)return tcp_reject(s);
    s->result->stage=4;
    length=s->options->fixture==TCP_OVERSIZE?DS_LIMIT+1:DS_LIMIT;
    if(BCryptGenRandom(NULL,sent,(ULONG)length,BCRYPT_USE_SYSTEM_PREFERRED_RNG)!=0)return tcp_error(s,ERROR_GEN_FAILURE);
    if(!tcp_write(s,client,sent,length) || !tcp_shutdown(s,client) || !tcp_read(s,proxy,received,DS_LIMIT,true,&count))return false;
    if(count!=length || memcmp(sent,received,length)!=0)return tcp_reject(s);
    if(!tcp_write(s,upstream,received,count) || !tcp_shutdown(s,upstream) || !tcp_read(s,backend,received,DS_LIMIT,true,&count))return false;
    if(count!=length)return tcp_reject(s);
    s->result->stage=5;
    if(s->options->ready)SetEvent(s->options->ready);
    if(s->options->fixture==TCP_SILENT) {
        /* Actual pending read; cancellation and the common deadline remain active. */
        return tcp_read(s,client,received,DS_LIMIT,true,&count) && tcp_reject(s);
    }
    received[0]^=0x5a;
    if(s->options->fixture==TCP_STALE)received[0]^=1;
    if(s->options->fixture==TCP_TRUNCATED)count--;
    if(!tcp_write(s,backend,received,count) || !tcp_shutdown(s,backend) || !tcp_read(s,upstream,received,DS_LIMIT,true,&count))return false;
    if(!tcp_write(s,proxy,received,count) || !tcp_shutdown(s,proxy) || !tcp_read(s,client,received,DS_LIMIT,true,&count))return false;
    sent[0]^=0x5a;
    if(count!=length || memcmp(sent,received,length)!=0)return tcp_reject(s);
    s->result->stage=6;
    return tcp_tick(s);
}
void isolated_tcp_run(const struct tcp_options *options,struct it_result *result) {
    if(!result)return;
    memset(result,0,sizeof(*result));result->status=IT_INVALID;result->cleanup_ok=true;
    if(!options || (options->family!=4 && options->family!=6) || !options->budget_ms || options->budget_ms>1200 ||
       options->fixture<TCP_NORMAL || options->fixture>TCP_OVERSIZE)return;
    ULONGLONG started=GetTickCount64();result->family=options->family;
    struct tcp_session session;memset(&session,0,sizeof(session));session.options=options;session.result=result;session.deadline=started+options->budget_ms;
    WSADATA data;
    int error=WSAStartup(MAKEWORD(2,2),&data);
    if(error) { tcp_error(&session,error);return; }
    result->status=IT_SYSTEM_ERROR;
    if(tcp_tick(&session) && tcp_exchange(&session))result->status=IT_OK;
    for(unsigned i=0;i<session.count;i++) {
        if(closesocket(session.owned[i])==0)result->sockets_closed++;
        else result->cleanup_ok=false;
    }
    if(WSACleanup()!=0)result->cleanup_ok=false;
    if(result->sockets_closed!=result->sockets_opened)result->cleanup_ok=false;
    if(!result->cleanup_ok)result->status=IT_CLEANUP_FAILED;
    result->elapsed_ms=(unsigned)(GetTickCount64()-started);
}
