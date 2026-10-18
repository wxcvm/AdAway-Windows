#include "dns_probe_win32.h"
#include "diagnostic_dns_reply.h"
#include "block_rule_snapshot.h"
#include <assert.h>
#include <stdio.h>

struct fixture { SOCKET udp, tcp; HANDLE cancel; int peer_closed; };
static DWORD WINAPI serve(void *opaque) {
    struct fixture *f = (struct fixture *)opaque;
    uint8_t bytes[512]; struct sockaddr_in peer; int peer_size = sizeof(peer);
    int n = recvfrom(f->udp,(char *)bytes,sizeof(bytes),0,(struct sockaddr *)&peer,&peer_size);
    assert(n == (int)DDNS_QUERY_SIZE); bytes[2] = 0x83;
    assert(sendto(f->udp,(const char *)bytes,n,0,(struct sockaddr *)&peer,peer_size) == n);
    SOCKET client = accept(f->tcp,NULL,NULL); assert(client != INVALID_SOCKET);
    DWORD timeout = 1500; assert(!setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,(const char *)&timeout,sizeof(timeout)));
    int total = 0;
    while (total < (int)DDNS_QUERY_SIZE + 2) {
        n = recv(client,(char *)bytes + total,(int)DDNS_QUERY_SIZE + 2 - total,0); assert(n > 0); total += n;
    }
    assert(SetEvent(f->cancel));
    n = recv(client,(char *)bytes,1,0);
    f->peer_closed = n == 0 || (n == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET);
    closesocket(client); return 0;
}
int main(void) {
    WSADATA data; assert(!WSAStartup(MAKEWORD(2,2),&data));
    for (unsigned attempt = 0; attempt < 8; attempt++) {
        struct fixture f; memset(&f,0,sizeof(f));
        f.tcp = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); assert(f.tcp != INVALID_SOCKET);
        struct sockaddr_in address; memset(&address,0,sizeof(address));
        address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        assert(!bind(f.tcp,(struct sockaddr *)&address,sizeof(address))); assert(!listen(f.tcp,1));
        int length=sizeof(address); assert(!getsockname(f.tcp,(struct sockaddr *)&address,&length));
        f.udp=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP); assert(f.udp != INVALID_SOCKET);
        assert(!bind(f.udp,(struct sockaddr *)&address,sizeof(address)));
        DWORD timeout=1500; assert(!setsockopt(f.udp,SOL_SOCKET,SO_RCVTIMEO,(const char *)&timeout,sizeof(timeout)));
        f.cancel=CreateEventW(NULL,TRUE,FALSE,NULL); assert(f.cancel);
        HANDLE thread=CreateThread(NULL,0,serve,&f,0,NULL); assert(thread);
        struct bs_store rules=BS_STORE_INITIALIZER; struct bs_builder builder; memset(&builder,0,sizeof(builder));
        assert(bs_finish(&builder)); assert(bs_publish(&rules,&builder,1)); bs_free_builder(&builder);
        uint8_t query[DDNS_QUERY_SIZE]; assert(ddns_query_type(query,42,attempt % 2 ? 1 : 28)); struct dns_probe_result result;
        assert(dns_probe_resolve(&rules,ntohs(address.sin_port),query,sizeof(query),1200,f.cancel,&result) == DNS_PROBE_CANCELLED);
        assert(result.size == 0 && result.via_tcp);
        assert(WaitForSingleObject(thread,2000) == WAIT_OBJECT_0 && f.peer_closed);
        assert(dns_probe_resolve(&rules,ntohs(address.sin_port),query,sizeof(query),1200,f.cancel,&result) == DNS_PROBE_CANCELLED);
        CloseHandle(thread); CloseHandle(f.cancel); closesocket(f.udp); closesocket(f.tcp); bs_dispose(&rules);
    }
    WSACleanup(); puts("8 real TCP cancellation/peer-close cycles passed"); return 0;
}
