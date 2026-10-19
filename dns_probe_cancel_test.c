#include "dns_probe_win32.h"
#include <ws2tcpip.h>
#include "diagnostic_dns_reply.h"
#include "block_rule_snapshot.h"
#include <assert.h>
#include <stdio.h>

struct fixture { SOCKET udp, tcp; HANDLE cancel; int peer_closed; };
static DWORD WINAPI serve(void *opaque) {
    struct fixture *f = (struct fixture *)opaque;
    uint8_t bytes[512]; struct sockaddr_storage peer; int peer_size = sizeof(peer);
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
        enum dns_probe_ip_version ip_version = (attempt / 2) % 2 ? DNS_PROBE_IPV6 : DNS_PROBE_IPV4;
        int family = ip_version == DNS_PROBE_IPV6 ? AF_INET6 : AF_INET;
        f.tcp = socket(family,SOCK_STREAM,IPPROTO_TCP); assert(f.tcp != INVALID_SOCKET);
        union { struct sockaddr_in v4; struct sockaddr_in6 v6; } address;
        memset(&address,0,sizeof(address)); int length;
        if (ip_version == DNS_PROBE_IPV6) {
            address.v6.sin6_family=AF_INET6; ((uint8_t *)&address.v6.sin6_addr)[15]=1; length=sizeof(address.v6);
            DWORD only=1; assert(!setsockopt(f.tcp,IPPROTO_IPV6,IPV6_V6ONLY,(const char *)&only,sizeof(only)));
        } else {
            address.v4.sin_family=AF_INET; address.v4.sin_addr.s_addr=htonl(INADDR_LOOPBACK); length=sizeof(address.v4);
        }
        assert(!bind(f.tcp,(struct sockaddr *)&address,length)); assert(!listen(f.tcp,1));
        assert(!getsockname(f.tcp,(struct sockaddr *)&address,&length));
        f.udp=socket(family,SOCK_DGRAM,IPPROTO_UDP); assert(f.udp != INVALID_SOCKET);
        if (ip_version == DNS_PROBE_IPV6) {
            DWORD only=1; assert(!setsockopt(f.udp,IPPROTO_IPV6,IPV6_V6ONLY,(const char *)&only,sizeof(only)));
        }
        assert(!bind(f.udp,(struct sockaddr *)&address,length));
        DWORD timeout=1500; assert(!setsockopt(f.udp,SOL_SOCKET,SO_RCVTIMEO,(const char *)&timeout,sizeof(timeout)));
        f.cancel=CreateEventW(NULL,TRUE,FALSE,NULL); assert(f.cancel);
        HANDLE thread=CreateThread(NULL,0,serve,&f,0,NULL); assert(thread);
        struct bs_store rules=BS_STORE_INITIALIZER; struct bs_builder builder; memset(&builder,0,sizeof(builder));
        assert(bs_finish(&builder)); assert(bs_publish(&rules,&builder,1)); bs_free_builder(&builder);
        uint8_t query[DDNS_QUERY_SIZE]; assert(ddns_query_type(query,42,attempt % 2 ? 1 : 28)); struct dns_probe_result result;
        unsigned short port = ntohs(ip_version == DNS_PROBE_IPV6 ? address.v6.sin6_port : address.v4.sin_port);
        enum dns_probe_status status = ip_version == DNS_PROBE_IPV4
            ? dns_probe_resolve(&rules,port,query,sizeof(query),1200,f.cancel,&result)
            : dns_probe_resolve_family(&rules,port,query,sizeof(query),1200,f.cancel,ip_version,&result);
        assert(status == DNS_PROBE_CANCELLED);
        assert(result.size == 0 && result.via_tcp);
        assert(WaitForSingleObject(thread,2000) == WAIT_OBJECT_0 && f.peer_closed);
        assert(dns_probe_resolve_family(&rules,port,query,sizeof(query),1200,f.cancel,ip_version,&result) == DNS_PROBE_CANCELLED);
        assert(dns_probe_resolve_family(&rules,port,query,sizeof(query),1200,NULL,(enum dns_probe_ip_version)5,&result) == DNS_PROBE_INVALID);
        assert(result.size == 0 && result.generation == 0);
        CloseHandle(thread); CloseHandle(f.cancel); closesocket(f.udp); closesocket(f.tcp); bs_dispose(&rules);
    }
    WSACleanup(); puts("8 IPv4/IPv6 A/AAAA TCP cancellation/peer-close cycles passed"); return 0;
}
