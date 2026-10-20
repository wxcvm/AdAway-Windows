#define _WIN32_WINNT 0x0A00
#include "listen_address.h"
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include "listener_arrival_win32.h"

/* Use the existing pinned OpenSSL, with Windows ROOT trust anchors copied
 * into a per-check store. No trust import, no insecure retry, no AIA/CRL
 * downloads, no proxy, redirect, or secondary DNS resolution. This is an
 * offline chain/name check, not a claim about every Windows TLS consumer. */
static bool at_roots(SSL_CTX *context) {
    HCERTSTORE roots=CertOpenSystemStoreW(0,L"ROOT");
    if (!roots) return false;
    PCCERT_CONTEXT certificate=NULL; bool loaded=false;
    while ((certificate=CertEnumCertificatesInStore(roots,certificate))!=NULL) {
        const unsigned char *cursor=certificate->pbCertEncoded;
        X509 *value=d2i_X509(NULL,&cursor,(long)certificate->cbCertEncoded);
        if (value) { if (X509_STORE_add_cert(SSL_CTX_get_cert_store(context),value)==1) loaded=true; X509_free(value); }
    }
    CertCloseStore(roots,0); return loaded;
}

static bool at_wait(SOCKET socket_value,int ssl_error,ULONGLONG deadline) {
    if (ssl_error!=SSL_ERROR_WANT_READ && ssl_error!=SSL_ERROR_WANT_WRITE) return false;
    ULONGLONG now=GetTickCount64(); if (now>=deadline) return false;
    fd_set ready; FD_ZERO(&ready); FD_SET(socket_value,&ready);
    ULONGLONG remaining=deadline-now;
    struct timeval timeout={(long)(remaining/1000),(long)(remaining%1000)*1000};
    return select(0,ssl_error==SSL_ERROR_WANT_READ ? &ready : NULL,
            ssl_error==SSL_ERROR_WANT_WRITE ? &ready : NULL,NULL,&timeout)>0;
}

struct arrival_tls_result arrival_tls(const char *ip,int port,const char *host) {
    struct arrival_tls_result result={0};
    char normalized[64]; int family=la_normalize(ip,normalized);
    if (!family || !arrival_local_address(ip) || port<1 || port>65535 || !host) return result;
    char literal[64]; bool host_ip=la_normalize(host,literal)!=0;
    if (!host_ip && strcmp(host,"localhost") && !arrival_domain_valid(host)) return result;
    SOCKET client=INVALID_SOCKET; SSL_CTX *context=NULL; SSL *tls=NULL;
    context=SSL_CTX_new(TLS_client_method()); if (!context) goto done;
    if (!SSL_CTX_set_min_proto_version(context,TLS1_2_VERSION) || !at_roots(context)) goto done;
    SSL_CTX_set_verify(context,SSL_VERIFY_PEER,NULL);
    tls=SSL_new(context); if (!tls) goto done;
    if (host_ip) { if (!X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(tls),literal)) goto done; }
    else if (!SSL_set1_host(tls,host) || !SSL_set_tlsext_host_name(tls,host)) goto done;
    client=socket(family==4 ? AF_INET : AF_INET6,SOCK_STREAM,IPPROTO_TCP);
    if (client==INVALID_SOCKET) goto done;
    u_long nonblocking=1; if (ioctlsocket(client,FIONBIO,&nonblocking)) goto done;
    union { struct sockaddr_in v4; struct sockaddr_in6 v6; } address;
    memset(&address,0,sizeof(address));
    if (family==4) { address.v4.sin_family=AF_INET; address.v4.sin_port=htons((u_short)port); inet_pton(AF_INET,ip,&address.v4.sin_addr); }
    else { address.v6.sin6_family=AF_INET6; address.v6.sin6_port=htons((u_short)port); inet_pton(AF_INET6,ip,&address.v6.sin6_addr); }
    ULONGLONG deadline=GetTickCount64()+2500;
    int status=connect(client,(struct sockaddr *)&address,family==4 ? sizeof(address.v4) : sizeof(address.v6));
    if (status==SOCKET_ERROR && WSAGetLastError()!=WSAEWOULDBLOCK) goto done;
    if (!at_wait(client,SSL_ERROR_WANT_WRITE,deadline)) goto done;
    int error=0,size=sizeof(error);
    if (getsockopt(client,SOL_SOCKET,SO_ERROR,(char *)&error,&size) || error || !SSL_set_fd(tls,(int)client)) goto done;
    do { ERR_clear_error(); status=SSL_connect(tls); } while (status!=1 && at_wait(client,SSL_get_error(tls,status),deadline));
    result.verify_error=SSL_get_verify_result(tls);
    if (status!=1) {
        if (result.verify_error!=X509_V_OK) result.state=ARRIVAL_TLS_CERTIFICATE_REJECTED;
        goto done;
    }
    result.state=ARRIVAL_TLS_NO_RECEIPT;
    snprintf(result.protocol,sizeof(result.protocol),"%s",SSL_get_version(tls));
    unsigned char random[16]; if (BCryptGenRandom(NULL,random,sizeof(random),BCRYPT_USE_SYSTEM_PREFERRED_RNG)!=0) goto done;
    char nonce[33]; for (int i=0;i<16;i++) snprintf(nonce+i*2,3,"%02x",random[i]);
    char request[512]; int length=snprintf(request,sizeof(request),"GET /adaway-listener-probe/%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",nonce,host);
    int sent=0;
    while (sent<length && GetTickCount64()<deadline) {
        int count=SSL_write(tls,request+sent,length-sent);
        if (count>0) sent+=count;
        else if (!at_wait(client,SSL_get_error(tls,count),deadline)) goto done;
    }
    if (sent!=length) goto done;
    char response[4097]; size_t used=0;
    while (used<sizeof(response)-1 && GetTickCount64()<deadline) {
        int count=SSL_read(tls,response+used,(int)(sizeof(response)-1-used));
        if (count>0) {
            used+=(size_t)count; response[used]=0;
            if (arrival_valid_receipt(response,nonce)) { result.state=ARRIVAL_TLS_RECEIPT; break; }
        } else if (!at_wait(client,SSL_get_error(tls,count),deadline)) break;
    }
done:
    if (tls) SSL_free(tls);
    if (context) SSL_CTX_free(context);
    if (client!=INVALID_SOCKET) closesocket(client);
    return result;
}
