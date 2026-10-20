#ifndef ADBLOCK_LISTENER_ARRIVAL_WIN32_H
#define ADBLOCK_LISTENER_ARRIVAL_WIN32_H
#include <stdbool.h>
#include <stddef.h>
#include <wchar.h>
struct arrival_config { char ip[64]; bool all; int http; int stats; char ipv6[64]; bool pair; int https; };
bool arrival_domain_valid(const char *domain);
bool arrival_valid_receipt(const char *response,const char *nonce);
bool arrival_receipt(const char *ip,int port);
bool arrival_local_address(const char *ip);
enum arrival_tls_state { ARRIVAL_TLS_UNAVAILABLE, ARRIVAL_TLS_RECEIPT, ARRIVAL_TLS_NO_RECEIPT, ARRIVAL_TLS_CERTIFICATE_REJECTED };
struct arrival_tls_result { enum arrival_tls_state state; long verify_error; char protocol[32]; };
struct arrival_tls_result arrival_tls(const char *ip,int port,const char *host);
void arrival_report(const struct arrival_config *config,const char *adblock,const char *hosts,wchar_t *out,size_t cap);
#endif
