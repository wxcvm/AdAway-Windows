#ifndef ADBLOCK_LISTENER_ARRIVAL_WIN32_H
#define ADBLOCK_LISTENER_ARRIVAL_WIN32_H
#include <stdbool.h>
#include <stddef.h>
#include <wchar.h>
struct arrival_config { char ip[64]; bool all; int http; int stats; };
bool arrival_domain_valid(const char *domain);
bool arrival_valid_receipt(const char *response,const char *nonce);
bool arrival_receipt(const char *ip,int port);
void arrival_report(const struct arrival_config *config,const char *adblock,const char *hosts,wchar_t *out,size_t cap);
#endif
