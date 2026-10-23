#ifndef ADBLOCK_LISTENER_ARRIVAL_WIN32_H
#define ADBLOCK_LISTENER_ARRIVAL_WIN32_H
#include <stdbool.h>
#include <stddef.h>
#include <wchar.h>
struct arrival_config { char ip[64]; bool all; int http; int stats; char ipv6[64]; bool pair; int https; };
/* Context must outlive the call. Cancellation never changes network settings. */
enum arrival_stage { ARRIVAL_STAGE_START, ARRIVAL_STAGE_MANAGEMENT, ARRIVAL_STAGE_HTTP,
    ARRIVAL_STAGE_HTTPS, ARRIVAL_STAGE_DNS, ARRIVAL_STAGE_UDP, ARRIVAL_STAGE_DONE, ARRIVAL_STAGE_CANCELLED };
struct arrival_cancel {
    bool (*requested)(void *context);
    void *context;
    void (*progress)(void *context,enum arrival_stage stage,const char *target,int port);
};
static inline bool arrival_cancel_requested(const struct arrival_cancel *cancel) {
    return cancel && cancel->requested && cancel->requested(cancel->context);
}
static inline void arrival_progress(const struct arrival_cancel *cancel,enum arrival_stage stage,
    const char *target,int port) {
    if (cancel && cancel->progress) cancel->progress(cancel->context,stage,target,port);
}
bool arrival_domain_valid(const char *domain);
bool arrival_valid_receipt(const char *response,const char *nonce);
bool arrival_receipt(const char *ip,int port);
bool arrival_receipt_cancel(const char *ip,int port,const struct arrival_cancel *cancel);
bool arrival_local_address(const char *ip);
enum arrival_tls_state { ARRIVAL_TLS_UNAVAILABLE, ARRIVAL_TLS_RECEIPT, ARRIVAL_TLS_NO_RECEIPT, ARRIVAL_TLS_CERTIFICATE_REJECTED, ARRIVAL_TLS_CANCELLED };
struct arrival_tls_result { enum arrival_tls_state state; long verify_error; char protocol[32]; };
struct arrival_tls_result arrival_tls(const char *ip,int port,const char *host);
struct arrival_tls_result arrival_tls_cancel(const char *ip,int port,const char *host,const struct arrival_cancel *cancel);
void arrival_report(const struct arrival_config *config,const char *adblock,const char *hosts,wchar_t *out,size_t cap);
/* False means cancelled; completed diagnostics may still report failed probes. */
bool arrival_report_cancel(const struct arrival_config *config,const char *adblock,const char *hosts,wchar_t *out,size_t cap,const struct arrival_cancel *cancel);
#endif
