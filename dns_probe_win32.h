#ifndef ADBLOCK_DNS_PROBE_WIN32_H
#define ADBLOCK_DNS_PROBE_WIN32_H
#include <winsock2.h>
#include <windows.h>
#include <stddef.h>
#include <stdint.h>

enum dns_probe_status { DNS_PROBE_OK, DNS_PROBE_INVALID, DNS_PROBE_TIMEOUT,
    DNS_PROBE_IO, DNS_PROBE_BAD_REPLY, DNS_PROBE_CANCELLED };
enum dns_probe_ip_version { DNS_PROBE_IPV4 = 4, DNS_PROBE_IPV6 = 6 };
struct dns_probe_result {
    uint8_t answer[512]; size_t size; int via_tcp;
    uint64_t generation; uint32_t source; int scope; int action;
};
struct bs_store;
/* Fixed example.com A/AAAA; only connects to 127.0.0.1:port or [::1]:port.
 * WSAStartup is caller-owned. The original function always selects IPv4.
 * No listener, DNS lookup, route, OS settings, cache or automatic retry on timeout.
 * Budget is shared by UDP and one TC-triggered TCP exchange, maximum 1200 ms.
 * A signalled optional event cancels waits. Caller owns the event. */
enum dns_probe_status dns_probe_resolve(struct bs_store *rules, unsigned short port,
    const uint8_t *query, size_t query_size, unsigned budget_ms, HANDLE cancel,
    struct dns_probe_result *result);
enum dns_probe_status dns_probe_resolve_family(struct bs_store *rules, unsigned short port,
    const uint8_t *query, size_t query_size, unsigned budget_ms, HANDLE cancel,
    enum dns_probe_ip_version ip_version, struct dns_probe_result *result);
#endif
