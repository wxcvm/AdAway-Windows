#ifndef ADBLOCK_DNS_POLICY_WIRE_H
#define ADBLOCK_DNS_POLICY_WIRE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Platform-independent DNS wire synthesis. No Windows API, socket, Wintun
 * adapter, route, DNS settings or allocation is performed by this module.
 * A future transport must explicitly forward queries when we return false.
 *
 * Actions have the same ordinal mapping as the shared core contract:
 * PASS=0, NXDOMAIN=1, REFUSED=2, ZERO_ADDRESS=3, REPLACE=4.
 */
enum dns_policy_action {
    DNS_POLICY_PASS = 0,
    DNS_POLICY_NXDOMAIN = 1,
    DNS_POLICY_REFUSED = 2,
    DNS_POLICY_ZERO_ADDRESS = 3,
    DNS_POLICY_REPLACE = 4
};

#define DNS_POLICY_MAX_MESSAGE 512u
struct dns_policy_question {
    char domain[254]; /* normalized lower-case ASCII, NUL-terminated */
    uint16_t qtype;
};

/* Supports exactly one uncompressed IN A/AAAA question, no EDNS/DNSSEC. */
bool dns_policy_parse_question(const uint8_t *query, size_t size,
                               struct dns_policy_question *result);

/* Return false without writing an answer when malformed, unsupported, PASS
 * or output buffer too small. TTL is zero for synthetic answer records.
 * A/AAAA replacement payload MUST match 4/16-byte question family. */
bool dns_policy_respond(const uint8_t *query, size_t query_size,
                        enum dns_policy_action action,
                        const uint8_t *address, size_t address_size,
                        uint8_t *output, size_t capacity, size_t *written);

#endif
