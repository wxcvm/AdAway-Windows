#include "dns_policy_wire.h"
#include "block_rule_snapshot.h"
#include "subscription_import.h"
#include "traffic_core_contract.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

_Static_assert((int)DNS_POLICY_PASS == (int)CORE_PASS, "shared PASS ordinal mismatch");
_Static_assert((int)DNS_POLICY_NXDOMAIN == (int)CORE_NXDOMAIN, "shared NXDOMAIN mismatch");
_Static_assert((int)DNS_POLICY_REFUSED == (int)CORE_REFUSED, "shared REFUSED mismatch");
_Static_assert((int)DNS_POLICY_ZERO_ADDRESS == (int)CORE_ZERO_ADDRESS, "shared ZERO mismatch");
_Static_assert((int)DNS_POLICY_REPLACE == (int)CORE_REPLACE, "shared REPLACE mismatch");

static size_t make_query(const char *domain, unsigned qtype, uint8_t *query) {
    memset(query, 0, 512);
    query[0] = 0x12; query[1] = 0x34; query[2] = 1; query[5] = 1;
    size_t pos = 12;
    const char *start = domain;
    do {
        const char *dot = strchr(start, '.');
        size_t len = dot ? (size_t)(dot - start) : strlen(start);
        assert(len > 0 && len <= 63 && pos + len + 6 <= 512);
        query[pos++] = (uint8_t)len;
        memcpy(query + pos, start, len);
        pos += len;
        if (!dot) break;
        start = dot + 1;
    } while (1);
    query[pos++] = 0;
    query[pos++] = (uint8_t)(qtype >> 8);
    query[pos++] = (uint8_t)qtype;
    query[pos++] = 0;
    query[pos++] = 1;
    return pos;
}
static uint16_t u16(const uint8_t *bytes, size_t offset) {
    return (uint16_t)((bytes[offset] << 8) | bytes[offset+1]);
}

int main(void) {
    uint8_t query[512], response[512], sample[512];
    size_t written = 0;
    size_t length = make_query("Example.Test", 1, query);
    struct dns_policy_question parsed;
    assert(dns_policy_parse_question(query, length, &parsed));
    assert(strcmp(parsed.domain, "example.test") == 0 && parsed.qtype == 1);

    /* Exact parity with Android's v1 DNS wire semantics. */
    assert(dns_policy_respond(query, length, DNS_POLICY_NXDOMAIN, NULL, 0,
                              response, sizeof(response), &written));
    assert(written == length && response[0] == 0x12 && response[1] == 0x34);
    assert(response[2] == 0x81 && response[3] == 3);
    assert(u16(response, 4) == 1 && u16(response, 6) == 0);
    assert(memcmp(response + 12, query + 12, length - 12) == 0);
    assert(dns_policy_respond(query, length, DNS_POLICY_REFUSED, NULL, 0,
                              response, sizeof(response), &written));
    assert(written == length && response[3] == 5);
    assert(!dns_policy_respond(query, length, DNS_POLICY_PASS, NULL, 0,
                               response, sizeof(response), &written));
    assert(written == 0);

    uint8_t v4[] = {203,0,113,9};
    assert(dns_policy_respond(query, length, DNS_POLICY_REPLACE, v4, sizeof(v4),
                              response, sizeof(response), &written));
    assert(written == length + 16);
    assert(response[3] == 0 && u16(response,6) == 1);
    assert(response[length] == 0xc0 && response[length+1] == 0x0c);
    assert(u16(response,length+2) == 1 && u16(response,length+4) == 1);
    assert(u16(response,length+10) == 4);
    for (int i = 6; i < 10; i++) assert(response[length+i] == 0); /* TTL 0 */
    assert(memcmp(response+length+12, v4, sizeof(v4)) == 0);

    assert(dns_policy_respond(query,length,DNS_POLICY_ZERO_ADDRESS,NULL,0,
                              response,sizeof(response),&written));
    for (size_t i = length+12; i < written; i++) assert(response[i] == 0);
    assert(!dns_policy_respond(query,length,DNS_POLICY_REPLACE,v4,3,
                               response,sizeof(response),&written));
    assert(!dns_policy_respond(query,length,DNS_POLICY_REPLACE,v4,4,
                               response,length+15,&written));

    length = make_query("ipv6.test", 28, query);
    uint8_t v6[16] = {0x20,0x01,0x0d,0xb8,0};
    v6[15] = 1;
    assert(dns_policy_respond(query,length,DNS_POLICY_REPLACE,v6,16,
                              response,sizeof(response),&written));
    assert(written == length+28 && u16(response,length+2)==28);
    assert(u16(response,length+10)==16);
    assert(memcmp(response+length+12,v6,16)==0);
    assert(!dns_policy_respond(query,length,DNS_POLICY_REPLACE,v4,4,
                               response,sizeof(response),&written));

    length = make_query("example.test", 1, query);
    memcpy(sample, query, length);
    sample[5] = 2; /* multi-question */
    assert(!dns_policy_parse_question(sample,length,&parsed));
    memcpy(sample, query, length);
    sample[11] = 1; /* EDNS/additional */
    assert(!dns_policy_parse_question(sample,length,&parsed));
    memcpy(sample, query, length);
    sample[2] = 0x81; /* response, not query */
    assert(!dns_policy_parse_question(sample,length,&parsed));
    memcpy(sample, query, length);
    sample[12] = 0xc0; /* QNAME compression */
    assert(!dns_policy_parse_question(sample,length,&parsed));
    memcpy(sample, query, length);
    sample[3] = 0x10; /* unexpected flag */
    assert(!dns_policy_parse_question(sample,length,&parsed));
    memcpy(sample, query, length);
    sample[length-1] = 3; /* non-IN qclass */
    assert(!dns_policy_parse_question(sample,length,&parsed));
    assert(!dns_policy_parse_question(query,length-1,&parsed));
    length = make_query("example.test",15,query);
    assert(!dns_policy_parse_question(query,length,&parsed));
    assert(!dns_policy_parse_question(NULL,0,&parsed));

    // Actual subscription importer -> serialized staging file -> production index -> DNS encoder.
    FILE *source = tmpfile(), *staged = tmpfile(); assert(source && staged);
    assert(fputs("||blocked.test^\n192.0.2.8 redirect.test\n@@||allow.blocked.test^\n", source) >= 0); rewind(source);
    struct si_stats stats = {0}; assert(si_import_source(source, staged, &stats, 2)); rewind(staged);
    struct bs_builder builder; memset(&builder, 0, sizeof(builder));
    assert(bs_parse_file(staged, &builder)); assert(bs_finish(&builder));
    struct bs_store rules = BS_STORE_INITIALIZER; assert(bs_publish(&rules, &builder, 1));
    length = make_query("sub.blocked.test", 1, query);
    assert(dns_policy_respond_from_rules(&rules,query,length,response,sizeof(response),&written));
    assert(response[3] == 3);
    length = make_query("redirect.test", 1, query);
    assert(dns_policy_respond_from_rules(&rules,query,length,response,sizeof(response),&written));
    assert(response[written - 1] == 8);
    length = make_query("redirect.test", 28, query);
    assert(!dns_policy_respond_from_rules(&rules,query,length,response,sizeof(response),&written));
    length = make_query("sub.allow.blocked.test", 1, query);
    assert(!dns_policy_respond_from_rules(&rules,query,length,response,sizeof(response),&written));
    assert(fclose(source) == 0); assert(fclose(staged) == 0); bs_dispose(&rules); bs_free_builder(&builder);
    puts("DNS wire policy: actual subscription import/snapshot integration, strict parsing and synthetic A/AAAA responses passed");
    return 0;
}
