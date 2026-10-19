#include "dns_policy_wire.h"
#include "block_rule_snapshot.h"
#include <string.h>

bool dns_policy_respond_from_rules(struct bs_store *rules, const uint8_t *query, size_t query_size,
                        uint8_t *output, size_t capacity, size_t *written) {
    if (written) *written = 0;
    struct dns_policy_question question;
    if (!rules || !dns_policy_parse_question(query, query_size, &question)) return false;
    struct bs_result resolved = bs_decide(rules, question.domain, question.qtype, 1);
    return resolved.generation && dns_policy_respond(query, query_size,
            (enum dns_policy_action)resolved.decision.action, resolved.address,
            resolved.family == 4 ? 4u : resolved.family == 6 ? 16u : 0u, output, capacity, written);
}

static uint16_t u16(const uint8_t *data, size_t offset) {
    return (uint16_t)(((uint16_t)data[offset] << 8) | data[offset + 1]);
}

bool dns_policy_parse_question(const uint8_t *query, size_t size,
                               struct dns_policy_question *result) {
    if (!query || !result || size < 19u || size > DNS_POLICY_MAX_MESSAGE)
        return false;
    if ((query[2] & 0xfeu) != 0 || query[3] != 0 ||
            u16(query, 4) != 1 || u16(query, 6) != 0 ||
            u16(query, 8) != 0 || u16(query, 10) != 0) return false;
    size_t offset = 12, name_length = 0, wire_name_length = 1;
    bool has_label = false;
    char domain[254] = {0};
    while (offset < size) {
        unsigned length = query[offset++];
        if (length == 0) break;
        if (length > 63 || length > size - offset ||
                wire_name_length + length + 1 > 255) return false;
        if (has_label) {
            if (name_length + 1 >= sizeof(domain)) return false;
            domain[name_length++] = '.';
        }
        for (unsigned i = 0; i < length; ++i) {
            unsigned char ch = query[offset + i];
            if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
                    || (ch >= '0' && ch <= '9') || ch == '-')) return false;
            if ((i == 0 || i + 1 == length) && ch == '-') return false;
            if (name_length + 1 >= sizeof(domain)) return false;
            domain[name_length++] = (ch >= 'A' && ch <= 'Z') ? (char)(ch + 32) : (char)ch;
        }
        offset += length;
        wire_name_length += length + 1;
        has_label = true;
    }
    if (!has_label || offset + 4 != size || name_length > 253)
        return false;
    uint16_t qtype = u16(query, offset);
    if (u16(query, offset + 2) != 1 || (qtype != 1 && qtype != 28))
        return false;
    domain[name_length] = 0;
    memcpy(result->domain, domain, name_length + 1);
    result->qtype = qtype;
    return true;
}

bool dns_policy_respond(const uint8_t *query, size_t query_size,
                        enum dns_policy_action action,
                        const uint8_t *address, size_t address_size,
                        uint8_t *output, size_t capacity, size_t *written) {
    if (written) *written = 0;
    if (!query || !output || !written) return false;
    struct dns_policy_question question;
    if (!dns_policy_parse_question(query, query_size, &question))
        return false;
    uint8_t rcode = 0;
    uint8_t zeros[16] = {0};
    const uint8_t *data = NULL;
    size_t data_size = 0;
    switch (action) {
    case DNS_POLICY_NXDOMAIN: rcode = 3; break;
    case DNS_POLICY_REFUSED: rcode = 5; break;
    case DNS_POLICY_ZERO_ADDRESS:
        data_size = question.qtype == 1 ? 4 : 16;
        data = zeros;
        break;
    case DNS_POLICY_REPLACE:
        data_size = question.qtype == 1 ? 4 : 16;
        if (!address || address_size != data_size) return false;
        data = address;
        break;
    default:
        return false;
    }

    const size_t answer_size = data ? 12u + data_size : 0;
    if (query_size + answer_size > DNS_POLICY_MAX_MESSAGE ||
            query_size + answer_size > capacity) return false;
    const size_t count = query_size + answer_size;
    memmove(output, query, query_size);
    output[2] = (uint8_t)(0x80u | (query[2] & 1u)); /* preserve RD, no RA */
    output[3] = rcode;
    output[6] = 0;
    output[7] = data ? 1 : 0;
    if (data) {
        size_t at = query_size;
        output[at++] = 0xc0;
        output[at++] = 0x0c;
        output[at++] = (uint8_t)(question.qtype >> 8);
        output[at++] = (uint8_t)question.qtype;
        output[at++] = 0;
        output[at++] = 1;
        memset(output + at, 0, 4); /* TTL 0: don't cache stale rule updates */
        at += 4;
        output[at++] = 0;
        output[at++] = (uint8_t)data_size;
        memcpy(output + at, data, data_size);
    }
    *written = count;
    return true;
}
