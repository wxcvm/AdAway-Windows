#ifndef QUERY_LOG_PAGE_H
#define QUERY_LOG_PAGE_H

#include "dashboard_response.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define QLP_PAGE_SIZE 300
#define QLP_MAX_TOTAL 10000u
#define QLP_GENERATION_SIZE 33
#define QLP_ANCHOR_SIZE 21
#define QLP_HOST_SIZE 192

/*
 * Query-log cursor state. Both cursor strings empty means "fresh page". If
 * either is nonempty, both must be present and are compared byte-for-byte
 * with the response cursor.
 */
struct qlp_request {
    uint32_t offset;
    char generation[QLP_GENERATION_SIZE];
    char anchor[QLP_ANCHOR_SIZE];
};

struct qlp_row {
    uint64_t timestamp;
    int uid; /* -1 when unknown or an older server omitted attribution */
    int action;
    int type;
    int mode;
    int family; /* Observed HTTP connection family: 0 unknown, 4 or 6. */
    char host[QLP_HOST_SIZE];
};

struct qlp_page {
    uint32_t offset;
    uint32_t next_offset;
    uint32_t total;
    uint32_t returned;
    bool has_more;
    char generation[QLP_GENERATION_SIZE];
    char anchor[QLP_ANCHOR_SIZE];
    struct qlp_row rows[QLP_PAGE_SIZE];
};

static inline bool qlp_json_is_space(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static inline struct mg_str qlp_json_trim(struct mg_str value) {
    if (value.buf == NULL) {
        value.len = 0;
        return value;
    }
    while (value.len != 0u && qlp_json_is_space(value.buf[0])) {
        value.buf++;
        value.len--;
    }
    while (value.len != 0u &&
           qlp_json_is_space(value.buf[value.len - 1u])) {
        value.len--;
    }
    return value;
}

static inline size_t qlp_bounded_strlen(const char *text, size_t capacity) {
    size_t length = 0;
    if (text == NULL) return capacity;
    while (length < capacity && text[length] != '\0') length++;
    return length;
}

static inline bool qlp_decimal_digits(const char *text, size_t length,
                                      uint64_t *value) {
    uint64_t parsed = 0;
    if (text == NULL || length == 0u ||
        (length > 1u && text[0] == '0')) {
        return false;
    }
    for (size_t i = 0; i < length; i++) {
        unsigned char character = (unsigned char) text[i];
        unsigned digit;
        if (character < (unsigned char) '0' ||
            character > (unsigned char) '9') {
            return false;
        }
        digit = (unsigned) (character - (unsigned char) '0');
        if (parsed > UINT64_MAX / 10u ||
            (parsed == UINT64_MAX / 10u &&
             (uint64_t) digit > UINT64_MAX % 10u)) {
            return false;
        }
        parsed = parsed * 10u + (uint64_t) digit;
    }
    if (value != NULL) *value = parsed;
    return true;
}

static inline bool qlp_json_integer(struct mg_str token, bool allow_negative,
                                    bool *negative, uint64_t *magnitude) {
    size_t start = 0;
    bool is_negative = false;
    if (magnitude == NULL) return false;
    token = qlp_json_trim(token);
    if (token.buf == NULL || token.len == 0u) return false;
    if (token.buf[0] == '-') {
        if (!allow_negative) return false;
        is_negative = true;
        start = 1;
    }
    if (!qlp_decimal_digits(token.buf + start, token.len - start,
                            magnitude)) {
        return false;
    }
    if (is_negative && *magnitude == 0u) return false;
    if (negative != NULL) *negative = is_negative;
    return true;
}

static inline bool qlp_json_uint(struct mg_str json, const char *path,
                                 uint64_t *value) {
    return qlp_json_integer(mg_json_get_tok(json, path), false, NULL, value);
}

static inline bool qlp_json_small_uint(struct mg_str json, const char *path,
                                       uint64_t maximum, int *value) {
    uint64_t parsed = 0;
    if (value == NULL || !qlp_json_uint(json, path, &parsed) ||
        parsed > maximum) {
        return false;
    }
    *value = (int) parsed;
    return true;
}

static inline bool qlp_json_type(struct mg_str json, int *value) {
    bool negative = false;
    uint64_t magnitude = 0;
    if (value == NULL) return false;
    if (!qlp_json_integer(mg_json_get_tok(json, "$.type"), true, &negative,
                          &magnitude)) {
        return false;
    }
    if (negative) {
        if (magnitude != 1u) return false;
        *value = -1;
    } else {
        if (magnitude > 65534u) return false;
        *value = (int) magnitude;
    }
    return true;
}

static inline bool qlp_json_bool(struct mg_str json, const char *path,
                                 bool *value) {
    struct mg_str token = qlp_json_trim(mg_json_get_tok(json, path));
    if (value == NULL) return false;
    if (token.len == 4u && memcmp(token.buf, "true", 4u) == 0) {
        *value = true;
        return true;
    }
    if (token.len == 5u && memcmp(token.buf, "false", 5u) == 0) {
        *value = false;
        return true;
    }
    return false;
}

static inline bool qlp_hex_generation(const char *text, size_t length) {
    if (text == NULL || length != 32u) return false;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char) text[i];
        if (!((c >= (unsigned char) '0' && c <= (unsigned char) '9') ||
              (c >= (unsigned char) 'a' && c <= (unsigned char) 'f') ||
              (c >= (unsigned char) 'A' && c <= (unsigned char) 'F'))) {
            return false;
        }
    }
    return true;
}

static inline bool qlp_utf8_host(const unsigned char *text, size_t length) {
    size_t i = 0;
    if (text == NULL || length == 0u) return false;
    while (i < length) {
        unsigned char first = text[i];
        if (first < 0x20 || first == 0x7f) return false;
        if (first < 0x80) {
            i++;
            continue;
        }
        if (first >= 0xc2 && first <= 0xdf) {
            unsigned char second;
            unsigned codepoint;
            if (i + 1u >= length) return false;
            second = text[i + 1u];
            if ((second & 0xc0) != 0x80) return false;
            codepoint = ((unsigned) (first & 0x1f) << 6) |
                        (unsigned) (second & 0x3f);
            if (codepoint >= 0x80u && codepoint <= 0x9fu) return false;
            i += 2u;
            continue;
        }
        if (first >= 0xe0 && first <= 0xef) {
            unsigned char second, third;
            if (i + 2u >= length) return false;
            second = text[i + 1u];
            third = text[i + 2u];
            if ((second & 0xc0) != 0x80 || (third & 0xc0) != 0x80) {
                return false;
            }
            if (first == 0xe0 && second < 0xa0) return false;
            if (first == 0xed && second >= 0xa0) return false;
            i += 3u;
            continue;
        }
        if (first >= 0xf0 && first <= 0xf4) {
            unsigned char second, third, fourth;
            if (i + 3u >= length) return false;
            second = text[i + 1u];
            third = text[i + 2u];
            fourth = text[i + 3u];
            if ((second & 0xc0) != 0x80 || (third & 0xc0) != 0x80 ||
                (fourth & 0xc0) != 0x80) {
                return false;
            }
            if (first == 0xf0 && second < 0x90) return false;
            if (first == 0xf4 && second > 0x8f) return false;
            i += 4u;
            continue;
        }
        return false;
    }
    return true;
}

static inline bool qlp_entries_empty(struct mg_str entries) {
    size_t i = 1;
    if (entries.buf == NULL || entries.len < 2u || entries.buf[0] != '[') {
        return false;
    }
    while (i < entries.len && qlp_json_is_space(entries.buf[i])) i++;
    if (i >= entries.len || entries.buf[i] != ']') return false;
    i++;
    while (i < entries.len && qlp_json_is_space(entries.buf[i])) i++;
    return i == entries.len;
}

static inline bool qlp_entries_end_object(struct mg_str entries) {
    size_t end = entries.len;
    if (entries.buf == NULL || end < 2u ||
        entries.buf[end - 1u] != ']') {
        return false;
    }
    end--;
    while (end > 0u && qlp_json_is_space(entries.buf[end - 1u])) end--;
    return end > 0u && entries.buf[end - 1u] == '}';
}

static inline bool qlp_entries_tail(struct mg_str entries, size_t offset) {
    size_t i = offset;
    if (i > entries.len) return false;
    while (i < entries.len && qlp_json_is_space(entries.buf[i])) i++;
    if (i < entries.len) {
        if (entries.buf[i] != ']') return false;
        i++;
    }
    while (i < entries.len && qlp_json_is_space(entries.buf[i])) i++;
    return i == entries.len;
}

/* This pinned Mongoose decoder supports only one-byte Unicode escapes and
 * may return a decoded prefix for other \uXXXX forms. Production emits UTF-8
 * directly. Reject unsupported escapes before decoding, never accept a prefix
 * or reinterpret escaped non-ASCII bytes as a different hostname. */
static inline bool qlp_string_escapes_supported(struct mg_str json, const char *path) {
    struct mg_str token = mg_json_get_tok(json, path);
    if (token.len < 2 || token.buf[0] != '"' || token.buf[token.len - 1] != '"') return false;
    for (size_t i = 1; i + 1 < token.len; i++) {
        if (token.buf[i] != '\\') continue;
        if (++i + 1 >= token.len) return false;
        if (token.buf[i] == 'u') {
            if (i + 5 >= token.len || token.buf[i + 1] != '0' || token.buf[i + 2] != '0' ||
                token.buf[i + 3] < '0' || token.buf[i + 3] > '7') return false;
            char last = token.buf[i + 4];
            if (!((last >= '0' && last <= '9') || (last >= 'a' && last <= 'f') || (last >= 'A' && last <= 'F'))) return false;
            i += 4;
        }
    }
    return true;
}

static inline bool qlp_read_generation(struct mg_str json,
                                       char out[QLP_GENERATION_SIZE]) {
    char stage[QLP_GENERATION_SIZE + 32];
    size_t length;
    if (!qlp_string_escapes_supported(json, "$.generation")) return false;
    memset(stage, 0, sizeof stage);
    length = mg_json_unescape(json, "$.generation", stage, sizeof stage);
    if (length != 32u || !qlp_hex_generation(stage, length)) return false;
    memcpy(out, stage, length);
    out[length] = '\0';
    return true;
}

static inline bool qlp_read_anchor(struct mg_str json,
                                   char out[QLP_ANCHOR_SIZE]) {
    char stage[32];
    size_t length;
    if (!qlp_string_escapes_supported(json, "$.anchor")) return false;
    memset(stage, 0, sizeof stage);
    length = mg_json_unescape(json, "$.anchor", stage, sizeof stage);
    if (length == 0u || length > (size_t) (QLP_ANCHOR_SIZE - 1) ||
        !qlp_decimal_digits(stage, length, NULL)) {
        return false;
    }
    memcpy(out, stage, length);
    out[length] = '\0';
    return true;
}

static inline bool qlp_json_family(struct mg_str row, int *family) {
    if (mg_json_get_tok(row, "$.family").len == 0) { *family = 0; return true; }
    return qlp_json_small_uint(row, "$.family", 6, family) &&
        (*family == 0 || *family == 4 || *family == 6);
}

static inline bool qlp_parse_row(struct mg_str row, struct qlp_row *out) {
    char host_stage[512];
    size_t host_length;
    uint64_t timestamp = 0;
    int action = 0;
    int type = 0;
    int mode = 0;
    int uid = -1;
    int family = 0;

    if (out == NULL || row.buf == NULL || row.len == 0u ||
        !dashboard_json_object(row)) {
        return false;
    }
    if (!qlp_json_uint(row, "$.ts", &timestamp) ||
        !qlp_json_small_uint(row, "$.action", 2u, &action) ||
        !qlp_json_type(row, &type) ||
        !qlp_json_small_uint(row, "$.mode", 255u, &mode) ||
        !qlp_json_family(row, &family)) {
        return false;
    }
    struct mg_str uid_token = mg_json_get_tok(row, "$.uid");
    if (uid_token.len) {
        bool negative = false;
        uint64_t value = 0;
        if (!qlp_json_integer(uid_token, true, &negative, &value) ||
            (negative ? value != 1u : value > INT_MAX)) return false;
        uid = negative ? -1 : (int)value;
    }
    if (!qlp_string_escapes_supported(row, "$.host")) return false;
    memset(host_stage, 0, sizeof host_stage);
    host_length = mg_json_unescape(row, "$.host", host_stage,
                                   sizeof host_stage);
    if (host_length == 0u ||
        host_length > (size_t) (QLP_HOST_SIZE - 1)) {
        return false;
    }
    if (!qlp_utf8_host((const unsigned char *) host_stage, host_length)) {
        return false;
    }

    out->timestamp = timestamp;
    out->uid = uid;
    out->action = action;
    out->type = type;
    out->mode = mode;
    out->family = family;
    memcpy(out->host, host_stage, host_length);
    out->host[host_length] = '\0';
    return true;
}

/*
 * Parses the JSON body of one /internal-qlog page. Returns false without
 * modifying *out on any validation, allocation, or cursor failure.
 */
static inline bool qlp_parse(struct mg_str json,
                             const struct qlp_request *request,
                             struct qlp_page *out) {
    struct mg_str entries = {NULL, 0};
    struct qlp_page *page = NULL;
    char generation[QLP_GENERATION_SIZE] = {0};
    char anchor[QLP_ANCHOR_SIZE] = {0};
    uint64_t offset_value = 0;
    uint64_t limit_value = 0;
    uint64_t total_value = 0;
    uint64_t returned_value = 0;
    uint64_t next_value = 0;
    size_t request_generation_length = 0;
    size_t request_anchor_length = 0;
    size_t entry_offset = 0;
    bool has_more = false;
    bool have_cursor = false;

    if (request == NULL || out == NULL || json.buf == NULL ||
        json.len == 0u || json.len > (size_t) INT_MAX ||
        memchr(json.buf, '\0', json.len) != NULL) {
        return false;
    }
    if (!dashboard_json_object(json)) return false;

    request_generation_length =
        qlp_bounded_strlen(request->generation, sizeof request->generation);
    request_anchor_length =
        qlp_bounded_strlen(request->anchor, sizeof request->anchor);
    if (request_generation_length == sizeof request->generation ||
        request_anchor_length == sizeof request->anchor) {
        return false;
    }
    have_cursor = request_generation_length != 0u;
    if (have_cursor != (request_anchor_length != 0u)) return false;
    if (have_cursor &&
        (!qlp_hex_generation(request->generation,
                             request_generation_length) ||
         !qlp_decimal_digits(request->anchor, request_anchor_length,
                             NULL))) {
        return false;
    }

    if (!qlp_json_uint(json, "$.offset", &offset_value) ||
        !qlp_json_uint(json, "$.limit", &limit_value) ||
        !qlp_json_uint(json, "$.total", &total_value) ||
        !qlp_json_uint(json, "$.returned", &returned_value) ||
        !qlp_json_uint(json, "$.nextOffset", &next_value) ||
        !qlp_json_bool(json, "$.hasMore", &has_more)) {
        return false;
    }

    if (limit_value != (uint64_t) QLP_PAGE_SIZE ||
        total_value > (uint64_t) QLP_MAX_TOTAL ||
        returned_value > (uint64_t) QLP_PAGE_SIZE ||
        offset_value != (uint64_t) request->offset ||
        offset_value > total_value) {
        return false;
    }
    if (next_value != offset_value + returned_value ||
        next_value > total_value) {
        return false;
    }
    if (has_more != (next_value < total_value)) return false;
    if (returned_value == 0u && has_more) return false;

    if (!qlp_read_generation(json, generation) ||
        !qlp_read_anchor(json, anchor)) {
        return false;
    }
    if (have_cursor &&
        (strcmp(request->generation, generation) != 0 ||
         strcmp(request->anchor, anchor) != 0)) {
        return false;
    }

    entries = mg_json_get_tok(json, "$.entries");
    if (entries.buf == NULL) return false;
    while (entries.len != 0u && qlp_json_is_space(entries.buf[0])) {
        entries.buf++;
        entries.len--;
    }
    while (entries.len != 0u &&
           qlp_json_is_space(entries.buf[entries.len - 1u])) {
        entries.len--;
    }
    if (entries.len < 2u || entries.buf[0] != '[' ||
        entries.buf[entries.len - 1u] != ']') {
        return false;
    }

    if (returned_value == 0u) {
        if (!qlp_entries_empty(entries)) return false;
    } else {
        if (!qlp_entries_end_object(entries)) return false;
    }

    page = (struct qlp_page *) calloc(1u, sizeof *page);
    if (page == NULL) return false;

    if (returned_value != 0u) {
        for (size_t i = 0; i < (size_t) returned_value; i++) {
            struct mg_str key = {NULL, 0};
            struct mg_str row = {NULL, 0};
            entry_offset = mg_json_next(entries, entry_offset, &key, &row);
            if (entry_offset == 0u ||
                !qlp_parse_row(row, &page->rows[i])) {
                free(page);
                return false;
            }
        }
        if (!qlp_entries_tail(entries, entry_offset)) {
            free(page);
            return false;
        }
    }

    page->offset = (uint32_t) offset_value;
    page->next_offset = (uint32_t) next_value;
    page->total = (uint32_t) total_value;
    page->returned = (uint32_t) returned_value;
    page->has_more = has_more;
    memcpy(page->generation, generation, sizeof generation);
    memcpy(page->anchor, anchor, sizeof anchor);
    *out = *page;
    free(page);
    return true;
}

#endif
