#ifndef ADBLOCK_DASHBOARD_RESPONSE_H
#define ADBLOCK_DASHBOARD_RESPONSE_H
#include "mongoose/mongoose.h"
#include <limits.h>
#include <string.h>

/* The loopback management server uses Content-Length. Keep HTTP parsing in
 * Mongoose and reject incomplete/error/ambiguous responses before JSON reads.
 * This is deliberately not a general purpose HTTP client or chunk decoder. */
static inline bool dashboard_response_body(const char *response, size_t length,
                                           struct mg_str *body) {
    struct mg_http_message hm;
    unsigned lengths = 0;
    if (!body) return false;
    *body = mg_str_n(NULL, 0);
    if (!response || length > INT_MAX || memchr(response, 0, length) ||
        mg_http_parse(response, length, &hm) <= 0 ||
        (mg_strcmp(hm.method, mg_str("HTTP/1.0")) != 0 &&
         mg_strcmp(hm.method, mg_str("HTTP/1.1")) != 0) ||
        mg_strcmp(hm.uri, mg_str("200")) != 0 ||
        mg_http_get_header(&hm, "Transfer-Encoding") != NULL) return false;
    for (size_t i = 0; i < sizeof(hm.headers) / sizeof(hm.headers[0]); i++) {
        if (mg_strcasecmp(hm.headers[i].name, mg_str("Content-Length")) == 0) lengths++;
    }
    if (lengths != 1 || hm.message.len != length || hm.head.len > length ||
        hm.body.len != length - hm.head.len) return false;
    *body = hm.body;
    return true;
}

static inline bool dashboard_json_object(struct mg_str body) {
    int token_length = 0;
    int offset = mg_json_get(body, "$", &token_length);
    if (offset < 0 || token_length < 2 || body.buf[offset] != '{') return false;
    size_t end = (size_t)offset + (size_t)token_length;
    for (; end < body.len; end++) {
        if (body.buf[end] != ' ' && body.buf[end] != '\t' &&
            body.buf[end] != '\r' && body.buf[end] != '\n') return false;
    }
    return true;
}

static inline bool dashboard_nonnegative(struct mg_str body, const char *path) {
    struct mg_str value = mg_json_get_tok(body, path);
    unsigned long long number = 0;
    if (!value.len || (value.len > 1 && value.buf[0] == '0')) return false;
    for (size_t i = 0; i < value.len; i++) {
        unsigned digit = (unsigned char)value.buf[i] - (unsigned)'0';
        if (digit > 9 || number > (unsigned long long)LLONG_MAX / 10 ||
            (number == (unsigned long long)LLONG_MAX / 10 &&
             digit > (unsigned long long)LLONG_MAX % 10)) return false;
        number = number * 10 + digit;
    }
    return true;
}

static inline bool dashboard_stats_valid(struct mg_str body) {
    return dashboard_json_object(body) &&
        dashboard_nonnegative(body, "$.uptime_seconds") &&
        dashboard_nonnegative(body, "$.total_requests");
}

static inline bool dashboard_qlog_valid(struct mg_str body) {
    struct mg_str rows = mg_json_get_tok(body, "$.entries");
    return dashboard_json_object(body) && dashboard_nonnegative(body, "$.offset") &&
        dashboard_nonnegative(body, "$.limit") && dashboard_nonnegative(body, "$.total") &&
        rows.len >= 2 && rows.buf[0] == '[';
}
#endif
