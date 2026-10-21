#include "dashboard_response.h"
#include <stdio.h>
#include <stdlib.h>
#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "FAIL %d: %s\n", __LINE__, #condition); exit(1); } } while (0)

static void framing(void) {
    struct mg_str body;
    const char good[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
    CHECK(dashboard_response_body(good, sizeof(good) - 1, &body));
    CHECK(body.len == 2 && memcmp(body.buf, "{}", 2) == 0);
    for (size_t n = 0; n < sizeof(good) - 1; n++) {
        /* Input is a bounded byte slice; no NUL terminator is required. */
        CHECK(!dashboard_response_body(good, n, &body));
        CHECK(body.buf == NULL && body.len == 0);
    }
    const char *invalid[] = {
        "HTTP/1.1 404 Missing\r\nContent-Length: 2\r\n\r\n{}",
        "HTTP/1.1 500 Error\r\nContent-Length: 2\r\n\r\n{}",
        "HTTP/1.1 2000 Bad\r\nContent-Length: 2\r\n\r\n{}",
        "HTTP/2.0 200 OK\r\nContent-Length: 2\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}extra",
        "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999999\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\ncontent-length: 3\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        CHECK(!dashboard_response_body(invalid[i], strlen(invalid[i]), &body));
    }
    const char lower[] = "HTTP/1.0 200 OK\r\ncontent-length: 2\r\n\r\n{}";
    CHECK(dashboard_response_body(lower, sizeof(lower) - 1, &body));
    char embedded[] = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{X}";
    embedded[sizeof(embedded) - 3] = 0;
    CHECK(!dashboard_response_body(embedded, sizeof(embedded) - 1, &body));
}

static void payloads(void) {
    CHECK(dashboard_stats_valid(mg_str("{\"uptime_seconds\":0,\"total_requests\":0}")));
    CHECK(dashboard_stats_valid(mg_str(" {\"uptime_seconds\":9223372036854775807,\"total_requests\":19} \r\n")));
    const char *invalid[] = {
        "{}", "{\"error\":\"busy\"}", "<html>failure</html>",
        "{\"uptime_seconds\":1,\"total_requests\":7,",
        "{\"uptime_seconds\":1,\"total_requests\":7}garbage",
        "{\"uptime_seconds\":-1,\"total_requests\":7}",
        "{\"uptime_seconds\":1,\"total_requests\":\"7\"}",
        "{\"uptime_seconds\":1,\"total_requests\":9223372036854775808}",
        "{\"uptime_seconds\":1,\"total_requests\":1.5}",
        "{\"nested\":{\"uptime_seconds\":1,\"total_requests\":7}}"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++)
        CHECK(!dashboard_stats_valid(mg_str(invalid[i])));
    CHECK(dashboard_qlog_valid(mg_str("{\"offset\":0,\"limit\":200,\"total\":0,\"entries\":[]}")));
    CHECK(!dashboard_qlog_valid(mg_str("{\"error\":\"expired\"}")));
    CHECK(!dashboard_qlog_valid(mg_str("{\"offset\":0,\"limit\":200,\"total\":0,\"entries\":{}}")));
}

int main(void) {
    mg_log_set(MG_LL_NONE);
    framing();
    payloads();
    puts("PASS: real Mongoose dashboard response framing, errors, truncation and payload validation");
    return 0;
}
