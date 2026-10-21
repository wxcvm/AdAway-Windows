#include "query_log_page.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition)                                                     \
    do {                                                                     \
        if (!(condition)) {                                                  \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,          \
                    #condition);                                             \
            exit(1);                                                         \
        }                                                                    \
    } while (0)

#define GEN_A "0123456789abcdef0123456789abcdef"
#define GEN_B "fedcba9876543210fedcba9876543210"

#define ROW_ONE                                                              \
    "{\"ts\":1000,\"uid\":-1,\"action\":1,\"type\":2,\"mode\":3,"           \
    "\"host\":\"one.example.test\"}"
#define ROW_MAX                                                              \
    "{\"ts\":18446744073709551615,\"action\":2,\"type\":65534,"              \
    "\"mode\":255,\"host\":\"max.example.test\"}"

struct json_writer {
    char *data;
    size_t capacity;
    size_t length;
    bool ok;
};

static void writer_init(struct json_writer *writer, char *data,
                        size_t capacity) {
    memset(writer, 0, sizeof *writer);
    writer->data = data;
    writer->capacity = capacity;
    writer->ok = capacity != 0u;
    if (capacity != 0u) data[0] = '\0';
}

static void writer_put(struct json_writer *writer, const char *text) {
    size_t length;
    size_t remaining;
    if (!writer->ok) return;
    length = strlen(text);
    remaining = writer->capacity - writer->length;
    if (length >= remaining) {
        writer->ok = false;
        writer->data[0] = '\0';
        return;
    }
    memcpy(writer->data + writer->length, text, length + 1u);
    writer->length += length;
}

static void writer_printf(struct json_writer *writer, const char *format, ...) {
    va_list args;
    size_t remaining;
    size_t written;
    if (!writer->ok) return;
    remaining = writer->capacity - writer->length;
    va_start(args, format);
    written = mg_vsnprintf(writer->data + writer->length, remaining, format,
                           &args);
    va_end(args);
    if (written >= remaining) {
        writer->ok = false;
        writer->data[0] = '\0';
        return;
    }
    writer->length += written;
}

static void writer_entries(struct json_writer *writer, unsigned first,
                           unsigned count, bool escaped_host) {
    unsigned i;
    writer_put(writer, "[");
    for (i = 0; i < count; i++) {
        unsigned value = first + i;
        if (i != 0u) writer_put(writer, ",");
        writer_printf(
            writer,
            "{\"ts\":%llu,\"uid\":-1,\"action\":%u,\"type\":%d,"
            "\"mode\":%u,\"host\":\"host-%u%s\"}",
            (unsigned long long) (1000u + value), value % 3u,
            (int) value - 1, value % 256u, value,
            escaped_host ? "\\u002eexample\\u002etest"
                         : ".example.test");
    }
    writer_put(writer, "]");
}

static void writer_page(struct json_writer *writer, unsigned offset,
                        unsigned total, unsigned returned,
                        unsigned next_offset, bool has_more,
                        const char *generation, const char *anchor,
                        unsigned first_entry, unsigned entry_count,
                        bool escaped_host) {
    writer_printf(
        writer,
        "{\"offset\":%u,\"limit\":300,\"total\":%u,\"returned\":%u,"
        "\"nextOffset\":%u,\"hasMore\":%s,\"generation\":\"%s\","
        "\"anchor\":\"%s\",\"entries\":",
        offset, total, returned, next_offset,
        has_more ? "true" : "false", generation, anchor);
    writer_entries(writer, first_entry, entry_count, escaped_host);
    writer_put(writer, "}");
}

static void writer_token_page(struct json_writer *writer,
                              const char *offset, const char *limit,
                              const char *total, const char *returned,
                              const char *next_offset,
                              const char *has_more,
                              const char *generation,
                              const char *anchor, const char *row) {
    writer_printf(
        writer,
        "{\"offset\":%s,\"limit\":%s,\"total\":%s,\"returned\":%s,"
        "\"nextOffset\":%s,\"hasMore\":%s,\"generation\":\"%s\","
        "\"anchor\":\"%s\",\"entries\":[%s]}",
        offset, limit, total, returned, next_offset, has_more, generation,
        anchor, row);
}

static void writer_host_literal_page(struct json_writer *writer,
                                     const char *host_literal) {
    writer_printf(
        writer,
        "{\"offset\":0,\"limit\":300,\"total\":1,\"returned\":1,"
        "\"nextOffset\":1,\"hasMore\":false,\"generation\":\"" GEN_A "\","
        "\"anchor\":\"1\",\"entries\":[{\"ts\":1,\"action\":0,"
        "\"type\":-1,\"mode\":0,\"host\":\"%s\"}]}",
        host_literal);
}

static void request_clear(struct qlp_request *request) {
    memset(request, 0, sizeof *request);
}

static void set_text(char *destination, size_t capacity, const char *source) {
    size_t length = strlen(source);
    CHECK(length < capacity);
    memcpy(destination, source, length + 1u);
}

static void request_cursor(struct qlp_request *request, uint32_t offset,
                           const char *generation, const char *anchor) {
    request_clear(request);
    request->offset = offset;
    set_text(request->generation, sizeof request->generation, generation);
    set_text(request->anchor, sizeof request->anchor, anchor);
}

static void parse_fail_preserving(const char *json,
                                  const struct qlp_request *request) {
    struct qlp_page page;
    struct qlp_page snapshot;
    memset(&page, 0xa5, sizeof page);
    memcpy(&snapshot, &page, sizeof page);
    CHECK(!qlp_parse(mg_str(json), request, &page));
    CHECK(memcmp(&page, &snapshot, sizeof page) == 0);
}

static void expect_bad_fields(const char *offset, const char *limit,
                              const char *total, const char *returned,
                              const char *next_offset,
                              const char *has_more, const char *row) {
    char json[4096];
    struct json_writer writer;
    struct qlp_request request;
    writer_init(&writer, json, sizeof json);
    writer_token_page(&writer, offset, limit, total, returned, next_offset,
                      has_more, GEN_A, "1", row);
    CHECK(writer.ok);
    request_clear(&request);
    parse_fail_preserving(json, &request);
}

static void check_row(const struct qlp_row *row, uint64_t timestamp,
                      int action, int type, int mode, const char *host) {
    CHECK(row->timestamp == timestamp);
    CHECK(row->action == action);
    CHECK(row->type == type);
    CHECK(row->mode == mode);
    CHECK(strcmp(row->host, host) == 0);
}

static void test_empty_final_page(void) {
    char json[4096];
    struct json_writer writer;
    struct qlp_request request;
    struct qlp_page page;

    writer_init(&writer, json, sizeof json);
    writer_page(&writer, 305u, 305u, 0u, 305u, false, GEN_A, "305", 0u, 0u,
                false);
    CHECK(writer.ok);
    request_cursor(&request, 305u, GEN_A, "305");
    CHECK(qlp_parse(mg_str(json), &request, &page));
    CHECK(page.offset == 305u);
    CHECK(page.next_offset == 305u);
    CHECK(page.total == 305u);
    CHECK(page.returned == 0u);
    CHECK(!page.has_more);
    CHECK(strcmp(page.generation, GEN_A) == 0);
    CHECK(strcmp(page.anchor, "305") == 0);

    writer_init(&writer, json, sizeof json);
    writer_page(&writer, 0u, 0u, 0u, 0u, false, GEN_B, "0", 0u, 0u, false);
    CHECK(writer.ok);
    request_clear(&request);
    CHECK(qlp_parse(mg_str(json), &request, &page));
    CHECK(page.offset == 0u);
    CHECK(page.next_offset == 0u);
    CHECK(page.total == 0u);
    CHECK(page.returned == 0u);
    CHECK(!page.has_more);
    CHECK(strcmp(page.generation, GEN_B) == 0);
    CHECK(strcmp(page.anchor, "0") == 0);

    writer_init(&writer, json, sizeof json);
    writer_page(&writer, 0u, 5u, 0u, 0u, true, GEN_A, "5", 0u, 0u, false);
    CHECK(writer.ok);
    request_clear(&request);
    parse_fail_preserving(json, &request);
}

static void test_normal_page(void) {
    char json[65536];
    struct json_writer writer;
    struct qlp_request request;
    struct qlp_page page;

    writer_init(&writer, json, sizeof json);
    writer_page(&writer, 0u, 600u, 300u, 300u, true, GEN_A, "600", 0u, 300u,
                false);
    CHECK(writer.ok);
    request_clear(&request);
    CHECK(qlp_parse(mg_str(json), &request, &page));
    CHECK(page.offset == 0u);
    CHECK(page.next_offset == 300u);
    CHECK(page.total == 600u);
    CHECK(page.returned == 300u);
    CHECK(page.has_more);
    CHECK(page.next_offset > page.offset);
    CHECK(strcmp(page.generation, GEN_A) == 0);
    CHECK(strcmp(page.anchor, "600") == 0);
    check_row(&page.rows[0], 1000u, 0, -1, 0, "host-0.example.test");
    check_row(&page.rows[299], 1299u, 2, 298, 43,
              "host-299.example.test");
}

static void test_short_page(void) {
    char json[4096];
    struct json_writer writer;
    struct qlp_request request;
    struct qlp_page page;

    writer_init(&writer, json, sizeof json);
    writer_page(&writer, 300u, 305u, 5u, 305u, false, GEN_A, "305", 300u,
                5u, false);
    CHECK(writer.ok);
    request_cursor(&request, 300u, GEN_A, "305");
    CHECK(qlp_parse(mg_str(json), &request, &page));
    CHECK(page.offset == 300u);
    CHECK(page.next_offset == 305u);
    CHECK(page.total == 305u);
    CHECK(page.returned == 5u);
    CHECK(!page.has_more);
    CHECK(page.next_offset > page.offset);
    check_row(&page.rows[0], 1300u, 0, 299, 44, "host-300.example.test");
    check_row(&page.rows[4], 1304u, 1, 303, 48, "host-304.example.test");
}

static void test_json_escaped_host(void) {
    char json[4096];
    struct json_writer writer;
    struct qlp_request request;
    struct qlp_page page;

    writer_init(&writer, json, sizeof json);
    writer_page(&writer, 0u, 1u, 1u, 1u, false, GEN_A, "1", 0u, 1u, true);
    CHECK(writer.ok);
    request_clear(&request);
    CHECK(qlp_parse(mg_str(json), &request, &page));
    check_row(&page.rows[0], 1000u, 0, -1, 0,
              "host-0.example.test");
}

static void test_row_boundaries(void) {
    char json[4096];
    struct json_writer writer;
    struct qlp_request request;
    struct qlp_page page;

    writer_init(&writer, json, sizeof json);
    writer_token_page(&writer, "0", "300", "1", "1", "1", "false", GEN_A,
                      "1", ROW_MAX);
    CHECK(writer.ok);
    request_clear(&request);
    CHECK(qlp_parse(mg_str(json), &request, &page));
    check_row(&page.rows[0], UINT64_MAX, 2, 65534, 255,
              "max.example.test");
}

static void test_cursor_changes(void) {
    char json[4096];
    struct json_writer writer;
    struct qlp_request request;
    struct qlp_page page;

    writer_init(&writer, json, sizeof json);
    writer_token_page(&writer, "0", "300", "1", "1", "1", "false", GEN_A,
                      "1", ROW_ONE);
    CHECK(writer.ok);

    /* Restart changes generation: the old cursor must not be reused. */
    request_cursor(&request, 0u, GEN_B, "1");
    parse_fail_preserving(json, &request);

    /* Cleared/overwritten history changes the anchor. */
    request_cursor(&request, 0u, GEN_A, "0");
    parse_fail_preserving(json, &request);

    /* The response offset must equal the requested offset. */
    request_cursor(&request, 1u, GEN_A, "1");
    parse_fail_preserving(json, &request);

    request_cursor(&request, 0u, GEN_A, "1");
    CHECK(qlp_parse(mg_str(json), &request, &page));
    check_row(&page.rows[0], 1000u, 1, 2, 3, "one.example.test");
}

static void test_generation_validation(void) {
    char json[4096];
    struct json_writer writer;
    struct qlp_request request;

    request_clear(&request);

    writer_init(&writer, json, sizeof json);
    writer_token_page(&writer, "0", "300", "1", "1", "1", "false",
                      "0123456789abcdef0123456789abcde", "1", ROW_ONE);
    CHECK(writer.ok);
    parse_fail_preserving(json, &request);

    writer_init(&writer, json, sizeof json);
    writer_token_page(&writer, "0", "300", "1", "1", "1", "false",
                      "0123456789abcdef0123456789abcdeg", "1", ROW_ONE);
    CHECK(writer.ok);
    parse_fail_preserving(json, &request);
}

static void test_anchor_validation(void) {
    char json[4096];
    struct json_writer writer;
    struct qlp_request request;
    struct qlp_page page;

    request_clear(&request);

    writer_init(&writer, json, sizeof json);
    writer_token_page(&writer, "0", "300", "1", "1", "1", "false", GEN_A,
                      "18446744073709551615", ROW_ONE);
    CHECK(writer.ok);
    CHECK(qlp_parse(mg_str(json), &request, &page));
    CHECK(strcmp(page.anchor, "18446744073709551615") == 0);

    writer_init(&writer, json, sizeof json);
    writer_token_page(&writer, "0", "300", "1", "1", "1", "false", GEN_A,
                      "18446744073709551616", ROW_ONE);
    CHECK(writer.ok);
    parse_fail_preserving(json, &request);
}

static void test_row_count_mismatch(void) {
    expect_bad_fields("0", "300", "2", "2", "2", "false", ROW_ONE);
    expect_bad_fields("0", "300", "1", "1", "1", "false",
                      ROW_ONE "," ROW_ONE);
    expect_bad_fields("0", "300", "0", "0", "0", "false", ROW_ONE);
    expect_bad_fields("0", "300", "1", "1", "1", "false", "");
}

static void test_malformed_json(void) {
    char json[4096];
    struct json_writer writer;
    struct qlp_request request;

    request_clear(&request);
    parse_fail_preserving("", &request);
    parse_fail_preserving("{", &request);
    parse_fail_preserving("[]", &request);
    parse_fail_preserving("{\"error\":\"busy\"}", &request);

    writer_init(&writer, json, sizeof json);
    writer_token_page(&writer, "0", "300", "1", "1", "1", "false", GEN_A,
                      "1", ROW_ONE);
    writer_put(&writer, "x");
    CHECK(writer.ok);
    parse_fail_preserving(json, &request);

    writer_init(&writer, json, sizeof json);
    writer_token_page(&writer, "0", "300", "1", "1", "1", "false", GEN_A,
                      "1", "{");
    CHECK(writer.ok);
    parse_fail_preserving(json, &request);

    parse_fail_preserving(
        "{\"offset\":0,\"limit\":300,\"total\":0,\"returned\":0,"
        "\"nextOffset\":0,\"hasMore\":false,\"generation\":\"" GEN_A "\","
        "\"anchor\":\"0\"}",
        &request);
}

static void test_invalid_scalars(void) {
    static const char *const bad_rows[] = {
        "{\"ts\":\"1000\",\"action\":1,\"type\":2,\"mode\":3,"
        "\"host\":\"row.example.test\"}",
        "{\"ts\":1000.5,\"action\":1,\"type\":2,\"mode\":3,"
        "\"host\":\"row.example.test\"}",
        "{\"ts\":-1,\"action\":1,\"type\":2,\"mode\":3,"
        "\"host\":\"row.example.test\"}",
        "{\"ts\":18446744073709551616,\"action\":1,\"type\":2,\"mode\":3,"
        "\"host\":\"row.example.test\"}",
        "{\"ts\":1000,\"action\":\"1\",\"type\":2,\"mode\":3,"
        "\"host\":\"row.example.test\"}",
        "{\"ts\":1000,\"action\":1.0,\"type\":2,\"mode\":3,"
        "\"host\":\"row.example.test\"}",
        "{\"ts\":1000,\"action\":3,\"type\":2,\"mode\":3,"
        "\"host\":\"row.example.test\"}",
        "{\"ts\":1000,\"action\":-1,\"type\":2,\"mode\":3,"
        "\"host\":\"row.example.test\"}",
        "{\"ts\":1000,\"action\":1,\"type\":-2,\"mode\":3,"
        "\"host\":\"row.example.test\"}",
        "{\"ts\":1000,\"action\":1,\"type\":65535,\"mode\":3,"
        "\"host\":\"row.example.test\"}",
        "{\"ts\":1000,\"action\":1,\"type\":\"2\",\"mode\":3,"
        "\"host\":\"row.example.test\"}",
        "{\"ts\":1000,\"action\":1,\"type\":2,\"mode\":-1,"
        "\"host\":\"row.example.test\"}",
        "{\"ts\":1000,\"action\":1,\"type\":2,\"mode\":256,"
        "\"host\":\"row.example.test\"}",
        "{\"ts\":1000,\"action\":1,\"type\":2,\"mode\":3.0,"
        "\"host\":\"row.example.test\"}",
        "{\"ts\":1000,\"action\":1,\"type\":2,\"mode\":3,\"host\":\"\"}"
    };

    for (size_t i = 0; i < sizeof bad_rows / sizeof bad_rows[0]; i++) {
        expect_bad_fields("0", "300", "1", "1", "1", "false", bad_rows[i]);
    }

    expect_bad_fields("\"0\"", "300", "1", "1", "1", "false", ROW_ONE);
    expect_bad_fields("-1", "300", "1", "1", "1", "false", ROW_ONE);
    expect_bad_fields("0", "300.0", "1", "1", "1", "false", ROW_ONE);
    expect_bad_fields("0", "300", "\"1\"", "1", "1", "false", ROW_ONE);
    expect_bad_fields("0", "300", "1", "\"1\"", "1", "false", ROW_ONE);
    expect_bad_fields("0", "300", "1", "1", "1.0", "false", ROW_ONE);
    expect_bad_fields("0", "300", "1", "1", "1", "\"false\"", ROW_ONE);
    expect_bad_fields("0", "300", "1", "1", "1", "0", ROW_ONE);
}

static void test_metadata_invariants(void) {
    expect_bad_fields("0", "299", "1", "1", "1", "false", ROW_ONE);
    expect_bad_fields("0", "301", "1", "1", "1", "false", ROW_ONE);
    expect_bad_fields("0", "300", "10001", "1", "1", "false", ROW_ONE);
    expect_bad_fields("0", "300", "1", "301", "1", "false", ROW_ONE);
    expect_bad_fields("0", "300", "2", "1", "2", "false", ROW_ONE);
    expect_bad_fields("0", "300", "1", "1", "1", "true", ROW_ONE);
    expect_bad_fields("0", "300", "2", "1", "1", "false", ROW_ONE);
}

static void test_host_boundaries(void) {
    char json[4096];
    char host[193];
    struct json_writer writer;
    struct qlp_request request;
    struct qlp_page page;

    request_clear(&request);

    memset(host, 'a', 191);
    host[191] = '\0';
    writer_init(&writer, json, sizeof json);
    writer_host_literal_page(&writer, host);
    CHECK(writer.ok);
    CHECK(qlp_parse(mg_str(json), &request, &page));
    CHECK(strlen(page.rows[0].host) == 191u);
    CHECK(page.rows[0].host[0] == 'a');
    CHECK(page.rows[0].host[190] == 'a');
    CHECK(page.rows[0].host[191] == '\0');

    host[191] = 'a';
    host[192] = '\0';
    writer_init(&writer, json, sizeof json);
    writer_host_literal_page(&writer, host);
    CHECK(writer.ok);
    parse_fail_preserving(json, &request);

    writer_init(&writer, json, sizeof json);
    writer_host_literal_page(&writer, "bad\\u0001host");
    CHECK(writer.ok);
    parse_fail_preserving(json, &request);

    writer_init(&writer, json, sizeof json);
    writer_host_literal_page(&writer, "bad\\u0000host");
    CHECK(writer.ok);
    parse_fail_preserving(json, &request);

    writer_init(&writer, json, sizeof json);
    writer_host_literal_page(&writer, "prefix\\u0100tail");
    CHECK(writer.ok);
    parse_fail_preserving(json, &request); /* Decoder must not accept only prefix. */

    writer_init(&writer, json, sizeof json);
    writer_host_literal_page(&writer, "caf\xC3\xA9.example.test");
    CHECK(writer.ok);
    CHECK(qlp_parse(mg_str(json), &request, &page));
    CHECK(strcmp(page.rows[0].host, "caf\xC3\xA9.example.test") == 0);

    writer_init(&writer, json, sizeof json);
    writer_token_page(&writer, "0", "300", "1", "1", "1", "false", GEN_A,
                      "1\\u0100", ROW_ONE);
    CHECK(writer.ok);
    parse_fail_preserving(json, &request);
}

static void test_request_attribution(void) {
    struct qlp_row row;
    CHECK(qlp_parse_row(mg_str(ROW_ONE), &row));
    CHECK(row.uid == -1);
    CHECK(qlp_parse_row(mg_str(ROW_MAX), &row));
    CHECK(row.uid == -1); /* absent is unknown, never PID zero */
    CHECK(qlp_parse_row(mg_str("{\"ts\":1,\"uid\":4321,\"action\":1,\"type\":2,\"mode\":1,\"host\":\"a.test\"}"), &row));
    CHECK(row.uid == 4321);
    const char *invalid[] = {
        "{\"ts\":1,\"uid\":-2,\"action\":1,\"type\":2,\"mode\":1,\"host\":\"a.test\"}",
        "{\"ts\":1,\"uid\":2147483648,\"action\":1,\"type\":2,\"mode\":1,\"host\":\"a.test\"}",
        "{\"ts\":1,\"uid\":\"4321\",\"action\":1,\"type\":2,\"mode\":1,\"host\":\"a.test\"}"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        struct qlp_row old = row;
        CHECK(!qlp_parse_row(mg_str(invalid[i]), &row));
        CHECK(memcmp(&row, &old, sizeof(row)) == 0);
    }
}

int main(void) {
    mg_log_set(MG_LL_NONE);
    test_request_attribution();
    test_empty_final_page();
    test_normal_page();
    test_short_page();
    test_json_escaped_host();
    test_row_boundaries();
    test_cursor_changes();
    test_generation_validation();
    test_anchor_validation();
    test_row_count_mismatch();
    test_malformed_json();
    test_invalid_scalars();
    test_metadata_invariants();
    test_host_boundaries();
    puts("PASS: AdAway Windows query_log_page parser tests (real Mongoose JSON)");
    return 0;
}
