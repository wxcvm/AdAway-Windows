"""Count-checked log hooks; the production portable core remains SHA-verified."""
import importlib.util
from pathlib import Path


def prepare_logs(source):
    spec = importlib.util.spec_from_file_location("frozen_core_hooks", Path(__file__).with_name("build-rule-core.py"))
    hooks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hooks)

    def replace(old, new):
        nonlocal source
        if source.count(old) != 1:
            raise ValueError("log hook changed: " + old[:100])
        source = source.replace(old, new)

    # Keep Windows' existing 4096-entry retention and the 400-row summary.
    replace("#define QLOG_MAX 4096", "#define QLOG_MAX 4096\n#define QLOG_PERSIST_MAX 4096")
    start = source.index("enum { QLOG_PROXY = 0, QLOG_BLOCK = 1, QLOG_ALLOW = 2 };")
    end = source.index("/*\n * 拦截排行。", start)
    if source[start:end].count("struct qlog_entry {") != 1:
        raise ValueError("query log record layout changed")
    source = source[:start] + source[end:]
    for signature in ("static void qlog_clear(", "static void qlog_add(",
                      "static void qlog_render(", "static void qlog_save(", "static void qlog_load("):
        start, end = hooks.function_span(source, signature)
        source = source[:start] + source[end:]
    start, end = hooks.function_span(source,
        "static void req_host_of(struct mg_http_message *hm, char *out, size_t cap) {")
    source = source[:start] + '''#include "request_host.h"
static void req_host_of(struct mg_http_message *hm, char *out, size_t cap) {
    struct mg_str *host = mg_http_get_header(hm, "Host");
    request_host_parse(host ? host->buf : NULL, host ? host->len : 0, out, cap);
}''' + source[end:]
    replace('#define QLOG_MAGIC 0x514C4F47u   /* "QLOG" */', "")
    # The shared log records the real accepted connection family. These are
    # the six call sites in the fixed Windows production core, checked by count
    # (it has one more local exemption branch than current Android).
    for old, expected in (("qlog_add(req_uid, QLOG_PROXY, hm);", 1),
                          ("qlog_add(req_uid, QLOG_ALLOW, hm);", 3),
                          ("qlog_add(conn_load_uid(c), QLOG_BLOCK, hm);", 2)):
        if source.count(old) != expected:
            raise ValueError("query log connection hook changed: " + old)
        source = source.replace(old, old.replace(", hm);", ", hm, c);"))
    # Mongoose returns a negative value for an absent form variable. A boolean
    # check never reached the existing header fallback for header-only clients.
    replace('if (!mg_http_get_var(&hm->body, "token", token_buf, sizeof(token_buf))) {',
            'if (mg_http_get_var(&hm->body, "token", token_buf, sizeof(token_buf)) < 0) {')
    start, end = hooks.function_span(source, "static void json_safe_copy(")
    source = source[:end] + '''
#include "query_log_atomic_win32.h"
#define fopen qlog_fopen_utf8
#define remove qlog_remove_utf8
#include "query_log_store.inc"
#undef remove
#undef fopen
''' + source[end:]
    replace('bool internal = mg_match(hm->uri, mg_str("/internal-stats"), NULL) ||',
            'bool internal = mg_match(hm->uri, mg_str("/internal-qlog"), NULL) ||\n'
            '                        mg_match(hm->uri, mg_str("/internal-stats"), NULL) ||')
    marker = '    if (mg_match(hm->uri, mg_str("/internal-stats"), NULL)) {'
    replace(marker, '''    if (mg_match(hm->uri, mg_str("/internal-qlog"), NULL)) {
        if (!internal_endpoint_reachable(c, s)) {
            mg_http_reply(c, 403, "Content-Type: text/plain\\r\\n", "forbidden");
            return;
        }
        qlog_reply(c, hm);
        return;
    }

''' + marker)
    replace('"{\\"uptime_seconds\\":%llu,"', '"{\\"snapshot_ts\\":%llu,\\"uptime_seconds\\":%llu,"')
    replace('        (unsigned long long)uptime,\n        (double)uptime / 86400.0,',
            '        (unsigned long long)time(NULL),\n        (unsigned long long)uptime,\n        (double)uptime / 86400.0,')
    spec = importlib.util.spec_from_file_location("stats_bounds_overlay", Path(__file__).with_name("stats-json-core-overlay.py"))
    stats = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stats)
    return stats.prepare_stats_bounds(source)
