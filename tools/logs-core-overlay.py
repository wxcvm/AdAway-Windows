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
    # Response evidence is captured after the actual reply, not guessed from
    # classification; keep-alive responses must start at this event's offset.
    replace('    struct mg_http_message *hm = (struct mg_http_message *)ev_data;\n    struct settings *s = (struct settings *)c->fn_data;',
            '    struct mg_http_message *hm = (struct mg_http_message *)ev_data;\n    struct settings *s = (struct settings *)c->fn_data;\n    size_t response_offset = c->send.len;')
    allow = 'qlog_add(req_uid, QLOG_ALLOW, hm, c);'
    # All three frozen local-exemption branches log before replying. Relocate
    # their log after that branch's first actual mg_http_reply call.
    for _ in range(3):
        left = source.index(allow)
        source = source[:left] + source[left + len(allow):]
        reply = source.index('mg_http_reply(c,', left)
        end = source.index(');', reply) + 2
        source = source[:end] + '\n        qlog_add_status(req_uid, QLOG_ALLOW, hm, c, response_log_status(c->send.buf, c->send.len, response_offset));' + source[end:]
    # These already-counted local HTTP replies are neither advertising-rule
    # blocks nor proof of a user allow-rule; retain their local handling evidence.
    for marker in ('/* Known portal host - serve a minimal page instead of blocking */',
                   '    /* CORS preflight: browsers send OPTIONS'):
        if source.count(marker) != 1: raise ValueError('local handling hook changed')
        begin = source.index(marker)
        reply = source.index('mg_http_reply(c,', begin)
        end = source.index(');', reply) + 2
        source = source[:end] + '\n        qlog_add_status(req_uid, QLOG_ALLOW, hm, c, response_log_status(c->send.buf, c->send.len, response_offset));' + source[end:]
    # There are exactly two blocked branches; the generic image reply happens
    # later, after mg_http_serve_file (including its 304/404 result).
    block = 'qlog_add(conn_load_uid(c), QLOG_BLOCK, hm, c);'
    if source.count(block) != 2: raise ValueError('blocked response hooks changed')
    first = source.index(block)
    source = source[:first] + source[first:].replace(block, 'qlog_add_status(conn_load_uid(c), QLOG_BLOCK, hm, c, response_log_status(c->send.buf, c->send.len, response_offset));', 1)
    replace(block, '')
    replace('    mg_http_serve_file(c, hm, img_path, &o);',
            '    mg_http_serve_file(c, hm, img_path, &o);\n    qlog_add_status(conn_load_uid(c), QLOG_BLOCK, hm, c, response_log_status(c->send.buf, c->send.len, response_offset));\n    ws_push_broadcast(s);')
    # Every local 403 in this exact production handler is an access refusal,
    # never a successful advertising-rule block or fabricated placeholder.
    import re
    start, end = hooks.function_span(source, 'static void fn(')
    handler = source[start:end]
    rejected = re.compile(r'mg_http_reply\(c, 403,[\s\S]*?\);')
    if len(rejected.findall(handler)) != 7: raise ValueError('denial reply hooks changed: ' + str(len(rejected.findall(handler))))
    handler = rejected.sub(lambda match: match.group(0) + '\n        qlog_add_status(conn_load_uid(c), QLOG_DENY, hm, c, response_log_status(c->send.buf, c->send.len, response_offset));', handler)
    source = source[:start] + handler + source[end:]
    # Account known-PID requests before proxy/exemption/portal early returns.
    account_start = source.index('    struct appstat *ra = internal_path ? NULL : app_find_or_add(req_uid);')
    account_end = source.index('    if (c->is_tls && c->tls) {', account_start)
    accounting = source[account_start:account_end]
    source = source[:account_start] + source[account_end:]
    marker = '    /*\n     * TRANSPARENT FILTERING PROXY'
    replace(marker, accounting + marker)
    # The frozen SNI observation block follows this exact accounting comment.
    marker = '    /* Management traffic is not user traffic:'
    start = source.index(marker)
    tls = source.index('    if (c->is_tls && c->tls) {', start)
    source = source[:tls] + source[tls:].replace('    if (c->is_tls && c->tls) {', '    if (!internal_path && c->is_tls && c->tls) {', 1)
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
            qlog_add_status(conn_load_uid(c), QLOG_DENY, hm, c, response_log_status(c->send.buf, c->send.len, response_offset));
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
