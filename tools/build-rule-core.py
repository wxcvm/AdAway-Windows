"""Apply only reviewed domain-loader hooks to the frozen portable Windows service source."""
import hashlib
import pathlib
import sys
import importlib.util

SOURCE_SHA256 = "ff4461fdc16d734568216d4c9827bbf965450248a014ea90f9b5c5398bdfe9dc"


def function_span(source, signature):
    start = source.index(signature)
    if source.count(signature) != 1:
        raise ValueError("ambiguous hook: " + signature)
    cursor = source.index("{", start)
    depth = 0
    while cursor < len(source):
        char = source[cursor]
        if source.startswith("/*", cursor):
            cursor = source.index("*/", cursor + 2) + 2
            continue
        if source.startswith("//", cursor):
            cursor = source.index("\n", cursor + 2)
            continue
        if char in "\"'":
            quote = char
            cursor += 1
            while source[cursor] != quote:
                cursor += 2 if source[cursor] == "\\" else 1
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return start, cursor + 1
        cursor += 1
    raise ValueError("unterminated hook")


def prepare(source):
    if hashlib.sha256(source.encode()).hexdigest() != SOURCE_SHA256:
        raise ValueError("production source differs from frozen 4470606 pin; no compatibility overlay applied")
    # SNI slot policy shared with Android #119. Keep Win32 cache capacity,
    # renewal age, context ownership and disk format exactly as before.
    declaration = "struct sni_entry { char hostname[256]; SSL_CTX *ctx; uint64_t issued_at; };"
    if source.count(declaration) != 1:
        raise ValueError("SNI cache declaration changed")
    source = source.replace(declaration, '#include "sni_cache_slot.h"', 1)
    start, end = function_span(source, "static int sni_callback(")
    callback = source[start:end]
    left = callback.index("    /* Fast path: cache lookup under lock */")
    right = callback.index("    /* Slow path: generate new cert outside the lock", left)
    callback = callback[:left] + """    /* Restored hostname slots need a new context, not a TLS cache hit. */
    pthread_mutex_lock(&s_sni_mutex);
    struct sni_slot_match match = sni_match_slot(
        s_sni_cache, SNI_CACHE_SIZE, host, mg_millis(), SNI_CERT_RENEW_MS);
    if (match.reusable) {
        SSL_set_SSL_CTX(ssl, s_sni_cache[match.slot].ctx);
        pthread_mutex_unlock(&s_sni_mutex);
        s_stats.sni_cache_hits++;
        s_sni_hits++;
        return SSL_TLSEXT_ERR_OK;
    }
    int expired_slot = match.slot;
    pthread_mutex_unlock(&s_sni_mutex);

""" + callback[right:]
    source = source[:start] + callback + source[end:]
    # Persisted metadata contains no TLS context or private key.
    old_comment = """/* SNI cache persistence: dump hostnames + issued_at to sni_cache.dat so
   a restart doesn't flush the whole cache (re-issue = slow EC keygen +
   new TLS handshakes). On load, entries are re-keyed lazily: the SSL_CTX
   is rebuilt only on the next hit that finds the entry expired, but the
   hostname is remembered so a "miss" is not counted as a fresh issue. */"""
    if source.count(old_comment) != 1:
        raise ValueError("SNI metadata comment changed")
    source = source.replace(old_comment, """/* Persist hostname slots, not certificates or private keys.
   Restored slots are renewed in place; fresh contexts count as misses. */""", 1)
    start, end = function_span(source, "static void domain_rule_normalize(")
    source = source[:start] + '#include "rule_norm.h"\n' + source[end:]
    start, end = function_span(source, "static bool domain_is_allowed(")
    source = source[:start] + '''#include "domain_allow_snapshot.h"
static struct da_repository s_domain_allow_repository = DA_REPOSITORY_INITIALIZER;
static bool domain_is_allowed(const char *host, const char *resource_dir) {
    struct da_result result = da_lookup(&s_domain_allow_repository, host, resource_dir);
    if (!result.update_valid && result.refresh_attempted) LOG_WARN("Domain exemption update rejected; retaining previous rules");
    return result.allowed;
}''' + source[end:]
    start = source.index("/* ── blocked-host table")
    end = source.index("static bool host_is_local(", start)
    source = source[:start] + '''#include "block_rule_snapshot.h"
static struct bs_store s_native_block_rules = BS_STORE_INITIALIZER;
static size_t s_block_used;
static size_t s_subs_domains;
static bool block_set_contains(const char *host, size_t length) {
    if (!host || !length || length > 253) return false;
    char domain[254]; memcpy(domain, host, length); domain[length] = 0;
    return bs_query(&s_native_block_rules, domain).decision.action == CORE_NXDOMAIN;
}
static void block_set_load(const char *resource_dir) {
    char path[PATH_MAX];
    int length = snprintf(path, sizeof(path), "%s/subscriptions.txt", resource_dir);
    if (length < 0 || (size_t)length >= sizeof(path) || !bs_reload(&s_native_block_rules, path)) {
        LOG_WARN("Subscription update rejected; retaining previous rules"); return;
    }
    struct bs_result state = bs_query(&s_native_block_rules, "localhost");
    s_block_used = state.count; s_subs_domains = state.count;
    LOG_INFO("proxy: %zu domain rules published at generation %llu", state.count, (unsigned long long)state.generation);
}

''' + source[end:]
    # Windows-only audited compatibility overlay. The upstream Android core
    # stays immutable and is verified above by SHA-256; do not mutate the
    # pinned jni/ source cache. This fixes independent installations sharing
    # Global\\ADBlockWebServer_Singleton: the second installation used to
    # broadcast to the first instance and exit before showing its own UI.
    begin = '    HANDLE single = CreateMutexW(NULL, FALSE, L"Global\\\\ADBlockWebServer_Singleton");'
    end_marker = '\n#endif\n    struct settings s = parse_cli_parameters'
    if source.count(begin) != 1 or source.count(end_marker) != 1:
        raise ValueError("upstream Win32 mutex guard changed; review before rebasing")
    left = source.index(begin)
    right = source.index(end_marker, left)
    replacement = r'''    /*
     * Installation-scoped single instance: stable + UI preview have separate
     * binaries and must not suppress each other's window. FNV-1a hashes the
     * normalized *absolute executable path*, not a world-visible raw path.
     * Same installed EXE across two launches retains singleton behavior.
     */
    wchar_t exe_path[MAX_PATH];
    DWORD exe_len = GetModuleFileNameW(NULL, exe_path, MAX_PATH);
    if (exe_len == 0 || exe_len >= MAX_PATH) {
        LOG_FATAL("Unable to determine installed EXE path for singleton guard.");
        return EXIT_FAILURE;
    }
    CharLowerBuffW(exe_path, exe_len);
    uint64_t exe_key = UINT64_C(14695981039346656037);
    for (DWORD k = 0; k < exe_len; ++k) {
        exe_key ^= (uint16_t)exe_path[k];
        exe_key *= UINT64_C(1099511628211);
    }
    wchar_t global_name[96], local_name[96];
    swprintf(global_name, 96, L"Global\\ADBlockWebServer_%016llx",
             (unsigned long long)exe_key);
    swprintf(local_name, 96, L"Local\\ADBlockWebServer_%016llx",
             (unsigned long long)exe_key);
    HANDLE single = CreateMutexW(NULL, FALSE, global_name);
    DWORD mutex_status = GetLastError();
    if (single == NULL) {
        /* Standard user tokens may not be allowed to CREATE in Global\\.
         * Falling back to Local\\ is vital; access denied is not proof
         * that this particular executable is already running. */
        single = CreateMutexW(NULL, FALSE, local_name);
        mutex_status = GetLastError();
    }
    if (single != NULL && mutex_status == ERROR_ALREADY_EXISTS) {
        UINT show = RegisterWindowMessageW(L"ADBlockShowDashboard");
        if (show != 0) PostMessageW(HWND_BROADCAST, show, 0, 0);
        LOG_INFO("ADBlock: same installed executable already running - exiting.");
        CloseHandle(single);
        return 0;
    }
    if (single == NULL) {
        LOG_WARN("Unable to obtain per-install singleton; launching UI anyway.");
    }'''
    source = source[:left] + replacement + source[right:]
    if "android/log.h" not in source or "win32_dirent.h" not in source:
        raise ValueError("portable source guards unexpectedly changed")
    spec = importlib.util.spec_from_file_location("listen_overlay", pathlib.Path(__file__).with_name("listen-core-overlay.py"))
    overlay = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(overlay)
    source = overlay.prepare_listener(source)
    spec = importlib.util.spec_from_file_location("restart_overlay", pathlib.Path(__file__).with_name("restart-core-overlay.py"))
    restart = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(restart)
    source = restart.prepare_restart(source)
    spec = importlib.util.spec_from_file_location("logs_overlay", pathlib.Path(__file__).with_name("logs-core-overlay.py"))
    logs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(logs)
    source = logs.prepare_logs(source)
    # Shared listener lifetime policy, applied after listener/log overlays.
    def listener_hook(old, new):
        nonlocal source
        if source.count(old) != 1:
            raise ValueError("listener activity hook changed: " + old[:80])
        source = source.replace(old, new, 1)
    listener_hook('#include "mongoose/mongoose.h"',
                  '#include "mongoose/mongoose.h"\n#include "listener_activity.h"')
    listener_hook("""        uint64_t t = mg_millis();
        memcpy(c->data, &t, sizeof(t));
        c->data[sizeof(t)] = 1;""", """        listener_touch(c, mg_millis());
        c->data[sizeof(uint64_t)] = 1;""")
    listener_hook("""        proxy_drop_for_client(c);
        /* Unregister from the WS push list. */
        pthread_mutex_lock(&s_sni_mutex);
        for (int i = 0; i < WS_PUSH_MAX; i++) {
            if (ws_clients[i] == c) { ws_clients[i] = NULL; break; }
        }
        pthread_mutex_unlock(&s_sni_mutex);""", """        if (s_proxy_active) proxy_drop_for_client(c);
        if (c->is_websocket) {
            pthread_mutex_lock(&s_sni_mutex);
            for (int i = 0; i < WS_PUSH_MAX; i++) {
                if (ws_clients[i] == c) { ws_clients[i] = NULL; break; }
            }
            pthread_mutex_unlock(&s_sni_mutex);
        }""")
    listener_hook("""    /* Idle-timeout enforcement */
    if (ev == MG_EV_POLL && c->data[sizeof(uint64_t)]) {
        /* A transparent-proxy request may legitimately take longer than the
           idle timeout, so it is exempt while it is in flight. */
        if (proxy_busy(c)) return;
        uint64_t accepted_at; memcpy(&accepted_at, c->data, sizeof(accepted_at));
        if (mg_millis() - accepted_at > IDLE_TIMEOUT_MS) {
            c->is_draining = 1; return;
        }
    }""", """    if (ev == MG_EV_POLL) {
        if (listener_idle_due(c, *(const uint64_t *)ev_data, IDLE_TIMEOUT_MS) &&
            !proxy_busy(c)) c->is_draining = 1;
        return;
    }
    if (ev == MG_EV_WRITE) {
        if (c->data[sizeof(uint64_t)] && *(const long *)ev_data > 0)
            listener_touch(c, mg_millis());
        return;
    }""")
    listener_hook("    if (ev != MG_EV_HTTP_MSG) return;",
                  "    if (ev != MG_EV_HTTP_MSG) return;\n    listener_touch(c, mg_millis());")
    # Coalesce stats pushes on the listener loop. A pending bit belongs to
    # a subscriber slot; close clears it before that slot can be reused.
    listener_hook("static struct mg_connection *ws_clients[WS_PUSH_MAX] = {0};",
                  "static struct mg_connection *ws_clients[WS_PUSH_MAX] = {0};\n"
                  "static uint32_t s_ws_pending;\n"
                  "static uint64_t s_ws_last_push_ms;")
    listener_hook("if (ws_clients[i] == c) { ws_clients[i] = NULL; break; }",
                  "if (ws_clients[i] == c) { ws_clients[i] = NULL; s_ws_pending &= ~(UINT32_C(1) << i); break; }")
    left, right = function_span(source, "static void ws_push_broadcast(")
    source = source[:left] + """static void ws_push_broadcast(struct settings *s) {
    if (!s || !s->init) return;
    for (int i = 0; i < WS_PUSH_MAX; ++i)
        if (ws_clients[i] && !ws_clients[i]->is_closing && !ws_clients[i]->is_draining)
            s_ws_pending |= UINT32_C(1) << i;
}

/* Event-loop owned; no queue of historical snapshots. Retry slow subscribers
   after their existing output drains, and build at most one snapshot per second. */
static void ws_push_flush(struct settings *s, uint64_t now) {
    if (!s_ws_pending || (s_ws_last_push_ms && now - s_ws_last_push_ms < 1000)) return;
    uint32_t ready = 0;
    for (int i = 0; i < WS_PUSH_MAX; ++i) {
        uint32_t bit = UINT32_C(1) << i;
        if (!(s_ws_pending & bit)) continue;
        struct mg_connection *cl = ws_clients[i];
        if (!cl || cl->is_closing || cl->is_draining) s_ws_pending &= ~bit;
        else if (cl->send.len == 0) ready |= bit;
    }
    if (!ready) return;
    s_ws_last_push_ms = now;
    char body[STATS_JSON_BUF];
    int n = build_stats_json(s, body, sizeof(body));
    if (n <= 0) return;
    for (int i = 0; i < WS_PUSH_MAX; ++i) {
        uint32_t bit = UINT32_C(1) << i;
        if (!(ready & bit)) continue;
        struct mg_connection *cl = ws_clients[i];
        size_t len = (size_t)n;
        size_t expected = len + (len < 126 ? 2 : len <= 65535 ? 4 : 10);
        size_t sent = mg_ws_send(cl, body, len, WEBSOCKET_OP_TEXT);
        if (sent == expected) s_ws_pending &= ~bit;
        else if (sent != 0) cl->is_closing = 1; /* incomplete frame */
    }
}""" + source[right:]
    listener_hook("        mg_mgr_poll(mgr, 1000);\n        uint64_t now_ms = mg_millis();",
                  "        mg_mgr_poll(mgr, 1000);\n        uint64_t now_ms = mg_millis();\n        ws_push_flush(s, now_ms);")
    return source


if __name__ == "__main__":
    source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
    prepared = prepare(source)
    output = pathlib.Path(sys.argv[2])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(prepared, encoding="utf-8", newline="\n")
    print("Frozen portable core preserved; reviewed rules + Win32 instance isolation overlays generated")
