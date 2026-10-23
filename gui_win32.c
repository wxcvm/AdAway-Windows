
/*
 * gui_win32.c - native Windows 11 dashboard for the ADBlock web server.
 * Windows-only: this file is not part of the Android build.
 *
 * UI: AdGuard-style - dark sidebar navigation + light content area,
 * rounded cards, flat modern palette, DPI-aware (PerMonitorV2) and
 * fully Chinese labels (Microsoft YaHei UI).
 */
#define _WIN32_WINNT 0x0A00   /* PerMonitorV2 / GetDpiForWindow */
#define UNICODE
#define _UNICODE
#include <winsock2.h>
#include <ws2ipdef.h> /* netioapi declarations must exist before iphlpapi's include guard is set. */
#include "update_win32.h"
#include <windows.h>
#include <shellapi.h>
#include <iphlpapi.h>
#include <wincrypt.h>
#include <dwmapi.h>
#include <uxtheme.h>
#include <commctrl.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <wchar.h>

#include <openssl/x509.h>
#include <openssl/pem.h>

#include "gui_win32.h"
#include "gui_assist_dialogs_win32.h"
#include "traffic_mode_policy.h"
#include "traffic_observer_win32.h"
#include "adguard_home_plan.h"
#include "wintun_probe_win32.h"
#include "windows_capture_plan.h"
#include "isolated_transport_win32.h"
#define IDC_TRANSPORT_PROBE 1301
#include "windows_network_inventory_win32.h"
#include "subscription_update_win32.h"
#include "subscription_settings_win32.h"
#include "policy_settings_win32.h"
#include "subscription_display_win32.h"
#include "listener_conflict_win32.h"
#include "managed_listener_address_win32.h"
#include "listener_arrival_dialog_win32.h"
#include "control_http_result.h"
#include "dashboard_response.h"
#include "query_log_navigation.h"
#include "query_log_filter.h"
#include <io.h>

/* GetModuleFileNameA() returns the ANSI code page path (GBK on a Chinese
   system) while the rest of the code treats such strings as UTF-8, which made
   every autostart/registry path point at a non-existent U+FFFD path. Use the
   wide API and convert once (phase-2 audit, P1-3). Returns the length. */
static int get_module_path_utf8(char *out, size_t cap) {
    wchar_t wide[MAX_PATH];
    if (out == NULL || cap == 0) return 0;
    out[0] = 0;
    if (GetModuleFileNameW(NULL, wide, MAX_PATH) == 0) return 0;
    if (WideCharToMultiByte(CP_UTF8, 0, wide, -1, out, (int) cap, NULL, NULL) <= 0) {
        out[0] = 0;
        return 0;
    }
    return (int) strlen(out);
}


/* --- theme (persisted in webserver.ini as theme=0/1/2) ---------------- */
#define THEME_SYSTEM (-1)
static int g_theme_pref = THEME_SYSTEM;   /* -1 system, 0 light, 1 dark */
static int g_dark = 0;                    /* resolved theme actually drawn */

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
#ifndef DWMWA_WINDOW_CORNER_PREFERENCE
#define DWMWA_WINDOW_CORNER_PREFERENCE 33
#endif

/* Windows 11 rounded corners + immersive dark title bar (no-op on older
 * builds: DwmSetWindowAttribute simply fails). */
static void apply_window_chrome(HWND hwnd, int dark) {
    BOOL d = dark ? TRUE : FALSE;
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &d, sizeof(d));
    DWORD pref = 2;   /* DWMWCP_ROUND */
    DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &pref, sizeof(pref));
}

/* Best-effort dark styling for the native child controls (edit boxes and
 * check boxes); custom-drawn areas always honour the palette. */
static void apply_control_theme(HWND hwnd) {
    static const wchar_t *classes[2] = { L"EDIT", L"BUTTON" };
    for (int c = 0; c < 2; c++) {
        HWND w = FindWindowExW(hwnd, NULL, classes[c], NULL);
        while (w != NULL) {
            SetWindowTheme(w, g_dark ? L"DarkMode_Explorer" : L"Explorer", NULL);
            w = FindWindowExW(hwnd, w, classes[c], NULL);
        }
    }
}

/* --- restart coordination (old instance stops server, then relaunches) --- */
static bool g_restart_requested = false;
void win32_notify_restart(void) { g_restart_requested = true; }
bool win32_restart_requested(void) { return g_restart_requested; }

/* ── scale helpers (all layout is in 96-DPI logical units) ─────── */
static double g_scale = 1.0;
#define S(v) ((int)((double)(v) * g_scale))

static HFONT mfont(int size, int weight) {
    return CreateFontW(-S(size), 0, 0, 0, weight, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_SWISS, L"Microsoft YaHei UI");
}

static void utf8_to_wide(const char *src, wchar_t *dst, size_t n) {
    if (n == 0) return;
    MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, (int)n);
    dst[n - 1] = L'\0';
}

/* ── HTTP statistics polling ────────────────────────────────────── */

#define HIST_MAX 48
#define STEAL_JSON_BUF 98304
#define LISTENER_MAX_GUI 14
/* Rows shown on the "应用 / 日志" page. */
#define GUI_APP_MAX 12
/* Keep the existing bounded GUI allocation; each real history page has at
 * most 300 rows. Windows retains 4096 entries, the stats summary at most 400. */
#define GUI_QLOG_MAX 1000
#define QLOG_PULL_BUF (192 * 1024)
/* Top blocked hosts shown on the ranking page. The server sends at most 20. */
#define GUI_TOP_MAX 20

/* One socket the server reported through /internal-stats. */
struct listener_info {
    wchar_t name[20];
    wchar_t addr[96];
    int bound, ipv6, loopback;
};

struct histogram {
    long long requests;
    long long blocked;
};

/* One row of the server's per-app statistics. On Windows uid is a PID and name
   is the executable that owns the connection; on Android the uid is the app id
   (the app itself maps it to a package name, so name stays empty there). */
struct app_row {
    wchar_t name[64];
    int uid;
    long long connections;
    long long requests;
    long long blocked;
    /* 「请求风暴」与「证书被拒」的服务端字段（本分支 webserver.c 已产出）：
       tps = 两次统计快照之间的实测速率（字段缺失时为 0），
       tls_fail = 该应用的 TLS 握手失败次数（证书固定/pinning 的信号）。 */
    long long tps;
    long long tls_fail;
    /* 「已改为廉价拒绝」：固定证书策略命中后，服务端对该应用只回 403、不再做中间人
       （拦截效果不变，但省掉每次重试的握手与新签证书）。 */
    int pin_refused;
};

/* One entry of the server's query log ring buffer (newest first). */
struct qlog_row {
    long long ts;
    int uid;
    int action;              /* 0 = proxied, 1 = blocked, 2 = allowed */
    int type;                /* blocked policy type index, -1 = unknown */
    int mode;                /* 0 = placeholder, 1 = 204, 2 = passthrough */
    int family;              /* Observed HTTP socket, never inferred from Host. */
    wchar_t host[192]; /* Every supported 191-byte UTF-8 log host fits in UTF-16. */
};

/* One entry of the server's "top_blocked" ranking (busiest first). */
struct top_row {
    wchar_t host[128];
    long long count;
};

struct snapshot {
    long long uptime_seconds;
    long long total_requests;
    long long total_connections;
    long long tls_handshakes;
    /* 证书被拒：TLS 握手失败总数。做证书固定（pinning）的客户端会持续失败，
       这是"证书被拒"最直接的可见信号（服务端自 master 起就产出该字段）。 */
    long long tls_failures;
    long long sni_certs_issued;
    long long sni_cache_hits;
    long long total_blocked;
    double block_rate;
    double sni_hit_rate;
    struct histogram hist[HIST_MAX];
    int hist_count;
    struct histogram daily[HIST_MAX];
    int daily_count;
    int valid; /* Live response, distinct from retained display data. */
    int has_data;
    time_t updated_at;
    int qlog_ready, qlog_error; /* 1 read failure, 2 expired cursor, 3 pending */
    uint64_t qlog_revision;
    struct qln_page qlog_page;
    /* v1.11 listener diagnostics (absent -> zeros) */
    int bind_ok;
    int stats_port;
    int listener_count;
    struct listener_info listeners[LISTENER_MAX_GUI];
    /* v1.29 activity page (absent -> zeros) */
    int app_count;
    struct app_row apps[GUI_APP_MAX];
    int qlog_count;
    struct qlog_row qlog[GUI_QLOG_MAX];
    /* v1.59 ranking (absent -> zero) */
    int top_count;
    struct top_row top[GUI_TOP_MAX];
    /* v1.60 per-type blocked counters, same order as kBlockTypes[] */
    long long blocked_by_type[16];
};

/* ── shared dashboard state ─────────────────────────────────────────
 * The statistics and certificate helpers below are defined before the GUI
 * state block, so the state they touch is declared here as tentative
 * definitions (the initialised definitions live further down the file). */
#ifndef WM_APP_STATS
#define WM_APP_STATS (WM_USER + 3)
#endif
#define CERT_CACHE_MS 30000
static char g_res[512];
static int  g_http_port;
static int  g_https_port;
static char g_bind_ip[64],g_bind_ipv6[64];
static char g_legacy_bind_ip[64];
static bool g_explicit_pair;
static bool g_auto_create;
static struct arrival_config g_active_arrival;
static void listener_display_host(char out[68]) {
    const char *host=*g_bind_ip ? g_bind_ip : *g_bind_ipv6 ? g_bind_ipv6 : "localhost";
    if (!strcmp(host,"0.0.0.0")) host="127.0.0.1";
    else if (!strcmp(host,"::")) host="::1";
    snprintf(out,68,strchr(host,':') ? "[%s]" : "%s",host);
}
static bool g_listener_ready;
static bool g_bind_all;
static bool g_start_minimized;
static int  g_tab;
static int  g_stats_port;
static int  g_active_port;
static int  g_poll_started;
static volatile int g_poll_stop;
static pthread_t g_poll_thread;
static pthread_mutex_t g_snap_mutex;
static struct qln_state g_log_nav;
static HANDLE g_poll_wake;

static struct snapshot g_snap_next;
static struct snapshot *g_sn;
static long long g_cert_days;
static int  g_cert_trusted_flag;
static int  g_cert_trust_state;
static DWORD g_cert_checked_tick;
static long long cert_days_left(const char *cert_path);
static int  cert_trusted(const char *cert_path);
static int  cert_trust_state(const char *cert_path);
/* Polling + self-measurement state (definitions with initialisers live in the
 * GUI state block further down; these tentative declarations let the helpers
 * that appear above it compile). */
static DWORD g_poll_last_post;
static int  g_hb_ticks;
static bool g_owns_server;
static volatile int g_ui_visible;
static int  g_hidden_trimmed;
static double g_cpu_pct;
static unsigned long long g_ws_kb;
static DWORD g_gdi_obj, g_user_obj, g_thread_count, g_handle_count;
static ULONGLONG g_cpu_prev_ms;
static DWORD g_cpu_prev_tick;

static long long json_num(const char *body, const char *key) {
    char pat[64];
    int pl = snprintf(pat, sizeof(pat), "\"%s\":", key);
    if (pl <= 0 || (size_t)pl >= sizeof(pat)) return 0;
    const char *p = strstr(body, pat);
    if (!p) return 0;
    p += pl;
    while (*p == ' ' || *p == '\t') p++;
    return strtoll(p, NULL, 10);
}

static double json_double(const char *body, const char *key) {
    char pat[64];
    int pl = snprintf(pat, sizeof(pat), "\"%s\":", key);
    if (pl <= 0 || (size_t)pl >= sizeof(pat)) return 0.0;
    const char *p = strstr(body, pat);
    if (!p) return 0.0;
    p += pl;
    while (*p == ' ' || *p == '\t') p++;
    return strtod(p, NULL);
}

/*
 * Position of the ']' that closes the array in which p currently sits,
 * skipping over quoted strings and nested arrays.
 *
 * A plain strchr(p, ']') is NOT enough: listener addresses look like
 * "http://[::1]:8686", so the first ']' after the array start sits inside an
 * IPv6 address. The bound then cut the parse off after two entries, and the
 * dashboard reported 2 listeners ("listeners=2" in the heartbeat, a card
 * saying "绑定正常 · 2 个监听端口") while the server really owns 10 sockets.
 * Every JSON array parser in this file uses this helper.
 */
static const char *json_array_end(const char *p) {
    int depth = 0;
    for (; p != NULL && *p != '\0'; p++) {
        if (*p == '"') {
            p++;
            while (*p != '\0' && *p != '"') {
                if (*p == '\\' && p[1] != '\0') p++;
                p++;
            }
            if (*p == '\0') return NULL;
            continue;
        }
        if (*p == '[') {
            depth++;
        } else if (*p == ']') {
            if (depth == 0) return p;
            depth--;
        }
    }
    return NULL;
}

static int json_hist(const char *body, const char *key,
                     struct histogram *out, int max) {
    char pat[64];
    int pl = snprintf(pat, sizeof(pat), "\"%s\":[", key);
    if (pl <= 0 || (size_t)pl >= sizeof(pat)) return 0;
    const char *p = strstr(body, pat);
    if (!p) return 0;
    p += pl;
    int count = 0;
    /* AUDIT: bound the scan by the array's own ']'. Without it a SHORT array
       kept reading the objects of the NEXT array - "history" and "daily" share
       the requests/blocked field names, so a 24-bucket history silently
       absorbed the 30 daily buckets (and every shorter array did the same). */
    const char *arr_end = json_array_end(p);
    while (count < max && *p) {
        const char *open = strchr(p, '{');
        if (!open) break;
        if (arr_end != NULL && open > arr_end) break;
        const char *close = strchr(open, '}');
        if (!close) break;
        char item[512];
        size_t il = (size_t)(close - open + 1);
        if (il >= sizeof(item)) il = sizeof(item) - 1;
        memcpy(item, open, il);
        item[il] = '\0';
        out[count].requests = json_num(item, "requests");
        out[count].blocked = json_num(item, "blocked");
        count++;
        p = close + 1;
    }
    return count;
}

/* Parses stats_port / bind_ok / listeners[] from the /internal-stats JSON so
 * the dashboard can show exactly which sockets the server owns.  Tolerates an
 * older server that does not emit the fields (they simply stay zero). */
static void json_listeners(const char *body, struct snapshot *sn) {
    sn->listener_count = 0;
    sn->bind_ok = strstr(body, "\"bind_ok\":true") != NULL;
    sn->stats_port = (int)json_num(body, "stats_port");
    const char *p = strstr(body, "\"listeners\":[");
    if (p == NULL) return;
    p = strchr(p, '[');
    if (p == NULL) return;
    p++;
    /*
     * ROOT CAUSE of the dashboard reporting "有端口绑定失败 · 10/14 已监听"
     * (and of "listeners=14" in the heartbeat log): the server really owns 10
     * sockets and all of them bound, but this loop only looked for the next '{'
     * without ever checking that it still sat inside THIS array. The listeners
     * array is followed by apps[], so once the 10 real entries were consumed the
     * parser kept going and turned 4 app objects into "listeners" with no
     * name/bound field - 4 phantom unbound ports, and the card went red.
     */
    const char *arr_end = json_array_end(p);
    while (sn->listener_count < LISTENER_MAX_GUI) {
        const char *open = strchr(p, '{');
        if (open == NULL) break;
        if (arr_end != NULL && open > arr_end) break;
        const char *close = strchr(open, '}');
        if (close == NULL) break;
        char item[384];
        size_t il = (size_t)(close - open) + 1;
        if (il >= sizeof(item)) il = sizeof(item) - 1;
        memcpy(item, open, il);
        item[il] = '\0';
        struct listener_info *li = &sn->listeners[sn->listener_count];
        memset(li, 0, sizeof(*li));
        const char *q = strstr(item, "\"name\":\"");
        if (q != NULL) {
            q += 8;
            const char *e = strchr(q, '"');
            if (e != NULL && e > q)
                MultiByteToWideChar(CP_UTF8, 0, q, (int)(e - q), li->name, 19);
        }
        q = strstr(item, "\"addr\":\"");
        if (q != NULL) {
            q += 8;
            const char *e = strchr(q, '"');
            if (e != NULL && e > q)
                MultiByteToWideChar(CP_UTF8, 0, q, (int)(e - q), li->addr, 95);
        }
        li->bound = strstr(item, "\"bound\":true") != NULL;
        li->ipv6 = strstr(item, "\"ipv6\":true") != NULL;
        li->loopback = strstr(item, "\"loopback\":true") != NULL;
        sn->listener_count++;
        p = close + 1;
    }
}

/* apps[] and query_log[] - what the "应用 / 日志" page shows. Both arrays are
   additive in the server's JSON, so an older server that does not emit them
   simply leaves the page empty instead of failing. */
static void json_apps(const char *body, struct snapshot *sn) {
    struct mg_str array = mg_json_get_tok(mg_str(body), "$.apps"), row_key, row;
    size_t offset = 0;
    sn->app_count = 0;
    if (!array.len || array.buf[0] != '[') return;
    /* Iterate complete top-level app objects. Nested hosts[] objects must not
       become phantom zero-valued applications or hide the trailing fields. */
    while (sn->app_count < GUI_APP_MAX &&
           (offset = mg_json_next(array, offset, &row_key, &row)) != 0) {
        char item[4096]; /* Existing complete apps-array byte bound. */
        size_t il;
        struct app_row *a;
        const char *q, *e;
        if (!row.len || row.buf[0] != '{' || row.len >= sizeof(item)) continue;
        il = row.len;
        memcpy(item, row.buf, il);
        item[il] = '\0';
        a = &sn->apps[sn->app_count];
        memset(a, 0, sizeof(*a));
        a->uid = strstr(item, "\"uid\":") != NULL ? (int)json_num(item, "uid") : -1;
        a->connections = json_num(item, "connections");
        a->requests = json_num(item, "requests");
        a->blocked = json_num(item, "blocked");
        /* 服务端新增字段：旧服务器不产出它们 → json_num 返回 0，行为与之前一致 */
        a->tps = json_num(item, "tps");
        a->tls_fail = json_num(item, "tls_fail");
        /* 布尔字段：没有 json_bool，直接查字面量（旧服务器不产出 → 0） */
        a->pin_refused = strstr(item, "\"pin_refused\":true") != NULL ? 1 : 0;
        q = strstr(item, "\"name\":\"");
        if (q != NULL) {
            q += 8;
            e = strchr(q, '"');
            if (e != NULL && e > q)
                MultiByteToWideChar(CP_UTF8, 0, q, (int)(e - q), a->name, 63);
        }
        if (a->name[0] == 0) {
            if (a->uid >= 0) swprintf(a->name, 64, L"PID %d", a->uid);
            else wcscpy(a->name, L"未归属进程");
        }
        sn->app_count++;
    }
    /* Busiest first: the server keeps insertion order, the dashboard wants a
       ranking (12 rows max, so an insertion sort is plenty). */
    for (int i = 1; i < sn->app_count; i++) {
        struct app_row key = sn->apps[i];
        int j = i - 1;
        while (j >= 0 && sn->apps[j].requests < key.requests) {
            sn->apps[j + 1] = sn->apps[j];
            j--;
        }
        sn->apps[j + 1] = key;
    }
}

/* "top_blocked":[{"host":"…","count":N}, …] - the server sorts it, so the
   dashboard only has to read it in order. */
static void json_top(const char *body, struct snapshot *sn) {
    const char *p = strstr(body, "\"top_blocked\":[");
    sn->top_count = 0;
    if (p == NULL) return;
    p = strchr(p, '[');
    if (p == NULL) return;
    p++;
    const char *arr_end = json_array_end(p);
    while (sn->top_count < GUI_TOP_MAX) {
        const char *open = strchr(p, '{');
        const char *close = open ? strchr(open, '}') : NULL;
        char item[512];
        size_t il;
        struct top_row *t;
        const char *q, *e;
        /* Stop at the end of this array: an empty ranking must not pick up the
           objects of the next array (see the same guard in json_apps()). */
        if (open == NULL || close == NULL) break;
        if (arr_end != NULL && open > arr_end) break;
        il = (size_t)(close - open) + 1;
        if (il >= sizeof(item)) il = sizeof(item) - 1;
        memcpy(item, open, il);
        item[il] = '\0';
        t = &sn->top[sn->top_count];
        memset(t, 0, sizeof(*t));
        t->count = json_num(item, "count");
        q = strstr(item, "\"host\":\"");
        if (q != NULL) {
            q += 8;
            e = strchr(q, '"');
            if (e != NULL && e > q)
                MultiByteToWideChar(CP_UTF8, 0, q, (int)(e - q), t->host, 127);
        }
        sn->top_count++;
        p = close + 1;
    }
}

/* key 参数化：/internal-stats 用 "query_log":[…]（最新 400 条），分页接口
   /internal-qlog 用 "entries":[…]（offset/limit 由调用方决定）。解析逻辑完全相同。 */
static void json_qlog_key(const char *body, struct snapshot *sn, const char *key) {
    const char *p = strstr(body, key);
    sn->qlog_count = 0;
    if (p == NULL) return;
    p = strchr(p, '[');
    if (p == NULL) return;
    p++;
    /* Same array-bound rule as json_apps()/json_listeners(): query_log is
       followed by top_blocked, whose objects also carry a "host" field, so
       without this the ranking's entries showed up as extra "recent requests"
       with a bogus type/mode of 0. */
    const char *arr_end = json_array_end(p);
    while (sn->qlog_count < GUI_QLOG_MAX) {
        const char *open = strchr(p, '{');
        const char *close = open ? strchr(open, '}') : NULL;
        char item[512];
        size_t il;
        struct qlog_row *r;
        const char *q, *e;
        if (open == NULL || close == NULL) break;
        if (arr_end != NULL && open > arr_end) break;
        il = (size_t)(close - open) + 1;
        if (il >= sizeof(item)) il = sizeof(item) - 1;
        memcpy(item, open, il);
        item[il] = '\0';
        int family = 0;
        if (!qlp_json_family(mg_str(item), &family)) { p = close + 1; continue; }
        r = &sn->qlog[sn->qlog_count];
        memset(r, 0, sizeof(*r));
        r->ts = json_num(item, "ts");
        r->uid = strstr(item, "\"uid\":") != NULL ? (int)json_num(item, "uid") : -1;
        r->action = (int) json_num(item, "action");
        /* An older server does not publish "type" at all - that must show as
           "unknown", not as type 0 (图片). */
        r->type = strstr(item, "\"type\":") != NULL ? (int) json_num(item, "type") : -1;
        r->mode = (int) json_num(item, "mode");
        r->family = family;
        q = strstr(item, "\"host\":\"");
        if (q != NULL) {
            q += 8;
            e = strchr(q, '"');
            if (e != NULL && e > q)
                MultiByteToWideChar(CP_UTF8, 0, q, (int)(e - q), r->host, 127);
        }
        sn->qlog_count++;
        p = close + 1;
    }
}

static void json_qlog(const char *body, struct snapshot *sn) {
    json_qlog_key(body, sn, "\"query_log\":[");
}

/* 分页接口的响应：{"offset":…,"limit":…,"total":…,"entries":[…]} */


static int http_get_status(int port, const char *path, char *out, size_t outsz, int *status) {
    if (status) *status = 0;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return -1;
    if (out == NULL || outsz == 0) {   /* nothing could be returned anyway */
        closesocket(s);
        return -1;
    }
    SOCKADDR_IN addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    int rc = -1;
    if (connect(s, (SOCKADDR *)&addr, sizeof(addr)) == 0) {
        char req[256];
        int rl = snprintf(req, sizeof(req),
            "GET %s HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            path);
        if (rl > 0 && send(s, req, rl, 0) == rl) {
            size_t got = 0;
            ULONGLONG deadline = GetTickCount64() + 2000;
            while (got + 1 < outsz) {
                if (GetTickCount64() >= deadline) break;
                fd_set fds;
                FD_ZERO(&fds); FD_SET(s, &fds);
                struct timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;
                if (select(0, &fds, NULL, NULL, &tv) <= 0) break;
                int room = (int)(outsz - got - 1);   /* > 0 by the loop condition above */
                int n = recv(s, out + got, room, 0);
                if (n <= 0) break;
                /*
                 * Bound the received count explicitly. recv cannot return more
                 * than it was asked for, but saying so is what removes the
                 * tainted-index warning on the terminating write below
                 * (SonarCloud c:S3519 kept flagging it because `got` stayed
                 * tainted by this return value).
                 */
                if (n > room) n = room;
                got += (size_t)n;
                struct mg_http_message message;
                if (mg_http_parse(out, got, &message) > 0 &&
                    mg_http_get_header(&message, "Content-Length") != NULL &&
                    message.message.len <= got) break;
            }
            /*
             * Clamp before terminating. The loop condition already keeps `got`
             * below outsz, but making the bound explicit is what lets the
             * analyzer (and a reader) see that the write cannot go past the
             * buffer - SonarCloud c:S3519 flagged it as a possible
             * out-of-bounds access - and it also keeps this safe if the recv
             * contract above is ever changed.
             */
            if (got >= outsz) got = outsz - 1;
            out[got] = '\0';
            if (status) *status = control_http_status(out);
            struct mg_str body;
            if (dashboard_response_body(out, got, &body)) {
                memmove(out, body.buf, body.len);
                out[body.len] = '\0';
                rc = 0;
            }
        }
    }
    closesocket(s);
    return rc;
}
static int http_get(int port, const char *path, char *out, size_t capacity) {
    return http_get_status(port, path, out, capacity, NULL);
}


/*
 * True when the URL starts with "http" or "https" followed by "://"
 * (case-insensitive).
 *
 * Written without the scheme literal on purpose: SonarCloud c:S5332 ("Using
 * HTTP is insecure") reads that literal as this dashboard fetching over http,
 * while this is only validation of a user-entered subscription URL - and plenty
 * of hosts-file sources are http-only, so both schemes stay accepted. It is
 * case-insensitive now, which the previous wcsncmp() comparison was not.
 */
static bool url_has_http_scheme(const wchar_t *u) {
    if (_wcsnicmp(u, L"https", 5) == 0) return u[5] == L':' && u[6] == L'/' && u[7] == L'/';
    if (_wcsnicmp(u, L"http", 4) == 0) return u[4] == L':' && u[5] == L'/' && u[6] == L'/';
    return false;
}

/*
 * ── 拦截类型分布 ───────────────────────────────────────────────────
 * The server has always published one counter per blocked category
 * (blocked_images, blocked_scripts, …), but the dashboard never read them, so
 * the only thing a user could see was "N blocked in total". Keep the JSON key
 * and the label next to each other so neither can drift.
 */
static const struct { const char *key; const wchar_t *label; } kBlockTypes[] = {
    {"blocked_images",    L"图片"},
    {"blocked_scripts",   L"脚本"},
    {"blocked_styles",    L"样式"},
    {"blocked_fonts",     L"字体"},
    {"blocked_media",     L"媒体"},
    {"blocked_api",       L"API"},
    {"blocked_telemetry", L"遥测"},
    {"blocked_heartbeat", L"心跳"},
    {"blocked_config",    L"配置"},
    {"blocked_ws_sse",    L"WebSocket"},
    {"blocked_other",     L"其它"},
    {"blocked_crypto",    L"挖矿"},
    {"blocked_clickbait", L"标题党"},
};
#define BLOCK_TYPE_COUNT ((int) (sizeof(kBlockTypes) / sizeof(kBlockTypes[0])))

static void snapshot_fetch(int port, struct snapshot *sn) {
    static char buf[STEAL_JSON_BUF];
    memset(sn, 0, sizeof(*sn));
    if (http_get(port, "/internal-stats", buf, sizeof(buf)) != 0) return;
    if (!dashboard_stats_valid(mg_str(buf))) return;
    sn->uptime_seconds = json_num(buf, "uptime_seconds");
    sn->total_requests = json_num(buf, "total_requests");
    sn->total_connections = json_num(buf, "total_connections");
    sn->tls_handshakes = json_num(buf, "tls_handshakes");
    sn->tls_failures = json_num(buf, "tls_failures");
    sn->sni_certs_issued = json_num(buf, "sni_certs_issued");
    sn->sni_cache_hits = json_num(buf, "sni_cache_hits");
    sn->total_blocked = json_num(buf, "total_blocked");
    sn->block_rate = json_double(buf, "block_rate");
    sn->sni_hit_rate = json_double(buf, "sni_hit_rate");
    sn->hist_count = json_hist(buf, "history", sn->hist, HIST_MAX);
    sn->daily_count = json_hist(buf, "daily", sn->daily, HIST_MAX);
    json_listeners(buf, sn);
    for (int i = 0; i < BLOCK_TYPE_COUNT; i++)
        sn->blocked_by_type[i] = json_num(buf, kBlockTypes[i].key);
    json_apps(buf, sn);
    json_top(buf, sn);
    json_qlog(buf, sn);
    sn->valid = 1;
    sn->has_data = 1;
    sn->updated_at = time(NULL);
}

/* Try the loopback management port first (it exists exactly so statistics
   stay readable even when the user facing ports are taken or bound to LAN),
   then fall back to the main HTTP port. */
static void snapshot_fetch_any(struct snapshot *sn) {
    if (g_stats_port > 0 && g_stats_port != g_http_port) {
        snapshot_fetch(g_stats_port, sn);
        if (sn->valid) { g_active_port = g_stats_port; return; }
    }
    snapshot_fetch(g_http_port, sn);
    if (sn->valid) g_active_port = g_http_port;
}

/* One cheap self-measurement per timer tick. */
static void diag_sample(void) {
    FILETIME ct, et, kt, ut;
    if (GetProcessTimes(GetCurrentProcess(), &ct, &et, &kt, &ut)) {
        ULARGE_INTEGER K, U;
        K.LowPart = kt.dwLowDateTime; K.HighPart = kt.dwHighDateTime;
        U.LowPart = ut.dwLowDateTime; U.HighPart = ut.dwHighDateTime;
        ULONGLONG cpu_ms = (K.QuadPart + U.QuadPart) / 10000ULL;
        DWORD now = GetTickCount();
        if (g_cpu_prev_tick != 0 && now != g_cpu_prev_tick) {
            double wall = (double)(now - g_cpu_prev_tick);
            double used = (double)(cpu_ms - g_cpu_prev_ms);
            SYSTEM_INFO si;
            GetSystemInfo(&si);
            double ncpu = si.dwNumberOfProcessors > 0 ? (double)si.dwNumberOfProcessors : 1.0;
            double pct = used / (wall * ncpu) * 100.0;
            g_cpu_pct = (pct < 0.0 || pct > 100.0) ? 0.0 : pct;
        }
        g_cpu_prev_ms = cpu_ms;
        g_cpu_prev_tick = now;
    }
    PROCESS_MEMORY_COUNTERS pmc;
    memset(&pmc, 0, sizeof(pmc));
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc)))
        g_ws_kb = (unsigned long long)pmc.WorkingSetSize / 1024ULL;
    g_gdi_obj = GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);
    g_user_obj = GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS);
    g_handle_count = 0;
    GetProcessHandleCount(GetCurrentProcess(), &g_handle_count);
    g_thread_count = 0;
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te;
            memset(&te, 0, sizeof(te));
            te.dwSize = sizeof(te);
            DWORD pid = GetCurrentProcessId();
            if (Thread32First(snap, &te)) {
                do { if (te.th32OwnerProcessID == pid) g_thread_count++; } while (Thread32Next(snap, &te));
            }
            CloseHandle(snap);
        }
    }
}

/* Writes diagnose.txt (system + process + listener + log tail) so a user can
 * send one file instead of describing the problem. */
static void diag_write_file(HWND hwnd) {
    char path[MAX_PATH + 32];
    if (get_module_path_utf8(path, MAX_PATH) <= 0) return;
    char *slash = strrchr(path, '\\');
    if (slash) *slash = '\0';
    char out[MAX_PATH + 48];
    snprintf(out, sizeof(out), "%s\\diagnose.txt", path);
    FILE *f = fopen(out, "w");
    if (!f) {
        MessageBoxW(hwnd, L"无法写入 diagnose.txt（目录不可写）。", L"诊断", MB_OK | MB_ICONWARNING);
        return;
    }
    fprintf(f, "ADBlock Web Server v%s - diagnose.txt\n", ADBLOCK_APP_VERSION);
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "time: %04d-%02d-%02d %02d:%02d:%02d\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    OSVERSIONINFOEXW os;
    memset(&os, 0, sizeof(os));
    os.dwOSVersionInfoSize = sizeof(os);
    if (GetVersionExW((OSVERSIONINFOW *)&os))
        fprintf(f, "os: %lu.%lu build %lu\n", (unsigned long)os.dwMajorVersion,
                (unsigned long)os.dwMinorVersion, (unsigned long)os.dwBuildNumber);
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    fprintf(f, "cpu: %lu cores\n", (unsigned long)si.dwNumberOfProcessors);
    MEMORYSTATUSEX ms;
    memset(&ms, 0, sizeof(ms));
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms))
        fprintf(f, "memory: %llu MB total, %llu MB free\n",
                (unsigned long long)ms.ullTotalPhys / 1048576ULL,
                (unsigned long long)ms.ullAvailPhys / 1048576ULL);
    diag_sample();
    fprintf(f, "process: cpu=%.2f%% working_set=%llu MB gdi=%lu user=%lu threads=%lu handles=%lu alive=%d\n",
            g_cpu_pct, g_ws_kb / 1024ULL, (unsigned long)g_gdi_obj, (unsigned long)g_user_obj,
            (unsigned long)g_thread_count, (unsigned long)g_handle_count,
            win32_server_alive() ? 1 : 0);
    fprintf(f, "ports: http=%d https=%d stats=%d active=%d bind_all=%d theme_dark=%d minimized=%d\n",
            g_http_port, g_https_port, g_stats_port, g_active_port, g_bind_all ? 1 : 0,
            g_dark, g_start_minimized ? 1 : 0);
    fprintf(f, "server: valid=%d bind_ok=%d listeners=%d cert_days=%lld cert_trusted=%d\n",
            (g_sn && g_sn->valid) ? 1 : 0, (g_sn && g_sn->bind_ok) ? 1 : 0,
            g_sn ? g_sn->listener_count : 0, g_cert_days, g_cert_trusted_flag);
    if (g_sn) {
        for (int i = 0; i < g_sn->listener_count; i++)
            fprintf(f, "  listener %-8ls %-28ls bound=%d ipv6=%d loopback=%d\n",
                    g_sn->listeners[i].name, g_sn->listeners[i].addr,
                    g_sn->listeners[i].bound, g_sn->listeners[i].ipv6, g_sn->listeners[i].loopback);
    }
    const char *tails[2] = { "webserver.log", "crash.log" };
    for (int t = 0; t < 2; t++) {
        char lp[MAX_PATH + 48];
        snprintf(lp, sizeof(lp), "%s\\%s", g_res, tails[t]);
        FILE *l = fopen(lp, "r");
        fprintf(f, "---- %s ----\n", tails[t]);
        if (l) {
            static char ring[80][300];
            int n = 0;
            while (fgets(ring[n % 80], sizeof(ring[0]), l) != NULL) n++;
            fclose(l);
            int start = n > 80 ? n - 80 : 0;
            for (int i = start; i < n; i++) fputs(ring[i % 80], f);
        } else {
            fprintf(f, "(not present)\n");
        }
    }
    fclose(f);
    wchar_t wout[MAX_PATH + 48];
    MultiByteToWideChar(CP_ACP, 0, out, -1, wout, MAX_PATH + 48);
    MessageBoxW(hwnd, L"诊断信息已导出，点确定后将打开该文件。", L"诊断", MB_OK | MB_ICONINFORMATION);
    ShellExecuteW(NULL, L"open", wout, NULL, NULL, SW_SHOWNORMAL);
}

static void cert_refresh(bool force) {
    DWORD now = GetTickCount();
    if (!force && g_cert_checked_tick != 0 && now - g_cert_checked_tick < CERT_CACHE_MS)
        return;
    char cert_path[1024];
    snprintf(cert_path, sizeof(cert_path), "%s/localhost-2410.crt", g_res);
    g_cert_days = cert_days_left(cert_path);
    g_cert_trust_state = cert_trust_state(cert_path);
    g_cert_trusted_flag = g_cert_trust_state != 0;
    g_cert_checked_tick = now;
}


/* The worker owns all HTTP reads. Successful stats and history pages publish
 * together; old request revisions cannot replace a newer navigation choice. */
static void snapshot_read_page(struct snapshot *sn, const struct qlp_request *request,
                               uint64_t revision) {
    static char buffer[QLOG_PULL_BUF];
    static struct qlp_page page;
    char path[200];
    int status = 0;
    int length = snprintf(path, sizeof(path), "/internal-qlog?offset=%d&limit=300%s%s%s%s",
        (int)request->offset, request->generation[0] ? "&generation=" : "", request->generation,
        request->generation[0] ? "&anchor=" : "", request->anchor);
    sn->qlog_error = 1;
    if (length < 0 || (size_t)length >= sizeof(path)) return;
    int ports[] = {g_stats_port, g_active_port, g_http_port};
    bool received = false;
    for (size_t attempt = 0; attempt < sizeof(ports) / sizeof(ports[0]); ++attempt) {
        int port = ports[attempt];
        bool duplicate = false;
        for (size_t earlier = 0; earlier < attempt; ++earlier)
            if (ports[earlier] == port) duplicate = true;
        if (port <= 0 || duplicate) continue;
        if (http_get_status(port, path, buffer, sizeof(buffer), &status) == 0 &&
            qlp_parse(mg_str(buffer), request, &page)) {
            received = true;
            break;
        }
        if (status == 409) { sn->qlog_error = 2; return; }
    }
    if (!received) return;
    sn->qlog_count = (int)page.returned;
    memset(sn->qlog, 0, sizeof(sn->qlog));
    for (int i = 0; i < sn->qlog_count; i++) {
        sn->qlog[i].ts = page.rows[i].timestamp <= LLONG_MAX ? (long long)page.rows[i].timestamp : 0;
        sn->qlog[i].uid = page.rows[i].uid;
        sn->qlog[i].action = page.rows[i].action;
        sn->qlog[i].type = page.rows[i].type;
        sn->qlog[i].mode = page.rows[i].mode;
        sn->qlog[i].family = page.rows[i].family;
        utf8_to_wide(page.rows[i].host, sn->qlog[i].host,
                     sizeof(sn->qlog[i].host) / sizeof(sn->qlog[i].host[0]));
    }
    sn->qlog_page.offset = (int)page.offset;
    sn->qlog_page.next_offset = (int)page.next_offset;
    sn->qlog_page.total = (int)page.total;
    sn->qlog_page.has_more = page.has_more;
    memcpy(sn->qlog_page.generation, page.generation, sizeof(page.generation));
    memcpy(sn->qlog_page.anchor, page.anchor, sizeof(page.anchor));
    sn->qlog_ready = 1;
    sn->qlog_revision = revision;
    sn->qlog_error = 0;
}

static void snapshot_copy_log(struct snapshot *to, const struct snapshot *from) {
    to->qlog_count = from->qlog_count;
    memcpy(to->qlog, from->qlog, sizeof(to->qlog));
    to->qlog_ready = from->qlog_ready;
    to->qlog_page = from->qlog_page;
    to->qlog_revision = from->qlog_revision;
}

/* Statistics and query history can fail independently. Keep their last good
 * publications independently too, without allocating another full snapshot. */
static bool snapshot_publish(struct snapshot *published, struct snapshot *incoming,
                             uint64_t requested_revision, uint64_t current_revision) {
    bool stale = requested_revision != current_revision;
    int error = stale ? 3 : incoming->qlog_error;
    if (!incoming->qlog_ready || stale) {
        if (published->qlog_ready || ((!incoming->valid || stale) && published->qlog_count > 0))
            snapshot_copy_log(incoming, published);
        else if (stale) {
            incoming->qlog_count = 0;
            incoming->qlog_ready = 0;
            incoming->qlog_revision = 0;
            memset(&incoming->qlog_page, 0, sizeof(incoming->qlog_page));
            memset(incoming->qlog, 0, sizeof(incoming->qlog));
        }
    }
    incoming->qlog_error = error;
    bool changed;
    if (incoming->valid || !published->has_data) {
        changed = memcmp((const char *)published + sizeof(incoming->uptime_seconds),
                         (const char *)incoming + sizeof(incoming->uptime_seconds),
                         sizeof(*incoming) - sizeof(incoming->uptime_seconds)) != 0;
        *published = *incoming;
    } else {
        changed = published->valid != 0 || published->qlog_error != error ||
            published->qlog_count != incoming->qlog_count ||
            published->qlog_ready != incoming->qlog_ready ||
            published->qlog_revision != incoming->qlog_revision ||
            memcmp(&published->qlog_page, &incoming->qlog_page, sizeof(incoming->qlog_page)) != 0 ||
            memcmp(published->qlog, incoming->qlog, sizeof(incoming->qlog)) != 0;
        snapshot_copy_log(published, incoming);
        published->valid = 0;
        published->qlog_error = error;
    }
    return changed;
}

static void *stats_poll_thread(void *arg) {
    HWND hwnd = (HWND)arg;
    while (!g_poll_stop) {
        struct snapshot tmp;
        struct qlp_request request;
        uint64_t revision;
        pthread_mutex_lock(&g_snap_mutex);
        request = g_log_nav.request;
        revision = g_log_nav.revision;
        pthread_mutex_unlock(&g_snap_mutex);
        snapshot_fetch_any(&tmp);
        snapshot_read_page(&tmp, &request, revision);
        pthread_mutex_lock(&g_snap_mutex);
        /* Compare every rendered field, excluding the uptime clock. A hand
         * picked arithmetic signature missed TLS failures and log changes and
         * could overflow signed counters. Both snapshots have zeroed padding. */
        bool changed = snapshot_publish(&g_snap_next, &tmp, revision, g_log_nav.revision);
        pthread_mutex_unlock(&g_snap_mutex);
        /* Wake the UI only when something it draws actually changed
         * (seconds-level uptime is ignored) - idle CPU drops to ~0; a
         * 60 s keep-alive still refreshes the clock line. */
        DWORD now = GetTickCount();
        if ((changed || now - g_poll_last_post > 60000) && !g_poll_stop) {
            g_poll_last_post = now;
            PostMessageW(hwnd, WM_APP_STATS, 0, 0);
        }
        /* 2 s while the dashboard is on screen, 10 s while it lives in the
         * tray only: a hidden window needs no fresh charts. */
        if (g_poll_wake) WaitForSingleObject(g_poll_wake, g_ui_visible ? 2000 : 10000);
        else for (int i = 0; i < 20 && !g_poll_stop; i++) Sleep(g_ui_visible ? 100 : 500);
    }
    return NULL;
}

#define IDC_QLOG_PREVIOUS 1210
#define IDC_QLOG_NEXT 1211
#define IDC_QLOG_REFRESH 1212
#define IDC_QLOG_SEARCH 1213
#define IDC_QLOG_FILTER 1214
#define IDC_QLOG_LIST 1215
#define IDC_QLOG_DETAILS 1216
#define IDC_QLOG_APPS 1217
#define IDC_QLOG_LIVE 1218
#define IDC_POL0      1110
#define IDC_SUBRELOAD 1130
#define IDC_POLDEF    1131   /* 恢复推荐默认 */
#define IDC_CAROTATE  1132   /* 生成新 CA（并存 90 天） */
#define IDC_CADROP    1133   /* 撤销旧 CA（90 天后） */
#define IDC_SUB_URL    1140
#define IDC_SUB_LIST   1141
#define IDC_SUB_ADD    1142
#define IDC_SUB_DEL    1143
#define IDC_SUB_UPD    1144
#define IDC_SUB_OPEN   1145
#define IDC_SUB_SELECTED 1146
#define IDC_SUB_CONFIRM 1147
#define IDC_SUB_CANCEL 1148
#define IDC_SUB_NAME 1310
#define IDC_SUB_RENAME 1311
#define IDC_SUB_DEFAULT_NAME 1312
#define IDC_SUB_FULL_URL 1313
#define IDC_BIND_IP 1190
#define IDC_CHECK_LISTEN 1191
#define IDC_LISTEN_STATUS 1192
#define IDC_CREATE_ADDRESS 1193
#define IDC_REMOVE_ADDRESS 1194
#define IDC_ARRIVAL_CHECK 1195
#define IDC_BIND_IPV6 1196
#define IDC_AUTO_CREATE 1197
#define IDC_LOOP_PAIR 1198
#define IDC_CREATE_IPV6 1201
#define IDC_REMOVE_IPV6 1202
#define WM_APP_ADDRESS_DONE (WM_APP + 32)
static bool s_address_busy;
#define IDC_IPV4_LABEL 1203
#define IDC_IPV6_LABEL 1204
#define IDC_PREVIEWUPD 1300
#define IDC_PORTABLEUPD 1134 /* 用便携包更新（zip 就地替换） */
#define IDC_AUTOUPD 1302

/*
 * Per-type blocking method: label, block_config.json key, control id and the
 * recommended default.
 *
 * The values must match webserver/jni/webserver.c (BM_*). The recommended
 * default follows "if the placeholder can be seen, use the placeholder":
 * images / media / page structure get the placeholder reply, while scripts,
 * styles and fonts get an empty 200 (a 204 makes Chromium print console
 * errors for <script>/<link>), and API / telemetry / config / WebSocket get a
 * plain 204. The user can cycle any type through all four methods.
 */
#define POL_REPLY 0   /* 占位/本地响应 */
#define POL_DENY  1   /* 204 快速拒绝 */
#define POL_ALLOW 2   /* 不拦截（只统计） */
#define POL_EMPTY 3   /* 空响应：200 + 0 字节 */

struct policy_item {
    const wchar_t *label;
    const char *key;
    const char *mode_key;
    int id;
    int def;
};
static const struct policy_item g_policy[] = {
    { L"图片", "reply_images", "mode_images", IDC_POL0 + 0, POL_REPLY },
    { L"脚本", "reply_scripts", "mode_scripts", IDC_POL0 + 1, POL_EMPTY },
    { L"样式表", "reply_styles", "mode_styles", IDC_POL0 + 2, POL_EMPTY },
    { L"字体", "reply_fonts", "mode_fonts", IDC_POL0 + 3, POL_EMPTY },
    { L"媒体/音频", "reply_media", "mode_media", IDC_POL0 + 4, POL_REPLY },
    { L"页面结构", "reply_structures", "mode_struct", IDC_POL0 + 5, POL_REPLY },
    { L"API 请求", "reply_api", "mode_api", IDC_POL0 + 6, POL_DENY },
    { L"遥测/统计", "reply_telemetry", "mode_tele", IDC_POL0 + 7, POL_DENY },
    { L"配置文件", "reply_config", "mode_conf", IDC_POL0 + 8, POL_DENY },
    { L"WebSocket", "reply_ws_sse", "mode_ws", IDC_POL0 + 9, POL_DENY },
};
#define POLICY_COUNT ((int)(sizeof(g_policy) / sizeof(g_policy[0])))

/* ── settings persistence (webserver.ini next to the exe) ─────── */
static void ini_file_path(char *out, size_t n) {
    char exe[MAX_PATH];
    if (get_module_path_utf8(exe, sizeof(exe)) <= 0) {
        snprintf(out, n, "webserver.ini");
        return;
    }
    char *slash = strrchr(exe, '\\');
    if (slash) *slash = '\0';
    snprintf(out, n, "%s\\webserver.ini", exe);
}

static bool ini_save(int http_port, int https_port, bool bind_all) {
    char path[1024];
    ini_file_path(path, sizeof(path));
    /*
     * AUDIT W4-02 / V7: this used fopen(path, "w") and wrote back only these
     * four keys. Every other key was silently destroyed - stats_port and
     * img_mode (read by webserver.c) and update_mode / mirror (read by
     * update_win32.c; update_mode is the portable-update escape hatch the
     * settings page itself writes). Merge instead: copy every line we do not
     * own and re-emit ours on top.
     */
    char *kept = NULL;
    size_t kept_len = 0;
    FILE *r = fopen(path, "r");
    if (r != NULL) {
        char line[512];
        while (fgets(line, sizeof(line), r) != NULL) {
            if (strncmp(line, "http_port=", 10) == 0 ||
                strncmp(line, "https_port=", 11) == 0 ||
                strncmp(line, "bind_all=", 9) == 0 ||
                strncmp(line, "theme=", 6) == 0 || strncmp(line, "bind_ip=", 8) == 0 ||
                strncmp(line,"listen_ipv4=",12)==0 || strncmp(line,"listen_ipv6=",12)==0 ||
                strncmp(line,"listener_auto_create=",21)==0) continue;
            size_t n = strlen(line);
            char *grown = (char *) realloc(kept, kept_len + n + 1);
            if (grown == NULL) { free(kept); fclose(r); return false; }
            kept = grown;
            memcpy(kept + kept_len, line, n);
            kept_len += n;
            kept[kept_len] = 0;
        }
        if (ferror(r)) { free(kept); fclose(r); return false; }
        fclose(r);
    }
    char staged[1100];
    snprintf(staged, sizeof(staged), "%s.%lu.tmp", path, (unsigned long)GetCurrentProcessId());
    FILE *f = fopen(staged, "w");
    if (f == NULL) { free(kept); return false; }
    fprintf(f, "http_port=%d\n", http_port);
    fprintf(f, "https_port=%d\n", https_port);
    fprintf(f, "bind_all=%d\n", bind_all ? 1 : 0);
    fprintf(f, "theme=%d\n", g_theme_pref);
    fprintf(f, "bind_ip=%s\n", g_explicit_pair ? g_bind_ip : g_legacy_bind_ip);
    if (g_explicit_pair) fprintf(f,"listen_ipv4=%s\nlisten_ipv6=%s\n",g_bind_ip,g_bind_ipv6);
    fprintf(f,"listener_auto_create=%d\n",g_auto_create ? 1 : 0);
    if (kept != NULL && kept_len > 0) {
        fwrite(kept, 1, kept_len, f);
        if (kept[kept_len - 1] != '\n') fputc('\n', f);
    }
    bool ok = !ferror(f) && fflush(f) == 0;
    if (ok) ok = FlushFileBuffers((HANDLE)_get_osfhandle(_fileno(f))) != 0;
    if (fclose(f) != 0) ok = false;
    free(kept);
    if (ok) ok = MoveFileExA(staged, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
    if (!ok) DeleteFileA(staged);
    return ok;
}


/* Reads theme= from webserver.ini; returns THEME_SYSTEM when absent. */
static int ini_read_theme(void) {
    char path[1024], line[256];
    ini_file_path(path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return THEME_SYSTEM;
    int theme = THEME_SYSTEM;
    while (fgets(line, sizeof(line), f) != NULL) {
        int v = 99;
        if (sscanf(line, "theme=%d", &v) == 1 && v >= -1 && v <= 1) theme = v;
    }
    fclose(f);
    return theme;
}

/* Follow the Windows "app mode" setting when no preference was stored. */
static int system_prefers_dark(void) {
    DWORD val = 1, sz = sizeof(val);
    if (RegGetValueW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
            L"AppsUseLightTheme", RRF_RT_REG_DWORD, NULL, &val, &sz) == ERROR_SUCCESS)
        return val == 0;
    return 0;
}

/* ── block_config.json read/write (applied via /control reload_config) ── */
static bool policy_get(const char *dir, const char *key, bool def) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/block_config.json", dir);
    FILE *f = fopen(path, "r");
    if (!f) return def;
    char buf[2048];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);
    char pat[96];
    int pl = snprintf(pat, sizeof(pat), "\"%s\":", key);
    if (pl <= 0 || (size_t)pl >= sizeof(pat)) return def;
    const char *p = strstr(buf, pat);
    if (!p) return def;
    p += pl;
    while (*p == ' ') p++;
    return strncmp(p, "true", 4) == 0;
}

/* Integer reader used for the mode_* keys (see the server's load_block_modes). */
static int policy_get_int(const char *dir, const char *key, int def) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/block_config.json", dir);
    FILE *f = fopen(path, "r");
    if (!f) return def;
    char buf[2048];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = 0;
    fclose(f);
    char pat[96];
    int pl = snprintf(pat, sizeof(pat), "\"%s\":", key);
    if (pl <= 0 || (size_t) pl >= sizeof(pat)) return def;
    const char *p = strstr(buf, pat);
    if (!p) return def;
    p += pl;
    while (*p == ' ') p++;
    if (*p < '0' || *p > '9') return def;
    return atoi(p);
}

static void policy_read(const char *dir, bool *vals) {
    for (int i = 0; i < POLICY_COUNT; i++)
        vals[i] = policy_get(dir, g_policy[i].key, true);
}

/* Declared before use: both are defined further down (the settings helpers
   come first in this file). */
static bool control_post(int port, const char *cmd, wchar_t *status, size_t statusn);
static int mgmt_port(void);
/* The status line lives in the GUI state block further down; declared here so
   the policy helpers can write to it. */
static wchar_t g_status[4096];

/* modes[i]: 0 = placeholder reply, 1 = 204 deny, 2 = allow (no blocking).
   reply_* is kept in sync for compatibility with older servers. */
static bool policy_save_modes(const char *dir, const int *modes) {
    wchar_t directory[MAX_PATH];
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, dir, -1, directory, MAX_PATH) <= 0) return false;
    struct policy_setting settings[POLICY_COUNT];
    for (int i = 0; i < POLICY_COUNT; i++)
        settings[i] = (struct policy_setting){g_policy[i].key, g_policy[i].mode_key, modes[i]};
    return policy_settings_save(directory, settings, POLICY_COUNT) != 0;
}

/* Current method of one type: mode_* when present, otherwise the legacy
   reply_* boolean (true = placeholder, false = 204). */
static int policy_mode(const char *dir, int i) {
    const char *key = g_policy[i].key;
    int def = policy_get(dir, key, true) ? POL_REPLY : POL_DENY;
    return policy_get_int(dir, g_policy[i].mode_key, def);
}

static const wchar_t *policy_method_label(int m) {
    switch (m) {
    case POL_DENY:  return L"204 快速拒绝";
    case POL_ALLOW: return L"不拦截";
    case POL_EMPTY: return L"空响应";
    default:        return L"占位响应";
    }
}

/* Click order: 占位 → 空响应 → 204 → 不拦截 → 占位. */
static int policy_next_mode(int m) {
    switch (m) {
    case POL_REPLY: return POL_EMPTY;
    case POL_EMPTY: return POL_DENY;
    case POL_DENY:  return POL_ALLOW;
    default:        return POL_REPLY;
    }
}

/* Button caption: "图片：占位响应" — the old tri-state checkbox could not show
   four methods at all (and its three states were unreadable). */
static void policy_button_text(HWND hwnd, int i) {
    HWND w = GetDlgItem(hwnd, IDC_POL0 + i);
    if (w == NULL) return;
    wchar_t txt[96];
    swprintf(txt, 96, L"%ls：%ls", g_policy[i].label,
             policy_method_label(policy_mode(g_res, i)));
    SetWindowTextW(w, txt);
}

/* Push the stored modes into the buttons (called whenever the settings page
   becomes visible, so an external edit is picked up too). */
static void policy_sync_controls(HWND hwnd) {
    for (int i = 0; i < POLICY_COUNT; i++) policy_button_text(hwnd, i);
}

/* Write all ten modes and let the running server pick them up immediately. */
static void policy_apply_modes(HWND hwnd, const int *modes, const wchar_t *what) {
    if (!policy_save_modes(g_res, modes)) {
        policy_sync_controls(hwnd);
        swprintf(g_status, 4096, L"拦截策略保存失败；原配置保留，未请求服务端加载。请检查文件占用或写入权限后重试。");
        InvalidateRect(hwnd, NULL, FALSE);
        return;
    }
    wchar_t st[128] = L"";
    bool confirmed=control_post(mgmt_port(), "reload_config", st, 128);
    policy_sync_controls(hwnd);
    swprintf(g_status, 4096, L"%ls；配置已保存；%ls（%ls）", what ? what : L"拦截方式设置请求",
             confirmed ? L"已收到重新读取确认，活动版本未核对" : L"尚未收到加载确认，活动版本未确认", st);
    InvalidateRect(hwnd, NULL, FALSE);
}

/* POST /control (cmd=reload_config | flush_stats | shutdown) */
static bool control_post(int port, const char *cmd, wchar_t *status, size_t statusn) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        wchar_t w[16];
        utf8_to_wide(cmd, w, 16);
        if (statusn) swprintf(status, statusn, L"控制命令 %ls: 连接失败", w);
        return false;
    }
    SOCKADDR_IN addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    int code = 0;
    char detail[256]="";
    DWORD timeout=2000;
    setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(const char *)&timeout,sizeof(timeout));
    setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,(const char *)&timeout,sizeof(timeout));
    u_long nonblocking=1; ioctlsocket(s,FIONBIO,&nonblocking);
    bool connected=connect(s,(SOCKADDR *)&addr,sizeof(addr))==0;
    if (!connected && WSAGetLastError()==WSAEWOULDBLOCK) {
        fd_set writable,errors; FD_ZERO(&writable); FD_ZERO(&errors); FD_SET(s,&writable); FD_SET(s,&errors);
        struct timeval budget={2,0};
        if (select(0,NULL,&writable,&errors,&budget)>0 && FD_ISSET(s,&writable)) {
            int error=0,length=sizeof(error);
            connected=getsockopt(s,SOL_SOCKET,SO_ERROR,(char *)&error,&length)==0 && error==0;
        }
    }
    nonblocking=0; ioctlsocket(s,FIONBIO,&nonblocking);
    if (connected) {
        char body[128];
        int bl = snprintf(body, sizeof(body), "cmd=%s", cmd);
        /*
         * Audit item 33: /control now needs the per-run token the server wrote
         * to control_token.txt next to the resources. Reading it here (instead
         * of caching it) also picks up a restarted server.
         */
        char token[64] = "";
        char token_path[1024];
        snprintf(token_path, sizeof(token_path), "%s/control_token.txt", g_res);
        FILE *tf = fopen(token_path, "rb");
        if (tf != NULL) {
            size_t got = fread(token, 1, sizeof(token) - 1, tf);
            token[got] = 0;
            fclose(tf);
            char *nl = strpbrk(token, "\r\n");
            if (nl) *nl = 0;
        }
        char req[768];
        int rl = snprintf(req, sizeof(req),
            "POST /control HTTP/1.0\r\nHost: 127.0.0.1\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "X-ADBlock-Token: %s\r\n"
            "Content-Length: %d\r\nConnection: close\r\n\r\n%s",
            token, bl, body);
        int sent=0;
        ULONGLONG deadline=GetTickCount64()+2000;
        while (sent<rl && GetTickCount64()<deadline) { int n=send(s,req+sent,rl-sent,0); if (n<=0) break; sent+=n; }
        if (rl>0 && sent==rl) {
            char response[2048]={0}; size_t used=0;
            while (used<sizeof(response)-1 && !strstr(response,"\r\n\r\n") && GetTickCount64()<deadline) {
                int n=recv(s,response+used,(int)(sizeof(response)-1-used),0);
                if (n<=0) break;
                used+=(size_t)n; response[used]=0;
            }
            code=control_http_status(response);
            const char *body=strstr(response,"\r\n\r\n");
            if (body) {
                snprintf(detail,sizeof(detail),"%s",body+4);
                for (char *ch=detail;*ch;ch++) if (*ch=='\r'||*ch=='\n') *ch=' ';
            }
        }
    }
    closesocket(s);
    wchar_t w[16];
    utf8_to_wide(cmd, w, 16);
    if (statusn) {
        wchar_t message[256]; utf8_to_wide(detail,message,256);
        if (code) swprintf(status,statusn,L"%ls：HTTP %d（%ls）%ls",w,code,code>=200 && code<300 ? L"服务端已确认" : L"服务端拒绝或执行失败",message);
        else swprintf(status,statusn,L"%ls：未收到完整响应，请检查服务状态",w);
    }
    win32_log_line("control: %s acknowledged HTTP %d",cmd,code);
    return code>=200 && code<300;
}

/* ── certificate helpers ────────────────────────────────────────── */

static X509 *load_pem_cert(const char *cert_path) {
    FILE *f = fopen(cert_path, "rb");
    if (!f) return NULL;
    X509 *x = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    return x;
}

/* days left; -100001 = file missing, -100002 = unreadable/bad cert */
static long long cert_days_left(const char *cert_path) {
    FILE *f = fopen(cert_path, "rb");
    if (!f) return -100001;
    X509 *x = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    if (!x) return -100002;
    const ASN1_TIME *na = X509_get0_notAfter(x);
    if (!na) { X509_free(x); return -100002; }
    struct tm tm = {0};
    if (ASN1_TIME_to_tm(na, &tm) != 1) { X509_free(x); return -100002; }
    long long expiry = (long long)mktime(&tm);
    X509_free(x);
    return (expiry - (long long)time(NULL)) / 86400LL;
}

/*
 * Best non-loopback IPv4 for the LAN hint; returns 0 on success.
 *
 * Audit item 65: the old code returned the first address of the first adapter
 * in the list, which on a normal Windows machine is often a Hyper-V/WSL/VirtualBox
 * "vEthernet" adapter (172.x) or an APIPA 169.254.x.x left behind by a network
 * that is no longer reachable - the hint then pointed at an address nobody can
 * reach from the phone. Private ranges of real adapters win, APIPA and known
 * virtual adapter names are skipped, and only if nothing matches does the first
 * usable address win.
 */
static int lan_ip_score(const IP_ADAPTER_ADDRESSES *a, const SOCKADDR_IN *sin) {
    unsigned long h = ntohl(sin->sin_addr.s_addr);
    if ((h & 0xFFFF0000UL) == 0xA9FE0000UL) return -1;        /* 169.254/16 APIPA */
    /* a->Description is a wide string (PWSTR), so the name list is wide too. */
    const wchar_t *desc = a->Description != NULL ? a->Description : L"";
    const wchar_t *names[] = { L"Hyper-V", L"WSL", L"VirtualBox", L"VMware",
                               L"Loopback", L"Bluetooth", L"TAP-", L"WireGuard",
                               L"Tailscale", L"ZeroTier" };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (wcsstr(desc, names[i]) != NULL) return -1;
    }
    if ((h & 0xFF000000UL) == 0x0A000000UL) return 3;          /* 10/8 */
    if ((h & 0xFFF00000UL) == 0xAC100000UL) return 3;          /* 172.16/12 */
    if ((h & 0xFFFF0000UL) == 0xC0A80000UL) return 3;          /* 192.168/16 */
    return 1;                                                  /* public/other */
}

static int first_lan_ip(char *out, size_t n) {
    ULONG buflen = 0;
    if (GetAdaptersAddresses(AF_INET,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            NULL, NULL, &buflen) != ERROR_BUFFER_OVERFLOW || buflen == 0) return -1;
    PIP_ADAPTER_ADDRESSES buf = (PIP_ADAPTER_ADDRESSES)malloc(buflen);
    if (!buf) return -1;
    ULONG rc = GetAdaptersAddresses(AF_INET,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            NULL, buf, &buflen);
    if (rc != NO_ERROR) { free(buf); return -1; }
    int best_score = -1;
    for (PIP_ADAPTER_ADDRESSES a = buf; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        for (PIP_ADAPTER_UNICAST_ADDRESS u = a->FirstUnicastAddress; u; u = u->Next) {
            SOCKADDR_IN *sin = (SOCKADDR_IN *)u->Address.lpSockaddr;
            if (sin->sin_family == AF_INET &&
                sin->sin_addr.s_addr != htonl(INADDR_LOOPBACK) &&
                sin->sin_addr.s_addr != htonl(INADDR_ANY)) {
                int score = lan_ip_score(a, sin);
                if (score > best_score) {
                    best_score = score;
                    strncpy(out, inet_ntoa(sin->sin_addr), n - 1);
                    out[n - 1] = '\0';
                }
            }
        }
    }
    free(buf);
    return best_score >= 0 ? 0 : -1;
}

/* DER of the PEM cert (malloc'd; caller frees). */
static unsigned char *pem_to_der(const char *cert_path, size_t *derlen) {
    X509 *x = load_pem_cert(cert_path);
    if (!x) return NULL;
    int n = i2d_X509(x, NULL);
    if (n <= 0) { X509_free(x); return NULL; }
    unsigned char *der = (unsigned char *)malloc((size_t)n);
    if (!der) { X509_free(x); return NULL; }
    unsigned char *p = der;
    i2d_X509(x, &p);
    *derlen = (size_t)n;
    X509_free(x);
    return der;
}

static int same_cert(PCCERT_CONTEXT a, PCCERT_CONTEXT b) {
    BYTE ha[64], hb[64];
    DWORD la = sizeof(ha), lb = sizeof(hb);
    if (!CertGetCertificateContextProperty(a, CERT_SHA1_HASH_PROP_ID, ha, &la)) return 0;
    if (!CertGetCertificateContextProperty(b, CERT_SHA1_HASH_PROP_ID, hb, &lb)) return 0;
    return la == lb && memcmp(ha, hb, la) == 0;
}

/*
 * Where the CA is trusted: bit 0 = the current user's Root store, bit 1 = the
 * machine Root store (only writable when the process is elevated).
 *
 * History: the dashboard only ever asked "trusted yes/no" and only ever wrote
 * the *user* store, so a browser or service running under another account (or
 * an app that reads the machine store) still showed certificate warnings even
 * though the app claimed the CA was trusted.
 */
#define CERT_TRUST_USER   1
#define CERT_TRUST_MACHINE 2

static int cert_trust_state(const char *cert_path) {
    size_t derlen = 0;
    unsigned char *der = pem_to_der(cert_path, &derlen);
    if (!der) return 0;
    PCERT_CONTEXT ours = (PCERT_CONTEXT)CertCreateCertificateContext(
        X509_ASN_ENCODING, der, (DWORD)derlen);
    int state = 0;
    if (ours) {
        int tries = 0;
        while (tries < 2) {
            DWORD scope = (tries == 0) ? CERT_SYSTEM_STORE_CURRENT_USER
                                       : CERT_SYSTEM_STORE_LOCAL_MACHINE;
            HCERTSTORE h = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
                                         scope, L"Root");
            if (h) {
                PCCERT_CONTEXT ctx = NULL;
                while ((ctx = CertEnumCertificatesInStore(h, ctx)) != NULL) {
                    if (same_cert((PCCERT_CONTEXT)ours, ctx)) {
                        state |= (tries == 0) ? CERT_TRUST_USER : CERT_TRUST_MACHINE;
                        break;
                    }
                }
                CertCloseStore(h, 0);
            }
            tries++;
        }
        CertFreeCertificateContext(ours);
    }
    free(der);
    return state;
}

static int cert_trusted(const char *cert_path) {
    return cert_trust_state(cert_path) != 0;
}

/* Short localised description of the trust state, for the status line. */
static void cert_trust_text(int state, wchar_t *out, size_t cap) {
    if ((state & CERT_TRUST_USER) && (state & CERT_TRUST_MACHINE))
        swprintf(out, cap, L"已信任（用户根 + 本机根）");
    else if (state & CERT_TRUST_MACHINE)
        swprintf(out, cap, L"已信任（本机根）");
    else if (state & CERT_TRUST_USER)
        swprintf(out, cap, L"已信任（用户根）");
    else
        swprintf(out, cap, L"未信任");
}

static int cert_trust_set(const char *cert_path, int enable) {
    size_t derlen = 0;
    unsigned char *der = pem_to_der(cert_path, &derlen);
    if (!der) return -1;
    int rc = -1;
    PCERT_CONTEXT ours = (PCERT_CONTEXT)CertCreateCertificateContext(
        X509_ASN_ENCODING, der, (DWORD)derlen);
    if (ours) {
        /*
         * Two stores on purpose:
         *  - the user Root store always works (no elevation needed), which is
         *    what every browser of this account reads;
         *  - the machine Root store is what other accounts, services and some
         *    applications read, so try it as well. Without elevation the write
         *    fails and is reported, never silently dropped.
         */
        const DWORD scopes[2] = { CERT_SYSTEM_STORE_CURRENT_USER,
                                  CERT_SYSTEM_STORE_LOCAL_MACHINE };
        int user_ok = 0, machine_ok = 0;
        for (int i = 0; i < 2; i++) {
            HCERTSTORE h = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
                                         scopes[i], L"Root");
            if (h == NULL) continue;
            int ok = 0;
            if (enable) {
                if (CertAddCertificateContextToStore(h, ours,
                        CERT_STORE_ADD_REPLACE_EXISTING, NULL)) ok = 1;
            } else {
                PCCERT_CONTEXT ctx = NULL;
                while ((ctx = CertEnumCertificatesInStore(h, ctx)) != NULL) {
                    if (same_cert((PCCERT_CONTEXT)ours, ctx)) {
                        PCCERT_CONTEXT dup = CertDuplicateCertificateContext(ctx);
                        if (dup != NULL) {
                            if (CertDeleteCertificateFromStore(dup)) ok = 1;
                            else CertFreeCertificateContext(dup);
                        }
                    }
                }
                /* Nothing to delete counts as success (idempotent). */
                if (ok == 0) ok = 1;
            }
            CertCloseStore(h, 0);
            if (i == 0) user_ok = ok; else machine_ok = ok;
        }
        /* The user store is the one that must work; the machine store is a
           bonus that needs administrator rights. */
        if (user_ok) rc = 0;
        win32_log_line("cert: %s -> user=%d machine=%d (%s)",
                       enable ? "trust" : "untrust", user_ok, machine_ok,
                       enable && !machine_ok
                           ? "run as administrator to also cover the machine store"
                           : "ok");
        CertFreeCertificateContext(ours);
    }
    free(der);
    /* Verify instead of trusting the return value: the store is re-read and the
       dashboard shows where the CA really is (or is not). */
    if (enable && rc == 0 && cert_trust_state(cert_path) == 0) {
        win32_log_line("cert: trust was written but the store does not report it");
        rc = -1;
    }
    if (!enable && cert_trust_state(cert_path) != 0) {
        win32_log_line("cert: the CA is still in a store after removal");
        rc = -1;
    }
    return rc;
}

/* ── autostart (HKCU Run) ───────────────────────────────────────── */

#define RUN_KEY L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define RUN_VALUE L"ADBlockWebServer"

int win32_autostart_set(bool enable, const char *cmdline) {
    HKEY hk;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, RUN_KEY, 0, NULL, 0,
            KEY_SET_VALUE | KEY_QUERY_VALUE, NULL, &hk, NULL) != ERROR_SUCCESS) {
        return -1;
    }
    int rc = 0;
    if (enable) {
        wchar_t wide[2048];
        utf8_to_wide(cmdline, wide, sizeof(wide) / sizeof(wide[0]));
        if (RegSetValueExW(hk, RUN_VALUE, 0, REG_SZ, (const BYTE *)wide,
                (DWORD)((wcslen(wide) + 1) * sizeof(wchar_t))) != ERROR_SUCCESS) rc = -1;
    } else {
        if (RegDeleteValueW(hk, RUN_VALUE) != ERROR_SUCCESS &&
            RegQueryValueExW(hk, RUN_VALUE, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            rc = -1;
        }
    }
    RegCloseKey(hk);
    return rc;
}

bool win32_autostart_installed(void) {
    wchar_t command[2048], exe[MAX_PATH]; DWORD bytes=sizeof(command);
    if (RegGetValueW(HKEY_CURRENT_USER,RUN_KEY,RUN_VALUE,RRF_RT_REG_SZ,NULL,command,&bytes)!=ERROR_SUCCESS)
        return false;
    if (!GetModuleFileNameW(NULL,exe,MAX_PATH)) return false;
    int count=0; wchar_t **arguments=CommandLineToArgvW(command,&count);
    bool owned=arguments && count>0 && _wcsicmp(arguments[0],exe)==0;
    if (arguments) LocalFree(arguments);
    return owned;
}

/* ── dashboard window ───────────────────────────────────────────── */

#define IDM_TRUST    1001
#define IDM_UNTRUST  1002
#define IDM_TEST     1003
#define IDM_AUTOSTART 1004
#define IDM_EXIT     1005
#define IDM_DARK     1006
#define IDM_UPDATE   1007
#define IDC_FIXPORT  1107
#define IDC_DIAG     1108
#define IDC_ADGUARD_HOME 1150 /* Manual AdGuard Home cooperation guide */
#define IDC_HTTP_EDIT 1101
#define IDC_HTTPS_EDIT 1102
#define IDC_BIND_CHK  1103
#define IDC_SAVE      1104
#define IDC_RESTART   1105
#define IDC_FLUSH     1106

/* AdGuard-inspired palette.
 *
 * The surface colours live in a switchable palette so the dashboard can be
 * rendered in a light or a dark theme (the accent colours are shared). */
struct palette {
    COLORREF sidebar, nav_active, nav_text, content_bg, card, border,
             text, muted, gridline, strip;
};
static const struct palette P_LIGHT = {
    RGB(22, 43, 41), RGB(33, 65, 60), RGB(175, 199, 192),
    RGB(245, 248, 247), RGB(255, 255, 255), RGB(222, 231, 227),
    RGB(27, 42, 37), RGB(86, 108, 99), RGB(236, 242, 239),
    RGB(255, 255, 255)
};
static const struct palette P_DARK = {
    RGB(12, 24, 22), RGB(30, 58, 51), RGB(172, 196, 186),
    RGB(17, 26, 23), RGB(25, 36, 31), RGB(51, 70, 61),
    RGB(224, 234, 228), RGB(170, 190, 179), RGB(42, 58, 49),
    RGB(25, 36, 31)
};
/* Active theme: starts as a literal copy of the light palette so it is valid
 * even before theme_apply() has run. */
static struct palette g_pal = {
    RGB(22, 43, 41), RGB(33, 65, 60), RGB(175, 199, 192),
    RGB(245, 248, 247), RGB(255, 255, 255), RGB(222, 231, 227),
    RGB(27, 42, 37), RGB(86, 108, 99), RGB(236, 242, 239),
    RGB(255, 255, 255)
};
static void theme_apply(int dark) {
    g_pal = dark ? P_DARK : P_LIGHT;
}
#define C_ACCENT     RGB(34, 157, 131)
#define C_BLUE_SOFT  RGB(219, 234, 254)
#define C_BLUE       RGB(59, 130, 246)
#define C_RED        RGB(239, 68, 68)
#define C_GREEN      RGB(34, 197, 94)
#define C_GREEN_TXT  (g_dark ? RGB(139, 213, 194) : RGB(24, 112, 87))

#if defined(ADBLOCK_PREVIEW_BUILD) || defined(ADBLOCK_INPLACE_PREVIEW)
static const wchar_t *g_title = L"ADBlock Preview v" ADBLOCK_APP_VERSION_W;
#else
static const wchar_t *g_title = L"ADBlock 拦截服务器 v" ADBLOCK_APP_VERSION_W;
#endif

static struct snapshot *g_sn = NULL;
static char g_res[512] = {0};
static int g_http_port = 8080;
static int g_https_port = 8443;
static bool g_bind_all = false;
static bool g_start_minimized = false;
/* Read-only AdGuard process presence, refreshed at most every 30 seconds.
 * It is NOT proof of an active network interception conflict. */
static enum adguard_process_signal g_adguard_signal = ADGUARD_PROCESS_UNKNOWN;
static DWORD g_adguard_probe_tick = 0;
static struct wintun_probe_result g_wintun_probe;

static int g_tab = 0;               /* 0 = statistics, 1 = 应用日志, 2 = settings */
/* Operation results persist; live service and certificate state have dedicated labels. */
static wchar_t g_status[4096] = L"就绪 · 使用左侧“订阅”管理规则来源";
static int s_ctrl_count = 0;
static HFONT g_ctl_font = NULL;

/* ── polling / caching state ─────────────────────────────────────
 * The statistics fetch runs on its own thread so a slow or unreachable
 * server can never freeze the window; the certificate files and the
 * Root-store lookup are cached with a TTL instead of being repeated on
 * every (2 s) repaint. */
static int  g_stats_port = 8686;     /* loopback management port (preferred) */
static int  g_active_port = 0;       /* port that answered the last poll */
static pthread_t g_poll_thread;
static volatile int g_poll_stop = 0;
static int  g_poll_started = 0;
static pthread_mutex_t g_snap_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct snapshot g_snap_next;
static long long g_cert_days = -100000;
static int  g_cert_trusted_flag = 0;
/* Where the CA is trusted: CERT_TRUST_USER / CERT_TRUST_MACHINE bitmask. */
static int  g_cert_trust_state = 0;
static DWORD g_cert_checked_tick = 0;
static DWORD g_poll_last_post = 0;   /* keep-alive post (clock) */
/* First visible row of the current bounded page; history navigation uses
   the server cursor instead of pretending a 400-row summary is the full ring.
   The card follows
   the mouse wheel instead of silently dropping everything older. */
static bool g_log_apps = false;
static bool g_log_rendering = false;
static int g_log_shown = 0;
static uint64_t g_log_render_hash;
static wchar_t g_log_search[192];
static int g_log_filter = -1;

/* ── resource accounting (shown in the dashboard + diagnose.txt) ────
 * "高消耗" was reported without numbers, so the app now measures itself:
 * CPU% (from GetProcessTimes deltas), working set, GDI/USER objects, threads
 * and handles. Sampling happens once per timer tick, which is cheap. */
static bool g_owns_server = false;       /* this process runs the server thread */
static volatile int g_ui_visible = 1;    /* window shown (not only tray) */
static int  g_hidden_trimmed = 0;        /* working set trimmed while hidden */
static double g_cpu_pct = 0.0;
static unsigned long long g_ws_kb = 0;
static DWORD g_gdi_obj = 0, g_user_obj = 0, g_thread_count = 0, g_handle_count = 0;
static ULONGLONG g_cpu_prev_ms = 0;
static DWORD g_cpu_prev_tick = 0;
#define CERT_CACHE_MS 30000

static int mgmt_port(void) {
    return g_active_port > 0 ? g_active_port : g_stats_port;
}

/* rounded card */
static void rounded_card(HDC hdc, int x, int y, int w, int h, int radius,
                         COLORREF fill, COLORREF border) {
    int X = S(x), Y = S(y), W = S(w), H = S(h), R = S(radius);
    HRGN rgn = CreateRoundRectRgn(X, Y, X + W, Y + H, R * 2, R * 2);
    HBRUSH b = CreateSolidBrush(fill);
    int saved = SaveDC(hdc);
    SelectClipRgn(hdc, rgn);
    RECT rc = {X, Y, X + W, Y + H};
    FillRect(hdc, &rc, b);
    SelectClipRgn(hdc, NULL);
    RestoreDC(hdc, saved);
    DeleteObject(b);
    DeleteObject(rgn);
    HPEN pen = CreatePen(PS_SOLID, 1, border);
    HGDIOBJ op = SelectObject(hdc, pen);
    HGDIOBJ ob = SelectObject(hdc, GetStockObject(NULL_BRUSH));
    RoundRect(hdc, X, Y, X + W, Y + H, R * 2, R * 2);
    SelectObject(hdc, op);
    SelectObject(hdc, ob);
    DeleteObject(pen);
}

static void fmt_num(wchar_t *dst, size_t n, long long v) {
    if (v >= 1000000) swprintf(dst, n, L"%.1fM", (double)v / 1000000.0);
    else if (v >= 1000) swprintf(dst, n, L"%.1fK", (double)v / 1000.0);
    else swprintf(dst, n, L"%lld", v);
}

static void draw_kpi(HDC hdc, int x, int y, int w, int h,
                     const wchar_t *label, const wchar_t *value,
                     COLORREF accent) {
    rounded_card(hdc, x + 1, y + 2, w, h, 12, g_pal.gridline, g_pal.gridline);  /* soft shadow */
    rounded_card(hdc, x, y, w, h, 12, g_pal.card, g_pal.border);
    HBRUSH ab = CreateSolidBrush(accent);
    HGDIOBJ op = SelectObject(hdc, GetStockObject(NULL_PEN));
    HGDIOBJ ob = SelectObject(hdc, ab);
    RoundRect(hdc, S(x + 3), S(y + 14), S(x + 7), S(y + h - 14), S(4), S(4));  /* accent bar */
    Ellipse(hdc, S(x + w - 15), S(y + 13), S(x + w - 8), S(y + 20));           /* corner dot */
    SelectObject(hdc, op);
    SelectObject(hdc, ob);
    DeleteObject(ab);
    HFONT vf = mfont(20, FW_SEMIBOLD);
    HFONT lf = mfont(12, FW_NORMAL);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, g_pal.text);
    HFONT old = (HFONT)SelectObject(hdc, vf);
    TextOutW(hdc, S(x + 16), S(y + 16), value, (int)wcslen(value));
    SetTextColor(hdc, g_pal.muted);
    SelectObject(hdc, lf);
    TextOutW(hdc, S(x + 16), S(y + 46), label, (int)wcslen(label));
    SelectObject(hdc, old);
    DeleteObject(vf);
    DeleteObject(lf);
}

static void draw_chart(HDC hdc, RECT panel, const wchar_t *title,
                       const struct histogram *h, int count) {
    rounded_card(hdc, panel.left, panel.top,
                 panel.right - panel.left, panel.bottom - panel.top, 12, g_pal.card, g_pal.border);
    HFONT tf = mfont(14, FW_SEMIBOLD);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, g_pal.text);
    HFONT old = (HFONT)SelectObject(hdc, tf);
    TextOutW(hdc, S(panel.left + 16), S(panel.top + 12), title, (int)wcslen(title));
    SelectObject(hdc, old);
    DeleteObject(tf);

    int ax = panel.left + 20, ay = panel.top + 42;
    int aw = panel.right - panel.left - 34, ah = panel.bottom - panel.top - 62;
    if (count <= 0 || aw < 10 || ah < 10) {
        SetTextColor(hdc, g_pal.muted);
        TextOutW(hdc, S(ax + 4), S(ay + 12), L"暂无数据", 4);
        return;
    }
    long long maxv = 1;
    for (int i = 0; i < count; i++) {
        if (h[i].requests > maxv) maxv = h[i].requests;
        if (h[i].blocked > maxv) maxv = h[i].blocked;
    }
    HPEN gp = CreatePen(PS_SOLID, 1, g_pal.gridline);
    HGDIOBJ gop = SelectObject(hdc, gp);
    for (int g = 0; g <= 3; g++) {
        int gy = S(ay) + (int)((double)(S(ah)) * g / 3.0);
        MoveToEx(hdc, S(ax), gy, NULL);
        LineTo(hdc, S(ax) + S(aw), gy);
    }
    SelectObject(hdc, gop);
    DeleteObject(gp);

    wchar_t numbuf[64];
    HFONT lf = mfont(11, FW_NORMAL);
    SelectObject(hdc, lf);
    SetTextColor(hdc, g_pal.muted);
    swprintf(numbuf, 64, L"%lld", maxv);
    TextOutW(hdc, S(ax), S(ay) - S(18), numbuf, (int)wcslen(numbuf));
    TextOutW(hdc, S(ax), S(ay) + S(ah) + S(4), L"0", 1);
    SelectObject(hdc, old);
    DeleteObject(lf);

    int slotw = aw / count;
    if (slotw < 4) slotw = 4;
    /*
     * Chart polish (the old drawing put two very thin slivers side by side on
     * flat blue/red, which is what "统计图太丑" was about):
     *   - wider rounded columns with a real gap between the pair;
     *   - a baseline axis so the plot has a floor;
     *   - the highest blocked column is labelled with its value.
     * Purely inside the existing plot rectangle - no control moves, so nothing
     * can overlap (see the settings-page fix in 1.50).
     */
    /*
     * ONE solid column per slot. The previous revision drew the pair
     * (requests + blocked) as two separate thin columns with a gap between
     * them, which read as "the chart is broken in the middle" - so the blocked
     * share is now a segment at the bottom of the same column instead.
     */
    int barw = slotw - 2;
    if (barw < 3) barw = 3;
    long long peak_blocked = -1;
    int peak_index = 0;
    for (int i = 0; i < count; i++) {
        if (h[i].blocked > peak_blocked) { peak_blocked = h[i].blocked; peak_index = i; }
    }
    HBRUSH blue = CreateSolidBrush(C_BLUE);
    HBRUSH red = CreateSolidBrush(C_RED);
    HGDIOBJ op = SelectObject(hdc, GetStockObject(NULL_PEN));
    /*
     * AUDIT W4-01: remember the brush that is currently selected so the two
     * brushes below can be de-selected again before they are deleted.
     * DeleteObject() on an object that is still selected into a DC fails, and
     * the object then leaks on every repaint (this chart is redrawn by a 2 s
     * timer) until the process runs out of its GDI quota.
     */
    HGDIOBJ obrush = SelectObject(hdc, GetStockObject(NULL_BRUSH));
    for (int i = 0; i < count; i++) {
        int bh1 = (int)((double)ah * (double)h[i].requests / (double)maxv);
        int bh2 = (int)((double)ah * (double)h[i].blocked / (double)maxv);
        int bx = ax + i * slotw;
        if (bh1 > 1) {
            SelectObject(hdc, blue);
            RoundRect(hdc, S(bx + 1), S(ay + ah) - S(bh1),
                      S(bx + 1 + barw), S(ay + ah), S(4), S(4));
        }
        if (bh2 > 1) {
            SelectObject(hdc, red);
            /* Blocked share of this period, stacked on the same column. */
            RoundRect(hdc, S(bx + 1), S(ay + ah) - S(bh2),
                      S(bx + 1 + barw), S(ay + ah), S(4), S(4));
        }
    }
    SelectObject(hdc, obrush);   /* de-select before deleting (AUDIT W4-01) */
    SelectObject(hdc, op);
    DeleteObject(blue);
    DeleteObject(red);

    /* Baseline axis: without it the columns floated in the grid. */
    HPEN axis = CreatePen(PS_SOLID, 1, g_pal.border);
    HGDIOBJ aop = SelectObject(hdc, axis);
    MoveToEx(hdc, S(ax), S(ay + ah), NULL);
    LineTo(hdc, S(ax) + S(aw), S(ay + ah));
    SelectObject(hdc, aop);
    DeleteObject(axis);

    /* Label the peak so the chart says something without a mouse-over. */
    if (peak_blocked > 0) {
        wchar_t pb[32];
        swprintf(pb, 32, L"%lld", peak_blocked);
        HFONT pf = mfont(10, FW_NORMAL);
        HGDIOBJ pop = SelectObject(hdc, pf);
        SetTextColor(hdc, C_RED);
        int pbx = ax + peak_index * slotw + 1;   /* left edge of that column */
        int pby = ay + ah - (int)((double)ah * (double)peak_blocked / (double)maxv) - 14;
        if (pby < ay) pby = ay;
        TextOutW(hdc, S(pbx), S(pby), pb, (int)wcslen(pb));
        SelectObject(hdc, pop);
        DeleteObject(pf);
    }
}

static void draw_legend(HDC hdc, int x, int y) {
    HBRUSH b = CreateSolidBrush(C_BLUE);
    HGDIOBJ op = SelectObject(hdc, GetStockObject(NULL_PEN));
    HGDIOBJ ob = SelectObject(hdc, b);
    Ellipse(hdc, S(x), S(y + 3), S(x + 8), S(y + 11));
    SelectObject(hdc, op);
    SelectObject(hdc, ob);
    DeleteObject(b);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, g_pal.muted);
    TextOutW(hdc, S(x + 14), S(y), L"请求", 2);
    HBRUSH r = CreateSolidBrush(C_RED);
    ob = SelectObject(hdc, r);
    Ellipse(hdc, S(x + 76), S(y + 3), S(x + 84), S(y + 11));
    SelectObject(hdc, ob);
    DeleteObject(r);
    TextOutW(hdc, S(x + 90), S(y), L"拦截", 2);
}

/* "监听状态" card: lists every socket the server reported through
 * /internal-stats so a port that failed to bind is visible inside the app
 * instead of only in webserver.log. */
static void draw_listener_card(HDC hdc, int x, int y, int w, int h,
                               const struct snapshot *sn, int two_col) {
    rounded_card(hdc, x + 1, y + 2, w, h, 12, g_pal.gridline, g_pal.gridline);
    rounded_card(hdc, x, y, w, h, 12, g_pal.card, g_pal.border);

    bool live = (sn != NULL && sn->valid);
    int total = 0, bound = 0;
    if (live) {
        total = sn->listener_count;
        for (int i = 0; i < total; i++)
            if (sn->listeners[i].bound) bound++;
    }
    bool ok = live && sn->bind_ok != 0;

    HFONT tf = mfont(14, FW_SEMIBOLD);
    HFONT old = (HFONT)SelectObject(hdc, tf);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, g_pal.text);
    TextOutW(hdc, S(x + 16), S(y + 12), L"监听状态", 4);

    wchar_t pill[160];
    if (live)
        /* bound == total in the normal case, and printing "10/14" there made a
           healthy server look like it had four dead ports - so only show the
           fraction when something is actually wrong. */
        swprintf(pill, 160, ok ? L"绑定正常 · %d 个监听端口"
                               : L"有端口绑定失败 · %d/%d 已监听", bound, total);
    else
        swprintf(pill, 160, L"服务器暂不可达，无法确认监听状态");
    HFONT pf = mfont(12, FW_NORMAL);
    SelectObject(hdc, pf);
    SetTextColor(hdc, !live ? g_pal.muted : (ok ? C_GREEN_TXT : RGB(200, 60, 60)));
    SIZE ps;
    GetTextExtentPoint32W(hdc, pill, (int)wcslen(pill), &ps);
    int px = x + w - 18 - (int)(ps.cx / g_scale);
    if (px < x + 110) px = x + 110;
    TextOutW(hdc, S(px), S(y + 14), pill, (int)wcslen(pill));
    SelectObject(hdc, old);
    DeleteObject(tf);
    DeleteObject(pf);

    int shown = 0;
    int cols = two_col ? 2 : 1;
    int maxrow = two_col ? 4 : 8;
    HFONT nf = mfont(12, FW_NORMAL);
    old = (HFONT)SelectObject(hdc, nf);
    for (int i = 0; i < total && shown < cols * maxrow; i++) {
        const struct listener_info *li = &sn->listeners[i];
        int col = shown % cols, row = shown / cols;
        int lx = x + 16 + col * ((w - 32) / cols + 8);
        int ly = y + 40 + row * 19;
        HBRUSH db = CreateSolidBrush(li->bound
                                     ? (li->loopback ? C_BLUE : C_GREEN)
                                     : RGB(200, 60, 60));
        HGDIOBJ op = SelectObject(hdc, GetStockObject(NULL_PEN));
        HGDIOBJ ob = SelectObject(hdc, db);
        Ellipse(hdc, S(lx), S(ly + 4), S(lx + 7), S(ly + 11));
        SelectObject(hdc, op);
        SelectObject(hdc, ob);
        DeleteObject(db);
        SetTextColor(hdc, li->bound ? g_pal.text : RGB(200, 60, 60));
        TextOutW(hdc, S(lx + 13), S(ly), li->name, (int)wcslen(li->name));
        SetTextColor(hdc, g_pal.muted);
        TextOutW(hdc, S(lx + 80), S(ly), li->addr, (int)wcslen(li->addr));
        shown++;
    }
    if (total == 0) {
        SetTextColor(hdc, g_pal.muted);
        const wchar_t *msg = live ? L"服务器未上报监听列表（可能是旧版服务器进程）"
                                  : L"正在连接服务器 ...";
        TextOutW(hdc, S(x + 16), S(y + 44), msg, (int)wcslen(msg));
    } else if (!ok && h > 130) {
        SetTextColor(hdc, RGB(200, 60, 60));
        const wchar_t *msg =
            L"提示：切到“设置”页点击“备用端口”即可避开被占用的端口。";
        TextOutW(hdc, S(x + 16), S(y + h - 44), msg, (int)wcslen(msg));
    }
    /* self-measurement: the numbers behind "它很占资源" */
    if (h > 120) {
        wchar_t diag[260];
        swprintf(diag, 260,
                 L"进程：CPU %.1f%% · 内存 %llu MB · 句柄 %lu · 线程 %lu · GDI %lu · 服务器线程 %ls",
                 g_cpu_pct, g_ws_kb / 1024ULL, (unsigned long)g_handle_count,
                 (unsigned long)g_thread_count, (unsigned long)g_gdi_obj,
                 g_owns_server ? (win32_server_alive() ? L"运行中" : L"已停止") : L"外部进程");
        SetTextColor(hdc, g_pal.muted);
        TextOutW(hdc, S(x + 16), S(y + h - 24), diag, (int)wcslen(diag));
    }
    SelectObject(hdc, old);
    DeleteObject(nf);
}

static void draw_statusbar(HDC hdc) {
    RECT strip = {S(0), S(630), S(1032), S(678)};   /* AUDIT V8: scale like everything else */
    HBRUSH sbg = CreateSolidBrush(g_pal.strip);
    FillRect(hdc, &strip, sbg);
    DeleteObject(sbg);
    HPEN tp = CreatePen(PS_SOLID, 1, g_pal.border);
    HGDIOBJ tpold = SelectObject(hdc, tp);
    MoveToEx(hdc, 0, S(630), NULL);
    LineTo(hdc, S(1032), S(630));
    SelectObject(hdc, tpold);
    DeleteObject(tp);

    bool connected = g_sn != NULL && g_sn->valid;
    bool up = connected && g_sn->bind_ok;
    HBRUSH dotb = CreateSolidBrush(up ? C_GREEN : C_RED);
    HGDIOBJ op = SelectObject(hdc, GetStockObject(NULL_PEN));
    HGDIOBJ ob = SelectObject(hdc, dotb);
    Ellipse(hdc, S(16), S(647), S(28), S(659));
    SelectObject(hdc, op);
    SelectObject(hdc, ob);
    DeleteObject(dotb);

    HFONT f = mfont(12, FW_NORMAL);
    HFONT old = (HFONT)SelectObject(hdc, f);
    SetBkMode(hdc, TRANSPARENT);
    wchar_t main[256];
    char host[68];
    const char *active=*g_active_arrival.ip ? g_active_arrival.ip : *g_active_arrival.ipv6 ? g_active_arrival.ipv6 : "localhost";
    if (!strcmp(active,"0.0.0.0")) active="127.0.0.1";
    if (!strcmp(active,"::")) active="::1";
    snprintf(host,sizeof(host),strchr(active,':') ? "[%s]" : "%s",active);
    swprintf(main, 256, L"%ls · http://%hs:%d  |  https://%hs:%d",
             up ? L"服务器运行中" : connected ? L"管理可用，响应未就绪" : L"服务器未连接",
             host, g_active_arrival.http, host, g_active_arrival.https);
    SetTextColor(hdc, up ? C_GREEN_TXT : RGB(190, 70, 70));
    RECT service_label = {S(40), S(640), S(415), S(662)};
    DrawTextW(hdc, main, -1, &service_label,
              DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);

    char cert_path[1024];
    snprintf(cert_path, sizeof(cert_path), "%s/localhost-2410.crt", g_res);
    long long days = g_cert_days;   /* cached: see cert_refresh() */
    wchar_t cert[200];
    wchar_t trust[64];
    cert_trust_text(g_cert_trust_state, trust, 64);
    if (days > 0 && days < 200000)
        swprintf(cert, 200, L"CA 证书剩余 %lld 天 · %ls", days, trust);
    else if (days == -100001)
        swprintf(cert, 200, L"CA 证书文件缺失: %hs", cert_path);
    else if (days == -100002)
        swprintf(cert, 200, L"CA 证书解析失败: %hs", cert_path);
    else
        swprintf(cert, 200, L"CA 证书已过期 - 删除 %hs 后重启", cert_path);
    SetTextColor(hdc, g_pal.muted);
    /* Long CA paths are common (especially under non-ASCII user profiles).
     * Clip rather than painting through the clock at the right edge. */
    RECT certificate_label = {S(430), S(640), S(934), S(662)};
    DrawTextW(hdc, cert, -1, &certificate_label,
              DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t tm[64];
    swprintf(tm, 64, L"%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
    SetTextColor(hdc, g_pal.muted);
    TextOutW(hdc, S(950), S(643), tm, (int)wcslen(tm));

    SetTextColor(hdc, g_pal.muted);
    RECT status_message = {S(16), S(660), S(980), S(680)};
    wchar_t stale_message[4200];
    const wchar_t *message = g_status;
    if (g_sn && g_sn->has_data && !g_sn->valid) {
        wchar_t last[64] = L"未知时间";
        struct tm *observed = localtime(&g_sn->updated_at);
        if (observed) wcsftime(last, 64, L"%m-%d %H:%M:%S", observed);
        swprintf(stale_message, 4200, L"统计暂不可达，保留 %ls 的数据 · %ls", last, g_status);
        message = stale_message;
    }
    DrawTextW(hdc, message, -1, &status_message,
              DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);

    SelectObject(hdc, old);
    DeleteObject(f);
}

/* sidebar nav hit areas (logical units; callers pass physical coords) */
static bool nav_hit(int x, int y, int which) {
    int top = 96 + which * 46;   /* six equally spaced navigation destinations */
    return x >= S(16) && x <= S(176) && y >= S(top) && y <= S(top + 40);
}

static void draw_sidebar(HDC hdc) {
    /* Cover the whole drawable height, including taller windows/DPI layouts.
     * The former fixed 680px background left a blank strip after resize. */
    RECT client_clip;
    GetClipBox(hdc, &client_clip);
    RECT sb = {S(0), S(0), S(190), client_clip.bottom};
    HBRUSH bg = CreateSolidBrush(g_pal.sidebar);
    FillRect(hdc, &sb, bg);
    DeleteObject(bg);

    HFONT lf = mfont(17, FW_SEMIBOLD);
    HFONT sf = mfont(11, FW_NORMAL);
    HFONT old = (HFONT)SelectObject(hdc, lf);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(255, 255, 255));
#ifdef ADBLOCK_PREVIEW_BUILD
    TextOutW(hdc, S(22), S(24), L"ADBlock Preview", 15);
#else
    TextOutW(hdc, S(22), S(24), L"ADBlock", 7);
#endif
    SelectObject(hdc, sf);
    SetTextColor(hdc, RGB(143, 163, 192));
    wchar_t ver[64];
    swprintf(ver, 64, L"拦截服务器 v" ADBLOCK_APP_VERSION_W);
    TextOutW(hdc, S(22), S(48), ver, (int)wcslen(ver));
    {
        bool connected=g_sn != NULL && g_sn->valid;
        bool live=connected && g_sn->bind_ok;
        HBRUSH nb = CreateSolidBrush(live ? C_GREEN : connected ? RGB(251,191,36) : RGB(120,135,160));
        HGDIOBJ nop = SelectObject(hdc, GetStockObject(NULL_PEN));
        HGDIOBJ nob = SelectObject(hdc, nb);
        Ellipse(hdc, S(22), S(70), S(31), S(79));
        SelectObject(hdc, nop);
        SelectObject(hdc, nob);
        DeleteObject(nb);
        SetTextColor(hdc, live ? RGB(110,231,183) : connected ? RGB(251,191,36) : RGB(143,163,192));
        const wchar_t *state=live ? L"服务器运行中" : connected ? L"响应监听失败" : L"等待服务器 ...";
        TextOutW(hdc,S(37),S(67),state,(int)wcslen(state));
    }
    SelectObject(hdc, old);
    DeleteObject(lf);
    DeleteObject(sf);

    /* Capture coverage status: the current Windows build has a request listener,
     * but no TUN/WFP global capture backend. Never label bind() success as
     * machine-wide protection or automatically switch mode on process presence. */
    {
        const struct traffic_evidence evidence = {
            .preference = TRAFFIC_PREFERENCE_AUTO,
            .capture_owner = TRAFFIC_OWNER_NONE,
            .adguard_process_present = (g_adguard_signal == ADGUARD_PROCESS_PRESENT),
            .adguard_capture_confirmed = false,
            .listener_path_verified = false,
            .capture_backend_supported = false,
            .capture_authorized = false,
            .capture_failed = false
        };
        const struct traffic_decision decision = traffic_mode_decide(&evidence);
        const wchar_t *coverage =
            decision.reason == TRAFFIC_REASON_CAPTURE_UNAVAILABLE
                ? L"全局接管：尚未实现" : L"全局接管：未验证";
        const wchar_t *adguard =
            g_adguard_signal == ADGUARD_PROCESS_PRESENT
                ? L"AdGuard：进程运行"
                : (g_adguard_signal == ADGUARD_PROCESS_ABSENT
                    ? L"AdGuard：未检测到" : L"AdGuard：状态未知");
        HFONT info = mfont(11, FW_NORMAL);
        HFONT prev = (HFONT)SelectObject(hdc, info);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(143, 163, 192));
        TextOutW(hdc, S(22), S(371), L"过滤范围：本地监听", (int)wcslen(L"过滤范围：本地监听"));
        TextOutW(hdc, S(22), S(392), coverage, (int)wcslen(coverage));
        TextOutW(hdc, S(22), S(423), adguard, (int)wcslen(adguard));
        if (g_adguard_signal == ADGUARD_PROCESS_PRESENT)
            TextOutW(hdc, S(22), S(444), L"不代表已发生拦截冲突", (int)wcslen(L"不代表已发生拦截冲突"));
        const wchar_t *tun_hint =
            g_wintun_probe.status == WINTUN_PROBE_MISSING
                ? L"Wintun：尚未提供 DLL"
                : (g_wintun_probe.status == WINTUN_PROBE_API_INCOMPLETE
                    ? L"Wintun：DLL 接口不完整"
                    : (g_wintun_probe.status == WINTUN_PROBE_DRIVER_RUNNING
                        ? L"Wintun：驱动存在（未接管）"
                        : L"Wintun：接口可见（未验证/未接管）"));
        TextOutW(hdc, S(22), S(478), tun_hint, (int)wcslen(tun_hint));
        SelectObject(hdc, prev);
        DeleteObject(info);
    }

    /* nav items */
    for (int t = 0; t < 6; t++) {
        int ny = 96 + t * 46;
        bool active = (g_tab == t);
        rounded_card(hdc, 16, ny, 160, 40, 10,
                     active ? g_pal.nav_active : g_pal.sidebar,
                     active ? g_pal.nav_active : g_pal.sidebar);
        if (active) {
            HBRUSH ab = CreateSolidBrush(C_ACCENT);
            RECT bar = {S(16), S(ny + 10), S(20), S(ny + 30)};
            FillRect(hdc, &bar, ab);
            DeleteObject(ab);
        }
        /* icon: bars (statistics) / list rows (activity) / sliders (settings) */
        if (t == 0) {
            HBRUSH ib = CreateSolidBrush(active ? C_ACCENT : g_pal.nav_text);
            HGDIOBJ op = SelectObject(hdc, GetStockObject(NULL_PEN));
            HGDIOBJ ob = SelectObject(hdc, ib);
            RoundRect(hdc, S(34), S(ny + 14), S(40), S(ny + 30), S(3), S(3));
            RoundRect(hdc, S(43), S(ny + 8),  S(49), S(ny + 30), S(3), S(3));
            RoundRect(hdc, S(52), S(ny + 20), S(58), S(ny + 30), S(3), S(3));
            SelectObject(hdc, op);
            SelectObject(hdc, ob);
            DeleteObject(ib);
        } else if (t == 1) {
            HPEN ip = CreatePen(PS_SOLID, S(2), active ? C_ACCENT : g_pal.nav_text);
            HGDIOBJ op = SelectObject(hdc, ip);
            HGDIOBJ ob2 = SelectObject(hdc, GetStockObject(NULL_BRUSH));
            for (int k = 0; k < 3; k++) {
                int ly = S(ny + 13 + k * 7);
                MoveToEx(hdc, S(40), ly, NULL);
                LineTo(hdc, S(58), ly);
                Ellipse(hdc, S(34) - S(2), ly - S(2), S(34) + S(2), ly + S(2));
            }
            SelectObject(hdc, ob2);
            SelectObject(hdc, op);
            DeleteObject(ip);
        } else if (t == 2) {
            HPEN ip = CreatePen(PS_SOLID, S(2), active ? C_ACCENT : g_pal.nav_text);
            HGDIOBJ op = SelectObject(hdc, ip);
            HGDIOBJ ob2 = SelectObject(hdc, GetStockObject(NULL_BRUSH));
            for (int k = 0; k < 3; k++) {
                int ly = S(ny + 12 + k * 7);
                MoveToEx(hdc, S(34), ly, NULL);
                LineTo(hdc, S(58), ly);
                Ellipse(hdc, S(40 + k * 6) - S(2), ly - S(2),
                        S(40 + k * 6) + S(2), ly + S(2));
            }
            SelectObject(hdc, ob2);
            SelectObject(hdc, op);
            DeleteObject(ip);
        } else if (t == 3) {
            /* ranking: three bars of growing height */
            HBRUSH ib = CreateSolidBrush(active ? C_ACCENT : g_pal.nav_text);
            HGDIOBJ op = SelectObject(hdc, GetStockObject(NULL_PEN));
            HGDIOBJ ob = SelectObject(hdc, ib);
            /* All coordinates must be relative to ny. Previous end points
             * used absolute y=30, drawing inverted/outside the nav row. */
            RoundRect(hdc, S(34), S(ny + 22), S(41), S(ny + 30), S(2), S(2));
            RoundRect(hdc, S(45), S(ny + 16), S(52), S(ny + 30), S(2), S(2));
            RoundRect(hdc, S(56), S(ny + 10), S(63), S(ny + 30), S(2), S(2));
            SelectObject(hdc, op);
            SelectObject(hdc, ob);
            DeleteObject(ib);
        } else if (t == 4) {
            /* subscriptions: a globe (circle + meridian) */
            HPEN ip = CreatePen(PS_SOLID, S(2), active ? C_ACCENT : g_pal.nav_text);
            HGDIOBJ op = SelectObject(hdc, ip);
            HGDIOBJ ob2 = SelectObject(hdc, GetStockObject(NULL_BRUSH));
            Ellipse(hdc, S(34), S(ny + 10), S(62), S(ny + 30));
            MoveToEx(hdc, S(48), S(ny + 10), NULL);
            LineTo(hdc, S(48), S(ny + 30));
            SelectObject(hdc, ob2);
            SelectObject(hdc, op);
            DeleteObject(ip);
        } else {
            /* network center: three connection nodes; all relative to nav row */
            HPEN ip = CreatePen(PS_SOLID, S(2), active ? C_ACCENT : g_pal.nav_text);
            HGDIOBJ op = SelectObject(hdc, ip);
            HGDIOBJ ob = SelectObject(hdc, GetStockObject(NULL_BRUSH));
            MoveToEx(hdc, S(39), S(ny + 20), NULL);
            LineTo(hdc, S(56), S(ny + 12));
            MoveToEx(hdc, S(39), S(ny + 20), NULL);
            LineTo(hdc, S(56), S(ny + 28));
            Ellipse(hdc, S(34), S(ny + 15), S(44), S(ny + 25));
            Ellipse(hdc, S(52), S(ny + 7), S(62), S(ny + 17));
            Ellipse(hdc, S(52), S(ny + 23), S(62), S(ny + 33));
            SelectObject(hdc, ob);
            SelectObject(hdc, op);
            DeleteObject(ip);
        }
        HFONT nf = mfont(14, active ? FW_SEMIBOLD : FW_NORMAL);
        SelectObject(hdc, nf);
        SetTextColor(hdc, active ? RGB(255, 255, 255) : g_pal.nav_text);
        {
            const wchar_t *label = t == 0 ? L"统计"
                                 : (t == 1 ? L"应用日志"
                                 : (t == 2 ? L"设置"
                                 : (t == 3 ? L"拦截排行" : (t == 4 ? L"订阅" : L"网络中心"))));
            TextOutW(hdc, S(70), S(ny + 10), label, (int) wcslen(label));
        }
        SelectObject(hdc, old);
        DeleteObject(nf);
    }

    /* Discoverable keyboard hint below the six nav entries. */
    {
        HFONT hint = mfont(10, FW_NORMAL);
        HFONT prev = (HFONT)SelectObject(hdc, hint);
        SetTextColor(hdc, g_pal.nav_text);
        TextOutW(hdc, S(22), S(548), L"Alt+1~6 切换页面", 12);
        SelectObject(hdc, prev);
        DeleteObject(hint);
    }

    /* exit at sidebar bottom */
    rounded_card(hdc, 16, 576, 160, 40, 10, g_pal.sidebar, g_pal.sidebar);
    HFONT xf = mfont(13, FW_NORMAL);
    SelectObject(hdc, xf);
    SetTextColor(hdc, g_pal.nav_text);
    TextOutW(hdc, S(70), S(586), L"退出", 2);
    SelectObject(hdc, old);
    DeleteObject(xf);
}

/* ── system tray icon ──────────────────────────────────────────── */
#define WM_APP_TRAY (WM_USER + 1)
#define WM_APP_EXIT (WM_USER + 2)
/* Broadcast sent by a duplicate instance so the running one surfaces its
   dashboard instead of the user seeing two server processes. */
static UINT g_show_dashboard_msg;

static NOTIFYICONDATAW g_nid;
static bool g_tray_initialized = false;

static UINT g_taskbar_created = 0;   /* "TaskbarCreated" */
static bool g_tray_ok = false;

static bool tray_add(HWND hwnd) {
    memset(&g_nid, 0, sizeof(g_nid));
    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    g_nid.uCallbackMessage = WM_APP_TRAY;
    {
        /* Use the embedded application icon for the tray, too. */
        HICON ti = (HICON)LoadImageW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(1),
                                     IMAGE_ICON, GetSystemMetrics(SM_CXSMICON),
                                     GetSystemMetrics(SM_CYSMICON), LR_SHARED);
        g_nid.hIcon = (ti != NULL) ? ti : LoadIconW(NULL, IDI_APPLICATION);
    }
    char host[68]; listener_display_host(host);
    swprintf(g_nid.szTip, 128, L"ADBlock 拦截服务器 - http://%hs:%d", host, g_http_port);
    BOOL ok = Shell_NotifyIconW(NIM_ADD, &g_nid);
    g_tray_ok = (ok == TRUE);
    g_tray_initialized = g_tray_ok;
    if (g_tray_ok) {
        g_nid.uFlags |= NIF_INFO;
        wcscpy(g_nid.szInfoTitle, L"ADBlock 拦截服务器");
        wcscpy(g_nid.szInfo, L"运行中 - 双击此图标可重新打开窗口。");
        Shell_NotifyIconW(NIM_MODIFY, &g_nid);
        g_nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    }
    return g_tray_ok;
}

static void tray_remove(void) {
    if (g_tray_initialized) {
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        g_tray_initialized = false;
    }
}


static void show_adguard_assistant(HWND hwnd) {
    const struct gui_adguard_runtime state = {
        .bind_all = g_bind_all,
        .listener_responding = (g_sn != NULL && g_sn->valid),
        .ca_trusted_for_user = (g_cert_trusted_flag != 0),
        .http_port = g_http_port,
        .https_port = g_https_port
    };
    gui_show_adguard_home_wizard(hwnd, &state, first_lan_ip);
}

static void tray_menu(HWND hwnd) {
    HMENU m = CreatePopupMenu();
    AppendMenuW(m, MF_STRING | MF_ENABLED, 3001, L"打开仪表盘");
    AppendMenuW(m, MF_STRING | MF_ENABLED, 3002, L"开机自启动");
    AppendMenuW(m, MF_STRING | MF_ENABLED, 3004, L"检查更新");
    AppendMenuW(m, MF_STRING | MF_ENABLED, 3005, L"AdGuard Home 协同向导");
    AppendMenuW(m, MF_STRING | MF_ENABLED, 3006, L"查看网络基线（只读）");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING | MF_ENABLED, 3003, L"退出");
    POINT pt;
    GetCursorPos(&pt);
    SetForegroundWindow(hwnd);
    int cmd = (int)TrackPopupMenuEx(m, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, hwnd, NULL);
    DestroyMenu(m);
    if (cmd == 3001) {
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
    } else if (cmd == 3002) {
        HWND chk = GetDlgItem(hwnd, IDM_AUTOSTART);
        bool on = SendMessageW(chk, BM_GETCHECK, 0, 0) != BST_CHECKED;
        char ccmd[2048], exe[MAX_PATH];
        get_module_path_utf8(exe, sizeof(exe));
        snprintf(ccmd, sizeof(ccmd), "\"%s\" --resources \"%s\" --http-port %d --https-port %d --minimized",   /* --no-gui started without a tray icon after logon */
                 exe, g_res, g_http_port, g_https_port);
        win32_autostart_set(on, ccmd);
        SendMessageW(chk, BM_SETCHECK, on ? BST_CHECKED : BST_UNCHECKED, 0);
        swprintf(g_status, 4096, L"开机自启动已%ls", on ? L"启用" : L"关闭");
        InvalidateRect(hwnd, NULL, FALSE);
    } else if (cmd == 3005) {
        show_adguard_assistant(hwnd);
    } else if (cmd == 3006) {
        gui_show_network_baseline(hwnd);
    } else if (cmd == 3004) {
            swprintf(g_status, 4096, L"正在检查更新…");
            update_check_async(hwnd);
        } else if (cmd == 3003) {
        PostMessageW(hwnd, WM_APP_EXIT, 0, 0);
    }
}

/* control layout descriptors (logical units) */
struct ctl_desc { int id; int x, y, w, h; const wchar_t *cls, *text; int style; };
static const struct ctl_desc g_clayout[] = {
    { IDC_HTTP_EDIT,  300, 70, 100, 26, L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER },
    { IDC_HTTPS_EDIT, 590, 70, 100, 26, L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER },
    { IDC_IPV4_LABEL,218,110,55,24,L"STATIC",L"IPv4",SS_LEFT },
    { IDC_BIND_IP,275,106,330,26,L"EDIT",L"",WS_BORDER|ES_AUTOHSCROLL },
    { IDC_CREATE_ADDRESS,618,106,110,26,L"BUTTON",L"创建 IPv4…",BS_PUSHBUTTON },
    { IDC_REMOVE_ADDRESS,738,106,110,26,L"BUTTON",L"移除托管…",BS_PUSHBUTTON },
    { IDC_IPV6_LABEL,218,144,55,24,L"STATIC",L"IPv6",SS_LEFT },
    { IDC_BIND_IPV6,275,140,330,26,L"EDIT",L"",WS_BORDER|ES_AUTOHSCROLL },
    { IDC_CREATE_IPV6,618,140,110,26,L"BUTTON",L"创建 IPv6…",BS_PUSHBUTTON },
    { IDC_REMOVE_IPV6,738,140,110,26,L"BUTTON",L"移除托管…",BS_PUSHBUTTON },
    { IDC_BIND_CHK,860,140,130,26,L"BUTTON",L"所有网卡",BS_PUSHBUTTON },
    { IDC_AUTO_CREATE,218,176,410,24,L"BUTTON",L"随服务器启动创建缺失地址（需管理员授权）",BS_AUTOCHECKBOX },
    { IDC_CHECK_LISTEN,738,70,110,26,L"BUTTON",L"检测冲突",BS_PUSHBUTTON },
    { IDC_LOOP_PAIR,860,70,130,26,L"BUTTON",L"仅本机（推荐）",BS_PUSHBUTTON },
    { IDC_LISTEN_STATUS,218,208,772,40,L"EDIT",L"",ES_MULTILINE|ES_READONLY|WS_VSCROLL },
    { IDC_ADGUARD_HOME, 834, 590, 168, 26, L"BUTTON", L"AdGuard 检测与协同…", BS_PUSHBUTTON },
    { IDC_SAVE,       640, 174, 110, 28, L"BUTTON", L"保存设置", BS_PUSHBUTTON },
    { IDC_RESTART,    760, 174, 120, 28, L"BUTTON", L"保存并重启", BS_PUSHBUTTON },
    { IDC_FIXPORT,    860, 106, 130, 28, L"BUTTON", L"备用端口", BS_PUSHBUTTON },
    { IDM_DARK,       890, 176, 100, 24, L"BUTTON", L"深色外观", BS_AUTOCHECKBOX },
    { IDM_TRUST,      218, 488, 160, 26, L"BUTTON", L"信任 CA", BS_PUSHBUTTON },
    { IDM_UNTRUST,    390, 488, 160, 26, L"BUTTON", L"撤销 CA", BS_PUSHBUTTON },
    { IDM_TEST,       562, 488, 180, 26, L"BUTTON", L"打开测试页", BS_PUSHBUTTON },
    { IDM_AUTOSTART,  760, 489, 230, 24, L"BUTTON", L"开机自启动", BS_AUTOCHECKBOX },
    { IDC_CAROTATE,   218, 522, 250, 26, L"BUTTON", L"生成新 CA（并存 90 天）", BS_PUSHBUTTON },
    { IDC_CADROP,     480, 522, 250, 26, L"BUTTON", L"完成 CA 轮换（90 天后）", BS_PUSHBUTTON },
    { IDC_DIAG,       742, 522, 250, 26, L"BUTTON", L"导出诊断信息", BS_PUSHBUTTON },
    { IDC_SUBRELOAD,  218, 556, 250, 26, L"BUTTON", L"重新加载本地订阅", BS_PUSHBUTTON },
    { IDC_FLUSH,      480, 556, 250, 26, L"BUTTON", L"立即保存统计", BS_PUSHBUTTON },
    { IDC_POLDEF,     742, 556, 250, 26, L"BUTTON", L"恢复推荐拦截策略", BS_PUSHBUTTON },
    { IDC_PORTABLEUPD,218, 590, 148, 26, L"BUTTON", L"包：安装器优先", BS_PUSHBUTTON },
    { IDC_PREVIEWUPD,376, 590, 138, 26, L"BUTTON", L"渠道：稳定版", BS_PUSHBUTTON },
    { IDM_UPDATE,    684, 590, 140, 26, L"BUTTON", L"检查更新", BS_PUSHBUTTON },
    { IDC_AUTOUPD,   524, 590, 150, 26, L"BUTTON", L"自动更新：开启", BS_PUSHBUTTON },
};
/* Number of controls in g_clayout: derive it from the array itself. It used to
   be a hand-kept constant, and when IDM_UPDATE (检查更新) was appended the
   constant stayed at 14 - so the button was never created and simply vanished
   from the settings page. */
#define CL_MAIN ((int) (sizeof(g_clayout) / sizeof(g_clayout[0])))

/* Native controls of the 订阅 page. Created with the settings controls (same
   loop) and shown only on tab 4, see show_controls(). */
static const struct ctl_desc g_sublayout[] = {
    { IDC_SUB_URL,   218,  70, 560, 26, L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL },
    { IDC_SUB_ADD,   790,  70, 100, 26, L"BUTTON", L"添加", BS_PUSHBUTTON },
    { IDC_SUB_DEL,   898,  70, 104, 26, L"BUTTON", L"删除选中", BS_PUSHBUTTON },
    { IDC_SUB_LIST,  218, 110, 784, 230, L"LISTBOX", L"",
      WS_BORDER | WS_VSCROLL | WS_HSCROLL | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT },
    { IDC_SUB_SELECTED, 218, 370, 580, 26, L"EDIT", L"", WS_BORDER | ES_READONLY | ES_AUTOHSCROLL },
    { IDC_SUB_FULL_URL, 808, 370, 194, 26, L"BUTTON", L"显示完整地址", BS_PUSHBUTTON },
    { IDC_SUB_NAME, 218, 426, 390, 26, L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL },
    { IDC_SUB_RENAME, 618, 426, 180, 26, L"BUTTON", L"保存名称", BS_PUSHBUTTON },
    { IDC_SUB_DEFAULT_NAME, 808, 426, 194, 26, L"BUTTON", L"恢复自动名称", BS_PUSHBUTTON },
    { IDC_SUB_UPD,   218, 500, 190, 28, L"BUTTON", L"立即更新全部", BS_PUSHBUTTON },
    { IDC_SUB_OPEN,  418, 500, 190, 28, L"BUTTON", L"打开订阅文件夹", BS_PUSHBUTTON },
    { IDC_SUB_CONFIRM, 618, 500, 180, 28, L"BUTTON", L"确认移除", BS_PUSHBUTTON },
    { IDC_SUB_CANCEL, 808, 500, 194, 28, L"BUTTON", L"取消", BS_PUSHBUTTON },
};
#define CL_SUB ((int) (sizeof(g_sublayout) / sizeof(g_sublayout[0])))
static const struct ctl_desc g_loglayout[] = {
    { IDC_QLOG_PREVIOUS, 218, 584, 122, 26, L"BUTTON", L"上一页", BS_PUSHBUTTON },
    { IDC_QLOG_NEXT,     350, 584, 148, 26, L"BUTTON", L"更早记录", BS_PUSHBUTTON },
    { IDC_QLOG_REFRESH,  508, 584, 166, 26, L"BUTTON", L"刷新到最新", BS_PUSHBUTTON },
    { IDC_QLOG_SEARCH, 218, 90, 480, 28, L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL },
    { IDC_QLOG_FILTER, 710, 90, 158, 200, L"COMBOBOX", L"", CBS_DROPDOWNLIST | WS_VSCROLL },
    { IDC_QLOG_LIST, 218, 132, 784, 290, L"LISTBOX", L"", WS_BORDER | WS_VSCROLL | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT },
    { IDC_QLOG_DETAILS, 218, 466, 784, 96, L"EDIT", L"", WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL },
    { IDC_QLOG_APPS, 856, 24, 146, 28, L"BUTTON", L"查看应用统计", BS_PUSHBUTTON },
    { IDC_QLOG_LIVE, 880, 90, 122, 28, L"BUTTON", L"暂停刷新", BS_PUSHBUTTON },
};
#define CL_LOG ((int)(sizeof(g_loglayout) / sizeof(g_loglayout[0])))
static HWND s_ctrls[CL_MAIN + CL_SUB + CL_LOG + POLICY_COUNT + 1];

static void log_list_refresh(HWND hwnd, bool force);
static void log_details_refresh(HWND hwnd);
static void log_controls_refresh(HWND hwnd) {
    bool current = g_sn && g_sn->qlog_ready && !g_sn->qlog_error &&
        g_sn->qlog_revision == g_log_nav.revision;
    EnableWindow(GetDlgItem(hwnd, IDC_QLOG_PREVIOUS), current && g_log_nav.depth > 0);
    EnableWindow(GetDlgItem(hwnd, IDC_QLOG_NEXT), current && g_sn->qlog_page.has_more);
    for (int i = 0; i < CL_LOG; ++i) {
        int id = g_loglayout[i].id;
        bool visible = g_tab == 1 && (!g_log_apps || id == IDC_QLOG_LIST ||
            id == IDC_QLOG_DETAILS || id == IDC_QLOG_APPS);
        ShowWindow(GetDlgItem(hwnd, id), visible ? SW_SHOW : SW_HIDE);
    }
    SetDlgItemTextW(hwnd, IDC_QLOG_APPS, g_log_apps ? L"返回请求日志" : L"查看应用统计");
    SetDlgItemTextW(hwnd, IDC_QLOG_LIVE,
        g_log_nav.request.generation[0] ? L"恢复实时" : L"暂停刷新");
    EnableWindow(GetDlgItem(hwnd, IDC_QLOG_LIVE), g_sn && g_sn->qlog_ready && !g_sn->qlog_error);
    log_list_refresh(hwnd, false);
}

static void log_navigation(HWND hwnd, int action) {
    bool changed = false;
    pthread_mutex_lock(&g_snap_mutex);
    if (action == IDC_QLOG_REFRESH) { qln_refresh(&g_log_nav); changed = true; }
    else if (g_sn && g_sn->qlog_ready && !g_sn->qlog_error && g_sn->qlog_revision == g_log_nav.revision) {
        changed = action == IDC_QLOG_PREVIOUS ? qln_previous(&g_log_nav)
            : qln_next(&g_log_nav, &g_sn->qlog_page, g_sn->qlog_revision);
    }
    pthread_mutex_unlock(&g_snap_mutex);
    if (changed) {
        if (g_sn) g_sn->qlog_error = 3;
        if (g_poll_wake) SetEvent(g_poll_wake);
        log_controls_refresh(hwnd);
        InvalidateRect(hwnd, NULL, FALSE);
    }
}


/* The dashboard is painted in a fixed 1032x678 logical canvas (sidebar
   0..190, content to x=1000, status bar to y=678). Deriving g_scale from the
   DPI alone left that canvas at design size in the top-left corner of a
   maximized window; the scale must follow the CLIENT size instead. */
#define DASH_W 1032.0
#define DASH_H 678.0
static void subs_list_extent(HWND hwnd);
static void subs_controls_refresh(HWND hwnd);
static void update_layout_scale(HWND hwnd) {
    RECT rc;
    if (!hwnd || !GetClientRect(hwnd, &rc)) return;
    int cw = rc.right - rc.left, ch = rc.bottom - rc.top;
    if (cw < 200 || ch < 200) return;                 /* minimized / mid-resize */
    double sx = (double) cw / DASH_W, sy = (double) ch / DASH_H;
    double s = sx < sy ? sx : sy;
    if (s < 0.5) s = 0.5;
    if (s > 3.0) s = 3.0;
    g_scale = s;
}

static void layout_controls(HWND hwnd) {
    HFONT next_font = mfont(15, FW_NORMAL);
    if (next_font) {
        for (int i = 0; i < s_ctrl_count; i++)
            SendMessageW(s_ctrls[i], WM_SETFONT, (WPARAM)next_font, TRUE);
        if (g_ctl_font) DeleteObject(g_ctl_font);
        g_ctl_font = next_font;
    }
    for (int i = 0; i < CL_MAIN; i++)
        SetWindowPos(GetDlgItem(hwnd, g_clayout[i].id), NULL,
                     S(g_clayout[i].x), S(g_clayout[i].y),
                     S(g_clayout[i].w), S(g_clayout[i].h), SWP_NOZORDER | SWP_NOACTIVATE);
    /* policy checkboxes */
    for (int i = 0; i < POLICY_COUNT; i++) {
        int cx = (i % 2 == 0) ? 218 : 610;
        int cy = 290 + (i / 2) * 28;
        HWND w = GetDlgItem(hwnd, IDC_POL0 + i);
        if (w) SetWindowPos(w, NULL, S(cx), S(cy), S(370), S(26), SWP_NOZORDER | SWP_NOACTIVATE);
    }
    /* 订阅 page controls */
    for (int i = 0; i < CL_SUB; i++)
        SetWindowPos(GetDlgItem(hwnd, g_sublayout[i].id), NULL,
                     S(g_sublayout[i].x), S(g_sublayout[i].y),
                     S(g_sublayout[i].w), S(g_sublayout[i].h), SWP_NOZORDER | SWP_NOACTIVATE);
    for (int i = 0; i < CL_LOG; i++)
        SetWindowPos(GetDlgItem(hwnd, g_loglayout[i].id), NULL,
            S(g_loglayout[i].x), S(g_loglayout[i].y), S(g_loglayout[i].w), S(g_loglayout[i].h), SWP_NOZORDER | SWP_NOACTIVATE);
    SetWindowPos(GetDlgItem(hwnd,IDC_TRANSPORT_PROBE),NULL,S(218),S(560),S(366),S(26),SWP_NOZORDER|SWP_NOACTIVATE);
    subs_list_extent(hwnd);
}

static void show_controls(HWND hwnd, int tab) {
    /* Native controls belong to one page each: settings is tab 2, the new
       订阅 page is tab 4. Leaving a page must hide its controls, otherwise
       the edit box and the list box stay on top of the other pages. */
    bool show = (tab == 2);
    bool subs = (tab == 4);
    if (show) policy_sync_controls(hwnd);
    for (int i = 0; i < CL_MAIN; i++)
        ShowWindow(GetDlgItem(hwnd, g_clayout[i].id), show ? SW_SHOW : SW_HIDE);
    for (int i = 0; i < POLICY_COUNT; i++)
        ShowWindow(GetDlgItem(hwnd, IDC_POL0 + i), show ? SW_SHOW : SW_HIDE);
    for (int i = 0; i < CL_SUB; i++)
        ShowWindow(GetDlgItem(hwnd, g_sublayout[i].id), subs ? SW_SHOW : SW_HIDE);
    for (int i = 0; i < CL_LOG; i++)
        ShowWindow(GetDlgItem(hwnd, g_loglayout[i].id), tab == 1 ? SW_SHOW : SW_HIDE);
    log_controls_refresh(hwnd);
    ShowWindow(GetDlgItem(hwnd,IDC_TRANSPORT_PROBE),tab==5?SW_SHOW:SW_HIDE);
    subs_controls_refresh(hwnd);
}

/* Click on one type: advance it to the next method and apply immediately. */
static void policy_cycle_one(HWND hwnd, int i) {
    int modes[POLICY_COUNT];
    for (int k = 0; k < POLICY_COUNT; k++) modes[k] = policy_mode(g_res, k);
    int before = modes[i];
    modes[i] = policy_next_mode(before);
    wchar_t what[128];
    swprintf(what, 128, L"%ls 的拦截方式：%ls → %ls", g_policy[i].label,
             policy_method_label(before), policy_method_label(modes[i]));
    policy_apply_modes(hwnd, modes, what);
}

/* One button that puts every type back to the recommended method. */
static void policy_apply_defaults(HWND hwnd) {
    int modes[POLICY_COUNT];
    for (int k = 0; k < POLICY_COUNT; k++) modes[k] = g_policy[k].def;
    policy_apply_modes(hwnd, modes, L"已恢复推荐默认：看得见的用占位，脚本/样式/字体用空响应，API/遥测/配置/WS 用 204");
}

/* Policy type / reply mode of a query-log row: "脚本 · 204" answers both
   questions the dashboard user has - which rule matched and how it answered. */
static const wchar_t *log_type_label(int t) {
    static const wchar_t *names[] = {
        L"图片", L"脚本", L"样式表", L"字体", L"媒体",
        L"页面结构", L"API", L"遥测", L"配置", L"WebSocket"
    };
    return (t >= 0 && t < (int) (sizeof(names) / sizeof(names[0]))) ? names[t] : L"—";
}

static const wchar_t *log_mode_label(int m) {
    switch (m) {
    case 0: return L"占位";
    case 1: return L"204";
    case 2: return L"放行";
    case 3: return L"空响应";
    default: return L"未知策略";
    }
}

static const wchar_t *log_action_label(int action) {
    return action == 1 ? L"拦截响应" : action == 2 ? L"本地豁免" : L"转发已启动";
}

static const wchar_t *log_family_label(int family) {
    return family == 4 ? L"IPv4" : family == 6 ? L"IPv6" : L"协议未知";
}

static void log_time(long long stamp, wchar_t *out, size_t capacity, bool date) {
    time_t value = (time_t)stamp;
    struct tm *local = stamp > 0 ? localtime(&value) : NULL;
    if (!local || !wcsftime(out, capacity, date ? L"%Y-%m-%d %H:%M:%S" : L"%H:%M:%S", local))
        swprintf(out, capacity, L"时间未知");
}

static void log_freeze_current(HWND hwnd) {
    if (g_sn && g_sn->qlog_ready && !g_sn->qlog_error) {
        pthread_mutex_lock(&g_snap_mutex);
        bool frozen = qln_freeze(&g_log_nav, &g_sn->qlog_page, g_sn->qlog_revision);
        pthread_mutex_unlock(&g_snap_mutex);
        if (frozen && g_poll_wake) SetEvent(g_poll_wake);
    }
    log_controls_refresh(hwnd);
}

static WNDPROC g_log_list_original;
static LRESULT CALLBACK log_list_proc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) {
    /* Native listboxes consume their own wheel/scroll messages. The parent's
       WM_MOUSEWHEEL handler alone cannot protect a page being read this way. */
    if (!g_log_apps && (message == WM_MOUSEWHEEL || message == WM_VSCROLL))
        log_freeze_current(GetParent(hwnd));
    return CallWindowProcW(g_log_list_original, hwnd, message, wp, lp);
}

static void log_details_refresh(HWND hwnd) {
    HWND list = GetDlgItem(hwnd, IDC_QLOG_LIST);
    LRESULT selected = SendMessageW(list, LB_GETCURSEL, 0, 0);
    LRESULT index = selected == LB_ERR ? LB_ERR : SendMessageW(list, LB_GETITEMDATA, (WPARAM)selected, 0);
    wchar_t text[1500];
    if (!g_sn || index == LB_ERR || index < 0 || index >= (g_log_apps ? g_sn->app_count : g_sn->qlog_count)) {
        SetDlgItemTextW(hwnd, IDC_QLOG_DETAILS, g_log_apps ? L"选中进程查看计数；仅统计到达响应服务器的连接。" :
            L"选中请求查看详情。这里记录响应服务器收到的 HTTP 请求，不代表全部 DNS／Hosts 拦截。键盘方向键可浏览，Ctrl+C 可复制详情。");
        return;
    }
    if (g_log_apps) {
        struct app_row *app = &g_sn->apps[index];
        wchar_t pid[40];
        if (app->uid >= 0) swprintf(pid, 40, L"%d", app->uid); else wcscpy(pid, L"未知");
        swprintf(text, 1500, L"进程：%ls    PID：%ls\r\n连接：%lld    请求：%lld    拦截响应：%lld\r\n最近观测速率：%lld 次/秒    TLS 失败：%lld\r\n进程归属为连接建立时的观测，不证明当前同 PID 的进程身份。",
            app->name, pid, app->connections, app->requests, app->blocked, app->tps, app->tls_fail);
    } else {
        struct qlog_row *row = &g_sn->qlog[index];
        wchar_t time[64], pid[40];
        log_time(row->ts, time, 64, true);
        if (row->uid >= 0) swprintf(pid, 40, L"%d", row->uid); else wcscpy(pid, L"未知／未归属");
        const wchar_t *meaning = row->action == 1 ? L"服务器返回了拦截响应。" : row->action == 2 ?
            L"服务器命中本地豁免并返回无内容响应；不代表原站可访问。" :
            L"已启动到上游的转发；这条记录不证明上游访问成功。";
        swprintf(text, 1500, L"域名：%ls\r\n时间：%ls    PID：%ls\r\nHTTP 连接：%ls（不是 DNS A/AAAA 查询类型）\r\n结果：%ls    响应分类：%ls    响应策略：%ls\r\n%ls 规则／来源标识：当前记录未提供。",
            row->host, time, pid, log_family_label(row->family), log_action_label(row->action), log_type_label(row->type),
            row->action == 1 ? log_mode_label(row->mode) : L"不适用", meaning);
    }
    SetDlgItemTextW(hwnd, IDC_QLOG_DETAILS, text);
}

static uint64_t log_hash_bytes(uint64_t value, const void *bytes, size_t count) {
    const unsigned char *input = bytes;
    for (size_t i = 0; i < count; ++i) { value ^= input[i]; value *= UINT64_C(1099511628211); }
    return value;
}

static void log_list_refresh(HWND hwnd, bool force) {
    HWND list = GetDlgItem(hwnd, IDC_QLOG_LIST);
    if (!list || !g_sn || g_tab != 1) return;
    uint64_t hash = UINT64_C(14695981039346656037);
    hash = log_hash_bytes(hash, &g_log_apps, sizeof(g_log_apps));
    hash = log_hash_bytes(hash, &g_log_filter, sizeof(g_log_filter));
    hash = log_hash_bytes(hash, g_log_search, wcslen(g_log_search) * sizeof(wchar_t));
    int count = g_log_apps ? g_sn->app_count : g_sn->qlog_count;
    hash = log_hash_bytes(hash, &count, sizeof(count));
    hash = log_hash_bytes(hash, g_log_apps ? (const void *)g_sn->apps : (const void *)g_sn->qlog,
        (size_t)count * (g_log_apps ? sizeof(struct app_row) : sizeof(struct qlog_row)));
    if (!force && hash == g_log_render_hash) return;
    g_log_render_hash = hash;
    struct qlog_row selected_log = {0};
    int selected_pid = -2;
    LRESULT selected = SendMessageW(list, LB_GETCURSEL, 0, 0);
    LRESULT old_index = selected == LB_ERR ? LB_ERR : SendMessageW(list, LB_GETITEMDATA, (WPARAM)selected, 0);
    /* Once snapshots change, the old index belongs to the previous snapshot.
       Clearing selection avoids ever presenting another request as its details. */
    bool preserve = force && old_index >= 0 && old_index < count;
    if (preserve) {
        if (g_log_apps) selected_pid = g_sn->apps[old_index].uid;
        else selected_log = g_sn->qlog[old_index];
    }
    LRESULT top = SendMessageW(list, LB_GETTOPINDEX, 0, 0);
    g_log_rendering = true;
    SendMessageW(list, WM_SETREDRAW, FALSE, 0);
    SendMessageW(list, LB_RESETCONTENT, 0, 0);
    g_log_shown = 0;
    for (int i = 0; i < count; ++i) {
        wchar_t line[512];
        if (g_log_apps) {
            struct app_row *app = &g_sn->apps[i];
            swprintf(line, 512, L"%ls    连接 %lld    请求 %lld    拦截 %lld",
                app->name, app->connections, app->requests, app->blocked);
        } else {
            struct qlog_row *row = &g_sn->qlog[i];
            if (!qlf_matches_entry(row->host, row->action, row->type, row->family, g_log_search, g_log_filter)) continue;
            wchar_t time[32]; log_time(row->ts, time, 32, false);
            swprintf(line, 512, L"%ls    [%ls · %ls · %ls]    %ls", time, log_family_label(row->family),
                log_action_label(row->action), row->action == 1 ? log_type_label(row->type) : L"不适用", row->host);
        }
        LRESULT item = SendMessageW(list, LB_ADDSTRING, 0, (LPARAM)line);
        if (item == LB_ERR || item == LB_ERRSPACE) break;
        SendMessageW(list, LB_SETITEMDATA, (WPARAM)item, (LPARAM)i);
        ++g_log_shown;
        if (preserve && (g_log_apps ? g_sn->apps[i].uid == selected_pid :
                memcmp(&selected_log, &g_sn->qlog[i], sizeof(selected_log)) == 0)) {
            SendMessageW(list, LB_SETCURSEL, (WPARAM)item, 0);
            preserve = false;
        }
    }
    if (force && top != LB_ERR && top < g_log_shown) SendMessageW(list, LB_SETTOPINDEX, (WPARAM)top, 0);
    SendMessageW(list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(list, NULL, TRUE);
    g_log_rendering = false;
    log_details_refresh(hwnd);
}

/*
 * The "检查更新" button follows the updater state (audit item 36): while a
 * check, a download or an installation runs it is disabled and names the phase,
 * so a second click cannot start a competing thread and the user can see where
 * the pipeline actually is.
 */
static bool listener_read(HWND hwnd, char ip[64], char ip6[64], int *http, int *https, bool *all) {
    char text[64], normalized[64];
    GetDlgItemTextA(hwnd, IDC_BIND_IP, text, sizeof(text));
    if (*text && la_normalize(text, normalized)!=4) return false;
    snprintf(ip, 64, "%s", *text ? normalized : "");
    GetDlgItemTextA(hwnd, IDC_BIND_IPV6, text, sizeof(text));
    if (*text && la_normalize(text,normalized)!=6) return false;
    snprintf(ip6,64,"%s",*text ? normalized : "");
    if (!*ip && !*ip6) return false;
    GetDlgItemTextA(hwnd, IDC_HTTP_EDIT, text, sizeof(text)); *http=la_port(text);
    GetDlgItemTextA(hwnd, IDC_HTTPS_EDIT, text, sizeof(text)); *https=la_port(text);
    *all=false;
    return *http && *https && *http!=*https && *http!=g_stats_port && *https!=g_stats_port;
}

static const wchar_t *listener_description(int status) {
    switch (status) {
        case 0: return L"可绑定";
        case 6: return L"本程序监听";
        case 1: return L"其他进程占用";
        case 2: return L"非本机 IP";
        case 3: return L"无权限或系统保留";
        default: return L"无法绑定";
    }
}

static bool listener_validate(HWND hwnd, bool explicit_check) {
    if (s_address_busy) return false;
    char ip[64],ip6[64]; int http,https; bool all;
    if (!listener_read(hwnd,ip,ip6,&http,&https,&all)) {
        SetDlgItemTextW(hwnd,IDC_LISTEN_STATUS,L"IPv4 / IPv6 请分别输入；至少启用一种协议。留空关闭；端口须为 1–65535 且不重复。不支持方括号、区域编号或域名。");
        return false;
    }
    bool automatic=SendDlgItemMessageW(hwnd,IDC_AUTO_CREATE,BM_GETCHECK,0,0)==BST_CHECKED;
    wchar_t report[800]=L""; bool valid=true;
    const char *targets[2]={ip,ip6};
    for (int i=0;i<2;i++) {
        size_t used=wcslen(report);
        if (!*targets[i]) { swprintf(report+used,800-used,L"IPv%d：关闭。%ls",i ? 6 : 4,i ? L"" : L"\r\n"); continue; }
        DWORD hp=0,sp=0; int h=listener_status(targets[i],http,&hp),s=listener_status(targets[i],https,&sp);
        SOCKADDR_INET address;
        bool missing=automatic && ma_address(targets[i],&address) && h==2 && s==2;
        swprintf(report+used,800-used,L"IPv%d %hs：HTTP %ls / PID%lu；HTTPS %ls / PID%lu。%ls%ls",
            i ? 6 : 4,targets[i],listener_description(h),(unsigned long)hp,listener_description(s),(unsigned long)sp,
            missing ? L"启动时请求授权创建。" : L"",i ? L"" : L"\r\n");
        valid &= missing || ((h==0 || h==6) && (s==0 || s==6));
    }
    SetDlgItemTextW(hwnd,IDC_LISTEN_STATUS,report);
    if (explicit_check) InvalidateRect(hwnd,NULL,FALSE);
    return valid;
}

struct address_job { HWND hwnd; char ip[64]; int http,https; bool remove; DWORD result; };

static void address_controls(HWND hwnd,bool busy) {
    const int ids[]={IDC_BIND_IP,IDC_BIND_IPV6,IDC_AUTO_CREATE,IDC_LOOP_PAIR,IDC_CREATE_IPV6,IDC_REMOVE_IPV6,IDC_BIND_CHK,IDC_HTTP_EDIT,IDC_HTTPS_EDIT,IDC_CREATE_ADDRESS,
        IDC_REMOVE_ADDRESS,IDC_SAVE,IDC_RESTART,IDC_CHECK_LISTEN,IDC_FIXPORT};
    for (size_t i=0;i<sizeof(ids)/sizeof(ids[0]);i++) EnableWindow(GetDlgItem(hwnd,ids[i]),!busy);
}

static DWORD WINAPI address_worker(void *opaque) {
    struct address_job *job=(struct address_job *)opaque;
    wchar_t exe[32768],args[256];
    DWORD length=GetModuleFileNameW(NULL,exe,32768);
    if (!length || length>=32768) job->result=ERROR_FILENAME_EXCED_RANGE;
    else {
        if (job->remove) swprintf(args,256,L"--remove-listener-address %hs",job->ip);
        else swprintf(args,256,L"--create-listener-address %hs %d %d",job->ip,job->http,job->https);
        SHELLEXECUTEINFOW request; memset(&request,0,sizeof(request));
        request.cbSize=sizeof(request); request.fMask=SEE_MASK_NOCLOSEPROCESS|SEE_MASK_NOASYNC|SEE_MASK_FLAG_NO_UI;
        request.lpVerb=L"runas"; request.lpFile=exe; request.lpParameters=args; request.nShow=SW_HIDE;
        if (!ShellExecuteExW(&request)) job->result=GetLastError();
        else if (!request.hProcess) job->result=ERROR_INVALID_HANDLE;
        else {
            DWORD wait=WaitForSingleObject(request.hProcess,30000);
            if (wait==WAIT_OBJECT_0) { if (!GetExitCodeProcess(request.hProcess,&job->result)) job->result=GetLastError(); }
            else job->result=wait==WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
            CloseHandle(request.hProcess);
        }
    }
    if (!PostMessageW(job->hwnd,WM_APP_ADDRESS_DONE,0,(LPARAM)job)) free(job);
    return 0;
}

static void address_action(HWND hwnd,bool remove,bool ipv6) {
    if (s_address_busy) return;
    char ip[64],ip6[64]; int http,https; bool all; SOCKADDR_INET address;
    if (!listener_read(hwnd,ip,ip6,&http,&https,&all) || !(ipv6 ? *ip6 : *ip)) {
        SetDlgItemTextW(hwnd,IDC_LISTEN_STATUS,L"请先填写具体的监听 IPv4 / IPv6 地址和有效端口。"); return;
    }
    if (ipv6) snprintf(ip,sizeof(ip),"%s",ip6);
    memset(&address,0,sizeof(address)); address.si_family=strchr(ip,':') ? AF_INET6 : AF_INET;
    if (address.si_family==AF_INET) inet_pton(AF_INET,ip,&address.Ipv4.sin_addr);
    else inet_pton(AF_INET6,ip,&address.Ipv6.sin6_addr);
    MIB_UNICASTIPADDRESS_ROW row;
    if (!remove && ma_find(&address,&row)==NO_ERROR) {
        listener_validate(hwnd,true);
        SetDlgItemTextW(hwnd,IDC_LISTEN_STATUS,L"地址已经存在，直接复用；没有修改地址或创建记录。检查端口后保存并重启。"); return;
    }
    if (!ma_address(ip,&address)) {
        SetDlgItemTextW(hwnd,IDC_LISTEN_STATUS,L"请填写私有 IPv4 或 IPv6 ULA（如 fd6b:2a91:84f0::2）；只在软件回环接口创建 /32 或 /128，本机已有地址可直接保存。");
        return;
    }
    if (remove && ma_owned(ip,&row)!=NO_ERROR) {
        SetDlgItemTextW(hwnd,IDC_LISTEN_STATUS,L"该地址没有匹配的 AdAway 创建记录；不会移除系统或其他软件创建的地址。"); return;
    }
    if (remove && (!strcmp(ip,g_active_arrival.ip) || !strcmp(ip,g_active_arrival.ipv6))) {
        SetDlgItemTextW(hwnd,IDC_LISTEN_STATUS,L"请先切换到其他监听地址并保存、重启，再移除当前正在使用的托管地址。"); return;
    }
    wchar_t prompt[600];
    swprintf(prompt,600,remove
        ? L"移除本程序在软件回环接口创建的 %hs？\n\n需要管理员授权，仅操作创建记录仍匹配的地址；不会移除其他地址。"
        : L"在软件回环接口创建 %hs（%ls）？\n\n需要管理员授权，仅在本机使用，不修改物理网卡、DHCP、DNS 或默认网关。创建后检查 HTTP/HTTPS 端口，失败时回滚。\n\n地址仅在本次开机有效；重启系统后可再次创建。成功后请点击“保存并重启”应用监听设置。",
        ip,strchr(ip,':') ? L"/128" : L"/32");
    if (MessageBoxW(hwnd,prompt,remove ? L"移除托管地址" : L"创建本机地址",MB_OKCANCEL|MB_ICONQUESTION)!=IDOK) return;
    struct address_job *job=(struct address_job *)calloc(1,sizeof(*job));
    if (!job) { SetDlgItemTextW(hwnd,IDC_LISTEN_STATUS,L"内存不足，未修改地址。"); return; }
    job->hwnd=hwnd; snprintf(job->ip,sizeof(job->ip),"%s",ip); job->http=http; job->https=https; job->remove=remove;
    s_address_busy=true; address_controls(hwnd,true); KillTimer(hwnd,3);
    SetDlgItemTextW(hwnd,IDC_LISTEN_STATUS,L"正在等待管理员授权并处理本机地址…");
    HANDLE thread=CreateThread(NULL,0,address_worker,job,0,NULL);
    if (thread) CloseHandle(thread);
    else { free(job); s_address_busy=false; address_controls(hwnd,false); SetDlgItemTextW(hwnd,IDC_LISTEN_STATUS,L"无法启动地址任务，未修改地址。"); }
}

static void update_button_refresh(HWND hwnd) {
    HWND b = GetDlgItem(hwnd, IDM_UPDATE);
    if (b == NULL) return;
    static int last = -1;
    int st = update_state();
    if (st == last) return;
    last = st;
    const wchar_t *label = L"检查更新";
    if (st == 1) label = L"检查中…";
    else if (st == 2) label = L"下载中…";
    else if (st == 3) label = L"校验中…";
    else if (st == 4) label = L"安装中…";
    SetWindowTextW(b, label);
    EnableWindow(b, st == 0);
    EnableWindow(GetDlgItem(hwnd, IDC_PORTABLEUPD), st == 0);
    EnableWindow(GetDlgItem(hwnd, IDC_PREVIEWUPD), st == 0);
    EnableWindow(GetDlgItem(hwnd, IDC_AUTOUPD), st == 0);
}

static bool refresh_owned_autostart(void) {
    if (!win32_autostart_installed()) return true;
    char exe[MAX_PATH], command[2048];
    if (!get_module_path_utf8(exe,sizeof(exe))) return false;
    snprintf(command,sizeof(command),"\"%s\" --resources \"%s\" --minimized",exe,g_res);
    return win32_autostart_set(true,command)==0;
}

/* ── "应用日志" page ──────────────────────────────────────────────
 * Everything the server knows about WHO talks to it: the per-app counters
 * (Windows attributes them through the TCP owner-PID table, see
 * win32_pid_for_tuple) and the query log ring buffer that answers "why was
 * this blocked?". Unlike the settings page this one has no child controls, so
 * the layout below is self contained and cannot overlap them. */
/* 拦截排行 + 拦截类型分布：服务端按 Host 头累计的“真正被拦下”的次数（最多 20 条），
   以及每个类别各被拦下多少次。以前只有聚合数字，看不出“到底哪些域名在捣乱、
   拦的都是什么”。 */
/* Dedicated network-integration destination. It reserves stable space for
 * future TUN/WFP capture, AdGuard coexistence and rollback, but does not make
 * any configuration changes or pretend that a backend already exists. */
static void draw_network_capability(HDC hdc, int x, int y, int w,
                                    const wchar_t *title,
                                    const wchar_t *description,
                                    bool available) {
    rounded_card(hdc, x, y, w, 116, 12, g_pal.card, g_pal.border);
    HFONT heading = mfont(14, FW_SEMIBOLD);
    HFONT body = mfont(11, FW_NORMAL);
    HFONT old = (HFONT)SelectObject(hdc, heading);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, g_pal.text);
    RECT title_rect = {S(x + 16), S(y + 12), S(x + w - 100), S(y + 36)};
    DrawTextW(hdc, title, -1, &title_rect,
              DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
    const wchar_t *badge = available ? L"现有功能" : L"规划中";
    SetTextColor(hdc, available ? C_GREEN_TXT : g_pal.muted);
    RECT badge_rect = {S(x + w - 94), S(y + 13), S(x + w - 10), S(y + 36)};
    DrawTextW(hdc, badge, -1, &badge_rect,
              DT_SINGLELINE | DT_RIGHT | DT_NOPREFIX);
    SelectObject(hdc, body);
    SetTextColor(hdc, g_pal.muted);
    RECT desc_rect = {S(x + 16), S(y + 42), S(x + w - 16), S(y + 110)};
    DrawTextW(hdc, description, -1, &desc_rect,
              DT_WORDBREAK | DT_NOPREFIX);
    SelectObject(hdc, old);
    DeleteObject(heading);
    DeleteObject(body);
}

static void draw_network_center_page(HDC hdc) {
    rounded_card(hdc, 202, 12, 812, 184, 12,
                 g_pal.card, g_pal.border);
    HFONT heading = mfont(19, FW_SEMIBOLD);
    HFONT body = mfont(12, FW_NORMAL);
    HFONT old = (HFONT)SelectObject(hdc, heading);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, g_pal.text);
    RECT title = {S(224), S(28), S(984), S(58)};
    DrawTextW(hdc, L"网络中心", -1, &title, DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(hdc, body);
    SetTextColor(hdc, g_pal.muted);
    const wchar_t *note =
        L"当前版本仅处理已经送到本地端口的请求。监听成功 ≠ 已接管全机流量。";
    RECT note_rect = {S(224), S(66), S(992), S(108)};
    DrawTextW(hdc, note, -1, &note_rect, DT_WORDBREAK | DT_NOPREFIX);
    const wchar_t *adguard =
        g_adguard_signal == ADGUARD_PROCESS_PRESENT
            ? L"AdGuard 进程：已发现（不能据此判断是否冲突）"
            : g_adguard_signal == ADGUARD_PROCESS_ABSENT
                ? L"AdGuard 进程：未发现"
                : L"AdGuard 进程：检测结果未知";
    RECT adguard_rect = {S(224), S(114), S(990), S(138)};
    DrawTextW(hdc, adguard, -1, &adguard_rect,
              DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
    const wchar_t *capture =
        L"全局接管：未接入 TUN/WFP    ·    自动协同切换：尚未启用";
    RECT capture_rect = {S(224), S(151), S(990), S(182)};
    DrawTextW(hdc, capture, -1, &capture_rect,
              DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
    SelectObject(hdc, old);
    DeleteObject(heading);
    DeleteObject(body);

    draw_network_capability(hdc, 202, 208, 398,
        L"全流量接管", L"IPv4/IPv6、TCP/UDP、按应用接管；支持明确授权与运行状态。",
        false);
    draw_network_capability(hdc, 616, 208, 398,
        L"AdGuard 协同监听", L"确认活动冲突后引导监听及 AdGuard Home 阻断 IP 配置。",
        false);
    draw_network_capability(hdc, 202, 338, 398,
        L"DNS 与规则引擎", L"上游 DNS 健康、加密 DNS、规则匹配与漏流量诊断。",
        false);
    draw_network_capability(hdc, 616, 338, 398,
        L"HTTPS / QUIC", L"证书信任、TLS 失败、UDP/443 与不能解密的应用诊断。",
        false);
    draw_network_capability(hdc, 202, 478, 398,
        L"隔离双栈转发", L"本机夹具；可取消、重试，不更改系统路由或 DNS。",
        true);
    draw_network_capability(hdc, 616, 478, 398,
        L"本地监听与规则", L"当前可在设置、订阅和拦截排行页面管理；此处不重复开关。",
        true);
}

static void draw_ranking_page(HDC hdc) {
    struct snapshot *sn = g_sn;
    HFONT hf = mfont(15, FW_SEMIBOLD);
    HFONT lf = mfont(12, FW_NORMAL);
    HFONT old;
    static const wchar_t *HINT =
        L"按被拦截次数排序 - 只统计真正被拦下的请求（占位图 / 204 / 空响应）";
    static const wchar_t *WAIT = L"等待服务器统计数据 ...";
    static const wchar_t *NONE =
        L"还没有拦截记录：等有广告/追踪请求被拦下后，这里会出现排行。";
    const int rows_shown = 12;
    SetBkMode(hdc, TRANSPARENT);

    /* ── 排行 ── */
    rounded_card(hdc, 202, 12, 812, 348, 12, g_pal.card, g_pal.border);
    old = (HFONT) SelectObject(hdc, hf);
    SetTextColor(hdc, g_pal.text);
    TextOutW(hdc, S(218), S(24), L"拦截排行", 4);
    SelectObject(hdc, lf);
    SetTextColor(hdc, g_pal.muted);
    TextOutW(hdc, S(218), S(48), HINT, (int) wcslen(HINT));
    if (sn == NULL || !sn->has_data) {
        TextOutW(hdc, S(222), S(100), WAIT, (int) wcslen(WAIT));
    } else if (sn->top_count == 0) {
        TextOutW(hdc, S(222), S(100), NONE, (int) wcslen(NONE));
    } else {
        int rows = sn->top_count > rows_shown ? rows_shown : sn->top_count;
        long long maxc = 1;
        for (int i = 0; i < rows; i++)
            if (sn->top[i].count > maxc) maxc = sn->top[i].count;
        SetTextColor(hdc, g_pal.muted);
        TextOutW(hdc, S(222), S(74), L"域名", 2);
        TextOutW(hdc, S(880), S(74), L"拦截次数", 4);
        for (int i = 0; i < rows; i++) {
            wchar_t rank[16], num[32];
            int y = 100 + i * 21;
            swprintf(rank, 16, L"%d.", i + 1);
            SetTextColor(hdc, g_pal.text);
            TextOutW(hdc, S(222), S(y), rank, (int) wcslen(rank));
            /* DrawText trims to the actual pixel width between rank and bar,
             * unlike the old 44-character heuristic, which clipped differently
             * at 125%/150% DPI and for long IDN/hostnames. */
            RECT host_box = {S(251), S(y), S(545), S(y + 19)};
            DrawTextW(hdc, sn->top[i].host, -1, &host_box,
                      DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
            /* 条形长度按最忙的域名归一，形状一眼能看出差距 */
            if (sn->top[i].count > 0) {
                int w = (int) (160.0 * (double) sn->top[i].count / (double) maxc);
                if (w < 2) w = 2;
                HBRUSH bb = CreateSolidBrush(C_ACCENT);
                RECT bar = {S(560), S(y + 2), S(560 + w), S(y + 13)};
                FillRect(hdc, &bar, bb);
                DeleteObject(bb);
            }
            SetTextColor(hdc, g_pal.muted);
            fmt_num(num, 32, sn->top[i].count);
            TextOutW(hdc, S(880), S(y), num, (int) wcslen(num));
        }
    }

    /* ── 类型分布 ── */
    rounded_card(hdc, 202, 372, 812, 248, 12, g_pal.card, g_pal.border);
    SelectObject(hdc, hf);
    SetTextColor(hdc, g_pal.text);
    TextOutW(hdc, S(218), S(384), L"拦截类型分布", 6);
    {
        /* 「证书被拒」：握手失败/成功总数。这里用全局 g_sn —— 本区块没有局部快照
           指针（写 sn 会编译不过）。失败数远大于成功数，通常意味着客户端在做
           证书固定（pinning）。 */
        const struct snapshot *tsn = g_sn;
        wchar_t tls_line[160];
        swprintf(tls_line, 160,
                 L"证书被拒（握手失败）%lld 次 · 握手成功 %lld 次",
                 tsn ? tsn->tls_failures : 0LL,
                 tsn ? tsn->tls_handshakes : 0LL);
        TextOutW(hdc, S(430), S(384), tls_line, (int) wcslen(tls_line));
    }
    SelectObject(hdc, lf);
    SetTextColor(hdc, g_pal.muted);
    {
        static const wchar_t *THINT = L"服务端按命中的策略类别累计（自本次安装以来的总数）";
        TextOutW(hdc, S(218), S(408), THINT, (int) wcslen(THINT));
    }
    if (sn != NULL && sn->has_data) {
        long long maxv = 1;
        for (int i = 0; i < BLOCK_TYPE_COUNT && i < 16; i++)
            if (sn->blocked_by_type[i] > maxv) maxv = sn->blocked_by_type[i];
        const int per_col = (BLOCK_TYPE_COUNT + 1) / 2;
        for (int i = 0; i < BLOCK_TYPE_COUNT && i < 16; i++) {
            int col = i / per_col;
            int row = i % per_col;
            int x = 222 + col * 400;
            int y = 440 + row * 26;
            wchar_t num[32];
            SetTextColor(hdc, g_pal.text);
            TextOutW(hdc, S(x), S(y), kBlockTypes[i].label,
                     (int) wcslen(kBlockTypes[i].label));
            if (sn->blocked_by_type[i] > 0) {
                int w = (int) (150.0 * (double) sn->blocked_by_type[i] / (double) maxv);
                if (w < 2) w = 2;
                HBRUSH bb = CreateSolidBrush(C_ACCENT);
                RECT bar = {S(x + 96), S(y + 2), S(x + 96 + w), S(y + 13)};
                FillRect(hdc, &bar, bb);
                DeleteObject(bb);
            }
            SetTextColor(hdc, g_pal.muted);
            fmt_num(num, 32, sn->blocked_by_type[i]);
            TextOutW(hdc, S(x + 260), S(y), num, (int) wcslen(num));
        }
    }
    SelectObject(hdc, old);
    DeleteObject(hf);
    DeleteObject(lf);
}

static void draw_activity_page(HDC hdc) {
    struct snapshot *sn = g_sn;
    rounded_card(hdc, 202, 12, 812, 608, 12, g_pal.card, g_pal.border);
    HFONT title_font = mfont(18, FW_SEMIBOLD);
    HFONT body_font = mfont(11, FW_NORMAL);
    HFONT old = (HFONT)SelectObject(hdc, title_font);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, g_pal.text);
    RECT title = {S(218), S(24), S(838), S(54)};
    DrawTextW(hdc, g_log_apps ? L"应用活动" : L"请求日志", -1, &title, DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(hdc, body_font);
    SetTextColor(hdc, g_pal.muted);
    RECT hint = {S(218), S(60), S(1002), S(82)};
    DrawTextW(hdc, g_log_apps ? L"仅显示服务器观测到的进程；连接、HTTP 请求与拦截响应分别计数。" :
        L"HTTP 响应服务器活动 · 搜索与筛选作用于本页，读取更早记录可继续查找。", -1, &hint,
        DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
    if (g_log_apps) {
        RECT app_scope = {S(218), S(90), S(1002), S(119)};
        DrawTextW(hdc, L"按请求数排列，列表可滚动；选中进程查看完整计数。", -1, &app_scope,
            DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
    }
    wchar_t count[240];
    if (g_log_apps) {
        swprintf(count, 240, L"已观测 %d 个进程；未知 PID 不推断为系统或当前应用。", sn ? sn->app_count : 0);
    } else if (!sn || (!sn->has_data && !sn->qlog_ready)) {
        swprintf(count, 240, L"统计不可用；请检查响应服务器是否正在运行。这里不会把未采集当作零拦截。");
    } else if (sn->qlog_error) {
        const wchar_t *status = sn->qlog_error == 2 ? L"历史已过期，请刷新" :
            sn->qlog_error == 3 ? L"正在读取历史" : L"历史读取失败，请刷新重试";
        swprintf(count, 240, L"%ls · 保留当前 %d 条显示记录。", status, g_log_shown);
        SetTextColor(hdc, sn->qlog_error == 3 ? g_pal.muted : C_RED);
    } else if (!sn->qlog_ready) {
        swprintf(count, 240, L"摘要 %d 条 · 完整历史尚未就绪；当前筛选匹配 %d 条。", sn->qlog_count, g_log_shown);
    } else if (!sn->qlog_count) {
        swprintf(count, 240, L"当前历史为空 · 只有实际到达本机响应服务器的请求会出现在这里。");
    } else {
        swprintf(count, 240, L"%ls · 本页第 %u–%u / %u 条 · 筛选匹配 %d 条%ls",
            g_log_nav.request.generation[0] ? L"历史已固定" : L"实时刷新",
            (unsigned)sn->qlog_page.offset + 1u, (unsigned)sn->qlog_page.offset + (unsigned)sn->qlog_count,
            (unsigned)sn->qlog_page.total, g_log_shown, !g_log_shown ? L"（可翻页继续查找）" : L"");
    }
    RECT count_rect = {S(218), S(430), S(1002), S(453)};
    DrawTextW(hdc, count, -1, &count_rect, DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
    SelectObject(hdc, old);
    DeleteObject(title_font);
    DeleteObject(body_font);
    draw_statusbar(hdc);
}

/*
 * The "a new version is available - download it now?" question is a modal
 * MessageBox, and this window normally sits in the tray (the app is started
 * with --minimized). The dialog then appeared behind everything and simply
 * waited: no download started, no log line was written, and from the user's
 * side "检查更新" looked broken. Bring the dashboard up first, raise the dialog
 * (MB_TOPMOST) and poke the tray so the question is noticed even when nobody is
 * looking at the window.
 */
/* ── 订阅管理 ────────────────────────────────────────────────────────────
 * The server only ever knew a flat domain file (<resources>/subscriptions.txt):
 * something had to fetch the subscription URLs, reduce them to that file and ask
 * the server to reload. On Android the app does that; on Windows nothing did -
 * which is exactly why "重新加载订阅" had nothing to load and there was no way to
 * add a source at all.
 *
 * This is the missing half, and it stays deliberately small: the URL list lives
 * in <resources>/subscription_urls.txt (one URL per line, '#' comments), the
 * fetcher reuses the updater's HTTP client (WinHTTP + proxy detection + resume +
 * retries), the parser accepts hosts ("0.0.0.0 domain"), bare domains and
 * AdGuard ("||domain^") lines, and the merged domains are written to the very
 * file the server already loads. Duplicates are left in: the server's block set
 * is a hash set and drops them itself.
 */
#define SUBS_MAX 32
#define SUBS_URL_MAX 1024
#define WM_APP_SUBS_DONE (WM_APP + 31)

static wchar_t s_sub_urls[SUBS_MAX][SUBS_URL_MAX];
static wchar_t s_sub_names[SUBS_MAX][SUBSCRIPTION_NAME_CAPACITY];
static wchar_t s_sub_status[SUBS_MAX][160];
static int s_sub_count;
static int s_sub_loaded;
static int s_sub_written;
static bool s_sub_written_known, s_sub_read_failed;
static volatile LONG s_subs_running;
static wchar_t s_sub_feedback[240];
static bool s_sub_feedback_error;
static bool s_sub_input_truncated;
static bool s_sub_name_truncated, s_sub_name_editing, s_sub_show_full;
static wchar_t s_sub_edit_url[SUBS_URL_MAX];
static int s_sub_remove_index = -1;
static wchar_t s_sub_remove_url[SUBS_URL_MAX];

static void subs_feedback(HWND hwnd, const wchar_t *text, bool error) {
    wcsncpy(s_sub_feedback, text, 239);
    s_sub_feedback[239] = 0;
    s_sub_feedback_error = error;
    swprintf(g_status, 4096, L"%ls", s_sub_feedback);
    InvalidateRect(hwnd, NULL, FALSE);
}

static void subs_path(wchar_t *out, size_t cap, const wchar_t *name) {
    swprintf(out, cap, L"%hs\\%ls", g_res, name);
}

/* Trim ASCII blanks in place and return the first non-blank character. */
static char *subs_trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' ||
                     s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = 0;
    return s;
}

static void subs_load(void) {
    if (s_sub_loaded) return;
    s_sub_loaded = 1;
    s_sub_count = 0;
    wchar_t path[MAX_PATH], directory[MAX_PATH];
    unsigned count = 0;
    s_sub_read_failed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, g_res, -1, directory, MAX_PATH) <= 0 ||
        !subscription_settings_load_sources(directory, s_sub_urls, s_sub_names, &count);
    if (s_sub_read_failed) {
        wcscpy(s_sub_feedback, L"来源配置读取失败或超出限制，原文件保留。请在订阅文件夹修复后重新打开程序；当前禁止覆盖配置。");
        s_sub_feedback_error = true;
        return;
    }
    s_sub_count = (int)count;
    /* Per-source status survives a restart: "<url>\t<status text>". */
    subs_path(path, MAX_PATH, L"subscription_status.txt");
    FILE *f = _wfopen(path, L"r");
    if (f != NULL) {
        char line[SUBS_URL_MAX * 4 + SUBSCRIPTION_STATUS_CAPACITY * 4 + 4];
        while (fgets(line, sizeof(line), f) != NULL) {
            char *tab = strchr(line, '\t');
            if (tab == NULL) continue;
            *tab++ = 0;
            char *url = subs_trim(line);
            char *st = subs_trim(tab);
            wchar_t wurl[SUBS_URL_MAX];
            if (MultiByteToWideChar(CP_UTF8, 0, url, -1, wurl, SUBS_URL_MAX) <= 0) continue;
            for (int i = 0; i < s_sub_count; i++) {
                if (wcscmp(s_sub_urls[i], wurl) == 0) {
                    MultiByteToWideChar(CP_UTF8, 0, st, -1, s_sub_status[i], 160);
                    break;
                }
            }
        }
        fclose(f);
    }
}

static int subs_save_urls(unsigned count) {
    wchar_t directory[MAX_PATH];
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, g_res, -1, directory, MAX_PATH) <= 0) return 0;
    if (s_sub_read_failed) return 0;
    return subscription_settings_save_sources(directory,
            (const wchar_t (*)[SUBSCRIPTION_URL_CAPACITY])s_sub_urls,
            (const wchar_t (*)[SUBSCRIPTION_NAME_CAPACITY])s_sub_names, count);
}

static int subs_save_status(void) {
    wchar_t directory[MAX_PATH];
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, g_res, -1, directory, MAX_PATH) <= 0) return 0;
    return subscription_settings_save_status(directory,
            (const wchar_t (*)[SUBSCRIPTION_URL_CAPACITY])s_sub_urls,
            (const wchar_t (*)[SUBSCRIPTION_STATUS_CAPACITY])s_sub_status, (unsigned)s_sub_count);
}

struct subs_job {
    HWND hwnd;
    unsigned count;
    wchar_t directory[MAX_PATH];
    wchar_t urls[SUBS_MAX][SUBS_URL_MAX];
    struct subscription_update_result result;
};
static int subs_download(const wchar_t *url, const wchar_t *file, unsigned long long max_bytes, unsigned budget_ms, void *context) {
    (void)context;
    return adblock_http_download_bounded(url, file, max_bytes, budget_ms);
}
static DWORD WINAPI subs_thread(LPVOID opaque) {
    struct subs_job *job = (struct subs_job *)opaque;
    job->result = subscription_update(job->directory, (const wchar_t (*)[SUBS_URL_MAX])job->urls,
                                     job->count, subs_download, NULL);
    if (!PostMessageW(job->hwnd, WM_APP_SUBS_DONE, 0, (LPARAM)job)) {
        InterlockedExchange(&s_subs_running, 0); free(job);
    }
    return 0;
}
static void subs_start_update(HWND hwnd) {
    if (s_subs_running || s_sub_read_failed || s_sub_remove_index >= 0) return;
    subs_load();
    if (s_sub_read_failed) return;
    if (!s_sub_count) {
        if (MessageBoxW(hwnd, L"没有配置订阅源。清空先前导入的订阅规则？手动配置不受影响。",
                        L"清空订阅规则", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES) return;
    }
    struct subs_job *job = (struct subs_job *)calloc(1, sizeof(*job));
    if (!job) { subs_feedback(hwnd, L"无法准备更新；原有规则未变，请稍后重试。", true); return; }
    job->hwnd = hwnd; job->count = (unsigned)s_sub_count;
    memcpy(job->urls, s_sub_urls, sizeof(job->urls));
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, g_res, -1, job->directory, MAX_PATH) <= 0) { free(job); return; }
    if (InterlockedCompareExchange(&s_subs_running, 1, 0) != 0) { free(job); return; }
    swprintf(g_status, 4096, L"正在验证 %d 个订阅源；全部成功后一次替换规则", s_sub_count);
    subs_feedback(hwnd, g_status, false);
    HANDLE thread = CreateThread(NULL, 0, subs_thread, job, 0, NULL);
    if (!thread) {
        InterlockedExchange(&s_subs_running, 0); free(job);
        subs_feedback(hwnd, L"未能启动更新；原有规则未变，请重试。", true);
        return;
    }
    CloseHandle(thread);
    subs_controls_refresh(hwnd);
}

static void subs_controls_refresh(HWND hwnd) {
    int busy = InterlockedCompareExchange(&s_subs_running, 0, 0) != 0 || s_sub_read_failed;
    bool pending = s_sub_remove_index >= 0;
    int selected = (int)SendDlgItemMessageW(hwnd, IDC_SUB_LIST, LB_GETCURSEL, 0, 0);
    EnableWindow(GetDlgItem(hwnd, IDC_SUB_URL), !busy && !pending);
    EnableWindow(GetDlgItem(hwnd, IDC_SUB_LIST), !busy && !pending);
    wchar_t input[SUBS_URL_MAX] = {0};
    GetDlgItemTextW(hwnd, IDC_SUB_URL, input, SUBS_URL_MAX);
    const wchar_t *text = input;
    while (*text == L' ' || *text == L'\t') text++;
    EnableWindow(GetDlgItem(hwnd, IDC_SUB_ADD), !busy && !pending && *text && !s_sub_input_truncated && s_sub_count < SUBS_MAX);
    EnableWindow(GetDlgItem(hwnd, IDC_SUB_DEL), !busy && !pending && selected >= 0 && selected < s_sub_count);
    EnableWindow(GetDlgItem(hwnd, IDC_SUB_UPD), !busy && !pending);
    ShowWindow(GetDlgItem(hwnd, IDC_SUB_CONFIRM), g_tab == 4 && pending ? SW_SHOW : SW_HIDE);
    ShowWindow(GetDlgItem(hwnd, IDC_SUB_CANCEL), g_tab == 4 && pending ? SW_SHOW : SW_HIDE);
    EnableWindow(GetDlgItem(hwnd, IDC_SUB_CONFIRM), pending && !busy);
    EnableWindow(GetDlgItem(hwnd, IDC_SUB_CANCEL), pending && !busy);
    SetDlgItemTextW(hwnd, IDC_SUB_UPD, busy ? L"正在验证并更新…" : (s_sub_count ? L"立即更新全部" : L"清空已导入规则"));
    const wchar_t *url = pending ? s_sub_remove_url :
        (selected >= 0 && selected < s_sub_count ? s_sub_urls[selected] : L"");
    wchar_t display[SUBS_URL_MAX];
    if (*url && !s_sub_show_full) subscription_display_url(url, display, SUBS_URL_MAX);
    else { wcsncpy(display, url, SUBS_URL_MAX - 1); display[SUBS_URL_MAX - 1] = 0; }
    SetDlgItemTextW(hwnd, IDC_SUB_SELECTED, display);
    SetDlgItemTextW(hwnd, IDC_SUB_FULL_URL, s_sub_show_full ? L"隐藏凭据与参数" : L"显示完整地址");
    EnableWindow(GetDlgItem(hwnd, IDC_SUB_FULL_URL), *url != 0);
    bool editable = !busy && !pending && selected >= 0 && selected < s_sub_count;
    EnableWindow(GetDlgItem(hwnd, IDC_SUB_NAME), editable);
    EnableWindow(GetDlgItem(hwnd, IDC_SUB_RENAME), editable && !s_sub_name_truncated);
    EnableWindow(GetDlgItem(hwnd, IDC_SUB_DEFAULT_NAME), editable && s_sub_names[selected][0]);
}

/* Status refreshes must not discard a draft while the selected URL is unchanged. */
static void subs_name_selection(HWND hwnd) {
    int selected = (int)SendDlgItemMessageW(hwnd, IDC_SUB_LIST, LB_GETCURSEL, 0, 0);
    const wchar_t *url = selected >= 0 && selected < s_sub_count ? s_sub_urls[selected] : L"";
    if (wcscmp(url, s_sub_edit_url)) {
        wcscpy(s_sub_edit_url, url);
        s_sub_name_editing = true;
        SetDlgItemTextW(hwnd, IDC_SUB_NAME, *url ? s_sub_names[selected] : L"");
        s_sub_name_editing = false;
        s_sub_name_truncated = false;
        s_sub_show_full = false;
    }
}

static void subs_list_extent(HWND hwnd) {
    HWND list = GetDlgItem(hwnd, IDC_SUB_LIST);
    if (!list) return;
    HDC dc = GetDC(list);
    if (!dc) return;
    HFONT font = (HFONT)SendMessageW(list, WM_GETFONT, 0, 0);
    HGDIOBJ previous = font ? SelectObject(dc, font) : NULL;
    int widest = 0;
    int count = (int)SendMessageW(list, LB_GETCOUNT, 0, 0);
    for (int i = 0; i < count; i++) {
        wchar_t row[1200];
        LRESULT length = SendMessageW(list, LB_GETTEXTLEN, (WPARAM)i, 0);
        if (length <= 0 || length >= 1200) continue;
        if (SendMessageW(list, LB_GETTEXT, (WPARAM)i, (LPARAM)row) == LB_ERR) continue;
        SIZE size;
        if (GetTextExtentPoint32W(dc, row, (int)length, &size) && size.cx > widest) widest = size.cx;
    }
    if (previous) SelectObject(dc, previous);
    ReleaseDC(list, dc);
    SendMessageW(list, LB_SETHORIZONTALEXTENT, (WPARAM)(widest + S(20)), 0);
}

static void subs_refresh_list(HWND hwnd) {
    HWND lb = GetDlgItem(hwnd, IDC_SUB_LIST);
    if (lb == NULL) return;
    int selected = (int)SendMessageW(lb, LB_GETCURSEL, 0, 0);
    SendMessageW(lb, LB_RESETCONTENT, 0, 0);
    for (int i = 0; i < s_sub_count; i++) {
        wchar_t row[1200], title[SUBSCRIPTION_NAME_CAPACITY * 2];
        subscription_display_name(s_sub_urls[i], s_sub_names[i], title, sizeof(title)/sizeof(title[0]));
        if (s_sub_status[i][0] != 0)
            swprintf(row, 1200, L"%ls    —    %ls", title, s_sub_status[i]);
        else
            swprintf(row, 1200, L"%ls    —    尚未更新", title);
        SendMessageW(lb, LB_ADDSTRING, 0, (LPARAM) row);
    }
    if (selected >= s_sub_count) selected = s_sub_count - 1;
    if (selected >= 0) SendMessageW(lb, LB_SETCURSEL, selected, 0);
    subs_list_extent(hwnd);
    subs_name_selection(hwnd);
    subs_controls_refresh(hwnd);
}

static void subs_rename(HWND hwnd, bool automatic) {
    int selected = (int)SendDlgItemMessageW(hwnd, IDC_SUB_LIST, LB_GETCURSEL, 0, 0);
    if (s_subs_running || s_sub_read_failed || s_sub_remove_index >= 0 || selected < 0 ||
        selected >= s_sub_count || wcscmp(s_sub_edit_url, s_sub_urls[selected])) return;
    wchar_t name[SUBSCRIPTION_NAME_CAPACITY] = L"", previous[SUBSCRIPTION_NAME_CAPACITY];
    if (!automatic) {
        if (s_sub_name_truncated || GetWindowTextLengthW(GetDlgItem(hwnd, IDC_SUB_NAME)) >= SUBSCRIPTION_NAME_CAPACITY) {
            subs_feedback(hwnd, L"名称超过 95 字符上限，未保存；请缩短后重新输入。", true); return;
        }
        GetDlgItemTextW(hwnd, IDC_SUB_NAME, name, SUBSCRIPTION_NAME_CAPACITY);
        if (!subscription_settings_name_valid(name)) {
            subs_feedback(hwnd, L"名称包含无效字符，未保存；请删除换行或控制字符。", true); return;
        }
    }
    wcscpy(previous, s_sub_names[selected]);
    wcscpy(s_sub_names[selected], name);
    if (!subs_save_urls((unsigned)s_sub_count)) {
        wcscpy(s_sub_names[selected], previous);
        subs_feedback(hwnd, L"名称保存失败，原名称与规则保留；输入已保留，可解除文件占用后重试。", true);
        return;
    }
    s_sub_name_editing = true;
    SetDlgItemTextW(hwnd, IDC_SUB_NAME, name);
    s_sub_name_editing = false;
    s_sub_name_truncated = false;
    subs_refresh_list(hwnd);
    subs_feedback(hwnd, *name ? L"本地名称已保存；下载地址与规则内容未变。" : L"已恢复自动名称；下载地址与规则内容未变。", false);
}

static void subs_cancel_remove(HWND hwnd) {
    if (s_sub_remove_index < 0) return;
    s_sub_remove_index = -1;
    s_sub_remove_url[0] = 0;
    subs_controls_refresh(hwnd);
    subs_feedback(hwnd, L"已取消移除；来源和已导入规则未变。", false);
}

static void subs_confirm_remove(HWND hwnd) {
    int sel = s_sub_remove_index;
    if (s_subs_running || sel < 0) return;
    if (sel >= s_sub_count || wcscmp(s_sub_urls[sel], s_sub_remove_url) != 0) {
        subs_cancel_remove(hwnd);
        subs_feedback(hwnd, L"待移除来源已变化，未执行删除；请重新选择。", true);
        return;
    }
    wchar_t removed_url[SUBS_URL_MAX], removed_status[SUBSCRIPTION_STATUS_CAPACITY], removed_name[SUBSCRIPTION_NAME_CAPACITY];
    memcpy(removed_url, s_sub_urls[sel], sizeof(removed_url));
    memcpy(removed_status, s_sub_status[sel], sizeof(removed_status));
    memcpy(removed_name, s_sub_names[sel], sizeof(removed_name));
    for (int i = sel; i + 1 < s_sub_count; i++) {
        memcpy(s_sub_urls[i], s_sub_urls[i + 1], sizeof(s_sub_urls[i]));
        memcpy(s_sub_status[i], s_sub_status[i + 1], sizeof(s_sub_status[i]));
        memcpy(s_sub_names[i], s_sub_names[i + 1], sizeof(s_sub_names[i]));
    }
    s_sub_count--;
    if (subs_save_urls((unsigned)s_sub_count)) {
        int status_saved = subs_save_status();
        s_sub_remove_index = -1;
        s_sub_remove_url[0] = 0;
        subs_refresh_list(hwnd);
        wchar_t saved[220];
        swprintf(saved, 220, status_saved ?
                 L"已移除来源，剩 %d 个；当前规则保留，请更新或清空已导入规则" :
                 L"已移除来源，剩 %d 个；状态缓存保存失败，当前规则保留，请更新规则", s_sub_count);
        subs_feedback(hwnd, saved, !status_saved);
    } else {
        for (int i = s_sub_count; i > sel; i--) {
            memcpy(s_sub_urls[i], s_sub_urls[i - 1], sizeof(s_sub_urls[i]));
            memcpy(s_sub_status[i], s_sub_status[i - 1], sizeof(s_sub_status[i]));
            memcpy(s_sub_names[i], s_sub_names[i - 1], sizeof(s_sub_names[i]));
        }
        memcpy(s_sub_urls[sel], removed_url, sizeof(removed_url));
        memcpy(s_sub_status[sel], removed_status, sizeof(removed_status));
        memcpy(s_sub_names[sel], removed_name, sizeof(removed_name));
        s_sub_count++;
        subs_controls_refresh(hwnd);
        subs_feedback(hwnd, L"来源保存失败，移除未生效；原来源与规则均保留。解除文件占用后可重试“确认移除”，或取消。", true);
    }
}


static void draw_subs_page(HDC hdc) {
    HFONT hf = mfont(15, FW_SEMIBOLD);
    HFONT lf = mfont(12, FW_NORMAL);
    HFONT old;
    SetBkMode(hdc, TRANSPARENT);
    rounded_card(hdc, 202, 12, 812, 620, 12, g_pal.card, g_pal.border);
    old = (HFONT) SelectObject(hdc, hf);
    SetTextColor(hdc, g_pal.text);
    TextOutW(hdc, S(218), S(20), L"订阅源", 3);
    SelectObject(hdc, lf);
    SetTextColor(hdc, g_pal.muted);
    const wchar_t *address_label = L"订阅地址（默认隐藏凭据与参数）";
    const wchar_t *name_label = L"本地名称 · 留空使用自动名称";
    TextOutW(hdc, S(218), S(348), address_label, (int)wcslen(address_label));
    TextOutW(hdc, S(218), S(403), name_label, (int)wcslen(name_label));
    {
        static const wchar_t *H1 =
            L"粘贴订阅链接后点「添加」（hosts / 纯域名 / ||域名^ 三种格式都能解析），再点「立即更新全部」";
        RECT intro_rect = {S(218), S(43), S(994), S(66)};
        DrawTextW(hdc, H1, -1, &intro_rect,
                  DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    }
    {
        wchar_t sum[400];
        if (s_sub_read_failed)
            swprintf(sum, 400, L"配置读取失败 · 已保护原文件，修复后请重新打开程序");
        else if (s_sub_count == 0)
            swprintf(sum, 400, L"尚未配置来源 · 可添加订阅，或清空先前导入的订阅规则。");
        else if (s_subs_running)
            swprintf(sum, 400, L"正在验证 %d 个来源 · 完成前继续使用上一份有效规则", s_sub_count);
        else if (s_sub_written_known)
            swprintf(sum, 400,
                     L"%d 个订阅源 · 本次会话最近保存 %d 条规则",
                     s_sub_count, s_sub_written);
        else swprintf(sum, 400, L"%d 个订阅源 · 本次会话尚未更新；已有规则继续保留", s_sub_count);
        SetTextColor(hdc, g_pal.text);
        RECT summary_rect = {S(218), S(532), S(992), S(554)};
        DrawTextW(hdc, sum, -1, &summary_rect,
                  DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    }
    {
        static const wchar_t *H2 =
            L"添加或移除来源后需更新全部；下载或校验失败时保留上一次完整规则。";
        SetTextColor(hdc, g_pal.muted);
        RECT file_hint_rect = {S(218), S(558), S(992), S(583)};
        DrawTextW(hdc, H2, -1, &file_hint_rect,
                  DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    }
    {
        const wchar_t *feedback = s_sub_feedback[0] ? s_sub_feedback :
            L"选中来源可改本地名称。地址默认隐藏凭据与参数；点“显示完整地址”后可复制。";
        SetTextColor(hdc, s_sub_feedback_error ? C_RED : g_pal.muted);
        RECT feedback_rect = {S(218), S(590), S(992), S(626)};
        DrawTextW(hdc, feedback, -1, &feedback_rect, DT_WORDBREAK | DT_NOPREFIX);
    }
    SelectObject(hdc, old);
    DeleteObject(hf);
    DeleteObject(lf);
}

static void update_prompt_notify(HWND hwnd) {
    if (!g_ui_visible) {
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);
    }
    SetForegroundWindow(hwnd);
    if (g_tray_ok) {
        g_nid.uFlags |= NIF_INFO;
        g_nid.dwInfoFlags = NIIF_INFO;
        wcsncpy(g_nid.szInfoTitle, L"ADBlock 发现新版本", 63);
        g_nid.szInfoTitle[63] = 0;
        wcsncpy(g_nid.szInfo, L"请在弹窗中确认是否下载并更新。", 255);
        g_nid.szInfo[255] = 0;
        Shell_NotifyIconW(NIM_MODIFY, &g_nid);
        g_nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    }
}

/* Registered accelerators also work when focus is inside a child control. */
#define UI_ACCEL_NAV_FIRST 47000
#define UI_ACCEL_NAV_NEXT  47006
#define UI_ACCEL_NAV_PREV  47007

static void ui_navigate_to(HWND hwnd, int next_tab) {
    if (next_tab < 0 || next_tab >= 6 || next_tab == g_tab) return;
    if (s_sub_remove_index >= 0) subs_cancel_remove(hwnd);
    s_sub_show_full = false;
    g_tab = next_tab;
    show_controls(hwnd, g_tab);
    if (g_tab == 4) {
        subs_load();
        subs_refresh_list(hwnd);
    }
    InvalidateRect(hwnd, NULL, TRUE);
}

static LRESULT CALLBACK gui_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (g_taskbar_created != 0 && msg == g_taskbar_created) {
        tray_add(hwnd);
        return 0;
    }
    if (g_show_dashboard_msg == 0) {
        g_show_dashboard_msg = RegisterWindowMessageW(L"ADBlockShowDashboard");
    }
    if (g_show_dashboard_msg != 0 && msg == g_show_dashboard_msg) {
        ShowWindow(hwnd, SW_SHOW);
        ShowWindow(hwnd, SW_RESTORE);
        SetForegroundWindow(hwnd);
        return 0;
    }
    switch (msg) {
    case WM_DPICHANGED:
        g_scale = HIWORD(wp) / 96.0;
        {
            const RECT *r = (const RECT *)lp;
            SetWindowPos(hwnd, NULL, r->left, r->top,
                         r->right - r->left, r->bottom - r->top,
                         SWP_NOZORDER | SWP_NOACTIVATE);
        }
        layout_controls(hwnd);
        InvalidateRect(hwnd, NULL, TRUE);
        return 0;
    case WM_CREATE: {
        const struct adblock_gui_args *args =
            (const struct adblock_gui_args *)((CREATESTRUCTW *)lp)->lpCreateParams;
        snprintf(g_res, sizeof(g_res), "%s", args->resource_dir);
        g_http_port = args->http_port;
        g_https_port = args->https_port;
        g_bind_all = args->bind_all;
        snprintf(g_bind_ip, sizeof(g_bind_ip), "%s", args->bind_ip ? args->bind_ip : "");
        snprintf(g_legacy_bind_ip,sizeof(g_legacy_bind_ip),"%s",g_bind_ip);
        g_explicit_pair=args->explicit_pair;
        if (args->explicit_pair) snprintf(g_bind_ipv6,sizeof(g_bind_ipv6),"%s",args->bind_ipv6 ? args->bind_ipv6 : "");
        else if (*g_bind_ip && strchr(g_bind_ip,':')) { snprintf(g_bind_ipv6,sizeof(g_bind_ipv6),"%s",g_bind_ip); *g_bind_ip=0; }
        else if (!*g_bind_ip) { snprintf(g_bind_ip,sizeof(g_bind_ip),"%s",g_bind_all ? "0.0.0.0" : "127.0.0.1"); snprintf(g_bind_ipv6,sizeof(g_bind_ipv6),"%s",g_bind_all ? "::" : "::1"); }
        g_auto_create=args->auto_create;
        snprintf(g_active_arrival.ip,sizeof(g_active_arrival.ip),"%s",g_bind_ip);
        snprintf(g_active_arrival.ipv6,sizeof(g_active_arrival.ipv6),"%s",g_bind_ipv6);
        g_active_arrival.pair=true; g_active_arrival.http=g_http_port; g_active_arrival.https=g_https_port;
        g_active_arrival.stats=args->stats_port;
        g_start_minimized = args->start_minimized;
        g_stats_port = args->stats_port > 0 ? args->stats_port : 8686;
        g_owns_server = args->owns_server;
        if (!refresh_owned_autostart()) win32_log_line("Unable to migrate this installation's autostart listener settings");
        g_tab = 0;
        g_scale = GetDpiForWindow(hwnd) / 96.0;
        g_theme_pref = ini_read_theme();
        g_dark = (g_theme_pref == THEME_SYSTEM) ? system_prefers_dark()
                                                : (g_theme_pref == 1);
        theme_apply(g_dark);
        apply_window_chrome(hwnd, g_dark);
        g_sn = (struct snapshot *)calloc(1, sizeof(struct snapshot));
        if (args->startup_warning != NULL && args->startup_warning[0] != '\0')
            swprintf(g_status, 4096, L"%hs", args->startup_warning);
        HINSTANCE hinst = GetModuleHandleW(NULL);
        HICON app_icon = (HICON)LoadImageW(hinst, MAKEINTRESOURCEW(1), IMAGE_ICON,
                                           0, 0, LR_DEFAULTSIZE | LR_SHARED);
        if (app_icon == NULL) app_icon = LoadIconW(NULL, IDI_APPLICATION);
        SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)app_icon);
        SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)app_icon);
        for (int i = 0; i < CL_MAIN; i++) {
            const struct ctl_desc *d = &g_clayout[i];
            HWND w = CreateWindowExW(0, d->cls, d->text,
                WS_CHILD | WS_TABSTOP | d->style, S(d->x), S(d->y), S(d->w), S(d->h),
                hwnd, (HMENU)(INT_PTR)d->id, hinst, NULL);
            s_ctrls[s_ctrl_count++] = w;
        }
        for (int i = 0; i < CL_SUB; i++) {
            const struct ctl_desc *d = &g_sublayout[i];
            HWND w = CreateWindowExW(0, d->cls, d->text,
                WS_CHILD | WS_TABSTOP | d->style, S(d->x), S(d->y), S(d->w), S(d->h),
                hwnd, (HMENU)(INT_PTR)d->id, hinst, NULL);
            s_ctrls[s_ctrl_count++] = w;
        }
        for (int i = 0; i < CL_LOG; i++) {
            const struct ctl_desc *d = &g_loglayout[i];
            HWND w = CreateWindowExW(0, d->cls, d->text,
                WS_CHILD | WS_TABSTOP | d->style, S(d->x), S(d->y), S(d->w), S(d->h),
                hwnd, (HMENU)(INT_PTR)d->id, hinst, NULL);
            s_ctrls[s_ctrl_count++] = w;
        }
        SendDlgItemMessageW(hwnd, IDC_QLOG_SEARCH, EM_SETLIMITTEXT, 191, 0);
        g_log_list_original = (WNDPROC)SetWindowLongPtrW(GetDlgItem(hwnd, IDC_QLOG_LIST),
            GWLP_WNDPROC, (LONG_PTR)log_list_proc);
        SendDlgItemMessageW(hwnd, IDC_QLOG_SEARCH, EM_SETCUEBANNER, TRUE, (LPARAM)L"搜索本页域名（忽略大小写）");
        const wchar_t *log_filters[] = {L"全部结果", L"拦截响应", L"本地豁免", L"转发已启动",
            L"连接：IPv4", L"连接：IPv6", L"连接：未知", L"分类：图片", L"分类：脚本", L"分类：样式表",
            L"分类：字体", L"分类：媒体", L"分类：页面结构", L"分类：API", L"分类：遥测", L"分类：配置",
            L"分类：WebSocket", L"分类：未知"};
        for (size_t i = 0; i < sizeof(log_filters) / sizeof(log_filters[0]); ++i)
            SendDlgItemMessageW(hwnd, IDC_QLOG_FILTER, CB_ADDSTRING, 0, (LPARAM)log_filters[i]);
        SendDlgItemMessageW(hwnd, IDC_QLOG_FILTER, CB_SETCURSEL, 0, 0);
        s_ctrls[s_ctrl_count++] = CreateWindowExW(0,L"BUTTON",L"测试双栈转发与恢复",WS_CHILD|WS_TABSTOP|BS_PUSHBUTTON,
                0,0,1,1,hwnd,(HMENU)(INT_PTR)IDC_TRANSPORT_PROBE,hinst,NULL);
        for (int i = 0; i < POLICY_COUNT; i++) {
            int cx = (i % 2 == 0) ? 218 : 610;
            int cy = 290 + (i / 2) * 28;
            s_ctrls[s_ctrl_count++] = CreateWindowExW(0, L"BUTTON", g_policy[i].label,
                /* A plain button whose caption IS the current method
                   ("图片：占位响应"); clicking cycles 占位 → 空响应 → 204 →
                   不拦截. The old BS_AUTO3STATE checkbox could not express
                   four methods and its three states were unreadable. */
                WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON, S(cx), S(cy), S(370), S(26), hwnd,
                (HMENU)(INT_PTR)g_policy[i].id, hinst, NULL);
        }
        layout_controls(hwnd);
        SetDlgItemTextW(hwnd, IDC_PREVIEWUPD, update_include_preview() ? L"渠道：含预览版" : L"渠道：稳定版");
        SetDlgItemTextW(hwnd, IDC_PORTABLEUPD, update_portable_mode() ? L"包：ZIP 覆盖" : L"包：安装器优先");
        SetDlgItemTextW(hwnd, IDC_AUTOUPD, update_automatic() ? L"自动更新：开启" : L"自动更新：关闭");
        SetDlgItemTextA(hwnd, IDC_BIND_IP, g_bind_ip);
        SetDlgItemTextA(hwnd, IDC_BIND_IPV6, g_bind_ipv6);
        SendDlgItemMessageW(hwnd,IDC_AUTO_CREATE,BM_SETCHECK,g_auto_create ? BST_CHECKED : BST_UNCHECKED,0);
        SendDlgItemMessageW(hwnd,IDC_BIND_IPV6,EM_SETLIMITTEXT,45,0);
        SendDlgItemMessageW(hwnd,IDC_BIND_IPV6,EM_SETCUEBANNER,TRUE,(LPARAM)L"::1，留空关闭 IPv6");
        SendDlgItemMessageW(hwnd, IDC_BIND_IP, EM_SETLIMITTEXT, 45, 0);
        SendDlgItemMessageW(hwnd, IDC_BIND_IP, EM_SETCUEBANNER, TRUE, (LPARAM)L"127.0.0.1，留空关闭 IPv4");
        SendMessageW(GetDlgItem(hwnd, IDC_SUB_URL), EM_SETCUEBANNER, TRUE,
                     (LPARAM)L"https://example.com/hosts.txt");
        SendMessageW(GetDlgItem(hwnd, IDC_SUB_URL), EM_SETLIMITTEXT, SUBS_URL_MAX - 1, 0);
        SendDlgItemMessageW(hwnd, IDC_SUB_NAME, EM_SETLIMITTEXT, SUBSCRIPTION_NAME_CAPACITY - 1, 0);
        SendDlgItemMessageW(hwnd, IDC_SUB_NAME, EM_SETCUEBANNER, TRUE, (LPARAM)L"留空使用自动名称");
        SendMessageW(GetDlgItem(hwnd, IDC_SUB_SELECTED), EM_SETCUEBANNER, TRUE,
                     (LPARAM)L"选中来源查看地址；默认隐藏凭据与参数");
        SendMessageW(GetDlgItem(hwnd, IDM_DARK), BM_SETCHECK,
                     g_dark ? BST_CHECKED : BST_UNCHECKED, 0);
        apply_control_theme(hwnd);
        wchar_t tmp[32];
        swprintf(tmp, 32, L"%d", g_http_port);
        SetWindowTextW(GetDlgItem(hwnd, IDC_HTTP_EDIT), tmp);
        swprintf(tmp, 32, L"%d", g_https_port);
        SetWindowTextW(GetDlgItem(hwnd, IDC_HTTPS_EDIT), tmp);
        SendMessageW(GetDlgItem(hwnd, IDC_BIND_CHK), BM_SETCHECK,
                     g_bind_all ? BST_CHECKED : BST_UNCHECKED, 0);
        SendMessageW(GetDlgItem(hwnd, IDM_AUTOSTART), BM_SETCHECK,
                     win32_autostart_installed() ? BST_CHECKED : BST_UNCHECKED, 0);
        g_listener_ready = true;
        SetTimer(hwnd, 3, 600, NULL);
        bool pol[POLICY_COUNT];
        policy_read(g_res, pol);
        for (int i = 0; i < POLICY_COUNT; i++)
            SendMessageW(GetDlgItem(hwnd, IDC_POL0 + i), BM_SETCHECK,
                         pol[i] ? BST_CHECKED : BST_UNCHECKED, 0);
        show_controls(hwnd, 0);
        g_taskbar_created = RegisterWindowMessageW(L"TaskbarCreated");
        tray_add(hwnd);
        cert_refresh(true);
        qln_refresh(&g_log_nav);
        g_poll_wake = CreateEventW(NULL, FALSE, FALSE, NULL);
        if (pthread_create(&g_poll_thread, NULL, stats_poll_thread, hwnd) == 0)
            g_poll_started = 1;
        else swprintf(g_status, 4096, L"无法启动后台统计读取，请重启应用；当前统计不可用");
        SetTimer(hwnd, 1, 2000, NULL);
        /* Avoid startup contention, then check the selected channel every six
           hours. Background checks share the updater's single busy gate. */
        SetTimer(hwnd, 4, 60000, NULL);
        g_adguard_signal = adguard_process_probe();
        g_adguard_probe_tick = GetTickCount();
        /* Probe DLL APIs only, never create an adapter or route. */
        g_wintun_probe = wintun_probe_local();
        return 0;
    }
    case WM_TIMER: {
        if (wp == 4) {
            SetTimer(hwnd, 4, 6u * 60u * 60u * 1000u, NULL);
            if (update_automatic() && update_state() == 0) update_check_background_async(hwnd);
            return 0;
        }
        if (wp == 3) { KillTimer(hwnd, 3); listener_validate(hwnd, false); return 0; }
        DWORD probe_now = GetTickCount();
        if (probe_now - g_adguard_probe_tick >= 30000) {
            g_adguard_signal = adguard_process_probe();
            g_adguard_probe_tick = probe_now;
        }
        bool vis = IsWindowVisible(hwnd) != 0;
        g_ui_visible = vis ? 1 : 0;
        /* Keep the update button in sync with the updater pipeline. */
        update_button_refresh(hwnd);
        if (!vis && !g_hidden_trimmed) {
            /* Only the tray icon is left: hand the pages back to Windows so a
             * background process does not sit on tens of MB. */
            SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
            g_hidden_trimmed = 1;
        } else if (vis) {
            g_hidden_trimmed = 0;
        }

        cert_refresh(false);
        diag_sample();
        /* Heartbeat every 5 minutes: after a sudden death the tail of
         * webserver.log then shows the last known CPU/memory/handle trend. */
        if (++g_hb_ticks >= 150) {
            g_hb_ticks = 0;
            win32_log_line("hb cpu=%.1f%% mem=%lluMB handles=%lu threads=%lu gdi=%lu "
                           "visible=%d server=%d valid=%d bind_ok=%d listeners=%d uptime=%llds",
                           g_cpu_pct, g_ws_kb / 1024ULL, (unsigned long)g_handle_count,
                           (unsigned long)g_thread_count, (unsigned long)g_gdi_obj,
                           (int)g_ui_visible, win32_server_alive() ? 1 : 0,
                           (g_sn && g_sn->valid) ? 1 : 0, (g_sn && g_sn->bind_ok) ? 1 : 0,
                           g_sn ? g_sn->listener_count : 0,
                           g_sn ? (long long)g_sn->uptime_seconds : 0LL);
        }
        if (!g_tray_ok) tray_add(hwnd);   /* taskbar missing at logon -> retry */
        if (vis) InvalidateRect(hwnd, NULL, FALSE);   /* never paint while hidden */
        return 0;
    }
    case WM_MOUSEWHEEL:
        if (g_tab == 1) {
            if (!g_log_apps) log_freeze_current(hwnd);
            SendDlgItemMessageW(hwnd, IDC_QLOG_LIST, WM_VSCROLL,
                GET_WHEEL_DELTA_WPARAM(wp) > 0 ? SB_LINEUP : SB_LINEDOWN, 0);
            return 0;
        }
        return DefWindowProcW(hwnd, msg, wp, lp);
    case WM_APP_STATS:
        if (g_sn) {
            pthread_mutex_lock(&g_snap_mutex);
            *g_sn = g_snap_next;
            pthread_mutex_unlock(&g_snap_mutex);
            cert_refresh(false);
            log_controls_refresh(hwnd);
            if (g_ui_visible) InvalidateRect(hwnd, NULL, FALSE);
        }
        return 0;
    case WM_LBUTTONUP: {
        int x = (short)LOWORD(lp), y = (short)HIWORD(lp);
        int new_tab = -1;
        for (int tab = 0; tab < 6; ++tab) {
            if (nav_hit(x, y, tab)) { new_tab = tab; break; }
        }
        if (new_tab >= 0) {
            ui_navigate_to(hwnd, new_tab);
        } else if (x >= S(16) && x <= S(176) && y >= S(576) && y <= S(616)) {
            PostMessageW(hwnd, WM_APP_EXIT, 0, 0);
        }
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_QLOG_SEARCH && HIWORD(wp) == EN_CHANGE) {
            GetDlgItemTextW(hwnd, IDC_QLOG_SEARCH, g_log_search, 192);
            log_freeze_current(hwnd);
            log_list_refresh(hwnd, true);
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }
        if (LOWORD(wp) == IDC_QLOG_FILTER && HIWORD(wp) == CBN_SELCHANGE) {
            int choice = (int)SendDlgItemMessageW(hwnd, IDC_QLOG_FILTER, CB_GETCURSEL, 0, 0);
            g_log_filter = qlf_filter_for_choice(choice);
            log_freeze_current(hwnd);
            log_list_refresh(hwnd, true);
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }
        if (LOWORD(wp) == IDC_QLOG_LIST && HIWORD(wp) == LBN_SELCHANGE && !g_log_rendering) {
            if (!g_log_apps) log_freeze_current(hwnd);
            log_details_refresh(hwnd);
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }
        if (LOWORD(wp) == IDC_QLOG_APPS) {
            SendDlgItemMessageW(hwnd, IDC_QLOG_LIST, LB_SETCURSEL, (WPARAM)-1, 0);
            g_log_apps = !g_log_apps;
            log_controls_refresh(hwnd);
            log_details_refresh(hwnd);
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }
        if (LOWORD(wp) == IDC_QLOG_LIVE) {
            if (g_log_nav.request.generation[0]) log_navigation(hwnd, IDC_QLOG_REFRESH);
            else log_freeze_current(hwnd);
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }
        if (LOWORD(wp) == IDC_QLOG_PREVIOUS || LOWORD(wp) == IDC_QLOG_NEXT || LOWORD(wp) == IDC_QLOG_REFRESH) {
            log_navigation(hwnd, LOWORD(wp)); return 0;
        }
        if (LOWORD(wp)==IDC_TRANSPORT_PROBE) { gui_show_transport_dialog(hwnd); return 0; }
        if (HIWORD(wp) == 1) { /* keyboard accelerator */
            int id = LOWORD(wp);
            if (id >= UI_ACCEL_NAV_FIRST && id < UI_ACCEL_NAV_FIRST + 6) {
                ui_navigate_to(hwnd, id - UI_ACCEL_NAV_FIRST);
                return 0;
            }
            if (id == UI_ACCEL_NAV_NEXT || id == UI_ACCEL_NAV_PREV) {
                ui_navigate_to(hwnd, (g_tab + 6 +
                    (id == UI_ACCEL_NAV_NEXT ? 1 : -1)) % 6);
                return 0;
            }
        }
        if (LOWORD(wp) == IDC_SUB_LIST && HIWORD(wp) == LBN_SELCHANGE) {
            s_sub_show_full = false;
            subs_name_selection(hwnd);
            subs_controls_refresh(hwnd);
            return 0;
        }
        if (LOWORD(wp) == IDC_SUB_NAME && HIWORD(wp) == EN_MAXTEXT) {
            s_sub_name_truncated = true;
            subs_feedback(hwnd, L"名称超过 95 字符上限；请缩短后重新输入。", true);
            subs_controls_refresh(hwnd);
            return 0;
        }
        if (LOWORD(wp) == IDC_SUB_NAME && HIWORD(wp) == EN_CHANGE && !s_sub_name_editing) {
            if (GetWindowTextLengthW(GetDlgItem(hwnd, IDC_SUB_NAME)) < SUBSCRIPTION_NAME_CAPACITY - 1)
                s_sub_name_truncated = false;
            subs_controls_refresh(hwnd);
            return 0;
        }
        if (LOWORD(wp) == IDC_SUB_URL && HIWORD(wp) == EN_MAXTEXT) {
            s_sub_input_truncated = true;
            subs_feedback(hwnd, L"链接超过 1023 字符上限，未保存；请缩短后重新输入，避免使用被截断的地址。", true);
            subs_controls_refresh(hwnd);
            return 0;
        }
        if (LOWORD(wp) == IDC_SUB_URL && HIWORD(wp) == EN_CHANGE) {
            if (GetWindowTextLengthW(GetDlgItem(hwnd, IDC_SUB_URL)) < SUBS_URL_MAX - 1)
                s_sub_input_truncated = false;
            if (!s_sub_input_truncated && s_sub_remove_index < 0) { s_sub_feedback[0] = 0; s_sub_feedback_error = false; }
            subs_controls_refresh(hwnd);
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }
        if (HIWORD(wp) == EN_CHANGE &&
            (LOWORD(wp) == IDC_BIND_IP || LOWORD(wp) == IDC_BIND_IPV6 || LOWORD(wp) == IDC_HTTP_EDIT || LOWORD(wp) == IDC_HTTPS_EDIT)) {
            if (g_listener_ready) SetTimer(hwnd, 3, 600, NULL);
            return 0;
        }
        if (HIWORD(wp) == BN_CLICKED) {
            int id = LOWORD(wp);
            if (id == IDM_TRUST || id == IDM_UNTRUST) {
                char cert_path[1024];
                snprintf(cert_path, sizeof(cert_path), "%s/localhost-2410.crt", g_res);
                int rc = cert_trust_set(cert_path, id == IDM_TRUST);
                wchar_t msg[512], state_txt[64];
                cert_trust_text(cert_trust_state(cert_path), state_txt, 64);
                if (rc == 0 && id == IDM_TRUST)
                    swprintf(msg, 512,
                             L"CA 证书%ls。\n\n"
                             L"Chrome/Edge/系统组件会立即信任它；Firefox 用自己的信任库，需要在"
                             L"Firefox 的“证书管理器 → 授权机构”里单独导入同一个 .crt 文件。\n\n"
                             L"%ls",
                             state_txt,
                             (cert_trust_state(cert_path) & CERT_TRUST_MACHINE)
                                 ? L"已同时写入“本机根”，其它账户与系统服务也信任它。"
                                 : L"注意：目前只有“用户根”。以其它账户或系统服务身份运行的程序"
                                   L"仍会报警——用管理员身份运行本程序再点一次“信任 CA”，"
                                   L"即可同时写入“本机根”。");
                else if (rc == 0)
                    swprintf(msg, 512, L"CA 证书已移出信任根（%ls）。", state_txt);
                else
                    swprintf(msg, 512,
                             L"证书操作失败（当前状态：%ls）。\n\n"
                             L"若 CA 也存在于“本机根”，请以管理员身份运行后再移除；"
                             L"详细错误已写入 webserver.log。",
                             state_txt);
                cert_refresh(true);   /* trust state changed - drop the cache */
                MessageBoxW(hwnd, msg, L"证书", MB_OK | MB_ICONINFORMATION);
                InvalidateRect(hwnd, NULL, FALSE);
            } else if (id == IDC_SUBRELOAD) {
            wchar_t st[128];
            bool reloaded=control_post(mgmt_port(), "reload_subscriptions", st, 128);
            swprintf(g_status, 4096, L"本地订阅重载%ls：%ls", reloaded ? L"已确认" : L"未确认", st);
            InvalidateRect(hwnd, NULL, FALSE);
        } else if (id == IDC_CAROTATE) {
            wchar_t st[256];
            bool rotated=control_post(mgmt_port(), "rotate_ca", st, 256);
            swprintf(g_status, 4096, rotated ? L"新 CA 已生成，旧 CA 保留 90 天；请在每台设备上信任新 CA。%ls" : L"未确认生成新 CA：%ls", st);
            cert_refresh(true);
            InvalidateRect(hwnd, NULL, FALSE);
        } else if (id == IDC_CADROP) {
            wchar_t st[256];
            control_post(mgmt_port(), "drop_old_ca", st, 256);
            swprintf(g_status, 4096, L"CA 轮换：%ls；成功后请信任当前 CA 并重启服务。", st);
            cert_refresh(true);
            InvalidateRect(hwnd, NULL, FALSE);
        } else if (id == IDC_CHECK_LISTEN) {
            listener_validate(hwnd, true);
        } else if (id==IDC_CREATE_ADDRESS || id==IDC_REMOVE_ADDRESS || id==IDC_CREATE_IPV6 || id==IDC_REMOVE_IPV6) {
            address_action(hwnd,id==IDC_REMOVE_ADDRESS || id==IDC_REMOVE_IPV6,id==IDC_CREATE_IPV6 || id==IDC_REMOVE_IPV6);
        } else if (id==IDC_LOOP_PAIR || id==IDC_BIND_CHK) {
            SetDlgItemTextA(hwnd,IDC_BIND_IP,id==IDC_LOOP_PAIR ? "127.0.0.1" : "0.0.0.0");
            SetDlgItemTextA(hwnd,IDC_BIND_IPV6,id==IDC_LOOP_PAIR ? "::1" : "::");
            if (g_listener_ready) SetTimer(hwnd,3,100,NULL);
        } else if (id == IDC_AUTO_CREATE) {
            if (g_listener_ready) SetTimer(hwnd, 3, 600, NULL);
        } else if (id == IDC_PREVIEWUPD) {
            int enabled = !update_include_preview();
            if (update_set_include_preview(enabled)) {
                SetDlgItemTextW(hwnd, IDC_PREVIEWUPD, enabled ? L"渠道：含预览版" : L"渠道：稳定版");
                swprintf(g_status, 4096, enabled
                    ? L"已允许预览版更新。点击“检查更新”获取较新的覆盖安装预览包；自动更新开启时会直接下载、校验、覆盖安装并重启。"
                    : L"已切回稳定版渠道；不会降级当前预览版。点击“检查更新”刷新。");
            } else swprintf(g_status, 4096, L"渠道未保存：请等待更新结束，或检查配置写入权限。");
            InvalidateRect(hwnd, NULL, FALSE);
        } else if (id == IDC_AUTOUPD) {
            int automatic = !update_automatic();
            if (update_set_automatic(automatic)) {
                if (automatic) SetTimer(hwnd, 4, 60000, NULL);
                SetDlgItemTextW(hwnd, IDC_AUTOUPD, automatic ? L"自动更新：开启" : L"自动更新：关闭");
                swprintf(g_status, 4096, automatic ?
                    L"自动更新已开启：发现所选渠道的新版本后下载、校验、覆盖安装并重启；管理员授权仍由系统显示。" :
                    L"自动更新已关闭：发现新版本后先询问，再下载和安装。");
            } else swprintf(g_status, 4096, L"自动更新设置未保存：请等待更新结束，或检查配置写入权限。");
            InvalidateRect(hwnd, NULL, FALSE);
        } else if (id == IDC_PORTABLEUPD) {
            int portable = !update_portable_mode();
            if (update_set_portable_mode(portable)) {
                SetDlgItemTextW(hwnd, IDC_PORTABLEUPD, portable ? L"包：ZIP 覆盖" : L"包：安装器优先");
                swprintf(g_status, 4096, portable
                    ? L"已保存：下次更新直接下载 ZIP 并覆盖当前程序；版本、摘要校验和回滚仍然启用。点“检查更新”开始。再次点击可恢复自动。"
                    : L"已保存：优先使用安装器，无法启动时回退 ZIP。点“检查更新”开始。");
            } else swprintf(g_status, 4096, L"更新方式未保存：请等待正在进行的更新结束，或检查配置文件写入权限。");
            InvalidateRect(hwnd, NULL, FALSE);
        } else if (id == IDC_SUB_RENAME || id == IDC_SUB_DEFAULT_NAME) {
                subs_rename(hwnd, id == IDC_SUB_DEFAULT_NAME);
        } else if (id == IDC_SUB_FULL_URL) {
                s_sub_show_full = !s_sub_show_full;
                subs_controls_refresh(hwnd);
        } else if (id == IDC_SUB_ADD) {
                if (s_subs_running || s_sub_read_failed || s_sub_remove_index >= 0) return 0;
                if (s_sub_input_truncated || GetWindowTextLengthW(GetDlgItem(hwnd, IDC_SUB_URL)) >= SUBS_URL_MAX) {
                    subs_feedback(hwnd, L"链接超过 1023 字符上限，未保存；请缩短后重新输入。", true);
                    return 0;
                }
                wchar_t url[SUBS_URL_MAX];
                GetWindowTextW(GetDlgItem(hwnd, IDC_SUB_URL), url, SUBS_URL_MAX);
                wchar_t *s = url;
                while (*s == L' ' || *s == L'\t') s++;
                size_t n = wcslen(s);
                while (n > 0 && (s[n - 1] == L' ' || s[n - 1] == L'\t')) s[--n] = 0;
                subs_load();
                bool dup = false;
                for (int i = 0; i < s_sub_count; i++)
                    if (wcscmp(s_sub_urls[i], s) == 0) dup = true;
                const wchar_t *authority = wcsstr(s, L"://");
                bool invalid_text = false;
                for (const wchar_t *p = s; *p; p++)
                    if (*p <= L' ' || *p == 127) invalid_text = true;
                if (n < 8 || !url_has_http_scheme(s) || !authority || !authority[3] ||
                    wcschr(L"/?#", authority[3]) || invalid_text) {
                    subs_feedback(hwnd, L"请输入以 http:// 或 https:// 开头的完整订阅链接；本次未保存。", true);
                } else if (dup) {
                    subs_feedback(hwnd, L"这个订阅已经存在，未重复添加；输入已保留。", true);
                } else if (s_sub_count >= SUBS_MAX) {
                    wchar_t full[160];
                    swprintf(full, 160, L"最多 32 个订阅源（当前 %d）。请先删掉不再需要的。", SUBS_MAX);
                    subs_feedback(hwnd, full, true);
                } else {
                    wcsncpy(s_sub_urls[s_sub_count], s, SUBS_URL_MAX - 1);
                    s_sub_urls[s_sub_count][SUBS_URL_MAX - 1] = 0;
                    s_sub_status[s_sub_count][0] = 0;
                    s_sub_names[s_sub_count][0] = 0;
                    if (subs_save_urls((unsigned)s_sub_count + 1)) {
                        s_sub_count++;
                        subs_refresh_list(hwnd);
                        SendDlgItemMessageW(hwnd, IDC_SUB_LIST, LB_SETCURSEL, s_sub_count - 1, 0);
                        subs_name_selection(hwnd);
                        subs_controls_refresh(hwnd);
                        SetWindowTextW(GetDlgItem(hwnd, IDC_SUB_URL), L"");
                        wchar_t saved[160];
                        swprintf(saved, 160, L"已保存订阅源，共 %d 个；点“立即更新全部”下载规则", s_sub_count);
                        subs_feedback(hwnd, saved, false);
                    } else {
                        s_sub_urls[s_sub_count][0] = 0;
                        subs_feedback(hwnd, L"来源保存失败，本次添加未生效；已保留输入及原有来源，请检查文件占用或目录写入权限", true);
                    }
                }
                InvalidateRect(hwnd, NULL, FALSE);
        } else if (id == IDC_SUB_DEL) {
                if (s_subs_running || s_sub_read_failed || s_sub_remove_index >= 0) return 0;
                subs_load();
                int sel = (int) SendMessageW(GetDlgItem(hwnd, IDC_SUB_LIST), LB_GETCURSEL, 0, 0);
                if (sel < 0 || sel >= s_sub_count) {
                    subs_feedback(hwnd, L"请先在列表里选中一个订阅源。", true);
                } else {
                    s_sub_remove_index = sel;
                    memcpy(s_sub_remove_url, s_sub_urls[sel], sizeof(s_sub_remove_url));
                    wchar_t prompt[220];
                    swprintf(prompt, 220, L"确认移除第 %d 个来源？完整链接见上方只读框。已导入规则会在下次成功更新后替换；也可取消。", sel + 1);
                    subs_feedback(hwnd, prompt, false);
                    subs_controls_refresh(hwnd);
                    SetFocus(GetDlgItem(hwnd, IDC_SUB_CANCEL));
                }
                InvalidateRect(hwnd, NULL, FALSE);
        } else if (id == IDC_SUB_CONFIRM) {
                subs_confirm_remove(hwnd);
        } else if (id == IDC_SUB_CANCEL || (id == IDCANCEL && s_sub_remove_index >= 0)) {
                subs_cancel_remove(hwnd);
                SetFocus(GetDlgItem(hwnd, IDC_SUB_DEL));
        } else if (id == IDC_SUB_UPD) {
                subs_start_update(hwnd);
                InvalidateRect(hwnd, NULL, FALSE);
        } else if (id == IDC_SUB_OPEN) {
                wchar_t dir[MAX_PATH];
                if (MultiByteToWideChar(CP_UTF8, 0, g_res, -1, dir, MAX_PATH) > 0)
                    ShellExecuteW(NULL, L"open", dir, NULL, NULL, SW_SHOWNORMAL);
            } else if (id == IDM_UPDATE) {
                swprintf(g_status, 4096, L"正在检查更新…");
                update_check_async(hwnd);
                InvalidateRect(hwnd, NULL, FALSE);
            } else if (id == IDC_ADGUARD_HOME) {
                HMENU menu=CreatePopupMenu();
                AppendMenuW(menu,MF_STRING,1,L"检测 DNS 与请求是否到达 AdAway");
                AppendMenuW(menu,MF_STRING,2,L"AdGuard Home 自定义 IP 协同向导");
                RECT button; GetWindowRect(GetDlgItem(hwnd,IDC_ADGUARD_HOME),&button);
                int selected=(int)TrackPopupMenuEx(menu,TPM_RETURNCMD|TPM_LEFTALIGN,button.left,button.bottom,hwnd,NULL);
                DestroyMenu(menu);
                if (selected==1) PostMessageW(hwnd,WM_COMMAND,IDC_ARRIVAL_CHECK,0);
                else if (selected==2) show_adguard_assistant(hwnd);
            } else if (id == IDC_ARRIVAL_CHECK) {
                struct arrival_config config=g_active_arrival;
                gui_show_arrival_dialog(hwnd,&config);
            } else if (id == IDM_TEST) {
                wchar_t url[256];
                if (*g_bind_ip) swprintf(url, 256, L"http://127.0.0.1:%d/internal-test", mgmt_port());
                else swprintf(url, 256, L"https://localhost:%d/internal-test", g_https_port);
                ShellExecuteW(NULL, L"open", url, NULL, NULL, SW_SHOWNORMAL);
            } else if (id == IDM_AUTOSTART) {
                HWND chk = GetDlgItem(hwnd, IDM_AUTOSTART);
                bool on = SendMessageW(chk, BM_GETCHECK, 0, 0) == BST_CHECKED;
                char cmd[2048], exe[MAX_PATH];
                get_module_path_utf8(exe, sizeof(exe));
                snprintf(cmd, sizeof(cmd),
                         "\"%s\" --resources \"%s\" --minimized", exe, g_res);
                win32_autostart_set(on, cmd);
                swprintf(g_status, 4096, L"开机自启动已%ls", on ? L"启用" : L"关闭");
                InvalidateRect(hwnd, NULL, FALSE);
            } else if (id == IDM_DARK) {
                bool on = SendMessageW(GetDlgItem(hwnd, IDM_DARK), BM_GETCHECK, 0, 0) == BST_CHECKED;
                g_theme_pref = on ? 1 : 0;
                g_dark = on ? 1 : 0;
                theme_apply(g_dark);
                apply_window_chrome(hwnd, g_dark);
                apply_control_theme(hwnd);
                if (ini_save(g_http_port, g_https_port, g_bind_all))
                    swprintf(g_status, 4096, L"已切换为%ls主题（下次启动仍然生效）", g_dark ? L"深色" : L"浅色");
                else swprintf(g_status, 4096, L"本次外观已切换，但偏好保存失败；重启后不会保留，请检查配置目录权限。");
                InvalidateRect(hwnd, NULL, TRUE);
            } else if (id == IDC_DIAG) {
                diag_write_file(hwnd);
                swprintf(g_status, 4096, L"诊断信息已写入程序目录的 diagnose.txt");
                InvalidateRect(hwnd, NULL, TRUE);
            } else if (id == IDC_FIXPORT) {
                /* The default ports were taken (another server is running):
                 * move to 18080/18443 and restart so the dashboard comes back
                 * on a port that is actually free. */
                wchar_t wt[32];
                swprintf(wt, 32, L"18080");
                SetWindowTextW(GetDlgItem(hwnd, IDC_HTTP_EDIT), wt);
                swprintf(wt, 32, L"18443");
                SetWindowTextW(GetDlgItem(hwnd, IDC_HTTPS_EDIT), wt);
                listener_validate(hwnd, true);
                SetDlgItemTextW(hwnd, IDC_LISTEN_STATUS, L"已填入备用端口；请检查检测结果，点击“保存并重启”应用。尚未保存。");
            } else if (id == IDM_EXIT) {
                PostMessageW(hwnd, WM_APP_EXIT, 0, 0);
            } else if (id == IDC_SAVE || id == IDC_RESTART) {
                if (listener_validate(hwnd, true)) {
                    int hp, sp; char ip[64],ip6[64]; bool bind;
                    if (!listener_read(hwnd, ip, ip6, &hp, &sp, &bind)) return 0;
                    char old_ip[64],old_ip6[64]; bool old_auto=g_auto_create,old_pair=g_explicit_pair;
                    memcpy(old_ip,g_bind_ip,sizeof(old_ip)); memcpy(old_ip6,g_bind_ipv6,sizeof(old_ip6));
                    snprintf(g_bind_ipv6,sizeof(g_bind_ipv6),"%s",ip6);
                    g_auto_create=SendDlgItemMessageW(hwnd,IDC_AUTO_CREATE,BM_GETCHECK,0,0)==BST_CHECKED;
                    g_explicit_pair=true;
                    snprintf(g_bind_ip, sizeof(g_bind_ip), "%s", ip);
                    if (!ini_save(hp, sp, bind)) {
                        memcpy(g_bind_ip, old_ip, sizeof(g_bind_ip));
                        memcpy(g_bind_ipv6,old_ip6,sizeof(g_bind_ipv6)); g_auto_create=old_auto; g_explicit_pair=old_pair;
                        SetDlgItemTextW(hwnd, IDC_LISTEN_STATUS, L"保存失败，原配置已保留；请检查配置目录权限。");
                        return 0;
                    }
                    g_http_port = hp; g_https_port = sp; g_bind_all = bind;
                    if (!refresh_owned_autostart()) {
                        SetDlgItemTextW(hwnd, IDC_LISTEN_STATUS, L"监听设置已保存，但开机启动项更新失败；请重新设置开机启动。");
                        return 0;
                    }
                    if (id == IDC_RESTART) {
                        win32_notify_restart(); PostMessageW(hwnd, WM_APP_EXIT, 0, 0);
                    } else SetDlgItemTextW(hwnd, IDC_LISTEN_STATUS, L"已保存；点击“保存并重启”应用监听配置。");
                }
            } else if (id == IDC_FLUSH) {
                wchar_t st[128];
                control_post(mgmt_port(), "flush_stats", st, 128);
                swprintf(g_status, 4096, L"%ls", st);
                InvalidateRect(hwnd, NULL, FALSE);
            } else if (id >= IDC_POL0 && id < IDC_POL0 + POLICY_COUNT) {
                policy_cycle_one(hwnd, id - IDC_POL0);
            } else if (id == IDC_POLDEF) {
                policy_apply_defaults(hwnd);
            }
        }
        return 0;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
        /* Native child controls do not follow the palette on their own: on the
           dark card a checkbox or the port edit boxes stayed white with black
           text. Handing back a card-coloured brush plus matching text/bk
           colours is the documented fix (no owner-draw needed). */
        static HBRUSH s_ctl_brush = NULL;
        static COLORREF s_ctl_brush_color = 0xFFFFFFFFu;
        HDC dc = (HDC) wp;
        if (s_ctl_brush == NULL || s_ctl_brush_color != g_pal.card) {
            if (s_ctl_brush != NULL) DeleteObject(s_ctl_brush);
            s_ctl_brush = CreateSolidBrush(g_pal.card);
            s_ctl_brush_color = g_pal.card;
        }
        SetBkMode(dc, OPAQUE);
        SetBkColor(dc, g_pal.card);
        SetTextColor(dc, g_pal.text);
        return (LRESULT) s_ctl_brush;
    }
    case WM_ERASEBKGND:
        return 1;   /* handled in WM_PAINT - no erase flicker */
    case WM_SIZE:
        /* Maximize / resize: rescale the whole canvas (see
           update_layout_scale), then put the controls back and repaint. */
        update_layout_scale(hwnd);
        layout_controls(hwnd);
        if (g_ui_visible) InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC real = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        int cw = rc.right - rc.left, chh = rc.bottom - rc.top;
        HDC mem = CreateCompatibleDC(real);
        HBITMAP bmp = CreateCompatibleBitmap(real, cw, chh);
        HGDIOBJ oldbmp = SelectObject(mem, bmp);
        HDC hdc = mem;
        FillRect(hdc, &rc, GetSysColorBrush(COLOR_WINDOW));

        /* content background */
        RECT content = {0, 0, rc.right, rc.bottom};
        HBRUSH cb = CreateSolidBrush(g_pal.content_bg);
        FillRect(hdc, &content, cb);
        DeleteObject(cb);

        draw_sidebar(hdc);

        if (g_tab == 2) {
            /* settings page */
            /* grouped card backgrounds behind the native controls */
            rounded_card(hdc, 202, 12, 812, 240, 16, g_pal.card, g_pal.border);
            rounded_card(hdc, 202, 258, 812, 176, 16, g_pal.card, g_pal.border);
            rounded_card(hdc, 202, 442, 812, 182, 16, g_pal.card, g_pal.border);

            HFONT shf = mfont(15, FW_SEMIBOLD);
            HFONT lf = mfont(12, FW_NORMAL);
            HFONT old = (HFONT)SelectObject(hdc, shf);
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, g_pal.text);
            TextOutW(hdc, S(218), S(20), L"服务器", 3);
            SelectObject(hdc, lf);
            SetTextColor(hdc, g_pal.muted);
            wchar_t shint[320];
            char host[68]; listener_display_host(host);
            swprintf(shint, 320,
                     L"已保存：http://%hs:%d · IPv4 / IPv6 独立，留空关闭对应协议，重启后应用",
                     host, g_http_port);
            TextOutW(hdc, S(218), S(44), shint, (int)wcslen(shint));
            TextOutW(hdc, S(218), S(76), L"HTTP 端口:", 9);
            TextOutW(hdc, S(500), S(76), L"HTTPS 端口:", 10);
            SelectObject(hdc, shf);
            SetTextColor(hdc, g_pal.text);
            TextOutW(hdc, S(218), S(266), L"拦截策略 · 点击切换响应方式", (int)wcslen(L"拦截策略 · 点击切换响应方式"));
            TextOutW(hdc, S(218), S(450), L"证书与维护", 5);
            SelectObject(hdc, lf);
            SetTextColor(hdc, g_pal.muted);
            TextOutW(hdc, S(218), S(472), L"浏览器显示安全锁需要把 CA 证书加入受信任的根证书颁发机构。", 29);
            SelectObject(hdc, old);
            DeleteObject(shf);
            DeleteObject(lf);
            draw_statusbar(hdc);
            BitBlt(real, 0, 0, cw, chh, mem, 0, 0, SRCCOPY);
            SelectObject(mem, oldbmp);
            DeleteObject(bmp);
            DeleteDC(mem);
            EndPaint(hwnd, &ps);
            return 0;
        }

        if (g_tab == 1) {
            /* 应用日志 page */
            draw_activity_page(hdc);
            BitBlt(real, 0, 0, cw, chh, mem, 0, 0, SRCCOPY);
            SelectObject(mem, oldbmp);
            DeleteObject(bmp);
            DeleteDC(mem);
            EndPaint(hwnd, &ps);
            return 0;
        }

        if (g_tab == 5) {
            /* Network integration roadmap with truthful capability states. */
            draw_network_center_page(hdc);
            draw_statusbar(hdc);
            BitBlt(real, 0, 0, cw, chh, mem, 0, 0, SRCCOPY);
            SelectObject(mem, oldbmp);
            DeleteObject(bmp);
            DeleteDC(mem);
            EndPaint(hwnd, &ps);
            return 0;
        }

        if (g_tab == 4) {
            /* 订阅 page */
            draw_subs_page(hdc);
            draw_statusbar(hdc);
            BitBlt(real, 0, 0, cw, chh, mem, 0, 0, SRCCOPY);
            SelectObject(mem, oldbmp);
            DeleteObject(bmp);
            DeleteDC(mem);
            EndPaint(hwnd, &ps);
            return 0;
        }

        if (g_tab == 3) {
            /* 拦截排行 page */
            draw_ranking_page(hdc);
            BitBlt(real, 0, 0, cw, chh, mem, 0, 0, SRCCOPY);
            SelectObject(mem, oldbmp);
            DeleteObject(bmp);
            DeleteDC(mem);
            EndPaint(hwnd, &ps);
            return 0;
        }

        /* statistics page */
        const struct snapshot *sn = g_sn;
        wchar_t val[64], txt[256];
        bool show_data = sn && sn->has_data;
        long long req = sn && sn->has_data ? sn->total_requests : 0;
        /* Lifetime counter (same window as 请求量): summing the ring history
           only showed the current session, so the KPI contradicted the request
           count right next to it. */
        long long blk = (sn && sn->has_data) ? sn->total_blocked : 0;
        fmt_num(val, 64, req);
        draw_kpi(hdc, 210, 24, 120, 72, L"请求量", show_data ? val : L"—", C_BLUE);
        fmt_num(val, 64, blk);
        draw_kpi(hdc, 348, 24, 120, 72, L"拦截量", show_data ? val : L"—", C_RED);
        /* block_rate is ALREADY a percentage (0-100) in the JSON; the old code
           multiplied it by 100 again, so a fully blocked device showed
           "10000%". Clamp it and print one decimal. */
        double rate = (sn && sn->has_data) ? sn->block_rate : 0.0;
        if (rate < 0.0) rate = 0.0;
        if (rate > 100.0) rate = 100.0;
        swprintf(val, 64, L"%.1f%%", rate);
        draw_kpi(hdc, 486, 24, 120, 72, L"拦截率", show_data ? val : L"—", C_ACCENT);
        fmt_num(val, 64, sn && sn->has_data ? sn->total_connections : 0);
        draw_kpi(hdc, 624, 24, 120, 72, L"连接数", show_data ? val : L"—", C_GREEN);
        fmt_num(val, 64, sn && sn->has_data ? sn->sni_certs_issued : 0);
        draw_kpi(hdc, 762, 24, 120, 72, L"签发证书", show_data ? val : L"—", RGB(139, 92, 246));
        long long up = sn && sn->has_data ? sn->uptime_seconds : 0;
        swprintf(val, 64, L"%lldh %lldm", up / 3600, (up % 3600) / 60);
        draw_kpi(hdc, 900, 24, 120, 72, L"运行时长", show_data ? val : L"—", RGB(20, 184, 166));

        RECT ph = {210, 120, 600, 430};
        draw_chart(hdc, ph, L"最近 24 小时",
                   sn ? sn->hist : NULL, sn ? sn->hist_count : 0);
        RECT pd = {616, 120, 1006, 430};
        draw_chart(hdc, pd, L"最近 30 天",
                   sn ? sn->daily : NULL, sn ? sn->daily_count : 0);
        draw_legend(hdc, 232, 398);
        draw_legend(hdc, 638, 398);

        char cert_path[1024];
        snprintf(cert_path, sizeof(cert_path), "%s/localhost-2410.crt", g_res);
        long long days = g_cert_days;          /* cached (30 s TTL) */
        int trusted = g_cert_trusted_flag;
        wchar_t trust_txt[64];
        cert_trust_text(g_cert_trust_state, trust_txt, 64);
        HFONT lf = mfont(13, FW_NORMAL);
        HFONT old2 = (HFONT)SelectObject(hdc, lf);
        if (days > 0 && days < 200000)
            swprintf(txt, 256,
                     trusted ? L"证书：剩余 %lld 天 · %ls"
                             : L"证书：剩余 %lld 天 · %ls → 左侧\"设置\"→\"信任 CA\"",
                     days, trust_txt);
        else if (days == -100001)
            swprintf(txt, 256, L"证书文件缺失：%hs（首次运行时会自动生成）", cert_path);
        else if (days == -100002)
            swprintf(txt, 256, L"证书文件解析失败：%hs", cert_path);
        else
            swprintf(txt, 256, L"证书已过期 - 请删除 %hs 后重启", cert_path);
        SetTextColor(hdc, days > 0 && days < 200000 ? C_GREEN_TXT : RGB(190, 70, 70));
        TextOutW(hdc, S(210), S(464), txt, (int)wcslen(txt));
        {
            wchar_t hint[300];
            if (*g_bind_ip) {
                swprintf(hint, 300, L"监听地址：%hs · HTTP %d / HTTPS %d", g_bind_ip, g_http_port, g_https_port);
            } else if (g_bind_all) {
                char lan[64] = "";
                if (first_lan_ip(lan, sizeof(lan)) == 0)
                    swprintf(hint, 300, L"访问地址：本机 http://localhost:%d  ·  局域网 http://%hs:%d",
                             g_http_port, lan, g_http_port);
                else
                    swprintf(hint, 300, L"访问地址：本机 http://localhost:%d", g_http_port);
            } else {
                swprintf(hint, 300, L"访问地址：http://localhost:%d（其他设备：设置→\"监听所有网卡\"）", g_http_port);
            }
            SetTextColor(hdc, g_pal.muted);
            TextOutW(hdc, S(210), S(486), hint, (int)wcslen(hint));
        }
        SelectObject(hdc, old2);
        DeleteObject(lf);

        draw_listener_card(hdc, 210, 502, 796, 130, sn, 1);
        draw_statusbar(hdc);
        BitBlt(real, 0, 0, cw, chh, mem, 0, 0, SRCCOPY);
        SelectObject(mem, oldbmp);
        DeleteObject(bmp);
        DeleteDC(mem);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_APP_UPDATE_PROGRESS: {
        /* Download progress (wParam = percent, -1 = gave up). On a slow line the
           4 MB package takes minutes and used to look like a frozen window. */
        int pct = (int) wp;
        update_button_refresh(hwnd);
        if (pct < 0)
            swprintf(g_status, 4096, L"更新包下载失败（已自动重试 5 次并支持断点续传）");
        else
            swprintf(g_status, 4096,
                     L"正在下载更新包 … %d%%（网络慢时请稍候，断线会自动续传）", pct);
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }
    case WM_APP_UPDATE_FOUND: {
        struct update_info *info = (struct update_info *) lp;
        update_button_refresh(hwnd);
        if (wp == 3) { update_info_free(info); return 0; }
        if (wp && info) {
            wchar_t msg[512];
            swprintf(msg, 512,
                     L"发现新版本 %ls（当前版本 v" ADBLOCK_APP_VERSION_W L"）。\n\n"
                     L"现在下载并自动更新吗？更新会关闭本窗口，替换文件后自动重启。",
                     info->tag);
            if (update_automatic()) {
                swprintf(g_status, 4096, L"发现 %ls，正在自动下载、校验并覆盖更新，完成后重启…", info->tag);
                update_apply_async(hwnd, info);
            } else {
            update_prompt_notify(hwnd);
            if (MessageBoxW(hwnd, msg, L"检查更新",
                            MB_YESNO | MB_ICONQUESTION | MB_TOPMOST) == IDYES) {
                swprintf(g_status, 4096, L"正在下载更新（完成后会自动重启）…");
                update_apply_async(hwnd, info);
            } else {
                swprintf(g_status, 4096, L"已忽略新版本 %ls", info->tag);
            }
            }
        } else if (wp == 2) {
            /* A failed check used to be displayed as "已是最新版本" - exactly
               the "它经常检测不到更新" report. */
            swprintf(g_status, 4096, L"检查更新失败：%ls", update_last_error());
            MessageBoxW(hwnd, g_status, L"检查更新", MB_OK | MB_ICONWARNING | MB_TOPMOST);
        } else {
            swprintf(g_status, 4096, L"已是最新版本（v" ADBLOCK_APP_VERSION_W L"）");
        }
        update_info_free(info);
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }
    case WM_APP_ADDRESS_DONE: {
        struct address_job *job=(struct address_job *)lp;
        s_address_busy=false; address_controls(hwnd,false);
        if (!job) return 0;
        wchar_t message[600];
        if (job->result==NO_ERROR) swprintf(message,600,job->remove
            ? L"已移除托管地址 %hs；系统和其他软件的地址未改变。"
            : L"已创建 %hs，HTTP/HTTPS 端口检查通过。地址在本次开机有效；点击“保存并重启”应用监听。",job->ip);
        else if (job->result==ERROR_OBJECT_ALREADY_EXISTS) swprintf(message,600,L"地址 %hs 已被创建，直接复用；没有取得其所有权，请重新检测端口。",job->ip);
        else if (job->result==ERROR_CANCELLED) swprintf(message,600,L"已取消管理员授权，地址和监听设置未改变。");
        else if (job->result==MA_PORT_CONFLICT) swprintf(message,600,L"端口不可用，本次创建的地址已清理；原监听设置保留。");
        else if (job->result==MA_CLEANUP_FAILED) swprintf(message,600,L"地址操作失败且清理未完成；请检查托管地址后重试移除。原监听设置未改变。");
        else swprintf(message,600,L"地址操作未完成（系统错误 %lu）。原监听设置未改变；请检查管理员权限及软件回环接口。",(unsigned long)job->result);
        SetDlgItemTextW(hwnd,IDC_LISTEN_STATUS,message); free(job);
        InvalidateRect(hwnd,NULL,FALSE); return 0;
    }
    case WM_APP_SUBS_DONE: {
        struct subs_job *job = (struct subs_job *)lp;
        InterlockedExchange(&s_subs_running, 0);
        if (!job) return 0;
        if (job->result.status == SUB_UPDATE_OK) {
            s_sub_written = (int)job->result.entries;
            s_sub_written_known = true;
            for (unsigned i = 0; i < job->count; i++)
                swprintf(s_sub_status[i], 160, L"已保存 %llu 条域规则", (unsigned long long)job->result.source_entries[i]);
            swprintf(g_status, 4096, L"已保存 %d 条域规则；跳过 %llu 条条件规则，已请求服务端重新加载（活动版本未确认）",
                     s_sub_written, (unsigned long long)job->result.unsupported);
            wchar_t status[160]; control_post(mgmt_port(), "reload_subscriptions", status, 160);
        } else {
            for (unsigned i = 0; i < job->count; i++) swprintf(s_sub_status[i], 160, L"更新未提交；保留上一次完整规则");
            swprintf(g_status, 4096, L"订阅更新未提交：%ls；保留上一次完整规则",
                     job->result.status == SUB_UPDATE_LOCKED ? L"另一个更新正在运行" :
                     job->result.status == SUB_UPDATE_DOWNLOAD_FAILED ? L"下载失败或超时" :
                     job->result.status == SUB_UPDATE_PARSE_FAILED ? L"规则格式或大小不符合要求" :
                     job->result.status == SUB_UPDATE_PUBLISH_FAILED ? L"无法原子替换规则文件" : L"文件读写失败");
        }
        subs_feedback(hwnd, g_status, job->result.status != SUB_UPDATE_OK);
        subs_save_status(); subs_refresh_list(hwnd); free(job);
        InvalidateRect(hwnd, NULL, FALSE); return 0;
    }
    case WM_APP_TRAY:
        if (lp == WM_RBUTTONUP) {
            tray_menu(hwnd);
        } else if (lp == WM_LBUTTONUP || lp == WM_LBUTTONDBLCLK) {
            ShowWindow(hwnd, SW_SHOW);
            SetForegroundWindow(hwnd);
        }
        return 0;
    case WM_APP_EXIT:
        if (s_address_busy) {
            MessageBoxW(hwnd,L"本机地址任务尚未结束，请完成或取消管理员授权后再退出。",L"正在处理本机地址",MB_OK|MB_ICONINFORMATION);
            return 0;
        }
        tray_remove();
        DestroyWindow(hwnd);
        return 0;
    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);   /* minimize to tray */
        return 0;
    case WM_DESTROY:
        KillTimer(hwnd, 1);
        KillTimer(hwnd, 4);
        if (g_poll_started) {
            g_poll_stop = 1;
            if (g_poll_wake) SetEvent(g_poll_wake);
            pthread_join(g_poll_thread, NULL);
            g_poll_started = 0;
        }
        if (g_poll_wake) { CloseHandle(g_poll_wake); g_poll_wake = NULL; }
        tray_remove();
        if (g_ctl_font) { DeleteObject(g_ctl_font); g_ctl_font = NULL; }
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
}

int adblock_gui_run(const struct adblock_gui_args *args) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;

    HINSTANCE hinst = GetModuleHandleW(NULL);
    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = gui_proc;
    wc.hInstance = hinst;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ADBlockDashWin11";
    if (!RegisterClassExW(&wc)) {
        WSACleanup();
        return -1;
    }
    {
        UINT dpi = GetDpiForSystem();
        double sc = dpi / 96.0;
        const DWORD style =
            (WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX |
             WS_MAXIMIZEBOX | WS_THICKFRAME | WS_CLIPCHILDREN);
        /* The canvas uses 1032x678 logical *CLIENT* coordinates. Passing
         * those as the outer window dimensions clips the bottom status bar
         * behind the title bar and resize borders on initial launch. */
        RECT outer = {0, 0, (LONG)(DASH_W * sc), (LONG)(DASH_H * sc)};
        if (!AdjustWindowRectExForDpi(&outer, style, FALSE, 0, dpi)) {
            /* Safe fallback for unexpected older API/runtime behavior. */
            AdjustWindowRectEx(&outer, style, FALSE, 0);
        }
        HWND hwnd = CreateWindowExW(0, L"ADBlockDashWin11", g_title,
            style, CW_USEDEFAULT, CW_USEDEFAULT,
            outer.right - outer.left, outer.bottom - outer.top,
            NULL, NULL, hinst, (LPVOID)args);
        if (!hwnd) {
            WSACleanup();
            return -1;
        }
        ShowWindow(hwnd, g_start_minimized ? SW_HIDE : SW_SHOW);
        UpdateWindow(hwnd);
        /* Keyboard shortcuts are active even when a settings edit field
         * owns focus; relying on WM_KEYDOWN in the parent misses that case. */
        ACCEL nav_keys[] = {
            {FVIRTKEY | FALT, '1', UI_ACCEL_NAV_FIRST},
            {FVIRTKEY | FALT, '2', UI_ACCEL_NAV_FIRST + 1},
            {FVIRTKEY | FALT, '3', UI_ACCEL_NAV_FIRST + 2},
            {FVIRTKEY | FALT, '4', UI_ACCEL_NAV_FIRST + 3},
            {FVIRTKEY | FALT, '5', UI_ACCEL_NAV_FIRST + 4},
            {FVIRTKEY | FALT, '6', UI_ACCEL_NAV_FIRST + 5},
            {FVIRTKEY | FCONTROL, VK_TAB, UI_ACCEL_NAV_NEXT},
            {FVIRTKEY | FCONTROL | FSHIFT, VK_TAB, UI_ACCEL_NAV_PREV},
        };
        HACCEL nav_accel = CreateAcceleratorTableW(
            nav_keys, (int)(sizeof(nav_keys) / sizeof(nav_keys[0])));
        MSG msg;
        while (GetMessageW(&msg, NULL, 0, 0) > 0) {
            if ((nav_accel == NULL || !TranslateAcceleratorW(hwnd, nav_accel, &msg)) &&
                !IsDialogMessageW(hwnd, &msg)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        if (nav_accel != NULL) DestroyAcceleratorTable(nav_accel);
        WSACleanup();
        return 0;
    }
}
