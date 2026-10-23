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
    start, end = function_span(source, "static void domain_rule_normalize(")
    source = source[:start] + '#include "rule_norm.h"\n' + source[end:]
    start, end = function_span(source, "static bool domain_is_allowed(")
    source = source[:start] + '''#include "domain_allow_snapshot.h"
static struct da_repository s_domain_allow_repository = DA_REPOSITORY_INITIALIZER;
static bool domain_is_allowed(const char *host, const char *resource_dir) {
    struct da_result result = da_lookup(&s_domain_allow_repository, host, resource_dir);
    if (!result.update_valid) LOG_WARN("Domain exemption update rejected; retaining previous rules");
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
    return logs.prepare_logs(source)


if __name__ == "__main__":
    source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
    prepared = prepare(source)
    output = pathlib.Path(sys.argv[2])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(prepared, encoding="utf-8", newline="\n")
    print("Frozen portable core preserved; reviewed rules + Win32 instance isolation overlays generated")
