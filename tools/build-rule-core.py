"""Apply only reviewed domain-loader hooks to the frozen portable Windows service source."""
import hashlib
import pathlib
import sys

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
    if "android/log.h" not in source or "win32_dirent.h" not in source:
        raise ValueError("portable source guards unexpectedly changed")
    return source


if __name__ == "__main__":
    source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
    prepared = prepare(source)
    output = pathlib.Path(sys.argv[2])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(prepared, encoding="utf-8", newline="\n")
    print("Frozen portable production core preserved; domain-loader overlay generated")
