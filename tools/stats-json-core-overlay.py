"""Keep complete rows within the existing fixed statistics JSON buffers."""
import importlib.util
from pathlib import Path


def prepare_stats_bounds(source):
    spec = importlib.util.spec_from_file_location("stats_core_hooks", Path(__file__).with_name("build-rule-core.py"))
    hooks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hooks)
    start, end = hooks.function_span(source, "static int build_stats_json(struct settings *s, char *out, size_t out_sz) {")
    body = source[start:end]

    def replace(old, new, count=1):
        nonlocal body
        if body.count(old) != count:
            raise ValueError("statistics bounds hook changed: " + old[:100])
        body = body.replace(old, new)

    loop = "for (int i = 0; i < s_app_count && off < (int)sizeof(apps_json) - 400; i++) {"
    left, right = hooks.function_span(body, loop)
    apps = body[left:right]
    apps = apps.replace(loop, loop + "\n        int app_start = off;")
    if apps.count("if (n > 0) off += n;") != 2 or apps.count("if (hn > 0) off += hn;") != 1:
        raise ValueError("app row append hooks changed")
    apps = apps.replace("if (n > 0) off += n;",
        "if (n <= 0 || (size_t)n >= sizeof(apps_json) - (size_t)off) goto app_row_full;\n        off += n;")
    apps = apps.replace("if (hn > 0) off += hn;",
        "if (hn <= 0 || (size_t)hn >= sizeof(apps_json) - (size_t)off) goto app_row_full;\n            off += hn;")
    marker = "if (s_apps[i].top_hosts[h][0] == '\\0') break;"
    if apps.count(marker) != 1 or apps.count("s_apps[i].top_hosts[h],") != 1:
        raise ValueError("app host hooks changed")
    apps = apps.replace(marker, marker + "\n            char app_host_safe[128];\n            json_safe_copy(app_host_safe, sizeof(app_host_safe), s_apps[i].top_hosts[h]);")
    apps = apps.replace("s_apps[i].top_hosts[h],", "app_host_safe,")
    apps = apps[:-1] + """    continue;
app_row_full:
        apps_json[app_start] = '\\0';
        off = app_start;
        break;
    }"""
    body = body[:left] + apps + body[right:]
    replace("if (w <= 0 || toff + w >= (int) sizeof(top_json)) break;",
            "if (w <= 0 || (size_t)w >= sizeof(top_json) - (size_t)toff) { top_json[toff] = '\\0'; break; }")
    replace("if (n > 0) off += n;",
            "if (n <= 0 || (size_t)n >= sizeof(tls_json) - (size_t)off) { tls_json[off] = '\\0'; break; }\n        off += n;")
    if "char listeners_json[" in body:
        replace("if (n <= 0 || loff + n >= (int)sizeof(listeners_json)) break;",
                "if (n <= 0 || (size_t)n >= sizeof(listeners_json) - (size_t)loff) { listeners_json[loff] = '\\0'; break; }")
    return source[:start] + body + source[end:]
