#include "update_feed.h"
#include "mongoose/mongoose.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

static int field(struct mg_str json, const char *key, char *out, size_t cap) {
    char *value = mg_json_get_str(json, key);
    size_t n = value ? strlen(value) : 0;
    if (n == 0 || n >= cap) { free(value); out[0] = 0; return 0; }
    memcpy(out, value, n + 1); free(value); return 1;
}

static int numeric_version(const char *v) {
    int digits = 0;
    for (; *v; v++) {
        if (*v == '.') { if (!digits) return 0; digits = 0; }
        else if (*v >= '0' && *v <= '9') { if (++digits > 8) return 0; }
        else return 0;
    }
    return digits != 0;
}

int update_version_cmp(const char *a, const char *b) {
    while (*a || *b) {
        unsigned va = 0, vb = 0;
        while (*a >= '0' && *a <= '9') va = va * 10 + (unsigned)(*a++ - '0');
        while (*b >= '0' && *b <= '9') vb = vb * 10 + (unsigned)(*b++ - '0');
        if (va != vb) return va > vb ? 1 : -1;
        if (*a) a++;
        if (*b) b++;
    }
    return 0;
}

int update_feed_cmp(const struct release_pick *a, const struct release_pick *b) {
    int v = update_version_cmp(a->ver, b->ver);
    if (v) return v;
    /* Missing legacy build identity never upgrades an equal version. */
    const char *left = a->build[0] ? a->build : "0";
    const char *right = b->build[0] ? b->build : "0";
    while (*left == '0' && left[1]) left++;
    while (*right == '0' && right[1]) right++;
    if (strlen(left) != strlen(right)) return strlen(left) > strlen(right) ? 1 : -1;
    return strcmp(left, right);
}

static int valid_preview_tag(const char *tag) {
    const char *p = tag;
    if (strncmp(p, "progress-win-", 13)) return 0;
    p += 13;
    for (int i = 0; i < 8; i++) if (*p < '0' || *p++ > '9') return 0;
    if (*p++ != '.' || !*p) return 0;
    for (; *p; p++) if (*p < '0' || *p > '9') return 0;
    return 1;
}

static int package_valid(const char *tag, const char *url, const char *sha, const char *name) {
    char expected[1200];
    snprintf(expected, sizeof(expected), "https://github.com/wxcvm/AdAway-Windows/releases/download/%s/%s", tag, name);
    if (strcmp(url, expected)) return 0;
    if (!strncmp(sha, "sha256:", 7)) sha += 7;
    if (strlen(sha) != 64) return 0;
    for (; *sha; sha++) if (!isxdigit((unsigned char)*sha)) return 0;
    return 1;
}

int update_feed_manifest(const char *body, int preview, const char *tag, struct release_pick *out) {
    struct mg_str json = mg_str(body);
    char channel[32];
    memset(out, 0, sizeof(*out));
    if (json.len > 65536 || !field(json, "$.tag", out->tag, sizeof(out->tag))
        || !field(json, "$.version", out->ver, sizeof(out->ver)) || !numeric_version(out->ver)) return 0;
    if (tag && strcmp(tag, out->tag)) return 0;
    field(json, "$.build", out->build, sizeof(out->build));
    if (strlen(out->build) > 20) return 0;
    for (const char *p = out->build; *p; p++) if (*p < '0' || *p > '9') return 0;
    if (preview && (!valid_preview_tag(out->tag) || !out->build[0]
        || !field(json, "$.channel", channel, sizeof(channel)) || strcmp(channel, "preview"))) return 0;
    if (!preview && (strncmp(out->tag, "win11-webserver-v", 17) || strcmp(out->tag + 17, out->ver))) return 0;
    field(json, "$.exe_url", out->exe_url, sizeof(out->exe_url));
    field(json, "$.exe_sha256", out->exe_sha, sizeof(out->exe_sha));
    field(json, "$.zip_url", out->zip_url, sizeof(out->zip_url));
    field(json, "$.zip_sha256", out->zip_sha, sizeof(out->zip_sha));
    if (out->exe_url[0] && !package_valid(out->tag, out->exe_url, out->exe_sha, "adblock-webserver-setup.exe")) return 0;
    if (out->zip_url[0] && !package_valid(out->tag, out->zip_url, out->zip_sha, "adblock-webserver-win64.zip")) return 0;
    out->preview = preview;
    return out->exe_url[0] || out->zip_url[0];
}

int update_feed_release(const char *body, unsigned index, int include_preview, struct release_pick *out) {
    char path[48]; int len = 0;
    struct mg_str all = mg_str(body);
    snprintf(path, sizeof(path), "$[%u]", index);
    int offset = mg_json_get(all, path, &len);
    if (offset < 0) return -1;
    struct mg_str json = mg_str_n(body + offset, (size_t)len);
    bool draft = true, preview = true;
    memset(out, 0, sizeof(*out));
    if (!mg_json_get_bool(json, "$.draft", &draft) || draft
        || !mg_json_get_bool(json, "$.prerelease", &preview) || (preview && !include_preview)
        || !field(json, "$.tag_name", out->tag, sizeof(out->tag))) return 0;
    out->preview = preview;
    if (preview) return valid_preview_tag(out->tag) ? 2 : 0;
    if (strncmp(out->tag, "win11-webserver-v", 17) || !numeric_version(out->tag + 17)) return 0;
    snprintf(out->ver, sizeof(out->ver), "%.63s", out->tag + 17);
    for (unsigned i = 0; i < 100; i++) {
        char url[1024], sha[128], name[128];
        snprintf(path, sizeof(path), "$.assets[%u].name", i);
        if (!field(json, path, name, sizeof(name))) break;
        int exe = !strcmp(name, "adblock-webserver-setup.exe");
        if (!exe && strcmp(name, "adblock-webserver-win64.zip")) continue;
        snprintf(path, sizeof(path), "$.assets[%u].browser_download_url", i);
        field(json, path, url, sizeof(url));
        snprintf(path, sizeof(path), "$.assets[%u].digest", i);
        field(json, path, sha, sizeof(sha));
        if (!package_valid(out->tag, url, sha, name)) continue;
        snprintf(exe ? out->exe_url : out->zip_url, 1024, "%s", url);
        snprintf(exe ? out->exe_sha : out->zip_sha, 128, "%s", sha);
        char api[512];
        const char *prefix = "https://api.github.com/repos/wxcvm/AdAway-Windows/releases/assets/";
        snprintf(path, sizeof(path), "$.assets[%u].url", i);
        if (field(json, path, api, sizeof(api)) && !strncmp(api, prefix, strlen(prefix))) {
            const char *id = api + strlen(prefix);
            if (*id && strlen(id) <= 20 && strspn(id, "0123456789") == strlen(id))
                snprintf(exe ? out->exe_api_url : out->zip_api_url, 512,
                         "https://api.github.com/repos/wxcvm/AdAway-Windows/releases/assets/%s", id);
        }
    }
    return out->exe_url[0] || out->zip_url[0];
}
