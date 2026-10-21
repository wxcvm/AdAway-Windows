#include "subscription_display_win32.h"
#include "subscription_settings_win32.h"
#include <winhttp.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static void display_copy(wchar_t *out, size_t capacity, const wchar_t *text) {
    if (!out || !capacity) return;
    size_t length = wcslen(text);
    if (length < capacity) { memcpy(out, text, (length + 1) * sizeof(*out)); return; }
    if (capacity == 1) { out[0] = 0; return; }
    size_t keep = capacity - 2;
    if (keep && text[keep-1] >= 0xd800 && text[keep-1] <= 0xdbff) keep--;
    memcpy(out, text, keep * sizeof(*out));
    out[keep++] = 0x2026;
    out[keep] = 0;
}

struct display_parts {
    wchar_t host[SUBSCRIPTION_URL_CAPACITY];
    wchar_t path[SUBSCRIPTION_URL_CAPACITY];
    unsigned port;
    bool https;
};

static bool parse(const wchar_t *url, struct display_parts *parts) {
    if (!url) return false;
    size_t length = 0;
    while (length < SUBSCRIPTION_URL_CAPACITY && url[length]) {
        if (url[length] <= 32 || url[length] == 127 || url[length] == L'\\') return false;
        length++;
    }
    if (length == 0 || length == SUBSCRIPTION_URL_CAPACITY ||
            !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, url, (int)length, NULL, 0, NULL, NULL)) return false;
    size_t scheme = _wcsnicmp(url, L"https://", 8) == 0 ? 8 :
                    _wcsnicmp(url, L"http://", 7) == 0 ? 7 : 0;
    if (!scheme || length <= scheme || wcschr(L"/?#", url[scheme])) return false;
    /* WinHTTP documents an ambiguous bare-host query form. Strip extras before
       cracking, and still request ExtraInfo so it never becomes part of path. */
    wchar_t clean[SUBSCRIPTION_URL_CAPACITY];
    size_t end = wcscspn(url, L"?#");
    memcpy(clean, url, end * sizeof(*url)); clean[end] = 0;
    URL_COMPONENTS value;
    memset(&value, 0, sizeof(value)); value.dwStructSize = sizeof(value);
    value.dwHostNameLength = value.dwUrlPathLength = value.dwExtraInfoLength = (DWORD)-1;
    if (!WinHttpCrackUrl(clean, (DWORD)end, 0, &value) ||
            (value.nScheme != INTERNET_SCHEME_HTTP && value.nScheme != INTERNET_SCHEME_HTTPS) ||
            !value.dwHostNameLength || value.dwHostNameLength >= SUBSCRIPTION_URL_CAPACITY ||
            value.dwUrlPathLength >= SUBSCRIPTION_URL_CAPACITY) return false;
    memcpy(parts->host, value.lpszHostName, value.dwHostNameLength * sizeof(wchar_t));
    parts->host[value.dwHostNameLength] = 0;
    if (wcspbrk(parts->host, L"@/?#")) return false;
    if (value.dwUrlPathLength) memcpy(parts->path, value.lpszUrlPath, value.dwUrlPathLength * sizeof(wchar_t));
    parts->path[value.dwUrlPathLength] = 0;
    parts->port = value.nPort; parts->https = value.nScheme == INTERNET_SCHEME_HTTPS;
    return parts->port != 0;
}

int subscription_display_url(const wchar_t *url, wchar_t *out, size_t capacity) {
    struct display_parts parts;
    if (!parse(url, &parts)) { display_copy(out, capacity, L"地址无效或无法显示"); return 0; }
    wchar_t host[SUBSCRIPTION_URL_CAPACITY + 4], port[16] = L"", text[SUBSCRIPTION_URL_CAPACITY + 32];
    if (wcschr(parts.host, L':') && parts.host[0] != L'[')
        swprintf(host, SUBSCRIPTION_URL_CAPACITY + 4, L"[%ls]", parts.host);
    else { wcscpy(host, parts.host); }
    if (parts.port != (parts.https ? 443u : 80u)) swprintf(port, 16, L":%u", parts.port);
    int written = swprintf(text, SUBSCRIPTION_URL_CAPACITY + 32, L"%ls://%ls%ls%ls",
                          parts.https ? L"https" : L"http", host, port, parts.path);
    if (written < 0 || written >= SUBSCRIPTION_URL_CAPACITY + 32) {
        display_copy(out, capacity, L"地址过长，无法显示"); return 0;
    }
    display_copy(out, capacity, text);
    return 1;
}

int subscription_display_name(const wchar_t *url, const wchar_t *custom,
                              wchar_t *out, size_t capacity) {
    if (custom && *custom) {
        if (!subscription_settings_name_valid(custom)) { display_copy(out, capacity, L"订阅源"); return 0; }
        display_copy(out, capacity, custom); return 1;
    }
    struct display_parts parts;
    if (!parse(url, &parts)) { display_copy(out, capacity, L"订阅源"); return 0; }
    wchar_t *first = parts.path;
    while (*first == L'/') first++;
    size_t length = wcslen(first);
    while (length && first[length-1] == L'/') first[--length] = 0;
    wchar_t *last = wcsrchr(first, L'/'); last = last ? last + 1 : first;
    wchar_t text[SUBSCRIPTION_URL_CAPACITY + 32];
    int written;
    if ((_wcsicmp(parts.host, L"raw.githubusercontent.com") == 0 ||
            _wcsicmp(parts.host, L"github.com") == 0) && *first) {
        wchar_t *slash = wcschr(first, L'/');
        if (slash && slash[1]) {
            wchar_t *repo = slash + 1, *repo_end = wcschr(repo, L'/');
            if (repo_end) *repo_end = 0;
            *slash = 0;
            written = swprintf(text, SUBSCRIPTION_URL_CAPACITY + 32, L"%ls/%ls%ls%ls",
                first, repo, repo_end ? L" · " : L"", repo_end ? last : L"");
        } else written = swprintf(text, SUBSCRIPTION_URL_CAPACITY + 32, L"%ls · %ls", parts.host, first);
    } else {
        const wchar_t *host = _wcsnicmp(parts.host, L"www.", 4) == 0 ? parts.host + 4 : parts.host;
        written = swprintf(text, SUBSCRIPTION_URL_CAPACITY + 32, L"%ls%ls%ls", host, *last ? L" · " : L"", last);
    }
    if (written < 0 || written >= SUBSCRIPTION_URL_CAPACITY + 32) {
        display_copy(out, capacity, L"订阅源"); return 0;
    }
    display_copy(out, capacity, text);
    return 1;
}
