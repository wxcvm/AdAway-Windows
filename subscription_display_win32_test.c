#include "subscription_display_win32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while (0)
static void vector(const wchar_t *url, const wchar_t *custom, const wchar_t *address, const wchar_t *title) {
    wchar_t out[1100];
    CHECK(subscription_display_url(url,out,1100)); CHECK(!wcscmp(out,address));
    CHECK(subscription_display_name(url,custom,out,1100)); CHECK(!wcscmp(out,title));
}
int main(void) {
    vector(L"https://raw.githubusercontent.com/owner/rules/main/hosts",L"",
        L"https://raw.githubusercontent.com/owner/rules/main/hosts",L"owner/rules · hosts");
    vector(L"https://user:password@raw.githubusercontent.com/owner/rules/refs/heads/main/hosts?token=secret#private",NULL,
        L"https://raw.githubusercontent.com/owner/rules/refs/heads/main/hosts",L"owner/rules · hosts");
    vector(L"https://github.com/owner/rules/",NULL,L"https://github.com/owner/rules/",L"owner/rules");
    vector(L"https://www.example.test/raw?key=secret",L"raw",L"https://www.example.test/raw",L"raw");
    vector(L"https://example.test?key=secret",NULL,L"https://example.test",L"example.test");
    vector(L"https://example.test/raw?key=secret",L"自定义规则",L"https://example.test/raw",L"自定义规则");
    vector(L"http://[::1]:8080/list#private",NULL,L"http://[::1]:8080/list",L"[::1] · list");
    vector(L"https://example.test:8443/path/",NULL,L"https://example.test:8443/path/",L"example.test · path");
    const wchar_t *bad[] = {L"ftp://secret.test/a",L"https://",L"https:///bad",L"https://example.test/a\nsecret",
        L"https://example.test/a\\secret",L"https://example.test/\xd800"};
    for (size_t i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
        wchar_t out[1024]; CHECK(!subscription_display_url(bad[i],out,1024));
        CHECK(!wcscmp(out,L"地址无效或无法显示"));
    }
    wchar_t bounded[6]={L'x',L'x',L'x',L'x',L'x',L'x'};
    CHECK(subscription_display_name(L"https://example.test",L"a\xd83d\xde03" L"bc",bounded+1,4));
    CHECK(bounded[0]==L'x' && bounded[5]==L'x' && bounded[3]==0 && bounded[2]==0x2026);
    CHECK(subscription_display_url(L"https://example.test",bounded+1,1) && bounded[1]==0);
    CHECK(subscription_display_url(L"https://example.test",bounded+1,2) && bounded[1]==0x2026 && bounded[2]==0);
    puts("Source display: actual WinHTTP parsing, privacy, Unicode and bounded output passed");
    return 0;
}
