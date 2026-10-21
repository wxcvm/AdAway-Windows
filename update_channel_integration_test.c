/* Real updater discovery and persistent settings, with isolated HTTP fixtures. */
#define UPDATE_FEED_TEST_HTTP 1
#include "update_win32.c"
#include <assert.h>

static unsigned requests, preview_requests;
static const char *stable_body;
static const char *preview_body;
static const char *api_body;

void win32_log_line(const char *format, ...) { (void)format; }
char *update_fixture_get(const wchar_t *host, const wchar_t *path, size_t *len, DWORD *status) {
    (void)host;
    requests++;
    const char *body=stable_body;
    if (wcsstr(path,L"preview") || wcsstr(path,L"progress-win-")) { preview_requests++; body=preview_body; }
    if (wcsstr(path,L"/repos/")) body=api_body;
    if (!body) { *status=404; *len=0; return NULL; }
    *status=200; *len=strlen(body);
    char *copy=malloc(*len+1); assert(copy); memcpy(copy,body,*len+1); return copy;
}

int main(void) {
    wchar_t ini[MAX_PATH]; struct release_pick pick; DWORD status=0;
    assert(ini_path(ini,MAX_PATH));
    /* Never overwrite a developer or installed application's settings. */
    assert(GetFileAttributesW(ini)==INVALID_FILE_ATTRIBUTES);
    stable_body="{\"tag\":\"win11-webserver-v1.75\",\"version\":\"1.75\","
        "\"zip_url\":\"https://github.com/wxcvm/AdAway-Windows/releases/download/win11-webserver-v1.75/adblock-webserver-win64.zip\","
        "\"zip_sha256\":\"610d5bf14041fff0347fc9c3c08cccc4295a654d0b1bbb87c82f555d37b97796\"}";
    /* Same app version, newer build: remain meaningful across app version bumps. */
    preview_body="{\"version\":\"" ADBLOCK_APP_VERSION "\",\"tag\":\"progress-win-20261020.4\",\"channel\":\"preview\",\"build\":\"99999999999999999999\","
        "\"exe_url\":\"https://github.com/wxcvm/AdAway-Windows/releases/download/progress-win-20261020.4/adblock-webserver-setup.exe\","
        "\"exe_sha256\":\"sha256:1177114d9bf58f070579b9da2ad373931010f701bb1f1432941cb15ad2526da9\"}";
    assert(!update_include_preview());
    assert(manifest_check(&pick,&status)==0); assert(preview_requests==0);
    assert(update_set_include_preview(1)); assert(update_include_preview());
    assert(manifest_check(&pick,&status)==1); assert(pick.preview); assert(preview_requests==1);
    wchar_t installer[1024], api[1024], alt[1024], alt_api[1024]; char sha[128], alt_sha[128];
    release_pick_choose(&pick,installer,1024,sha,128,api,1024,alt,1024,alt_sha,128,alt_api,1024);
    assert(wcsstr(installer,L"progress-win-20261020.4/adblock-webserver-setup.exe"));
    assert(!strcmp(sha,pick.exe_sha));
    InterlockedExchange(&s_update_state,UPDATE_STATE_CHECKING);
    assert(!update_set_include_preview(0)); assert(update_include_preview());
    InterlockedExchange(&s_update_state,UPDATE_STATE_IDLE);
    char enabled_cache[MAX_PATH*3], disabled_cache[MAX_PATH*3];
    update_cache_path(enabled_cache,sizeof(enabled_cache));
    assert(update_set_include_preview(0));
    update_cache_path(disabled_cache,sizeof(disabled_cache));
    assert(strcmp(enabled_cache,disabled_cache));
    assert(manifest_check(&pick,&status)==0); assert(preview_requests==1);
    struct update_info stale={0}; wcscpy(stale.tag,L"progress-win-20261020.4");
    update_apply_async(NULL,&stale); assert(update_state()==UPDATE_STATE_IDLE);
    api_body="[{\"draft\":false,\"prerelease\":true,\"tag_name\":\"progress-win-20261020.4\"}]";
    assert(find_latest_update(&pick,&status)<0);
    assert(update_set_include_preview(1));
    assert(find_latest_update(&pick,&status)==1); assert(pick.preview);
    assert(DeleteFileW(ini));
    printf("Actual updater: channel settings, stable short-circuit fix, immutable package/digest selection, cache isolation, busy/stale offer guards and API fallback passed (%u requests)\n",requests);
    return 0;
}
