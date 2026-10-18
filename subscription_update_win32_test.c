#include "subscription_import.h"
#include "subscription_update_win32.h"
#include <wchar.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
struct fixture { unsigned calls; int failure; const char *first, *second; };
static int download(const wchar_t *url, const wchar_t *path, unsigned long long limit, unsigned budget, void *opaque) {
    (void)url; struct fixture *fixture = (struct fixture *)opaque;
    CHECK(limit == DR_MAX_BYTES && budget > 0 && budget <= 180000);
    unsigned call = fixture->calls++;
    if (fixture->failure == (int)call) return 0;
    const char *text = call ? fixture->second : fixture->first;
    FILE *file = _wfopen(path, L"wb"); CHECK(file);
    CHECK(fwrite(text, 1, strlen(text), file) == strlen(text)); CHECK(fclose(file) == 0); return 1;
}
static void assert_old(const wchar_t *path) {
    char bytes[64] = {0}; FILE *file = _wfopen(path, L"rb"); CHECK(file);
    CHECK(fread(bytes, 1, sizeof(bytes) - 1, file) == strlen("0.0.0.0 old.test\n")); CHECK(fclose(file) == 0);
    CHECK(strcmp(bytes, "0.0.0.0 old.test\n") == 0);
}
int main(void) {
    wchar_t temporary[MAX_PATH], directory[MAX_PATH], target[MAX_PATH], lock_path[MAX_PATH];
    CHECK(GetTempPathW(MAX_PATH, temporary) > 0); CHECK(GetTempFileNameW(temporary, L"asu", 0, directory));
    CHECK(DeleteFileW(directory)); CHECK(CreateDirectoryW(directory, NULL));
    CHECK(swprintf(target, MAX_PATH, L"%ls\\subscriptions.txt", directory) > 0);
    CHECK(swprintf(lock_path, MAX_PATH, L"%ls\\.subscription-update.lock", directory) > 0);
    FILE *old = _wfopen(target, L"wb"); CHECK(old); CHECK(fputs("0.0.0.0 old.test\n", old) >= 0); CHECK(fclose(old) == 0);
    const wchar_t urls[2][SUBSCRIPTION_URL_CAPACITY] = {L"https://fixture.test/one", L"https://fixture.test/two"};
    struct fixture fixture = {0, 1, "0.0.0.0 new.test\n", "@@||new.test^\n"};
    struct subscription_update_result result = subscription_update(directory, urls, 2, download, &fixture);
    CHECK(result.status == SUB_UPDATE_DOWNLOAD_FAILED && result.failed_source == 1); assert_old(target);
    fixture = (struct fixture){0, -1, "0.0.0.0 new.test\n", "999.1.1.1 bad.test\n"};
    result = subscription_update(directory, urls, 2, download, &fixture);
    CHECK(result.status == SUB_UPDATE_PARSE_FAILED); assert_old(target);
    HANDLE lock = CreateFileW(lock_path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); CHECK(lock != INVALID_HANDLE_VALUE);
    fixture.calls = 0; result = subscription_update(directory, urls, 2, download, &fixture);
    CHECK(result.status == SUB_UPDATE_LOCKED && fixture.calls == 0); assert_old(target); CHECK(CloseHandle(lock));
    HANDLE reader = CreateFileW(target, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); CHECK(reader != INVALID_HANDLE_VALUE);
    fixture = (struct fixture){0, -1, "0.0.0.0 new.test\n", "@@||new.test^\n||conditional.test^$script\n"};
    result = subscription_update(directory, urls, 2, download, &fixture);
    CHECK(result.status == SUB_UPDATE_PUBLISH_FAILED); CHECK(CloseHandle(reader)); assert_old(target);
    fixture.calls = 0; result = subscription_update(directory, urls, 2, download, &fixture);
    CHECK(result.status == SUB_UPDATE_OK && result.entries == 2 && result.unsupported == 1);
    char bytes[256] = {0}; FILE *file = _wfopen(target, L"rb"); CHECK(file); CHECK(fread(bytes, 1, sizeof(bytes) - 1, file) > 0); CHECK(fclose(file) == 0);
    CHECK(strcmp(bytes, "@adaway-rule-v1\t2\t1\t0\t0\tnew.test\t-\n@adaway-rule-v1\t3\t1\t1\t1\tnew.test\t-\n") == 0);
    CHECK(DeleteFileW(target)); CHECK(DeleteFileW(lock_path)); CHECK(RemoveDirectoryW(directory));
    puts("Actual Windows subscription transaction: download/parse/lock/atomic-replace failure rollback and complete success passed; no networking or OS changes");
    return 0;
}
