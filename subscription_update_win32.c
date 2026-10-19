#include "subscription_import.h"
#include "block_rule_snapshot.h"
#include "subscription_update_win32.h"
#include <io.h>
#include <wchar.h>

struct subscription_update_result subscription_update(const wchar_t *directory,
        const wchar_t urls[][SUBSCRIPTION_URL_CAPACITY], unsigned count,
        subscription_download download, void *context) {
    struct subscription_update_result result; memset(&result, 0, sizeof(result)); result.status = SUB_UPDATE_IO_FAILED;
    if (!directory || !*directory || !urls || count > SUBSCRIPTION_MAX_SOURCES || !download
            || wcslen(directory) > MAX_PATH - 40) return result;
    wchar_t target[MAX_PATH], lock_path[MAX_PATH], staging[MAX_PATH] = L"", input_path[MAX_PATH] = L"";
    if (swprintf(target, MAX_PATH, L"%ls\\subscriptions.txt", directory) < 0
            || swprintf(lock_path, MAX_PATH, L"%ls\\.subscription-update.lock", directory) < 0) return result;
    HANDLE lock = CreateFileW(lock_path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (lock == INVALID_HANDLE_VALUE) { result.status = GetLastError() == ERROR_SHARING_VIOLATION ? SUB_UPDATE_LOCKED : SUB_UPDATE_IO_FAILED; return result; }
    FILE *output = NULL;
    if (!GetTempFileNameW(directory, L"ads", 0, staging) || !GetTempFileNameW(directory, L"adi", 0, input_path)) goto cleanup;
    output = _wfopen(staging, L"wb"); if (!output) goto cleanup;
    struct si_stats stats; memset(&stats, 0, sizeof(stats));
    unsigned long long started = GetTickCount64();
    for (unsigned i = 0; i < count; i++) {
        result.failed_source = i;
        unsigned long long elapsed = GetTickCount64() - started;
        result.status = SUB_UPDATE_DOWNLOAD_FAILED;
        if (elapsed >= 180000u || !download(urls[i], input_path, DR_MAX_BYTES, (unsigned)(180000u - elapsed), context)) goto cleanup;
        FILE *input = _wfopen(input_path, L"rb"); if (!input) { result.status = SUB_UPDATE_IO_FAILED; goto cleanup; }
        size_t before = stats.entries;
        bool parsed = si_import_source(input, output, &stats, 2 + i); if (fclose(input) != 0) parsed = false;
        if (!parsed) { result.status = SUB_UPDATE_PARSE_FAILED; goto cleanup; }
        result.source_entries[i] = stats.entries - before;
    }
    result.status = SUB_UPDATE_IO_FAILED;
    if (ferror(output) || fflush(output) != 0 || _commit(_fileno(output)) != 0) goto cleanup;
    if (fclose(output) != 0) { output = NULL; goto cleanup; } output = NULL;
    // Validate the actual production index and name-pool bound before replacing
    // the last valid file. Successful text parsing alone is not a reload guarantee.
    result.status = SUB_UPDATE_PARSE_FAILED;
    FILE *verified = _wfopen(staging, L"rb");
    if (!verified) goto cleanup;
    struct bs_builder prepared; memset(&prepared, 0, sizeof(prepared));
    bool valid = bs_parse_file(verified, &prepared);
    if (fclose(verified) != 0) valid = false;
    valid = valid && bs_finish(&prepared);
    bs_free_builder(&prepared);
    if (!valid) goto cleanup;
    result.status = SUB_UPDATE_PUBLISH_FAILED;
    if (!MoveFileExW(staging, target, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) goto cleanup;
    staging[0] = 0; result.status = SUB_UPDATE_OK; result.entries = stats.entries; result.unsupported = stats.unsupported;
cleanup:
    if (output) fclose(output);
    if (staging[0]) DeleteFileW(staging);
    if (input_path[0]) DeleteFileW(input_path);
    CloseHandle(lock); return result;
}
