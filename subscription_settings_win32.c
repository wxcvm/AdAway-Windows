#include "subscription_settings_win32.h"
#include <stdio.h>
#include <io.h>
#include <wchar.h>

static int write_utf8(FILE *file, const wchar_t *value, size_t capacity) {
    size_t length = 0;
    while (length < capacity && value[length]) {
        if (value[length] == L'\r' || value[length] == L'\n' || value[length] == L'\t') return 0;
        length++;
    }
    if (length == capacity) return 0;
    if (!length) return 1;
    char utf8[SUBSCRIPTION_URL_CAPACITY * 4];
    int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, (int)length,
                                  utf8, (int)sizeof(utf8), NULL, NULL);
    return bytes > 0 && fwrite(utf8, 1, (size_t)bytes, file) == (size_t)bytes;
}

static int save(const wchar_t *directory, const wchar_t *name,
        const wchar_t urls[][SUBSCRIPTION_URL_CAPACITY],
        const wchar_t status[][SUBSCRIPTION_STATUS_CAPACITY], unsigned count) {
    if (!directory || !*directory || !urls || count > SUBSCRIPTION_MAX_SOURCES
            || wcslen(directory) > MAX_PATH - 40) return 0;
    wchar_t target[MAX_PATH], lock_path[MAX_PATH], staging[MAX_PATH] = L"";
    if (swprintf(target, MAX_PATH, L"%ls\\%ls", directory, name) < 0
            || swprintf(lock_path, MAX_PATH, L"%ls\\.subscription-settings.lock", directory) < 0) return 0;
    HANDLE lock = CreateFileW(lock_path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                             OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (lock == INVALID_HANDLE_VALUE) return 0;
    FILE *file = NULL;
    int result = 0;
    if (!GetTempFileNameW(directory, L"asc", 0, staging)) goto cleanup;
    file = _wfopen(staging, L"wb");
    if (!file) goto cleanup;
    if (!status && fputs("# ADBlock subscription sources (UTF-8)\n", file) < 0) goto cleanup;
    for (unsigned i = 0; i < count; i++) {
        if (!urls[i][0] || !write_utf8(file, urls[i], SUBSCRIPTION_URL_CAPACITY)) goto cleanup;
        if (status && (fputc('\t', file) == EOF
                || !write_utf8(file, status[i], SUBSCRIPTION_STATUS_CAPACITY))) goto cleanup;
        if (fputc('\n', file) == EOF) goto cleanup;
    }
    if (ferror(file) || fflush(file) != 0 || _commit(_fileno(file)) != 0) goto cleanup;
    if (fclose(file) != 0) { file = NULL; goto cleanup; }
    file = NULL;
    if (!MoveFileExW(staging, target, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) goto cleanup;
    staging[0] = 0;
    result = 1;
cleanup:
    if (file) fclose(file);
    if (staging[0]) DeleteFileW(staging);
    CloseHandle(lock);
    return result;
}

int subscription_settings_save_urls(const wchar_t *directory,
        const wchar_t urls[][SUBSCRIPTION_URL_CAPACITY], unsigned count) {
    return save(directory, L"subscription_urls.txt", urls, NULL, count);
}
int subscription_settings_save_status(const wchar_t *directory,
        const wchar_t urls[][SUBSCRIPTION_URL_CAPACITY],
        const wchar_t status[][SUBSCRIPTION_STATUS_CAPACITY], unsigned count) {
    if (!status) return 0;
    return save(directory, L"subscription_status.txt", urls, status, count);
}
