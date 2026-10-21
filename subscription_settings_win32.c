#include "subscription_settings_win32.h"
#include <stdio.h>
#include <io.h>
#include <wchar.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

int subscription_settings_name_valid(const wchar_t *name) {
    if (!name) return 0;
    size_t length = 0;
    while (length < SUBSCRIPTION_NAME_CAPACITY && name[length]) {
        if (name[length] < 32 || name[length] == 127) return 0;
        length++;
    }
    if (length == SUBSCRIPTION_NAME_CAPACITY) return 0;
    return length == 0 || WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, name,
            (int)length, NULL, 0, NULL, NULL) > 0;
}

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
        const wchar_t status[][SUBSCRIPTION_STATUS_CAPACITY],
        const wchar_t names[][SUBSCRIPTION_NAME_CAPACITY], unsigned count) {
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
        if (names && !subscription_settings_name_valid(names[i])) goto cleanup;
        if (names && names[i][0] && (fputs("# name: ", file) < 0 ||
                !write_utf8(file, names[i], SUBSCRIPTION_NAME_CAPACITY) ||
                fputc('\n', file) == EOF)) goto cleanup;
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
    return save(directory, L"subscription_urls.txt", urls, NULL, NULL, count);
}
int subscription_settings_save_status(const wchar_t *directory,
        const wchar_t urls[][SUBSCRIPTION_URL_CAPACITY],
        const wchar_t status[][SUBSCRIPTION_STATUS_CAPACITY], unsigned count) {
    if (!status) return 0;
    return save(directory, L"subscription_status.txt", urls, status, NULL, count);
}

int subscription_settings_save_sources(const wchar_t *directory,
        const wchar_t urls[][SUBSCRIPTION_URL_CAPACITY],
        const wchar_t names[][SUBSCRIPTION_NAME_CAPACITY], unsigned count) {
    if (!names) return 0;
    return save(directory, L"subscription_urls.txt", urls, NULL, names, count);
}

struct source_stage {
    wchar_t urls[SUBSCRIPTION_MAX_SOURCES][SUBSCRIPTION_URL_CAPACITY];
    wchar_t names[SUBSCRIPTION_MAX_SOURCES][SUBSCRIPTION_NAME_CAPACITY];
};

int subscription_settings_load_sources(const wchar_t *directory,
        wchar_t urls[][SUBSCRIPTION_URL_CAPACITY],
        wchar_t names[][SUBSCRIPTION_NAME_CAPACITY], unsigned *count) {
    if (!directory || !*directory || !urls || !names || !count ||
            wcslen(directory) > MAX_PATH - 40) return 0;
    wchar_t path[MAX_PATH];
    if (swprintf(path, MAX_PATH, L"%ls\\subscription_urls.txt", directory) < 0) return 0;
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
        DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) return 0;
        memset(urls, 0, SUBSCRIPTION_MAX_SOURCES * sizeof(urls[0]));
        memset(names, 0, SUBSCRIPTION_MAX_SOURCES * sizeof(names[0]));
        *count = 0;
        return 1;
    }
    FILE *file = _wfopen(path, L"rb");
    if (!file) return 0;
    struct source_stage *stage = calloc(1, sizeof(*stage));
    if (!stage) { fclose(file); return 0; }
    char line[SUBSCRIPTION_URL_CAPACITY * 4 + 32];
    wchar_t pending[SUBSCRIPTION_NAME_CAPACITY] = L"";
    bool pending_name = false, first = true;
    unsigned used = 0;
    size_t bytes = 0;
    int result = 0;
    for (;;) {
        size_t length = 0;
        int ch;
        while ((ch = fgetc(file)) != EOF) {
            if (++bytes > SUBSCRIPTION_MAX_SOURCES *
                    (SUBSCRIPTION_URL_CAPACITY * 4 + SUBSCRIPTION_NAME_CAPACITY * 4 + 32) + 4096) goto cleanup_load;
            if (ch == '\n') break;
            if (!ch || length + 1 >= sizeof(line)) goto cleanup_load;
            line[length++] = (char)ch;
        }
        if (ferror(file)) goto cleanup_load;
        if (ch == EOF && length == 0) break;
        line[length] = 0;
        char *text = line;
        if (first && length >= 3 && memcmp(text, "\xef\xbb\xbf", 3) == 0) text += 3;
        first = false;
        while (*text == ' ' || *text == '\t') text++;
        size_t trimmed = strlen(text);
        if (trimmed && text[trimmed-1] == '\r') text[--trimmed] = 0;
        if (!*text) continue;
        if (strncmp(text, "# name:", 7) == 0) {
            if (pending_name) goto cleanup_load;
            text += 7;
            if (*text == ' ') text++;
            if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1,
                                    pending, SUBSCRIPTION_NAME_CAPACITY) ||
                    !subscription_settings_name_valid(pending)) goto cleanup_load;
            pending_name = true;
        } else if (*text != '#') {
            while (trimmed && (text[trimmed-1] == ' ' || text[trimmed-1] == '\t')) text[--trimmed] = 0;
            if (!trimmed) continue;
            if (used >= SUBSCRIPTION_MAX_SOURCES ||
                    !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1,
                                        stage->urls[used], SUBSCRIPTION_URL_CAPACITY)) goto cleanup_load;
            for (const wchar_t *p = stage->urls[used]; *p; p++)
                if (*p < 32 || *p == 127) goto cleanup_load;
            if (pending_name) memcpy(stage->names[used], pending, sizeof(pending));
            pending_name = false;
            pending[0] = 0;
            used++;
        }
    }
    if (pending_name) goto cleanup_load;
    if (fclose(file) != 0) { file = NULL; goto cleanup_load; }
    file = NULL;
    memcpy(urls, stage->urls, sizeof(stage->urls));
    memcpy(names, stage->names, sizeof(stage->names));
    *count = used;
    result = 1;
cleanup_load:
    if (file) fclose(file);
    free(stage);
    return result;
}
