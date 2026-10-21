#include "policy_settings_win32.h"
#include <windows.h>
#include <stdio.h>
#include <io.h>
#include <string.h>

static int valid_key(const char *key) {
    if (!key || !*key) return 0;
    size_t length = 0;
    while (length < 64 && key[length]) {
        unsigned char ch = (unsigned char)key[length++];
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9') || ch == '_')) return 0;
    }
    return length < 64;
}

int policy_settings_save(const wchar_t *directory,
                         const struct policy_setting *settings, size_t count) {
    if (!directory || !*directory || !settings || count != POLICY_SETTINGS_COUNT ||
            wcslen(directory) > MAX_PATH - 40) return 0;
    for (size_t i = 0; i < count; i++) {
        if (!valid_key(settings[i].reply_key) || !valid_key(settings[i].mode_key) ||
                settings[i].mode < 0 || settings[i].mode > 3 ||
                strcmp(settings[i].reply_key, settings[i].mode_key) == 0) return 0;
        for (size_t j = 0; j < i; j++)
            if (!strcmp(settings[i].reply_key, settings[j].reply_key) ||
                !strcmp(settings[i].reply_key, settings[j].mode_key) ||
                !strcmp(settings[i].mode_key, settings[j].reply_key) ||
                !strcmp(settings[i].mode_key, settings[j].mode_key)) return 0;
    }
    wchar_t target[MAX_PATH], lock_path[MAX_PATH], staged[MAX_PATH] = L"";
    if (swprintf(target, MAX_PATH, L"%ls\\block_config.json", directory) < 0 ||
            swprintf(lock_path, MAX_PATH, L"%ls\\.policy-settings.lock", directory) < 0) return 0;
    HANDLE lock = CreateFileW(lock_path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                             OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (lock == INVALID_HANDLE_VALUE) return 0;
    FILE *file = NULL;
    int result = 0;
    if (!GetTempFileNameW(directory, L"pol", 0, staged)) goto done;
    file = _wfopen(staged, L"wb");
    if (!file || fputs("{\n", file) < 0) goto done;
    for (size_t i = 0; i < count; i++)
        if (fprintf(file, "  \"%s\": %s,\n", settings[i].reply_key,
                    settings[i].mode != 2 ? "true" : "false") < 0) goto done;
    for (size_t i = 0; i < count; i++)
        if (fprintf(file, "  \"%s\": %d%s\n", settings[i].mode_key, settings[i].mode,
                    i + 1 < count ? "," : "") < 0) goto done;
    if (fputs("}\n", file) < 0 || ferror(file) || fflush(file) != 0 ||
            _commit(_fileno(file)) != 0) goto done;
    if (fclose(file) != 0) { file = NULL; goto done; }
    file = NULL;
    if (!MoveFileExW(staged, target, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) goto done;
    staged[0] = 0;
    result = 1;
done:
    if (file) fclose(file);
    if (staged[0]) DeleteFileW(staged);
    CloseHandle(lock);
    return result;
}
