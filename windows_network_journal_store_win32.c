#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "windows_network_journal_store_win32.h"

enum { JOURNAL_FILE_SIZE = 8 + 4 + 4 + NETWORK_JOURNAL_MAX * 16 + 4 };
static const unsigned char JOURNAL_MAGIC[8] =
        {'A','D','N','E','T','J','0','1'};

static void put32(unsigned char *out, uint32_t v) {
    out[0] = (unsigned char)v;
    out[1] = (unsigned char)(v >> 8);
    out[2] = (unsigned char)(v >> 16);
    out[3] = (unsigned char)(v >> 24);
}
static uint32_t get32(const unsigned char *in) {
    return (uint32_t)in[0] | ((uint32_t)in[1] << 8)
            | ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
}
static void put64(unsigned char *out, uint64_t v) {
    put32(out, (uint32_t)v);
    put32(out + 4, (uint32_t)(v >> 32));
}
static uint64_t get64(const unsigned char *in) {
    return (uint64_t)get32(in) | ((uint64_t)get32(in + 4) << 32);
}
static uint32_t checksum(const unsigned char *data, size_t length) {
    uint32_t hash = UINT32_C(2166136261);
    for (size_t i = 0; i < length; ++i) {
        hash ^= data[i];
        hash *= UINT32_C(16777619);
    }
    return hash;
}

static bool serialize(const struct network_journal *journal,
                      unsigned char out[JOURNAL_FILE_SIZE]) {
    if (!journal || journal->count > NETWORK_JOURNAL_MAX) return false;
    memset(out, 0, JOURNAL_FILE_SIZE);
    memcpy(out, JOURNAL_MAGIC, sizeof(JOURNAL_MAGIC));
    put32(out + 8, journal->count);
    for (unsigned i = 0; i < journal->count; ++i) {
        const struct network_undo_entry *entry = &journal->entries[i];
        if (entry->kind < NETWORK_ACTION_ROUTE_ADD
                || entry->kind > NETWORK_ACTION_ADAPTER_CREATE
                || entry->token == 0) return false;
        size_t offset = 16 + (size_t)i * 16;
        put32(out + offset, (uint32_t)entry->kind);
        put32(out + offset + 4, entry->active ? 1 : 0);
        put64(out + offset + 8, entry->token);
    }
    put32(out + JOURNAL_FILE_SIZE - 4,
            checksum(out, JOURNAL_FILE_SIZE - 4));
    return true;
}

static bool deserialize(const unsigned char in[JOURNAL_FILE_SIZE],
                        struct network_journal *journal) {
    if (!journal
            || memcmp(in, JOURNAL_MAGIC, sizeof(JOURNAL_MAGIC)) != 0
            || get32(in + 12) != 0
            || get32(in + JOURNAL_FILE_SIZE - 4) !=
                    checksum(in, JOURNAL_FILE_SIZE - 4)) return false;
    uint32_t count = get32(in + 8);
    if (count > NETWORK_JOURNAL_MAX) return false;
    struct network_journal temp;
    memset(&temp, 0, sizeof(temp));
    temp.count = (unsigned)count;
    for (unsigned i = 0; i < NETWORK_JOURNAL_MAX; ++i) {
        size_t offset = 16 + (size_t)i * 16;
        uint32_t kind = get32(in + offset);
        uint32_t active = get32(in + offset + 4);
        uint64_t token = get64(in + offset + 8);
        if (i >= count) {
            if (kind != 0 || active != 0 || token != 0) return false;
            continue;
        }
        if (kind < NETWORK_ACTION_ROUTE_ADD || kind > NETWORK_ACTION_ADAPTER_CREATE
                || active > 1 || token == 0) return false;
        temp.entries[i].kind = (enum network_action_kind)kind;
        temp.entries[i].token = token;
        temp.entries[i].active = (active == 1);
    }
    *journal = temp;  /* never overwrite caller data on invalid input */
    return true;
}

bool network_journal_save_file(const wchar_t *path,
                               const struct network_journal *journal) {
    if (!path || path[0] == L'\0') return false;
    unsigned char bytes[JOURNAL_FILE_SIZE];
    if (!serialize(journal, bytes)) return false;

    size_t length = wcslen(path);
    if (length == 0 || length > 30000) return false;
    wchar_t *temporary = (wchar_t *)malloc((length + 5) * sizeof(wchar_t));
    if (!temporary) return false;
    wcscpy(temporary, path);
    wcscat(temporary, L".new");

    HANDLE handle = CreateFileW(temporary, GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        free(temporary);
        return false;
    }
    DWORD written = 0;
    bool ok = WriteFile(handle, bytes, sizeof(bytes), &written, NULL) != 0
            && written == sizeof(bytes)
            && FlushFileBuffers(handle) != 0;
    if (!CloseHandle(handle)) ok = false;
    if (ok) {
        ok = MoveFileExW(temporary, path,
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
    }
    if (!ok) DeleteFileW(temporary);
    free(temporary);
    return ok;
}

bool network_journal_load_file(const wchar_t *path,
                               struct network_journal *journal) {
    if (!path || path[0] == L'\0' || !journal) return false;
    HANDLE handle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER length;
    bool ok = GetFileSizeEx(handle, &length) != 0
            && length.QuadPart == JOURNAL_FILE_SIZE;
    unsigned char bytes[JOURNAL_FILE_SIZE];
    DWORD readCount = 0;
    if (ok) ok = ReadFile(handle, bytes, sizeof(bytes), &readCount, NULL) != 0
            && readCount == sizeof(bytes);
    CloseHandle(handle);
    return ok && deserialize(bytes, journal);
}
