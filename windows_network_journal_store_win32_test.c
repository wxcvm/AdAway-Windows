#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "windows_network_journal_store_win32.h"

static bool fake_undo(enum network_action_kind kind, uint64_t token, void *ctx) {
    (void)kind;
    unsigned *counter = (unsigned *)ctx;
    ++*counter;
    return token != 42;
}

int main(void) {
    wchar_t folder[MAX_PATH], path[MAX_PATH];
    DWORD len = GetTempPathW(MAX_PATH, folder);
    assert(len > 0 && len < MAX_PATH);
    assert(GetTempFileNameW(folder, L"adj", 0, path) != 0);
    assert(DeleteFileW(path));

    struct network_journal original = {0}, recovered = {0};
    assert(network_journal_record(&original, NETWORK_ACTION_ADAPTER_CREATE, 123));
    assert(network_journal_record(&original, NETWORK_ACTION_ROUTE_ADD, 42));
    assert(network_journal_record(&original, NETWORK_ACTION_DNS_CHANGE, 77));
    assert(network_journal_save_file(path, &original));
    assert(network_journal_load_file(path, &recovered));
    assert(recovered.count == 3);
    assert(recovered.entries[0].token == 123);
    assert(recovered.entries[1].token == 42);
    assert(recovered.entries[2].token == 77);

    unsigned calls = 0;
    assert(network_journal_rollback(&recovered, fake_undo, &calls) == 1);
    assert(calls == 3 && !network_journal_is_clean(&recovered));
    assert(network_journal_save_file(path, &recovered));
    struct network_journal pending = {0};
    assert(network_journal_load_file(path, &pending));
    assert(!pending.entries[0].active);
    assert(pending.entries[1].active);
    assert(!pending.entries[2].active);

    /* Manual corruption must never be read as a recoverable journal. */
    HANDLE handle = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    assert(handle != INVALID_HANDLE_VALUE);
    LARGE_INTEGER seek;
    seek.QuadPart = 20;
    assert(SetFilePointerEx(handle, seek, NULL, FILE_BEGIN));
    BYTE invalid = 0;
    DWORD n = 0;
    assert(ReadFile(handle, &invalid, 1, &n, NULL) && n == 1);
    invalid ^= 0x80;
    assert(SetFilePointerEx(handle, seek, NULL, FILE_BEGIN));
    assert(WriteFile(handle, &invalid, 1, &n, NULL) && n == 1);
    CloseHandle(handle);
    struct network_journal sentinel = {0};
    sentinel.count = 7;
    assert(!network_journal_load_file(path, &sentinel));
    assert(sentinel.count == 7); /* invalid input cannot corrupt live state */

    /* A fresh valid replace restores the ability to load. */
    assert(network_journal_save_file(path, &original));
    assert(network_journal_load_file(path, &recovered));
    assert(recovered.count == 3);

    /* Concurrent owners cannot overwrite/read a transaction mid-operation. */
    wchar_t lockpath[MAX_PATH + 6];
    swprintf(lockpath, MAX_PATH + 6, L"%ls.lock", path);
    HANDLE lock = CreateFileW(lockpath, GENERIC_READ | GENERIC_WRITE, 0, NULL,
            OPEN_EXISTING, 0, NULL);
    assert(lock != INVALID_HANDLE_VALUE);
    assert(!network_journal_save_file(path, &original));
    sentinel.count = 7;
    assert(!network_journal_load_file(path, &sentinel));
    assert(sentinel.count == 7);
    CloseHandle(lock);
    assert(network_journal_load_file(path, &recovered));

    /* A truncated write cannot replace the caller's current in-memory model. */
    handle = CreateFileW(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    assert(handle != INVALID_HANDLE_VALUE);
    seek.QuadPart = 16;
    assert(SetFilePointerEx(handle, seek, NULL, FILE_BEGIN) && SetEndOfFile(handle));
    CloseHandle(handle);
    sentinel.count = 7;
    assert(!network_journal_load_file(path, &sentinel));
    assert(sentinel.count == 7);
    assert(network_journal_save_file(path, &original));

    assert(!network_journal_save_file(NULL, &original));
    assert(!network_journal_load_file(NULL, &recovered));
    assert(!network_journal_save_file(path, NULL));

    DeleteFileW(path);
    DeleteFileW(lockpath);
    puts("Windows model journal: DPAPI, lock contention, atomic replace, tampering and truncation passed");
    return 0;
}
