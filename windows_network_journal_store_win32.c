#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <sddl.h>
#include <aclapi.h>
#include <wincrypt.h>
#include <bcrypt.h>
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

static const unsigned char SEALED_MAGIC[8] = {'A','D','N','E','T','P','0','2'};

/* Explicit current-user owner and protected DACL; no inherited broad access. */
static PSECURITY_DESCRIPTOR private_security(void) {
    HANDLE token = NULL;
    DWORD size = 0;
    PSECURITY_DESCRIPTOR result = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return NULL;
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    TOKEN_USER *user = (TOKEN_USER *)malloc(size);
    wchar_t *sid = NULL;
    if (user && GetTokenInformation(token, TokenUser, user, size, &size)
            && ConvertSidToStringSidW(user->User.Sid, &sid)) {
        size_t capacity = wcslen(sid) * 2 + 64;
        wchar_t *sddl = (wchar_t *)malloc(capacity * sizeof(wchar_t));
        if (sddl) {
            swprintf(sddl, capacity, L"O:%lsD:P(A;;FA;;;SY)(A;;FA;;;%ls)", sid, sid);
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,
                    SDDL_REVISION_1, &result, NULL)) result = NULL;
            free(sddl);
        }
        LocalFree(sid);
    }
    free(user);
    CloseHandle(token);
    return result;
}

static bool owned_regular(HANDLE file, PSECURITY_DESCRIPTOR expected) {
    BY_HANDLE_FILE_INFORMATION info;
    PSID wanted = NULL, actual = NULL;
    BOOL defaulted = FALSE;
    PSECURITY_DESCRIPTOR security = NULL;
    if (!GetFileInformationByHandle(file, &info)
            || (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))
            || !GetSecurityDescriptorOwner(expected, &wanted, &defaulted)) return false;
    DWORD status = GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
            &actual, NULL, NULL, NULL, &security);
    bool ok = status == ERROR_SUCCESS && actual && EqualSid(actual, wanted);
    if (security) LocalFree(security);
    return ok;
}

static HANDLE lock_store(const wchar_t *path, PSECURITY_DESCRIPTOR security) {
    size_t length = wcslen(path);
    if (!length || length > 30000) return INVALID_HANDLE_VALUE;
    wchar_t *lockpath = (wchar_t *)malloc((length + 6) * sizeof(wchar_t));
    if (!lockpath) return INVALID_HANDLE_VALUE;
    wcscpy(lockpath, path); wcscat(lockpath, L".lock");
    SECURITY_ATTRIBUTES attrs = {sizeof(attrs), security, FALSE};
    HANDLE lock = CreateFileW(lockpath, GENERIC_READ | GENERIC_WRITE, 0, &attrs,
            OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    free(lockpath);
    if (lock != INVALID_HANDLE_VALUE && !owned_regular(lock, security)) {
        CloseHandle(lock); lock = INVALID_HANDLE_VALUE;
    }
    return lock; /* Persistent filename, exclusive handle: no unlink/open race. */
}

bool network_journal_save_file(const wchar_t *path, const struct network_journal *journal) {
    if (!path || !path[0]) return false;
    unsigned char bytes[JOURNAL_FILE_SIZE];
    if (!serialize(journal, bytes)) return false;
    PSECURITY_DESCRIPTOR security = private_security();
    if (!security) return false;
    HANDLE lock = lock_store(path, security);
    if (lock == INVALID_HANDLE_VALUE) { LocalFree(security); return false; }
    HANDLE previous = CreateFileW(path, READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    bool target_ok = previous == INVALID_HANDLE_VALUE
            ? GetLastError() == ERROR_FILE_NOT_FOUND : owned_regular(previous, security);
    if (previous != INVALID_HANDLE_VALUE) CloseHandle(previous);
    if (!target_ok) { CloseHandle(lock); LocalFree(security); return false; }
    DATA_BLOB input = {sizeof(bytes), bytes}, sealed = {0};
    bool ok = CryptProtectData(&input, L"ADBlock diagnostic journal model", NULL, NULL, NULL,
            CRYPTPROTECT_UI_FORBIDDEN, &sealed) != 0;
    size_t length = wcslen(path);
    wchar_t *temporary = (wchar_t *)malloc((length + 40) * sizeof(wchar_t));
    unsigned char nonce[16];
    HANDLE file = INVALID_HANDLE_VALUE;
    if (!temporary || !ok || sealed.cbData > 65520 ||
            BCryptGenRandom(NULL, nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) ok = false;
    if (ok) {
        wcscpy(temporary, path); wcscat(temporary, L".new-");
        for (unsigned i = 0; i < sizeof(nonce); i++)
            swprintf(temporary + length + 5 + i * 2, 3, L"%02x", (unsigned)nonce[i]);
        SECURITY_ATTRIBUTES attrs = {sizeof(attrs), security, FALSE};
        file = CreateFileW(temporary, GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES, 0, &attrs, CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        ok = file != INVALID_HANDLE_VALUE && owned_regular(file, security);
    }
    if (ok) {
        unsigned char header[12]; DWORD written = 0;
        memcpy(header, SEALED_MAGIC, 8); put32(header + 8, sealed.cbData);
        ok = WriteFile(file, header, sizeof(header), &written, NULL) && written == sizeof(header)
                && WriteFile(file, sealed.pbData, sealed.cbData, &written, NULL) && written == sealed.cbData
                && FlushFileBuffers(file);
    }
    if (file != INVALID_HANDLE_VALUE) {
        if (!CloseHandle(file)) ok = false;
        if (ok) ok = MoveFileExW(temporary, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
        if (!ok) DeleteFileW(temporary);
    }
    if (sealed.pbData) LocalFree(sealed.pbData);
    SecureZeroMemory(bytes, sizeof(bytes));
    free(temporary); CloseHandle(lock); LocalFree(security);
    return ok;
}

bool network_journal_load_file(const wchar_t *path, struct network_journal *journal) {
    if (!path || !path[0] || !journal) return false;
    PSECURITY_DESCRIPTOR security = private_security();
    if (!security) return false;
    HANDLE lock = lock_store(path, security);
    if (lock == INVALID_HANDLE_VALUE) { LocalFree(security); return false; }
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    LARGE_INTEGER size;
    bool ok = file != INVALID_HANDLE_VALUE && owned_regular(file, security)
            && GetFileSizeEx(file, &size) && size.QuadPart >= 12 && size.QuadPart <= 65536;
    unsigned char *bytes = ok ? (unsigned char *)malloc((size_t)size.QuadPart) : NULL;
    DWORD read = 0;
    if (ok) ok = bytes && ReadFile(file, bytes, (DWORD)size.QuadPart, &read, NULL)
            && read == (DWORD)size.QuadPart && memcmp(bytes, SEALED_MAGIC, 8) == 0
            && get32(bytes + 8) == read - 12;
    DATA_BLOB plain = {0};
    if (ok) {
        DATA_BLOB sealed = {read - 12, bytes + 12};
        ok = CryptUnprotectData(&sealed, NULL, NULL, NULL, NULL,
                CRYPTPROTECT_UI_FORBIDDEN, &plain) && plain.cbData == JOURNAL_FILE_SIZE;
        if (ok) ok = deserialize(plain.pbData, journal);
    }
    if (plain.pbData) { SecureZeroMemory(plain.pbData, plain.cbData); LocalFree(plain.pbData); }
    free(bytes);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    CloseHandle(lock); LocalFree(security);
    return ok;
}
