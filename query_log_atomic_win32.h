#ifndef ADBLOCK_QUERY_LOG_ATOMIC_WIN32_H
#define ADBLOCK_QUERY_LOG_ATOMIC_WIN32_H
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static FILE *qlog_fopen_utf8(const char *path, const char *mode) {
    wchar_t wide[PATH_MAX], wide_mode[16];
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, PATH_MAX) ||
        !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, mode, -1, wide_mode, 16)) return NULL;
    return _wfopen(wide, wide_mode);
}

static int qlog_remove_utf8(const char *path) {
    wchar_t wide[PATH_MAX];
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, PATH_MAX)) return -1;
    return _wremove(wide);
}

/* A unique same-directory staging file, published only after a successful
 * flush/commit/close. UTF-8 resource paths are converted before Win32 I/O. */
static FILE *open_atomic_write(const char *path, char *tmp, size_t capacity) {
    static LONG sequence;
    wchar_t wide[PATH_MAX];
    int length = snprintf(tmp, capacity, "%s.tmp.%lu.%lu", path,
                          (unsigned long)GetCurrentProcessId(),
                          (unsigned long)InterlockedIncrement(&sequence));
    if (length < 0 || (size_t)length >= capacity ||
        !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, tmp, -1, wide, PATH_MAX)) return NULL;
    HANDLE handle = CreateFileW(wide, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                                FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE) return NULL;
    int fd = _open_osfhandle((intptr_t)handle, _O_WRONLY | _O_BINARY);
    if (fd < 0) { CloseHandle(handle); DeleteFileW(wide); return NULL; }
    FILE *file = _fdopen(fd, "wb");
    if (!file) { _close(fd); DeleteFileW(wide); }
    return file;
}

static void finish_atomic_write(FILE *file, const char *path, const char *tmp) {
    wchar_t final_path[PATH_MAX], staged_path[PATH_MAX];
    bool valid = fflush(file) == 0;
    if (valid) valid = _commit(_fileno(file)) == 0;
    if (fclose(file) != 0) valid = false;
    bool staged_valid = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, tmp, -1, staged_path, PATH_MAX) != 0;
    valid = valid && staged_valid &&
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, final_path, PATH_MAX) != 0;
    if (valid && MoveFileExW(staged_path, final_path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) return;
    if (staged_valid) DeleteFileW(staged_path);
}
#endif
