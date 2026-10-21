#include "query_log_atomic_win32.h"
#include <stdlib.h>
#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "FAIL %d: %s\n", __LINE__, #condition); exit(1); } } while (0)

static void contents(const char *path, const char *expected) {
    char data[64] = {0};
    FILE *file = qlog_fopen_utf8(path, "rb");
    CHECK(file != NULL);
    CHECK(fread(data, 1, sizeof(data) - 1, file) == strlen(expected));
    CHECK(fclose(file) == 0);
    CHECK(strcmp(data, expected) == 0);
}

int main(int argc, char **argv) {
    CHECK(argc == 2); /* Existing disposable directory, no host configuration. */
    char path[PATH_MAX], tmp[PATH_MAX];
    int length = snprintf(path, sizeof(path), "%s/log-\xE6\xB5\x8B\xE8\xAF\x95.dat", argv[1]);
    CHECK(length > 0 && (size_t)length < sizeof(path));
    FILE *file = open_atomic_write(path, tmp, sizeof(tmp));
    CHECK(file != NULL);
    CHECK(fwrite("previous", 1, 8, file) == 8);
    finish_atomic_write(file, path, tmp);
    contents(path, "previous");
    wchar_t wide[PATH_MAX];
    CHECK(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, PATH_MAX) > 0);
    HANDLE locked = CreateFileW(wide, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(locked != INVALID_HANDLE_VALUE);
    file = open_atomic_write(path, tmp, sizeof(tmp));
    CHECK(file != NULL);
    CHECK(fwrite("new", 1, 3, file) == 3);
    finish_atomic_write(file, path, tmp); /* Replacement denied; previous file stays. */
    CHECK(CloseHandle(locked));
    contents(path, "previous");
    CHECK(qlog_fopen_utf8(tmp, "rb") == NULL);
    file = open_atomic_write(path, tmp, sizeof(tmp));
    CHECK(file != NULL);
    CHECK(fwrite("new", 1, 3, file) == 3);
    finish_atomic_write(file, path, tmp);
    contents(path, "new");
    CHECK(qlog_remove_utf8(path) == 0);
    CHECK(open_atomic_write(path, tmp, 4) == NULL);
    puts("PASS: query log UTF-8 paths, atomic replacement, locked-file rollback and staging cleanup");
    return 0;
}
