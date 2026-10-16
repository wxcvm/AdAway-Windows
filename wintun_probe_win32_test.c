#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include "wintun_probe_win32.h"

int main(int argc, char **argv) {
    (void)argv;
    wchar_t folder[MAX_PATH], marker[MAX_PATH];
    assert(GetTempPathW(MAX_PATH, folder));
    assert(GetTempFileNameW(folder, L"tun", 0, marker));
    assert(DeleteFileW(marker));
    assert(SetEnvironmentVariableW(L"ADBLOCK_WINTUN_TEST_MARKER", marker));
    struct wintun_probe_result result = wintun_probe_local();
    if (argc > 1) assert(result.status == WINTUN_PROBE_API_INCOMPLETE);
    else assert(result.status == WINTUN_PROBE_API_PRESENT_UNVERIFIED);
    assert(result.driver_version == 0);
    assert(GetFileAttributesW(marker) == INVALID_FILE_ATTRIBUTES);
    assert(GetLastError() == ERROR_FILE_NOT_FOUND);
    SetEnvironmentVariableW(L"ADBLOCK_WINTUN_TEST_MARKER", NULL);
    puts("Wintun probe: DLL entry points and driver exports were not executed");
    return 0;
}
