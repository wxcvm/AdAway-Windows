#define _WIN32_WINNT 0x0A00
#include "wintun_probe_win32.h"

/* Wintun is an optional third-party dependency. Use Windows 11 safe DLL
 * search flags. In particular, NEVER load a Wintun DLL from CWD or PATH.
 *
 * This module only validates exports/driver presence. The actual capture
 * backend cannot be enabled until TCP/UDP+DNS forwarding and rollback exist.
 */
struct wintun_probe_result wintun_probe_local(void) {
    struct wintun_probe_result info = {WINTUN_PROBE_MISSING, 0, 0};
    HMODULE dll = LoadLibraryExW(L"wintun.dll", NULL,
                    LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!dll) {
        info.last_error = GetLastError();
        return info;
    }
    static const char *required[] = {
        "WintunOpenAdapter", "WintunCloseAdapter",
        "WintunCreateAdapter", "WintunGetAdapterLuid",
        "WintunStartSession", "WintunEndSession",
        "WintunGetReadWaitEvent", "WintunReceivePacket",
        "WintunReleaseReceivePacket", "WintunAllocateSendPacket",
        "WintunSendPacket", "WintunGetRunningDriverVersion"
    };
    for (unsigned i = 0; i < sizeof(required) / sizeof(required[0]); ++i) {
        if (!GetProcAddress(dll, required[i])) {
            info.status = WINTUN_PROBE_API_INCOMPLETE;
            info.last_error = ERROR_PROC_NOT_FOUND;
            FreeLibrary(dll);
            return info;
        }
    }
    info.status = WINTUN_PROBE_DLL_READY_DRIVER_NOT_RUNNING;
    typedef DWORD (WINAPI *get_running_version_fn)(void);
    get_running_version_fn version =
        (get_running_version_fn)(void *)GetProcAddress(
            dll, "WintunGetRunningDriverVersion");
    info.driver_version = version();
    if (info.driver_version != 0) {
        info.status = WINTUN_PROBE_DRIVER_RUNNING;
    } else {
        info.last_error = GetLastError();
    }
    FreeLibrary(dll);
    return info;
}
