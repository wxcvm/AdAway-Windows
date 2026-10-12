#define _WIN32_WINNT 0x0A00
#include "wintun_probe_win32.h"

/* Wintun is an optional third-party dependency. Use Windows 11 safe DLL
 * search flags. In particular, NEVER load a Wintun DLL from CWD or PATH.
 *
 * This module inspects exports WITHOUT DLL initialization or calling exports.
 * No optional/unverified DLL may execute code during a status probe. The actual capture
 * backend cannot be enabled until TCP/UDP+DNS forwarding and rollback exist.
 */
struct wintun_probe_result wintun_probe_local(void) {
    struct wintun_probe_result info = {WINTUN_PROBE_MISSING, 0, 0};
    HMODULE dll = LoadLibraryExW(L"wintun.dll", NULL,
                    LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32
                    | DONT_RESOLVE_DLL_REFERENCES);
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
    info.status = WINTUN_PROBE_API_PRESENT_UNVERIFIED;
    /* M3 must verify the official artifact/publisher before normal loading.
     * DONT_RESOLVE modules are never callable and never prove a running driver. */
    FreeLibrary(dll);
    return info;
}
