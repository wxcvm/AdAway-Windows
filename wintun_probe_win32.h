#ifndef ADBLOCK_WINTUN_PROBE_WIN32_H
#define ADBLOCK_WINTUN_PROBE_WIN32_H

#include <windows.h>

/* Discovery only: never installs a driver, creates an adapter, sets a route,
 * starts a session or borrows another program's existing Wintun adapter. */
enum wintun_probe_status {
    WINTUN_PROBE_MISSING = 0,
    WINTUN_PROBE_API_INCOMPLETE,
    WINTUN_PROBE_DLL_READY_DRIVER_NOT_RUNNING,
    WINTUN_PROBE_DRIVER_RUNNING,
    WINTUN_PROBE_API_PRESENT_UNVERIFIED
};

struct wintun_probe_result {
    enum wintun_probe_status status;
    DWORD driver_version;
    DWORD last_error;
};

struct wintun_probe_result wintun_probe_local(void);

#endif
