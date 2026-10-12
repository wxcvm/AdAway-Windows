#include "windows_capture_plan.h"

enum windows_capture_decision windows_capture_preflight(
        const struct windows_capture_input *p) {
    if (!p || !p->user_authorized || p->foreign_interceptor_confirmed) {
        return WINDOWS_CAPTURE_DENY;
    }
    if (p->route_is_default) return WINDOWS_CAPTURE_DENY;
    if (!p->driver_api_available || !p->rollback_snapshot_valid) {
        return WINDOWS_CAPTURE_DENY;
    }
    if (!p->forwarding_backend_ready || !p->dns_forwarder_ready) {
        /*
         * A probe may enumerate capabilities but must not install any route,
         * even a scoped one, until the complete forwarder is implemented.
         */
        return WINDOWS_CAPTURE_DIAGNOSTIC_ONLY;
    }
    /* No real recovery executor exists; booleans supplied by a caller are not
     * proof of an OS-restorable snapshot. Even scoped capture stays read-only. */
    return WINDOWS_CAPTURE_DIAGNOSTIC_ONLY;
}
