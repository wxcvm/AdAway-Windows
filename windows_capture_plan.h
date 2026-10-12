#ifndef ADBLOCK_WINDOWS_CAPTURE_PLAN_H
#define ADBLOCK_WINDOWS_CAPTURE_PLAN_H
#include <stdbool.h>

/*
 * Windows capture transition preflight. This structure is independent of
 * any Wintun or WFP implementation: no network API is invoked by this module.
 * No default routes may be installed until a real forwarding engine passes
 * end-to-end tests and the old network configuration can be restored.
 */
struct windows_capture_input {
    bool user_authorized;
    bool driver_api_available;
    bool forwarding_backend_ready;
    bool dns_forwarder_ready;
    bool rollback_snapshot_valid;
    bool foreign_interceptor_confirmed;
    bool route_is_default;
};

enum windows_capture_decision {
    WINDOWS_CAPTURE_DENY = 0,
    WINDOWS_CAPTURE_DIAGNOSTIC_ONLY,
    WINDOWS_CAPTURE_ROUTE_ALLOWED
};

enum windows_capture_decision windows_capture_preflight(
        const struct windows_capture_input *input);

#endif
