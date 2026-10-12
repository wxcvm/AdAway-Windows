#include "windows_capture_plan.h"
#include <assert.h>
#include <stdio.h>

static struct windows_capture_input good(void) {
    struct windows_capture_input p = {0};
    p.user_authorized = true;
    p.driver_api_available = true;
    p.forwarding_backend_ready = true;
    p.dns_forwarder_ready = true;
    p.rollback_snapshot_valid = true;
    return p;
}

int main(void) {
    struct windows_capture_input p = good();
    assert(windows_capture_preflight(&p) == WINDOWS_CAPTURE_DIAGNOSTIC_ONLY);
    p.route_is_default = true;
    assert(windows_capture_preflight(&p) == WINDOWS_CAPTURE_DENY);
    p.route_is_default = false;
    p.foreign_interceptor_confirmed = true;
    assert(windows_capture_preflight(&p) == WINDOWS_CAPTURE_DENY);
    p = good(); p.user_authorized = false;
    assert(windows_capture_preflight(&p) == WINDOWS_CAPTURE_DENY);
    p = good(); p.driver_api_available = false;
    assert(windows_capture_preflight(&p) == WINDOWS_CAPTURE_DENY);
    p = good(); p.rollback_snapshot_valid = false;
    assert(windows_capture_preflight(&p) == WINDOWS_CAPTURE_DENY);
    p = good(); p.forwarding_backend_ready = false;
    assert(windows_capture_preflight(&p) == WINDOWS_CAPTURE_DIAGNOSTIC_ONLY);
    p = good(); p.dns_forwarder_ready = false;
    assert(windows_capture_preflight(&p) == WINDOWS_CAPTURE_DIAGNOSTIC_ONLY);
    assert(windows_capture_preflight(NULL) == WINDOWS_CAPTURE_DENY);
    for (unsigned mask = 0; mask < 128; mask++) {
        p.user_authorized = (mask & 1) != 0;
        p.driver_api_available = (mask & 2) != 0;
        p.forwarding_backend_ready = (mask & 4) != 0;
        p.dns_forwarder_ready = (mask & 8) != 0;
        p.rollback_snapshot_valid = (mask & 16) != 0;
        p.foreign_interceptor_confirmed = (mask & 32) != 0;
        p.route_is_default = (mask & 64) != 0;
        assert(windows_capture_preflight(&p) != WINDOWS_CAPTURE_ROUTE_ALLOWED);
        if (p.route_is_default) assert(windows_capture_preflight(&p) == WINDOWS_CAPTURE_DENY);
    }
    puts("Windows capture preflight: 9 cases + 128 no-capture combinations passed");
    return 0;
}
