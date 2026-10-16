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
    assert(windows_capture_preflight(&p) == WINDOWS_CAPTURE_ROUTE_ALLOWED);
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
    puts("Windows capture preflight: 8 cases passed");
    return 0;
}
