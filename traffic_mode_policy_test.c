#include "traffic_mode_policy.h"
#include <assert.h>
#include <stdio.h>

static struct traffic_evidence base(void) {
    struct traffic_evidence e = {0};
    e.preference = TRAFFIC_PREFERENCE_AUTO;
    e.capture_owner = TRAFFIC_OWNER_NONE;
    e.capture_backend_supported = true;
    e.capture_authorized = true;
    return e;
}
static void expect(const struct traffic_evidence *e, enum traffic_target t,
                   enum traffic_reason r) {
    struct traffic_decision d = traffic_mode_decide(e);
    assert(d.target == t);
    assert(d.reason == r);
}
int main(void) {
    struct traffic_evidence e = base();
    expect(&e, TRAFFIC_TARGET_CAPTURE, TRAFFIC_REASON_CAPTURE_READY);
    e.adguard_process_present = true;
    expect(&e, TRAFFIC_TARGET_CAPTURE, TRAFFIC_REASON_CAPTURE_READY);
    e.capture_backend_supported = false;
    expect(&e, TRAFFIC_TARGET_NO_CHANGE, TRAFFIC_REASON_CAPTURE_UNAVAILABLE);
    e.capture_backend_supported = true;
    e.capture_authorized = false;
    expect(&e, TRAFFIC_TARGET_NO_CHANGE, TRAFFIC_REASON_CAPTURE_AUTH_REQUIRED);
    e.capture_authorized = true;
    e.capture_owner = TRAFFIC_OWNER_UNKNOWN;
    expect(&e, TRAFFIC_TARGET_NO_CHANGE, TRAFFIC_REASON_OWNERSHIP_UNKNOWN);
    e.capture_owner = TRAFFIC_OWNER_OTHER;
    expect(&e, TRAFFIC_TARGET_NO_CHANGE, TRAFFIC_REASON_OTHER_CAPTURE_ACTIVE);
    e.adguard_capture_confirmed = true;
    expect(&e, TRAFFIC_TARGET_PREPARE_LISTENER, TRAFFIC_REASON_LISTENER_NOT_VERIFIED);
    e.listener_path_verified = true;
    expect(&e, TRAFFIC_TARGET_LISTENER, TRAFFIC_REASON_ADGUARD_CONFLICT);
    e.capture_owner = TRAFFIC_OWNER_NONE;
    expect(&e, TRAFFIC_TARGET_LISTENER, TRAFFIC_REASON_ADGUARD_CONFLICT);
    e.adguard_capture_confirmed = false;
    e.preference = TRAFFIC_PREFERENCE_LISTEN_ONLY;
    expect(&e, TRAFFIC_TARGET_LISTENER, TRAFFIC_REASON_USER_LISTEN_ONLY);
    e.listener_path_verified = false;
    expect(&e, TRAFFIC_TARGET_PREPARE_LISTENER, TRAFFIC_REASON_LISTENER_NOT_VERIFIED);
    e.capture_failed = true;
    expect(&e, TRAFFIC_TARGET_RESTORE, TRAFFIC_REASON_CAPTURE_FAILED);
    expect(NULL, TRAFFIC_TARGET_NO_CHANGE, TRAFFIC_REASON_OWNERSHIP_UNKNOWN);
    puts("traffic mode policy: 13 cases passed");
    return 0;
}
