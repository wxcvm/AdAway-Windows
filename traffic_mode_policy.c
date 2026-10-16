#include "traffic_mode_policy.h"

static struct traffic_decision result(enum traffic_target target,
                                      enum traffic_reason reason) {
    struct traffic_decision d = {target, reason};
    return d;
}

struct traffic_decision traffic_mode_decide(const struct traffic_evidence *e) {
    if (e == 0) {
        return result(TRAFFIC_TARGET_NO_CHANGE, TRAFFIC_REASON_OWNERSHIP_UNKNOWN);
    }
    /* Fail closed before any other decision; restore only OUR changes. */
    if (e->capture_failed) {
        return result(TRAFFIC_TARGET_RESTORE, TRAFFIC_REASON_CAPTURE_FAILED);
    }
    if (e->capture_owner == TRAFFIC_OWNER_UNKNOWN) {
        return result(TRAFFIC_TARGET_NO_CHANGE, TRAFFIC_REASON_OWNERSHIP_UNKNOWN);
    }
    if (e->preference == TRAFFIC_PREFERENCE_LISTEN_ONLY) {
        return e->listener_path_verified
            ? result(TRAFFIC_TARGET_LISTENER, TRAFFIC_REASON_USER_LISTEN_ONLY)
            : result(TRAFFIC_TARGET_PREPARE_LISTENER, TRAFFIC_REASON_LISTENER_NOT_VERIFIED);
    }
    if (e->capture_owner == TRAFFIC_OWNER_OTHER) {
        if (e->adguard_capture_confirmed) {
            return e->listener_path_verified
                ? result(TRAFFIC_TARGET_LISTENER, TRAFFIC_REASON_ADGUARD_CONFLICT)
                : result(TRAFFIC_TARGET_PREPARE_LISTENER,
                         TRAFFIC_REASON_LISTENER_NOT_VERIFIED);
        }
        return result(TRAFFIC_TARGET_NO_CHANGE, TRAFFIC_REASON_OTHER_CAPTURE_ACTIVE);
    }
    if (e->adguard_capture_confirmed) {
        return e->listener_path_verified
            ? result(TRAFFIC_TARGET_LISTENER, TRAFFIC_REASON_ADGUARD_CONFLICT)
            : result(TRAFFIC_TARGET_PREPARE_LISTENER,
                     TRAFFIC_REASON_LISTENER_NOT_VERIFIED);
    }
    /* A current backend may still be in planning: do not claim capture simply
     * because the local web server is listening. */
    if (!e->capture_backend_supported) {
        return result(TRAFFIC_TARGET_NO_CHANGE, TRAFFIC_REASON_CAPTURE_UNAVAILABLE);
    }
    if (!e->capture_authorized) {
        return result(TRAFFIC_TARGET_NO_CHANGE, TRAFFIC_REASON_CAPTURE_AUTH_REQUIRED);
    }
    return result(TRAFFIC_TARGET_CAPTURE, TRAFFIC_REASON_CAPTURE_READY);
}
