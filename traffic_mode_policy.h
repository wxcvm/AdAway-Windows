#ifndef ADBLOCK_TRAFFIC_MODE_POLICY_H
#define ADBLOCK_TRAFFIC_MODE_POLICY_H

#include <stdbool.h>

/* Pure, platform-independent policy. This header never changes the network. */
enum traffic_preference {
    TRAFFIC_PREFERENCE_AUTO,
    TRAFFIC_PREFERENCE_CAPTURE,
    TRAFFIC_PREFERENCE_LISTEN_ONLY
};
enum traffic_capture_owner {
    TRAFFIC_OWNER_NONE,
    TRAFFIC_OWNER_OURS,
    TRAFFIC_OWNER_OTHER,
    TRAFFIC_OWNER_UNKNOWN
};
enum traffic_target {
    TRAFFIC_TARGET_NO_CHANGE,
    TRAFFIC_TARGET_CAPTURE,
    TRAFFIC_TARGET_PREPARE_LISTENER,
    TRAFFIC_TARGET_LISTENER,
    TRAFFIC_TARGET_RESTORE
};
enum traffic_reason {
    TRAFFIC_REASON_CAPTURE_READY,
    TRAFFIC_REASON_CAPTURE_UNAVAILABLE,
    TRAFFIC_REASON_CAPTURE_AUTH_REQUIRED,
    TRAFFIC_REASON_USER_LISTEN_ONLY,
    TRAFFIC_REASON_ADGUARD_CONFLICT,
    TRAFFIC_REASON_OTHER_CAPTURE_ACTIVE,
    TRAFFIC_REASON_LISTENER_NOT_VERIFIED,
    TRAFFIC_REASON_OWNERSHIP_UNKNOWN,
    TRAFFIC_REASON_CAPTURE_FAILED
};

/* Evidence fields MUST come from independent probes; an installed or running
 * AdGuard process alone is NOT confirmation of a traffic interception conflict.
 * listener_path_verified means end-to-end routing to the local listener was
 * tested, not just that bind() succeeded. */
struct traffic_evidence {
    enum traffic_preference preference;
    enum traffic_capture_owner capture_owner;
    bool adguard_process_present;
    bool adguard_capture_confirmed;
    bool listener_path_verified;
    bool capture_backend_supported;
    bool capture_authorized;
    bool capture_failed;
};
struct traffic_decision {
    enum traffic_target target;
    enum traffic_reason reason;
};

struct traffic_decision traffic_mode_decide(const struct traffic_evidence *evidence);

#endif
