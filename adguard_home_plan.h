#ifndef ADBLOCK_ADGUARD_HOME_PLAN_H
#define ADBLOCK_ADGUARD_HOME_PLAN_H

#include <stdbool.h>

/*
 * Preflight for AdGuard Home custom blocking IP integration.
 *
 * WARNING: This is a configuration-only check. It cannot prove that a remote
 * DNS client reaches this HTTP listener, that a third-party program is
 * intercepting traffic, or that TLS clients trust the generated CA.
 */
struct adguard_home_inputs {
    bool remote_clients;         /* false: same Windows host; true: other devices */
    bool bind_all;
    bool listener_responding;    /* local /internal-stats observation */
    bool lan_address_available;
    bool ca_trusted_for_user;
    int http_port;
    int https_port;
};

enum adguard_home_warning {
    ADGUARD_HOME_SERVER_UNVERIFIED = 1u << 0,
    ADGUARD_HOME_HTTP_PORT        = 1u << 1,
    ADGUARD_HOME_HTTPS_PORT       = 1u << 2,
    ADGUARD_HOME_LAN_BIND         = 1u << 3,
    ADGUARD_HOME_LAN_IP           = 1u << 4,
    ADGUARD_HOME_CA_TRUST         = 1u << 5,
    ADGUARD_HOME_DNS_UNVERIFIED   = 1u << 6
};

unsigned adguard_home_preflight(const struct adguard_home_inputs *inputs);

#endif
