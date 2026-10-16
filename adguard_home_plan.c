#include "adguard_home_plan.h"

unsigned adguard_home_preflight(const struct adguard_home_inputs *p) {
    /* DNS end-to-end verification is never inferred from a config snapshot. */
    unsigned warnings = ADGUARD_HOME_DNS_UNVERIFIED;
    if (!p) {
        return warnings | ADGUARD_HOME_SERVER_UNVERIFIED
            | ADGUARD_HOME_HTTP_PORT | ADGUARD_HOME_HTTPS_PORT
            | ADGUARD_HOME_LAN_BIND | ADGUARD_HOME_LAN_IP | ADGUARD_HOME_CA_TRUST;
    }
    if (!p->listener_responding) warnings |= ADGUARD_HOME_SERVER_UNVERIFIED;
    /* DNS responses only carry an IP. Standard URLs still connect to 80/443. */
    if (p->http_port != 80) warnings |= ADGUARD_HOME_HTTP_PORT;
    if (p->https_port != 443) warnings |= ADGUARD_HOME_HTTPS_PORT;
    if (p->remote_clients) {
        if (!p->bind_all) warnings |= ADGUARD_HOME_LAN_BIND;
        if (!p->lan_address_available) warnings |= ADGUARD_HOME_LAN_IP;
    }
    /* Current-user root trust does not imply other devices trust this CA. */
    if (!p->ca_trusted_for_user) warnings |= ADGUARD_HOME_CA_TRUST;
    return warnings;
}
