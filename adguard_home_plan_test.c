#include "adguard_home_plan.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    struct adguard_home_inputs p = {
        .remote_clients = false,
        .bind_all = false,
        .listener_responding = true,
        .lan_address_available = false,
        .ca_trusted_for_user = true,
        .http_port = 80,
        .https_port = 443
    };
    unsigned v = adguard_home_preflight(&p);
    assert(v == ADGUARD_HOME_DNS_UNVERIFIED);
    p.http_port = 8080;
    assert(adguard_home_preflight(&p) & ADGUARD_HOME_HTTP_PORT);
    p.http_port = 80;
    p.https_port = 8443;
    assert(adguard_home_preflight(&p) & ADGUARD_HOME_HTTPS_PORT);
    p.https_port = 443;
    p.remote_clients = true;
    v = adguard_home_preflight(&p);
    assert((v & (ADGUARD_HOME_LAN_BIND | ADGUARD_HOME_LAN_IP)) ==
           (ADGUARD_HOME_LAN_BIND | ADGUARD_HOME_LAN_IP));
    p.bind_all = true;
    assert(!(adguard_home_preflight(&p) & ADGUARD_HOME_LAN_BIND));
    p.lan_address_available = true;
    assert(!(adguard_home_preflight(&p) & ADGUARD_HOME_LAN_IP));
    p.listener_responding = false;
    assert(adguard_home_preflight(&p) & ADGUARD_HOME_SERVER_UNVERIFIED);
    p.listener_responding = true;
    p.ca_trusted_for_user = false;
    assert(adguard_home_preflight(&p) & ADGUARD_HOME_CA_TRUST);
    /* No configuration-only plan is allowed to claim DNS success. */
    assert(adguard_home_preflight(&p) & ADGUARD_HOME_DNS_UNVERIFIED);
    assert(adguard_home_preflight(NULL) & ADGUARD_HOME_DNS_UNVERIFIED);
    puts("AdGuard Home preflight: 10 cases passed");
    return 0;
}
