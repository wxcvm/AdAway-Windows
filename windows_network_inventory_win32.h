#ifndef ADBLOCK_WINDOWS_NETWORK_INVENTORY_WIN32_H
#define ADBLOCK_WINDOWS_NETWORK_INVENTORY_WIN32_H

#include <windows.h>

/*
 * Read-only, privacy-minimal baseline. We deliberately retain COUNTS ONLY,
 * not addresses or identifiable interface IDs. This is not a rollback image.
 * IPv4 route totals come from GetIpForwardTable; IPv6 gateway candidates
 * come from GetAdaptersAddresses, NOT the IPv6 routing table.
 */
struct windows_network_inventory {
    DWORD route_error;
    DWORD adapter_error;
    unsigned route_count;
    unsigned default_ipv4;
    unsigned ipv6_gateway_candidates;
    unsigned active_adapters;
    unsigned dns_servers;
};

/* All calls use Windows IP Helper query APIs; no privilege escalation or writes. */
struct windows_network_inventory windows_network_inventory_read(void);

#endif
