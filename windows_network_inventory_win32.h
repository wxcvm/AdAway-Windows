#ifndef ADBLOCK_WINDOWS_NETWORK_INVENTORY_WIN32_H
#define ADBLOCK_WINDOWS_NETWORK_INVENTORY_WIN32_H

#include <windows.h>

/*
 * Read-only, privacy-minimal baseline. We deliberately retain COUNTS ONLY,
 * not addresses or identifiable interface IDs. This is not a rollback image.
 */
struct windows_network_inventory {
    DWORD route_error;
    DWORD adapter_error;
    unsigned route_count;
    unsigned default_ipv4;
    unsigned default_ipv6;
    unsigned active_adapters;
    unsigned dns_servers;
};

/* All calls use Windows IP Helper query APIs; no privilege escalation or writes. */
struct windows_network_inventory windows_network_inventory_read(void);

#endif
