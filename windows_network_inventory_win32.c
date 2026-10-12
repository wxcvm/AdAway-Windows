#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <string.h>
#include "windows_network_inventory_win32.h"

/* Diagnostic only. Snapshot counts cannot restore routes/DNS, so the actual
 * capture preflight must still mark rollback_snapshot_valid = false. */
struct windows_network_inventory windows_network_inventory_read(void) {
    struct windows_network_inventory result;
    memset(&result, 0, sizeof(result));

    PMIB_IPFORWARD_TABLE2 table = NULL;
    result.route_error = GetIpForwardTable2(AF_UNSPEC, &table);
    if (result.route_error == NO_ERROR && table != NULL) {
        result.route_count = table->NumEntries;
        for (ULONG i = 0; i < table->NumEntries; ++i) {
            const MIB_IPFORWARD_ROW2 *row = &table->Table[i];
            if (row->DestinationPrefix.PrefixLength != 0) continue;
            ADDRESS_FAMILY family = row->DestinationPrefix.Prefix.si_family;
            if (family == AF_INET) result.default_ipv4++;
            if (family == AF_INET6) result.default_ipv6++;
        }
    }
    if (table != NULL) FreeMibTable(table);

    ULONG bytes = 16 * 1024;
    for (int attempt = 0; attempt < 3; ++attempt) {
        if (bytes == 0 || bytes > 1024 * 1024) {
            result.adapter_error = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }
        PIP_ADAPTER_ADDRESSES adapters = (PIP_ADAPTER_ADDRESSES)malloc(bytes);
        if (adapters == NULL) {
            result.adapter_error = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }
        ULONG next = bytes;
        ULONG error = GetAdaptersAddresses(AF_UNSPEC,
                GAA_FLAG_INCLUDE_PREFIX, NULL, adapters, &next);
        if (error == ERROR_BUFFER_OVERFLOW) {
            free(adapters);
            bytes = next;
            result.adapter_error = error;
            continue;
        }
        result.adapter_error = error;
        if (error == NO_ERROR) {
            for (PIP_ADAPTER_ADDRESSES adapter = adapters; adapter != NULL;
                    adapter = adapter->Next) {
                if (adapter->OperStatus != IfOperStatusUp) continue;
                result.active_adapters++;
                for (PIP_ADAPTER_DNS_SERVER_ADDRESS dns =
                        adapter->FirstDnsServerAddress;
                        dns != NULL; dns = dns->Next) {
                    if (result.dns_servers < 10000) result.dns_servers++;
                }
            }
        }
        free(adapters);
        break;
    }
    return result;
}
