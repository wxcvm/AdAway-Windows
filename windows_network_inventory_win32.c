#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <string.h>
#include "windows_network_inventory_win32.h"

/* A deliberately limited, read-only diagnostic. Current mingw-w64 headers
 * in CI expose IPv4 GetIpForwardTable and dual-stack GetAdaptersAddresses,
 * but NOT GetIpForwardTable2/MIB_IPFORWARD_ROW2. We do not hand-roll the
 * Windows SDK structures: field layout mistakes would corrupt memory.
 *
 * IPv4 default route counts are exact from GetIpForwardTable. The IPv6
 * value is a count of UP-adapter gateways, NOT the system's v6 route table.
 * These counts can NEVER be used as an actual DNS/route rollback snapshot.
 */
struct windows_network_inventory windows_network_inventory_read(void) {
    struct windows_network_inventory result;
    memset(&result, 0, sizeof(result));

    ULONG bytes = 0;
    result.route_error = GetIpForwardTable(NULL, &bytes, FALSE);
    if (result.route_error == ERROR_INSUFFICIENT_BUFFER
            && bytes > 0 && bytes <= 1024 * 1024) {
        PMIB_IPFORWARDTABLE table = (PMIB_IPFORWARDTABLE)malloc(bytes);
        if (table != NULL) {
            result.route_error = GetIpForwardTable(table, &bytes, FALSE);
            if (result.route_error == NO_ERROR) {
                result.route_count = table->dwNumEntries;
                for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                    const MIB_IPFORWARDROW *row = &table->table[i];
                    if (row->dwForwardDest == 0 && row->dwForwardMask == 0)
                        result.default_ipv4++;
                }
            }
            free(table);
        } else {
            result.route_error = ERROR_NOT_ENOUGH_MEMORY;
        }
    }

    bytes = 16 * 1024;
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
                GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
                NULL, adapters, &next);
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
                        dns != NULL; dns = dns->Next)
                    if (result.dns_servers < 10000) result.dns_servers++;
                for (PIP_ADAPTER_GATEWAY_ADDRESS_LH gateway =
                        adapter->FirstGatewayAddress;
                        gateway != NULL; gateway = gateway->Next)
                    if (gateway->Address.lpSockaddr != NULL &&
                            gateway->Address.lpSockaddr->sa_family == AF_INET6)
                        result.ipv6_gateway_candidates++;
            }
        }
        free(adapters);
        break;
    }
    return result;
}
