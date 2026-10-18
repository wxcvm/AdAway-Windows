#include "dns_probe_win32.h"
#include "diagnostic_dns_reply.h"
#include "block_rule_snapshot.h"
#include "subscription_import.h"
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

int wmain(int argc, wchar_t **argv) {
    if (argc < 3 || argc > 4) { fputs("Usage: dns-loopback-probe.exe <hosts-or-abp-file> <loopback-port> [budget-ms]\nFixed example.com A; budget 1..1200 ms; no DNS/route changes.\n", stderr); return 2; }
    wchar_t *end; long port = wcstol(argv[2], &end, 10);
    if (!*argv[2] || *end || port < 1 || port > 65535) return 2;
    long budget = 1200;
    if (argc == 4) { budget = wcstol(argv[3], &end, 10); if (!*argv[3] || *end || budget < 1 || budget > 1200) return 2; }
    FILE *file = _wfopen(argv[1], L"rb"); if (!file) { fputs("Cannot read rule file\n",stderr); return 2; }
    FILE *staged = tmpfile();
    if (!staged) { fclose(file); return 2; }
    struct si_stats stats; memset(&stats,0,sizeof(stats));
    int imported = si_import_source(file,staged,&stats,2); fclose(file); rewind(staged);
    struct bs_builder builder; memset(&builder,0,sizeof(builder));
    int loaded = imported && bs_parse_file(staged,&builder) && bs_finish(&builder); fclose(staged);
    if (!loaded) { bs_free_builder(&builder); fputs("Invalid or oversized rule file\n",stderr); return 2; }
    struct bs_store rules = BS_STORE_INITIALIZER;
    if (!bs_publish(&rules,&builder,1)) { bs_free_builder(&builder); return 2; }
    bs_free_builder(&builder);
    WSADATA data; if (WSAStartup(MAKEWORD(2,2),&data)) { bs_dispose(&rules); return 2; }
    uint8_t query[DDNS_QUERY_SIZE]; ddns_query(query,0x5353); struct dns_probe_result result;
    enum dns_probe_status status = dns_probe_resolve(&rules,(unsigned short)port,query,sizeof(query),(unsigned)budget,NULL,&result);
    printf("{\"status\":%d,\"transport\":\"%s\",\"bytes\":%llu,\"rule_action\":%d,\"source\":%lu,\"scope\":%d,\"generation\":%llu}\n",
        (int)status, result.size && !result.via_tcp && result.action ? "local" : result.via_tcp ? "tcp" : "udp",
        (unsigned long long)result.size,result.action,(unsigned long)result.source,result.scope,(unsigned long long)result.generation);
    WSACleanup(); bs_dispose(&rules); return status == DNS_PROBE_OK ? 0 : 1;
}
