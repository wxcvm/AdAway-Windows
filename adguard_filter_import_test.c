#include "adguard_filter_import.h"
#include <stdio.h>
#include <stdlib.h>
#define CHECK(x) do { if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);} }while(0)
int main(void){
    unsigned char sensitive[]={0x41,0x00,0xff,0x7f};
    ag_import_clear_bytes(sensitive,sizeof sensitive);
    for(size_t i=0;i<sizeof sensitive;i++)CHECK(sensitive[i]==0);
    uint64_t micros=0; int64_t sec=0;
    CHECK(ag_parse_timestamp("2026-11-04T10:10:24.0822308+08:00",&micros,&sec));
    CHECK(micros==1793758224082230ULL && sec==1793758224LL);
    CHECK(!ag_parse_timestamp("2026-02-30T10:10:24+08:00",&micros,&sec));
    CHECK(!ag_parse_timestamp("2026-11-04T10:10:24.0+25:00",&micros,&sec));
    CHECK(ag_parse_timestamp("2026-11-04T02:10:24.0822308Z",&micros,&sec));
    CHECK(micros==1793758224082230ULL);
    const char *body =
       "{\"ProtocolVersion\":\"1\",\"LogRecords\":["
       "{\"RequestArgId\":\"00000000-0000-0000-0000-000000000001\","
       "\"Time\":\"2026-11-04T10:10:24.0822308+08:00\","
       "\"Host\":\"blocked.example.test\",\"RemoteIpAddress\":\"192.0.2.10:443\","
       "\"ProtocolType\":\"Tcp\",\"Type\":2048,\"AppliedStealthModeOptions\":16384,"
       "\"LogRecordType\":0,\"ProcessId\":4242,\"FiredFilterId\":3,"
       "\"StatusCode\":0,\"AppPath\":\"C:\\\\synthetic\\\\test-app.exe\","
       "\"Rule\":\"||blocked.example.test^\","
       "\"RequestHeaders\":{\"Cookie\":\"DO-NOT-IMPORT\",\"Nested\":{\"Key\":1}}},"
       "{\"RequestArgId\":\"00000000-0000-0000-0000-000000000002\","
       "\"Time\":\"2026-11-04T10:10:54.1350494+08:00\","
       "\"Host\":\"blocked.example.test\",\"RemoteIpAddress\":null,"
       "\"ProtocolType\":\"Dns\",\"Type\":8192,"
       "\"LogRecordType\":0,\"ProcessId\":0,\"FiredFilterId\":5,"
       "\"StatusCode\":0,\"DnsType\":\"A\",\"AppPath\":null,\"Rule\":\"||blocked.example.test^\"},"
       "{\"RequestArgId\":\"00000000-0000-0000-0000-000000000003\","
       "\"Time\":\"2026-11-04T10:10:30.100+08:00\","
       "\"Host\":\"ignored.example\",\"ProtocolType\":\"Tcp\","
       "\"LogRecordType\":3,\"ProcessId\":99,\"FiredFilterId\":0,"
       "\"StatusCode\":200,\"Rule\":null,\"AppPath\":\"Demo.exe\"},"
       "{\"RequestArgId\":\"00000000-0000-0000-0000-000000000001\","
       "\"Time\":\"2026-11-04T10:10:24.0822308+08:00\","
       "\"Host\":\"blocked.example.test\",\"ProtocolType\":\"Tcp\","
       "\"LogRecordType\":0,\"ProcessId\":4242,\"FiredFilterId\":3,\"StatusCode\":0},"
       "{\"RequestArgId\":\"00000000-0000-0000-0000-000000000004\","
       "\"Time\":\"2026-11-04T10:10:31+08:00\","
       "\"Host\":null,\"ProtocolType\":\"Tcp\",\"LogRecordType\":5,"
       "\"ProcessId\":0,\"FiredFilterId\":0,\"StatusCode\":0}]}";
    struct ag_import *import=NULL;
    CHECK(ag_import_parse(body,strlen(body),&import)==AG_IMPORT_OK);
    CHECK(import && import->scanned==5 && import->count==4);
    CHECK(import->blocked==2 && import->dns_events==1);
    CHECK(import->duplicates==1 && import->missing_host==1);
    CHECK(import->top_count==1 && import->top[0].count==2);
    CHECK(import->top[0].dns_count==1 && import->top[0].tcp_count==1 &&
          import->top[0].other_count==0);
    CHECK(import->events[0].log_type==0 && import->events[0].dns_type[0]=='A');
    CHECK(import->events[1].log_type==5 && !import->events[1].host[0]);
    CHECK(import->events[2].log_type==3);
    CHECK(import->events[3].timestamp_us==1793758224082230ULL);
    CHECK(!strcmp(import->events[3].remote_address,"192.0.2.10:443"));
    CHECK(import->events[3].request_type==2048);
    CHECK(import->events[3].stealth_options==16384u);
    CHECK(!strcmp(import->events[3].app,"test-app.exe"));
    CHECK(!strstr(import->events[3].app,"synthetic"));
    ag_import_free(import);
    import=NULL;
    /* A hostless *blocked* observation still belongs to imported totals,
       but cannot become a blank domain in the block ranking. */
    const char *hostless_block =
        "{\"ProtocolVersion\":\"1\",\"LogRecords\":[{"
        "\"RequestArgId\":\"00000000-0000-0000-0000-000000000009\","
        "\"Time\":\"2026-11-04T10:10:24+08:00\","
        "\"Host\":null,\"ProtocolType\":\"Tcp\","
        "\"LogRecordType\":0,\"ProcessId\":1,\"FiredFilterId\":1,"
        "\"StatusCode\":0},{"
        "\"RequestArgId\":\"00000000-0000-0000-0000-000000000009\","
        "\"Time\":\"2026-11-04T10:10:24+08:00\","
        "\"Host\":null,\"ProtocolType\":\"Tcp\","
        "\"LogRecordType\":0,\"ProcessId\":1,\"FiredFilterId\":1,"
        "\"StatusCode\":0}]}";
    CHECK(ag_import_parse(hostless_block,strlen(hostless_block),&import)==AG_IMPORT_OK);
    CHECK(import->count==1 && import->scanned==2 && import->missing_host==1 && import->duplicates==1);
    CHECK(import->blocked==1 && import->top_count==0);
    CHECK(!import->events[0].host[0] && import->events[0].log_type==0);
    ag_import_free(import);
    import=NULL;
    /* Source-reported localhost endpoints are diagnostic clues only.
       Strict parsing must not count public addresses or malformed ports. */
    CHECK(ag_loopback_remote_port("127.0.0.2:443")==443);
    CHECK(ag_loopback_remote_port("127.255.0.1:80")==80);
    CHECK(ag_loopback_remote_port("[::1]:443")==443);
    CHECK(ag_loopback_remote_port("127.0.0.2:8443")==8443);
    CHECK(ag_loopback_remote_port("127.0.0.256:443")==0);
    CHECK(ag_loopback_remote_port("127.0.0.2:65536")==0);
    CHECK(ag_loopback_remote_port("127.0.0.2:443evil")==0);
    CHECK(ag_loopback_remote_port("127.0.0.2.example:443")==0);
    CHECK(ag_loopback_remote_port("128.0.0.2:443")==0);
    CHECK(ag_loopback_remote_port("[::2]:443")==0);
    CHECK(ag_loopback_remote_port(NULL)==0);
    /* The actual HTTP/HTTPS listener port takes precedence over standard
       ports; standard 80/443 remain mismatch diagnostics. */
    CHECK(ag_tcp_listener_hint_role(8080,8080,8443)==1);
    CHECK(ag_tcp_listener_hint_role(8443,8080,8443)==2);
    CHECK(ag_tcp_listener_hint_role(80,8080,8443)==1);
    CHECK(ag_tcp_listener_hint_role(443,8080,8443)==2);
    CHECK(ag_tcp_listener_hint_role(443,443,80)==1);
    CHECK(ag_tcp_listener_hint_role(80,443,80)==2);
    CHECK(ag_tcp_listener_hint_role(5353,8080,8443)==0);
    CHECK(ag_tcp_listener_hint_role(0,8080,8443)==0);
    /* A managed ULA is not loopback, but it can be the explicitly started
       listener. Compare IP literals exactly; never treat DNS as TCP arrival. */
    CHECK(ag_configured_remote_port("127.0.0.2:80",
        "127.0.0.2","fd6b:2a91:84f0::2")==80);
    CHECK(ag_configured_remote_port("[fd6b:2a91:84f0::2]:443",
        "127.0.0.2","fd6b:2a91:84f0::2")==443);
    CHECK(ag_configured_remote_port("[FD6B:2A91:84F0::2]:8443",
        "127.0.0.2","fd6b:2a91:84f0::2")==8443);
    CHECK(!ag_configured_remote_port("[fd6b:2a91:84f0::3]:443",
        "127.0.0.2","fd6b:2a91:84f0::2"));
    CHECK(!ag_configured_remote_port("127.0.0.20:80",
        "127.0.0.2","fd6b:2a91:84f0::2"));
    CHECK(!ag_configured_remote_port("[fd6b:2a91:84f0::2]:443garbage",
        "127.0.0.2","fd6b:2a91:84f0::2"));
    CHECK(!ag_configured_remote_port("[fd6b:2a91:84f0::2]:65536",
        "127.0.0.2","fd6b:2a91:84f0::2"));
    CHECK(!ag_configured_remote_port("[fd6b:2a91:84f0::2]:443",
        "127.0.0.2","::"));
    CHECK(!ag_configured_remote_port("127.0.0.2:80","0.0.0.0",""));
    CHECK(!ag_configured_remote_port("fd6b:2a91:84f0::2:443",
        "127.0.0.2","fd6b:2a91:84f0::2"));
    struct ag_event managed_events[]={
        {.protocol="Tcp", .log_type=0, .remote_address="127.0.0.2:80"},
        {.protocol="Tcp", .log_type=0, .remote_address="[fd6b:2a91:84f0::2]:443"},
        {.protocol="Quic",.log_type=5, .remote_address="[fd6b:2a91:84f0::2]:8443"},
        {.protocol="Quic",.log_type=0, .remote_address="[fd6b:2a91:84f0::2]:443"},
        {.protocol="Tcp", .log_type=3, .remote_address="[fd6b:2a91:84f0::2]:8443"},
        {.protocol="Dns", .log_type=0, .remote_address="[fd6b:2a91:84f0::2]:443"},
        {.protocol="Tcp", .log_type=0, .remote_address="[fd6b:2a91:84f0::3]:443"},
        {.protocol="Tcp", .log_type=0, .remote_address="203.0.113.5:443"}
    };
    struct ag_import managed_snapshot={.events=managed_events,.count=8};
    struct ag_loopback_evidence managed=ag_count_local_endpoints(
        &managed_snapshot,"127.0.0.2","fd6b:2a91:84f0::2");
    CHECK(managed.http==1 && managed.blocked_http==1);
    CHECK(managed.https==1 && managed.blocked_https==1);
    CHECK(managed.other==1 && managed.blocked_other==0);
    CHECK(ag_count_loopback_endpoints(&managed_snapshot).https==0);
    /* Summary counts follow the ports actually started, not standard
       defaults or a newly saved draft. Exclude DNS/QUIC and public IPs. */
    struct ag_event port_events[]={
        {.protocol="Tcp", .log_type=0, .remote_address="127.0.0.2:8080"},
        {.protocol="Tcp", .log_type=0, .remote_address="[fd6b:2a91:84f0::2]:8443"},
        {.protocol="Tcp", .log_type=3, .remote_address="127.0.0.2:80"},
        {.protocol="Tcp", .log_type=5, .remote_address="[fd6b:2a91:84f0::2]:443"},
        {.protocol="Dns", .log_type=0, .remote_address="127.0.0.2:8080"},
        {.protocol="Quic",.log_type=0, .remote_address="[fd6b:2a91:84f0::2]:8443"},
        {.protocol="Tcp", .log_type=0, .remote_address="203.0.113.10:8443"}
    };
    struct ag_import port_snapshot={.events=port_events,.count=7};
    struct ag_loopback_evidence custom=ag_count_local_endpoints_ports(
        &port_snapshot,"127.0.0.2","fd6b:2a91:84f0::2",8080,8443);
    CHECK(custom.http==1 && custom.blocked_http==1);
    CHECK(custom.https==1 && custom.blocked_https==1);
    CHECK(custom.other==2 && custom.blocked_other==0);
    custom=ag_count_local_endpoints_ports(&port_snapshot,
        "127.0.0.2","fd6b:2a91:84f0::2",80,443);
    CHECK(custom.http==1 && custom.blocked_http==0);
    CHECK(custom.https==1 && custom.blocked_https==0);
    CHECK(custom.other==2 && custom.blocked_other==2);
    custom=ag_count_local_endpoints_ports(&port_snapshot,
        "127.0.0.2","fd6b:2a91:84f0::2",8443,8080);
    CHECK(custom.http==1 && custom.blocked_http==1);
    CHECK(custom.https==1 && custom.blocked_https==1);
    CHECK(custom.other==2 && custom.blocked_other==0);
    struct ag_event endpoints[]={
        {.protocol="Tcp",.log_type=0,.remote_address="127.0.0.2:443"},
        {.protocol="Tcp",.log_type=5,.remote_address="127.0.0.1:80"},
        {.protocol="Quic",.log_type=0,.remote_address="[::1]:443"},
        {.protocol="Dns",.log_type=0,.remote_address="127.0.0.1:443"},
        {.protocol="Tcp",.log_type=0,.remote_address="203.0.113.5:443"},
        {.protocol="Tcp",.log_type=3,.remote_address="127.0.0.2:8443"}
    };
    struct ag_import endpoint_snapshot={.events=endpoints,.count=6};
    struct ag_loopback_evidence evidence=ag_count_loopback_endpoints(&endpoint_snapshot);
    CHECK(evidence.http==1 && evidence.blocked_http==0);
    CHECK(evidence.https==1 && evidence.blocked_https==1);
    CHECK(evidence.other==1 && evidence.blocked_other==0);
    CHECK(ag_count_loopback_endpoints(NULL).https==0);
    CHECK(ag_import_parse(body,strlen(body),&import)==AG_IMPORT_OK);
    ag_import_free(import);
    const char *unicode_body =
       "{\"ProtocolVersion\":\"1\",\"LogRecords\":["
       "{\"RequestArgId\":\"00000000-0000-0000-0000-000000000005\","
       "\"Time\":\"2026-11-04T02:10:24Z\","
       "\"Host\":\"unicode.example\",\"ProtocolType\":\"Quic\","
       "\"LogRecordType\":0,\"ProcessId\":1,\"FiredFilterId\":1,"
       "\"StatusCode\":0,\"AppPath\":\"C:\\\\Users\\\\"
       "\\u6d4b\\u8bd5\\u5e94\\u7528.exe\"}]}";
    CHECK(ag_import_parse(unicode_body,strlen(unicode_body),&import)==AG_IMPORT_OK);
    CHECK(import->count==1);
    CHECK(!strcmp(import->events[0].protocol,"Quic"));
    CHECK(!strcmp(import->events[0].app,"\xe6\xb5\x8b\xe8\xaf\x95\xe5\xba\x94\xe7\x94\xa8.exe"));
    ag_import_free(import);
    /* A valid zero-row export must replace stale imported observations. */
    const char *empty="{\"ProtocolVersion\":\"1\",\"LogRecords\":[]}";
    CHECK(ag_import_parse(empty,strlen(empty),&import)==AG_IMPORT_OK);
    CHECK(import && import->count==0 && import->scanned==0 &&
          import->blocked==0 && import->top_count==0);
    CHECK(!ag_compare_window(import,900).has_import);
    ag_import_free(import);
    import=NULL;
    const char nul_input[]="{\"ProtocolVersion\":\"1\"}\0trailer";
    CHECK(ag_import_parse(nul_input,sizeof nul_input-1,&import)==AG_IMPORT_INVALID);
    CHECK(import==NULL);
    CHECK(ag_import_parse(NULL,0,&import)==AG_IMPORT_INVALID && import==NULL);
    char invalid[400];snprintf(invalid,sizeof invalid,
        "{\"ProtocolVersion\":\"2\",\"LogRecords\":[]}");
    CHECK(ag_import_parse(invalid,strlen(invalid),&import)==AG_IMPORT_UNSUPPORTED);
    /* A time-window comparison uses UTC seconds, not the source's wall clock.
       Only the visible AdAway history page is countable; never infer a match. */
    struct ag_event event_rows[3] = {
        {.unix_seconds=1000,.log_type=0},
        {.unix_seconds=1030,.log_type=3},
        {.unix_seconds=1100,.log_type=0}
    };
    struct ag_import source={0};
    source.events=event_rows;source.count=3;
    struct ag_source_compare window=ag_compare_window(&source,60);
    CHECK(window.has_import && window.start_utc==1040 && window.end_utc==1100);
    CHECK(window.adguard_events==1 && window.adguard_blocked==1);
    ag_compare_local_page_row(&window,1040,1);
    ag_compare_local_page_row(&window,1041,1);
    ag_compare_local_page_row(&window,1100,2);
    ag_compare_local_page_row(&window,1101,1);
    CHECK(window.local_events==2 && window.local_blocked==1);
    CHECK(!ag_compare_window(NULL,3600).has_import);
    CHECK(!ag_compare_window(&source,0).has_import);
    window=ag_compare_window(&source,120);
    CHECK(window.adguard_events==3 && window.adguard_blocked==2);

    /* Failures must return NO snapshot and retain no partially parsed rows. */
    const char *malformed_cases[] = {
        "{\"ProtocolVersion\":\"1\",\"LogRecords\":{}}",
        "{\"ProtocolVersion\":\"1\",\"LogRecords\":[{}]}",
        "{\"ProtocolVersion\":\"1\",\"LogRecords\":[{\"Host\":\"example.test\"}]}",
        "{\"ProtocolVersion\":\"1\",\"LogRecords\":[{\"RequestArgId\":\"broken\","
        "\"Time\":\"2026-11-04T10:10:24+08:00\",\"Host\":\"x.test\"}]}",
        "{\"ProtocolVersion\":\"1\",\"LogRecords\":[{\"RequestArgId\":\"00000000-0000-0000-0000-000000000006\","
        "\"Time\":\"2026-11-04T10:10:24+08:00\",\"Host\":\"x.test\","
        "\"ProtocolType\":\"Tcp\",\"LogRecordType\":0,\"ProcessId\":1,"
        "\"FiredFilterId\":1,\"StatusCode\":0,\"AppPath\":\"\\uD800\"}]}",
    };
    for(size_t i=0;i<sizeof malformed_cases/sizeof malformed_cases[0];i++) {
        import=NULL;
        CHECK(ag_import_parse(malformed_cases[i],strlen(malformed_cases[i]),&import)==AG_IMPORT_INVALID);
        CHECK(import==NULL);
    }
    char very_long_host[400];
    memset(very_long_host,'x',sizeof very_long_host-1);
    very_long_host[sizeof very_long_host-1]=0;
    char long_body[900];
    snprintf(long_body,sizeof long_body,
        "{\"ProtocolVersion\":\"1\",\"LogRecords\":[{"
        "\"RequestArgId\":\"00000000-0000-0000-0000-000000000007\","
        "\"Time\":\"2026-11-04T10:10:24+08:00\",\"Host\":\"%s\","
        "\"ProtocolType\":\"Dns\",\"LogRecordType\":0,"
        "\"ProcessId\":1,\"FiredFilterId\":1,\"StatusCode\":0}]}",very_long_host);
    CHECK(ag_import_parse(long_body,strlen(long_body),&import)==AG_IMPORT_INVALID);
    CHECK(import==NULL);
    CHECK(ag_import_parse(body,AG_IMPORT_MAX_BYTES+1,&import)==AG_IMPORT_TOO_LARGE);
    CHECK(import==NULL);
    /* Long Windows directory paths must not cause an entire valid export to
       fail when only the short basename is retained. */
    char directory[2049], long_doc[4096];
    memset(directory,'x',2048);
    directory[2048]=0;
    int length=snprintf(long_doc,sizeof(long_doc),
        "{\"ProtocolVersion\":\"1\",\"LogRecords\":[{"
        "\"RequestArgId\":\"00000000-0000-0000-0000-000000000008\","
        "\"Time\":\"2026-11-04T10:10:24+08:00\","
        "\"Host\":\"longpath.example.test\",\"ProtocolType\":\"Tcp\","
        "\"LogRecordType\":0,\"ProcessId\":1,\"FiredFilterId\":1,"
        "\"StatusCode\":0,\"AppPath\":\"C:/%s/worker.exe\"}]}",
        directory);
    CHECK(length>1024 && (size_t)length<sizeof long_doc);
    CHECK(ag_import_parse(long_doc,(size_t)length,&import)==AG_IMPORT_OK);
    CHECK(import && import->count==1);
    CHECK(!strcmp(import->events[0].app,"worker.exe"));
    ag_import_free(import);
    import=NULL;
    /* Mixed JSON-escaped slash, Unicode backslash and Unicode basename. */
    struct mg_str escaped=mg_str("{\"AppPath\":\"C:\\u005cUsers\\/\\u6d4b\\u8bd5.exe\"}");
    char decoded_basename[96]={0};
    CHECK(ag_json_basename(escaped,"$.AppPath",decoded_basename,sizeof decoded_basename));
    CHECK(!strcmp(decoded_basename,"\xe6\xb5\x8b\xe8\xaf\x95.exe"));
    /* A basename that itself exceeds the privacy-reduced bound still fails. */
    length=snprintf(long_doc,sizeof(long_doc),
        "{\"AppPath\":\"C:/%s\"}",directory);
    CHECK(length>0 && (size_t)length<sizeof long_doc);
    CHECK(!ag_json_basename(mg_str(long_doc),"$.AppPath",decoded_basename,sizeof decoded_basename));
    puts("PASS: AdGuard v1 synthetic JSON, UTC offset, independent DNS/TCP events, dedup, privacy, ranking");
    return 0;
}
