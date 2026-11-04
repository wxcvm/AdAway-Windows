#include "adguard_filter_import.h"
#include <stdio.h>
#include <stdlib.h>
#define CHECK(x) do { if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(1);} }while(0)
int main(void){
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
    CHECK(import && import->scanned==5 && import->count==3);
    CHECK(import->blocked==2 && import->dns_events==1);
    CHECK(import->duplicates==1 && import->missing_host==1);
    CHECK(import->top_count==1 && import->top[0].count==2);
    CHECK(import->events[0].log_type==0 && import->events[0].dns_type[0]=='A');
    CHECK(import->events[1].log_type==3);
    CHECK(import->events[2].timestamp_us==1793758224082230ULL);
    CHECK(!strcmp(import->events[2].remote_address,"192.0.2.10:443"));
    CHECK(import->events[2].request_type==2048);
    CHECK(import->events[2].stealth_options==16384u);
    CHECK(!strcmp(import->events[2].app,"test-app.exe"));
    CHECK(!strstr(import->events[2].app,"synthetic"));
    ag_import_free(import);
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
    char invalid[400];snprintf(invalid,sizeof invalid,
        "{\"ProtocolVersion\":\"2\",\"LogRecords\":[]}");
    CHECK(ag_import_parse(invalid,strlen(invalid),&import)==AG_IMPORT_UNSUPPORTED);
    puts("PASS: AdGuard v1 synthetic JSON, UTC offset, independent DNS/TCP events, dedup, privacy, ranking");
    return 0;
}
