#ifndef ADAWAY_ADGUARD_FILTER_IMPORT_H
#define ADAWAY_ADGUARD_FILTER_IMPORT_H
/* User-selected, read-only AdGuard Filtering Log ProtocolVersion "1" JSON.
 * No Url, headers, cookies, redirect chain, DNS answer, user path or raw
 * document is retained. Imported events never modify local Web counters. */
#include "query_log_page.h"
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AG_IMPORT_MAX_BYTES (12u * 1024u * 1024u)
#define AG_IMPORT_MAX_ROWS 5000u
#define AG_IMPORT_TOP 20u

struct ag_event {
    char id[40];                 /* RequestArgId; disambiguates DNS/TCP events */
    char host[192];
    char remote_address[128];    /* endpoint only; never retain URL or DNS answers */
    char app[96];                /* basename only; never store full AppPath */
    char rule[192];              /* local preview only, never copied to telemetry */
    char protocol[12];
    char dns_type[16];
    char observed_time[48];         /* source wall time and explicit UTC offset */
    uint64_t timestamp_us;      /* absolute UTC, derived from Time's offset */
    uint32_t position;          /* original file order, tie-break only */
    int64_t unix_seconds;       /* local-time display from observed UTC */
    int process_id, status, filter_id, log_type, request_type;
    uint32_t stealth_options;
};
/* The rank is a count of source events, not unique user requests. */
struct ag_rank {
    char host[192];
    uint32_t count, dns_count, tcp_count, other_count;
};
struct ag_import {
    struct ag_event *events;
    size_t count, scanned, missing_host, duplicates, blocked, dns_events;
    struct ag_rank top[AG_IMPORT_TOP];
    size_t top_count;
};

/* These are AdGuard-reported remote endpoints, not proof that an AdAway
 * listener accepted a connection. Only accept numeric loopback addresses;
 * never guess from hostnames or similarly prefixed public addresses. */
struct ag_loopback_evidence {
    size_t http, https, other;
    size_t blocked_http, blocked_https, blocked_other;
};
static inline unsigned ag_loopback_remote_port(const char *address) {
    if(!address)return 0;
    const char *p=address;
    if(strncmp(p,"[::1]:",6)==0) {
        p+=6;
    } else if(strncmp(p,"127.",4)==0) {
        p+=4;
        for(int part=0;part<3;part++) {
            unsigned octet=0, digits=0;
            while(*p>='0' && *p<='9' && digits<3) {
                octet=octet*10u+(unsigned)(*p++-'0');
                digits++;
            }
            if(!digits || octet>255u)return 0;
            if(*p!=(part<2?'.':':'))return 0;
            ++p;
        }
    } else return 0;
    if(*p<'0'||*p>'9')return 0;
    unsigned port=0;
    for(;*p;p++) {
        if(*p<'0'||*p>'9')return 0;
        port=port*10u+(unsigned)(*p-'0');
        if(port>65535u)return 0;
    }
    return port;
}
static inline struct ag_loopback_evidence ag_count_loopback_endpoints(
    const struct ag_import *snapshot) {
    struct ag_loopback_evidence out={0};
    if(!snapshot)return out;
    for(size_t i=0;i<snapshot->count;i++) {
        const struct ag_event *event=&snapshot->events[i];
        if(strcmp(event->protocol,"Dns")==0)continue;
        unsigned port=ag_loopback_remote_port(event->remote_address);
        if(!port)continue;
        size_t *all=port==80u?&out.http:port==443u?&out.https:&out.other;
        ++*all;
        if(event->log_type==0) {
            size_t *blocks=port==80u?&out.blocked_http:
                port==443u?&out.blocked_https:&out.blocked_other;
            ++*blocks;
        }
    }
    return out;
}
/* Side-by-side source totals in a user-selected UTC time window, anchored
 * to the newest imported AdGuard event. Local counts are supplied ONLY from
 * the currently available AdAway HTTP history page, never from global stats.
 * There is no shared event identity: no inferred matches, rate or latency. */
struct ag_source_compare {
    int64_t start_utc, end_utc;
    size_t adguard_events, adguard_blocked, local_events, local_blocked;
    bool has_import;
};
static inline struct ag_source_compare ag_compare_window(
    const struct ag_import *snapshot, int64_t window_seconds) {
    struct ag_source_compare report={0};
    if (!snapshot || !snapshot->count || window_seconds<=0) return report;
    int64_t latest=snapshot->events[0].unix_seconds;
    for(size_t i=1;i<snapshot->count;i++)
        if(snapshot->events[i].unix_seconds>latest)
            latest=snapshot->events[i].unix_seconds;
    report.start_utc=latest-window_seconds;
    report.end_utc=latest;
    report.has_import=true;
    for(size_t i=0;i<snapshot->count;i++) {
        const struct ag_event *event=&snapshot->events[i];
        if(event->unix_seconds>report.start_utc && event->unix_seconds<=report.end_utc) {
            report.adguard_events++;
            if(event->log_type==0)report.adguard_blocked++;
        }
    }
    return report;
}
static inline void ag_compare_local_page_row(
    struct ag_source_compare *report, int64_t unix_seconds, int action) {
    if(!report || !report->has_import) return;
    if(unix_seconds>report->start_utc && unix_seconds<=report->end_utc) {
        report->local_events++;
        if(action==1)report->local_blocked++;
    }
}
enum ag_import_error {
    AG_IMPORT_OK=0, AG_IMPORT_INVALID, AG_IMPORT_TOO_LARGE,
    AG_IMPORT_UNSUPPORTED, AG_IMPORT_NO_MEMORY
};
/* Erase the privacy-reduced event snapshot too, before replacement,
 * explicit dismissal or process exit. Volatile stores avoid dead-store
 * elimination in the portable parser shared by the native test runner. */
static inline void ag_import_clear_bytes(void *pointer, size_t bytes) {
    volatile unsigned char *p=(volatile unsigned char *)pointer;
    while (bytes--) *p++=0;
}
static inline void ag_import_free(struct ag_import *state) {
    if (!state) return;
    if (state->events) {
        ag_import_clear_bytes(state->events,state->count*sizeof(*state->events));
        free(state->events);
    }
    ag_import_clear_bytes(state,sizeof(*state));
    free(state);
}
static inline int ag_date_number(const char *s, size_t length) {
    int out = 0;
    for (size_t i=0; i<length; ++i) {
        if (s[i]<'0'||s[i]>'9') return -1;
        out=out*10+s[i]-'0';
    }
    return out;
}
static inline bool ag_is_leap(int year) {
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}
static inline int ag_month_days(int year, int month) {
    static const unsigned char days[]={0,31,28,31,30,31,30,31,31,30,31,30,31};
    return month == 2 ? 28 + ag_is_leap(year) : days[month];
}
/* Gregorian days relative to the Unix epoch; no timegm()/TZ mutation. */
static inline int64_t ag_days_from_civil(int y, unsigned m, unsigned d) {
    y -= (m <= 2);
    const int era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = (unsigned)(y - era * 400);
    const int adjusted_month = (int)m + (m > 2 ? -3 : 9);
    const unsigned doy = (153u * (unsigned)adjusted_month + 2u) / 5u + d - 1u;
    const unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
    return (int64_t)era * 146097 + (int64_t)doe - 719468;
}
/* AdGuard example: 2026-11-04T10:10:24.0822308+08:00. */
static inline bool ag_parse_timestamp(const char *str, uint64_t *micros,
                                       int64_t *unix_seconds) {
    if (!str || !micros || !unix_seconds || strlen(str) < 20 ||
        str[4]!='-' || str[7]!='-' || str[10]!='T' ||
        str[13]!=':' || str[16]!=':') return false;
    int y=ag_date_number(str,4), mo=ag_date_number(str+5,2);
    int d=ag_date_number(str+8,2), h=ag_date_number(str+11,2);
    int mi=ag_date_number(str+14,2), se=ag_date_number(str+17,2);
    if (y<1970||y>2100||mo<1||mo>12||d<1||d>ag_month_days(y,mo)||
        h<0||h>23||mi<0||mi>59||se<0||se>59) return false;
    size_t cursor=19, digits=0;
    uint32_t fraction=0;
    if (str[cursor]=='.') {
        ++cursor;
        while(str[cursor]>='0'&&str[cursor]<='9') {
            if (digits<6) fraction=fraction*10+(uint32_t)(str[cursor]-'0');
            ++cursor;
            if (++digits>9) return false;
        }
        if(!digits) return false;
    }
    if (digits<6) for(size_t i=digits;i<6;++i) fraction*=10;
    int sign=0, offh=0, offm=0;
    if (str[cursor]=='Z' && str[cursor+1]==0) {
        ++cursor;
    } else {
        if(str[cursor]=='+' )sign=1;
        else if(str[cursor]=='-')sign=-1;
        else return false;
        if(strlen(str+cursor)!=6 || str[cursor+3]!=':')return false;
        offh=ag_date_number(str+cursor+1,2);
        offm=ag_date_number(str+cursor+4,2);
        if(offh<0||offh>14||offm<0||offm>59||(offh==14&&offm>0))return false;
        cursor+=6;
    }
    if(str[cursor])return false;
    int64_t seconds=ag_days_from_civil(y,(unsigned)mo,(unsigned)d)*86400+
        (int64_t)h*3600+mi*60+se-(int64_t)sign*(offh*3600+offm*60);
    if(seconds<0)return false;
    *micros=(uint64_t)seconds*1000000u+fraction;
    *unix_seconds=seconds;
    return true;
}
static inline int ag_json_hex_digit(char c) {
    if(c>='0'&&c<='9')return c-'0';
    if(c>='a'&&c<='f')return c-'a'+10;
    if(c>='A'&&c<='F')return c-'A'+10;
    return -1;
}
static inline bool ag_json_hex4(const char *s,uint32_t *value) {
    uint32_t out=0;
    for(int i=0;i<4;i++) {
        int digit=ag_json_hex_digit(s[i]);
        if(digit<0)return false;
        out=(out<<4)|(uint32_t)digit;
    }
    *value=out;
    return true;
}
static inline bool ag_json_append_utf8(char *out,size_t capacity,size_t *used,uint32_t cp) {
    unsigned char bytes[4];size_t n=0;
    if(cp<=0x7f){bytes[0]=(unsigned char)cp;n=1;}
    else if(cp<=0x7ff){
        bytes[0]=(unsigned char)(0xc0|(cp>>6));
        bytes[1]=(unsigned char)(0x80|(cp&0x3f));n=2;
    }else if(cp<=0xffff){
        if(cp>=0xd800&&cp<=0xdfff)return false;
        bytes[0]=(unsigned char)(0xe0|(cp>>12));
        bytes[1]=(unsigned char)(0x80|((cp>>6)&0x3f));
        bytes[2]=(unsigned char)(0x80|(cp&0x3f));n=3;
    }else if(cp<=0x10ffff){
        bytes[0]=(unsigned char)(0xf0|(cp>>18));
        bytes[1]=(unsigned char)(0x80|((cp>>12)&0x3f));
        bytes[2]=(unsigned char)(0x80|((cp>>6)&0x3f));
        bytes[3]=(unsigned char)(0x80|(cp&0x3f));n=4;
    }else return false;
    if(*used>capacity || n>=capacity-*used)return false;
    memcpy(out+*used,bytes,n);*used+=n;
    return true;
}
/* Decode JSON strings including UTF-16 surrogate pairs. AdGuard's serializer
 * may escape non-ASCII process names as \\uXXXX; Mongoose's generic unescaper
 * intentionally supports only byte-sized Unicode escapes. */
static inline bool ag_json_string_decode(struct mg_str row, const char *key,
                                          char *out, size_t capacity,
                                          bool optional, bool basename_only) {
    if(!out||!capacity)return false;
    out[0]=0;
    struct mg_str tok=mg_json_get_tok(row,key);
    if(!tok.len)return optional;
    if(tok.len==4&&tok.buf&&memcmp(tok.buf,"null",4)==0)return optional;
    if(!tok.buf||tok.len<2||tok.buf[0]!='"'||tok.buf[tok.len-1]!='"')return false;
    size_t n=0;
    bool overflow=false; /* a long directory prefix is never retained */
    for(size_t i=1;i+1<tok.len;i++) {
        unsigned char ch=(unsigned char)tok.buf[i];
        if(ch=='\\') {
            if(i+1>=tok.len-1)return false;
            char esc=tok.buf[++i];
            uint32_t cp=0;
            switch(esc) {
                case '"': case '\\': case '/': cp=(unsigned char)esc;break;
                case 'b': cp=8;break;
                case 'f': cp=12;break;
                case 'n': cp=10;break;
                case 'r': cp=13;break;
                case 't': cp=9;break;
                case 'u':
                    if(i+4>=tok.len-1||!ag_json_hex4(tok.buf+i+1,&cp))return false;
                    i+=4;
                    if(cp>=0xd800&&cp<=0xdbff) {
                        uint32_t low=0;
                        if(i+6>=tok.len-1||tok.buf[i+1]!='\\'||tok.buf[i+2]!='u'||
                           !ag_json_hex4(tok.buf+i+3,&low)||low<0xdc00||low>0xdfff)return false;
                        cp=0x10000u+((cp-0xd800u)<<10)+(low-0xdc00u);
                        i+=6;
                    }else if(cp>=0xdc00&&cp<=0xdfff)return false;
                    break;
                default:return false;
            }
            if(basename_only && (cp==0 || cp<0x20 || cp==0x7f))return false;
            if(basename_only && (cp=='/' || cp=='\\')) {
                n=0;overflow=false; /* decoded path separator */
            } else if(!overflow && !ag_json_append_utf8(out,capacity,&n,cp)) {
                if(!basename_only)return false;
                overflow=true;
            }
        }else{
            if(ch=='"'||ch<0x20||ch==0x7f)return false;
            if(basename_only && ch=='/') {
                n=0;overflow=false;
            } else if(!overflow) {
                if(n+1>=capacity) {
                    if(!basename_only)return false;
                    overflow=true;
                } else out[n++]=(char)ch;
            }
        }
    }
    if(overflow)return false; /* only the final basename length is bounded */
    out[n]=0;
    if(memchr(out,'\0',n))return false;
    if(!n)return optional;
    return qlp_utf8_host((const unsigned char *)out,n);
}
static inline bool ag_json_string(struct mg_str row,const char *key,
                                   char *out,size_t capacity,bool optional) {
    return ag_json_string_decode(row,key,out,capacity,optional,false);
}
static inline bool ag_json_basename(struct mg_str row,const char *key,
                                    char *out,size_t capacity) {
    return ag_json_string_decode(row,key,out,capacity,true,true);
}
static inline bool ag_uuid(const char *id) {
    if (!id || strlen(id)!=36)return false;
    for(int i=0;i<36;i++) {
        char c=id[i];
        if(i==8||i==13||i==18||i==23) { if(c!='-')return false; }
        else if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')||
                  (c>='A'&&c<='F')))return false;
    }
    return true;
}
static inline bool ag_row_parse(struct mg_str json, struct ag_event *out) {
    if(!out || !dashboard_json_object(json))return false;
    struct ag_event row={0};
    char time[64];
    if(!ag_json_string(json,"$.RequestArgId",row.id,sizeof row.id,false)||
       !ag_uuid(row.id)||
       !ag_json_string(json,"$.Time",time,sizeof time,false)||
       !ag_parse_timestamp(time,&row.timestamp_us,&row.unix_seconds)||
       strlen(time)>=sizeof row.observed_time||
       !ag_json_string(json,"$.Host",row.host,sizeof row.host,true)||
       !ag_json_string(json,"$.RemoteIpAddress",row.remote_address,sizeof row.remote_address,true)||
       !ag_json_string(json,"$.ProtocolType",row.protocol,sizeof row.protocol,false)||
       !ag_json_string(json,"$.DnsType",row.dns_type,sizeof row.dns_type,true)||
       !ag_json_string(json,"$.Rule",row.rule,sizeof row.rule,true)||
       !ag_json_basename(json,"$.AppPath",row.app,sizeof row.app))return false;
    memcpy(row.observed_time,time,strlen(time)+1);
    uint64_t value=0;
    if(mg_json_get_tok(json,"$.Type").len) {
        if(!qlp_json_uint(json,"$.Type",&value)||value>INT_MAX)return false;
        row.request_type=(int)value;
    }
    if(mg_json_get_tok(json,"$.AppliedStealthModeOptions").len) {
        if(!qlp_json_uint(json,"$.AppliedStealthModeOptions",&value)||value>UINT32_MAX)return false;
        row.stealth_options=(uint32_t)value;
    }
    if(!qlp_json_uint(json,"$.LogRecordType",&value)||value>65535)return false;
    row.log_type=(int)value;
    if(!qlp_json_uint(json,"$.ProcessId",&value)||value>INT_MAX)return false;
    row.process_id=(int)value;
    if(!qlp_json_uint(json,"$.FiredFilterId",&value)||value>INT_MAX)return false;
    row.filter_id=(int)value;
    if(!qlp_json_uint(json,"$.StatusCode",&value)||value>999)return false;
    row.status=(int)value;
    /* Preserve unknown future AdGuard protocol labels (e.g. QUIC) safely. */
    *out=row;
    return true;
}
static inline int ag_cmp_event(const void *a,const void *b) {
    const struct ag_event *x=a,*y=b;
    if(x->timestamp_us!=y->timestamp_us)
        return x->timestamp_us>y->timestamp_us?-1:1;
    return x->position<y->position?-1:x->position>y->position?1:0;
}
static inline int ag_cmp_rank(const void *a,const void *b) {
    const struct ag_rank *x=a,*y=b;
    if(x->count!=y->count)return x->count>y->count?-1:1;
    return strcmp(x->host,y->host);
}
static inline enum ag_import_error ag_import_parse(
    const char *text, size_t length, struct ag_import **output) {
    if(!output)return AG_IMPORT_INVALID;
    *output=NULL;
    if(!text || !length)return AG_IMPORT_INVALID;
    if(length>AG_IMPORT_MAX_BYTES)return AG_IMPORT_TOO_LARGE;
    if(memchr(text,'\0',length))return AG_IMPORT_INVALID;
    struct mg_str json={(char *)text,length}; /* Mongoose scans read-only bytes */
    char version[12];
    if(!dashboard_json_object(json) ||
       !ag_json_string(json,"$.ProtocolVersion",version,sizeof version,false))
        return AG_IMPORT_INVALID;
    if(strcmp(version,"1"))return AG_IMPORT_UNSUPPORTED;
    struct mg_str arr=mg_json_get_tok(json,"$.LogRecords");
    if(!arr.buf || arr.len<2 || arr.buf[0]!='[' ||
       arr.buf[arr.len-1]!=']')return AG_IMPORT_INVALID;
    struct ag_import *result=calloc(1,sizeof(*result));
    if(!result)return AG_IMPORT_NO_MEMORY;
    result->events=calloc(AG_IMPORT_MAX_ROWS,sizeof(struct ag_event));
    if(!result->events){ag_import_free(result);return AG_IMPORT_NO_MEMORY;}
    size_t off=0;
    struct mg_str key={NULL,0},row={NULL,0};
    while((off=mg_json_next(arr,off,&key,&row))!=0) {
        if(++result->scanned>AG_IMPORT_MAX_ROWS){
            ag_import_free(result);return AG_IMPORT_TOO_LARGE;
        }
        struct ag_event item={0};
        if(!ag_row_parse(row,&item)){
            ag_import_free(result);return AG_IMPORT_INVALID;
        }
        if(!item.host[0]){result->missing_host++;continue;}
        bool duplicate=false;
        for(size_t i=0;i<result->count;i++)
            if(strcmp(result->events[i].id,item.id)==0){duplicate=true;break;}
        if(duplicate){result->duplicates++;continue;}
        item.position=(uint32_t)(result->scanned-1);
        result->events[result->count++]=item;
        if(item.log_type==0)result->blocked++;
        if(strcmp(item.protocol,"Dns")==0)result->dns_events++;
    }
    struct ag_rank *all=calloc(result->count?result->count:1,sizeof(*all));
    if(!all){ag_import_free(result);return AG_IMPORT_NO_MEMORY;}
    size_t ranks=0;
    for(size_t i=0;i<result->count;i++){
        const struct ag_event *event=&result->events[i];
        if(event->log_type!=0)continue; /* explicit AdGuard block event */
        size_t j=0;
        while(j<ranks && strcmp(all[j].host,event->host))++j;
        if(j==ranks) {
            memcpy(all[j].host,event->host,sizeof all[j].host);
            ++ranks;
        }
        ++all[j].count;
        if(strcmp(event->protocol,"Dns")==0) ++all[j].dns_count;
        else if(strcmp(event->protocol,"Tcp")==0) ++all[j].tcp_count;
        else ++all[j].other_count;
    }
    qsort(all,ranks,sizeof(*all),ag_cmp_rank);
    result->top_count=ranks<AG_IMPORT_TOP?ranks:AG_IMPORT_TOP;
    memcpy(result->top,all,result->top_count*sizeof(*all));
    free(all);
    qsort(result->events,result->count,sizeof(*result->events),ag_cmp_event);
    *output=result;
    return AG_IMPORT_OK;
}
#endif
