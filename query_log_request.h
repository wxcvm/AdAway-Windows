#ifndef ADAWAY_QUERY_LOG_REQUEST_H
#define ADAWAY_QUERY_LOG_REQUEST_H
#include "query_log_page.h"

/* No truncation: overlong/non-UTF8 filters fail before any network request. */
static inline bool qlp_request_path(const struct qlp_request *request, char *path, size_t capacity) {
    if (!request || !path || !capacity) return false;
    char encoded[192*3+1]; size_t used=0;
    const unsigned char *q=(const unsigned char *)request->filter.query;
    size_t n=qlp_bounded_strlen((const char *)q,sizeof(request->filter.query));
    if (n>=sizeof(request->filter.query)) return false;
    static const char hex[]="0123456789ABCDEF";
    for(size_t i=0;i<n;++i){
        unsigned char c=q[i];
        if((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.'||c=='~')encoded[used++]=(char)c;
        else {encoded[used++]='%';encoded[used++]=hex[c>>4];encoded[used++]=hex[c&15];}
    }
    encoded[used]=0;
    char cursor[192]="", filters[800]="", expected[65];
    if(request->filter.enabled){
        if(!qlp_filter_key(&request->filter,expected))return false;
        char a[32]="", f[32]="",t[32]="",u[32]="";
        if(request->filter.has_action)snprintf(a,sizeof(a),"&action=%d",request->filter.action);
        if(request->filter.has_family)snprintf(f,sizeof(f),"&family=%d",request->filter.family);
        if(request->filter.has_type)snprintf(t,sizeof(t),"&type=%d",request->filter.type);
        if(request->filter.has_uid)snprintf(u,sizeof(u),"&uid=%d",request->filter.uid);
        int count=snprintf(filters,sizeof(filters),"&filterVersion=1%s%s%s%s&q=%s",a,f,t,u,encoded);
        if(count<0||(size_t)count>=sizeof(filters))return false;
    }
    if(request->generation[0]){
        if(!qlp_hex_generation(request->generation,qlp_bounded_strlen(request->generation,sizeof(request->generation))) ||
           !qlp_decimal_digits(request->anchor,qlp_bounded_strlen(request->anchor,sizeof(request->anchor)),NULL) ||
           (request->filter.enabled&&strcmp(request->query_key,expected)))return false;
        int count=snprintf(cursor,sizeof(cursor),"&generation=%s&anchor=%s%s%s",request->generation,request->anchor,request->filter.enabled?"&queryKey=":"",request->filter.enabled?request->query_key:"");
        if(count<0||(size_t)count>=sizeof(cursor))return false;
    }else if(request->anchor[0]||request->query_key[0])return false;
    int count=snprintf(path,capacity,"/internal-qlog?offset=%u&limit=300%s%s",request->offset,filters,cursor);
    return count>=0&&(size_t)count<capacity;
}
#endif
