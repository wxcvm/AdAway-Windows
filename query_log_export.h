#ifndef ADAWAY_QUERY_LOG_EXPORT_H
#define ADAWAY_QUERY_LOG_EXPORT_H
#include "query_log_request.h"
typedef bool (*qlx_read)(void *, const struct qlp_request *, struct qlp_page *);
typedef bool (*qlx_write)(void *, const char *, size_t);
typedef bool (*qlx_cancel)(void *);
typedef void (*qlx_progress)(void *, uint32_t, uint32_t);

static inline bool qlx_cell(void *context, qlx_write write, const char *text, bool last) {
    if (!write(context,"\"",1)) return false;
    for(const char *p=text;*p;++p){if(*p=='"'&&!write(context,"\"",1))return false;if(!write(context,p,1))return false;}
    return write(context,last?"\"\r\n":"\",",last?3:2);
}
/* Caller publishes its unique staging file only on true; failure/cancellation
 * never produces an apparently complete export. Query strings are never stored. */
static inline bool qlx_export(struct qlp_request request, void *context, qlx_read read,
                              qlx_write write, qlx_cancel cancelled, qlx_progress progress) {
    if(!request.filter.enabled||!read||!write||!cancelled)return false;
    struct qlp_page *page=calloc(1,sizeof(*page));if(!page)return false;
    request.offset=0;uint32_t done=0,total=0,retained=0;uint64_t previous=0;bool have_previous=false,ok=false;
    const char *header="generation,sequence,epoch_seconds,uid,action,response_type,mode,family,host,path,http_status,path_truncated\r\n";
    if(!write(context,header,strlen(header)))goto finish;
    do {
        if(cancelled(context)||!read(context,&request,page)||page->offset!=done)goto finish;
        if(done && (page->total!=total||page->retained_total!=retained))goto finish;
        total=page->total;retained=page->retained_total;
        if(total>QLP_MAX_TOTAL||page->next_offset!=done+page->returned||page->next_offset>total)goto finish;
        for(uint32_t i=0;i<page->returned;++i){
            if(cancelled(context))goto finish;
            const struct qlp_row *row=&page->rows[i];uint64_t sequence=0;
            if(!qlp_decimal_digits(row->sequence,strlen(row->sequence),&sequence)||!sequence||(have_previous&&sequence>=previous))goto finish;
            previous=sequence;have_previous=true;
            char ts[24],uid[24],action[24],type[24],mode[24],family[24],status[24];
            snprintf(ts,sizeof(ts),"%llu",(unsigned long long)row->timestamp);snprintf(uid,sizeof(uid),"%d",row->uid);
            snprintf(action,sizeof(action),"%d",row->action);snprintf(type,sizeof(type),"%d",row->type);
            snprintf(mode,sizeof(mode),"%d",row->mode);snprintf(family,sizeof(family),"%d",row->family);
            if(row->status)snprintf(status,sizeof(status),"%d",row->status);else status[0]=0;
            const char *cells[]={page->generation,row->sequence,ts,uid,action,type,mode,family,row->host,row->path,status,row->path_truncated?"true":"false"};
            for(unsigned c=0;c<12;++c)if(!qlx_cell(context,write,cells[c],c==11))goto finish;
        }
        done=page->next_offset;if(progress)progress(context,done,total);
        memcpy(request.generation,page->generation,sizeof(request.generation));memcpy(request.anchor,page->anchor,sizeof(request.anchor));memcpy(request.query_key,page->query_key,sizeof(request.query_key));request.offset=done;
        if(page->has_more!=(done<total)||(!page->returned&&page->has_more))goto finish;
        if(!page->has_more)break;
    }while(done<QLP_MAX_TOTAL);
    ok=done==total&&!cancelled(context);
finish:free(page);return ok;
}
#endif
