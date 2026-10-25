#include "query_log_export.h"
#include "query_log_navigation.h"
#include <assert.h>
#include <stdio.h>

static void parser(void) {
    struct qlp_request request={0};request.filter.enabled=true;request.filter.has_action=true;request.filter.action=3;
    strcpy(request.filter.query,"403");char key[65];assert(qlp_filter_key(&request.filter,key));
    char body[2000],path[1200];
    snprintf(body,sizeof(body),"{\"offset\":0,\"limit\":300,\"total\":1,\"retainedTotal\":9,\"returned\":1,\"nextOffset\":1,\"hasMore\":false,\"generation\":\"0123456789abcdef0123456789abcdef\",\"anchor\":\"9\",\"filterVersion\":1,\"queryKey\":\"%s\",\"entries\":[{\"ts\":1000,\"uid\":-1,\"action\":3,\"type\":-1,\"mode\":0,\"family\":6,\"host\":\"same.example\",\"path\":\"/internal-test\",\"status\":403,\"pathTruncated\":false,\"sequence\":\"9\"}]}",key);
    struct qlp_page *page=calloc(1,sizeof(*page));assert(page);
    assert(qlp_parse(mg_str(body),&request,page));assert(page->retained_total==9&&page->total==1);
    assert(page->rows[0].action==3&&page->rows[0].status==403&&!strcmp(page->rows[0].path,"/internal-test")&&!strcmp(page->rows[0].sequence,"9"));
    assert(qlp_request_path(&request,path,sizeof(path)));assert(strstr(path,"filterVersion=1")&&strstr(path,"action=3")&&strstr(path,"q=403"));
    struct qlp_request next=request;strcpy(next.generation,page->generation);strcpy(next.anchor,page->anchor);strcpy(next.query_key,key);
    assert(qlp_request_path(&next,path,sizeof(path)));assert(strstr(path,"&queryKey="));next.query_key[0]='x';assert(!qlp_request_path(&next,path,sizeof(path)));
    body[strstr(body,"filterVersion")-body]='X';assert(!qlp_parse(mg_str(body),&request,page));
    assert(!qlp_parse(mg_str("{\"offset\":0,\"limit\":300,\"total\":0,\"returned\":0,\"nextOffset\":0,\"hasMore\":false,\"generation\":\"0123456789abcdef0123456789abcdef\",\"anchor\":\"0\",\"entries\":[]}"),&request,page));
    struct qlp_row row={0};assert(!qlp_parse_row(mg_str("{\"ts\":1,\"action\":3,\"type\":-1,\"mode\":0,\"host\":\"a.example\",\"path\":\"/secret?token=bad\",\"status\":403}"),&row));
    assert(!qlp_parse_row(mg_str("{\"ts\":1,\"action\":3,\"type\":-1,\"mode\":0,\"host\":\"a.example\",\"status\":99}"),&row));
    struct qlp_filter other=request.filter;strcpy(other.query,"HOST/");assert(qlp_filter_key(&other,key));strcpy(other.query,"host/");char lowercase[65];assert(qlp_filter_key(&other,lowercase)&&!strcmp(key,lowercase));
    strcpy(other.query,"x& y/\xc3\xa9");request.filter=other;assert(qlp_request_path(&request,path,sizeof(path))&&strstr(path,"x%26%20y%2F%C3%A9"));
    memset(request.filter.query,'a',191);request.filter.query[191]=0;assert(qlp_request_path(&request,path,sizeof(path)));
    memset(request.filter.query,'a',192);assert(!qlp_request_path(&request,path,sizeof(path)));
    free(page);
}
struct fixture{unsigned reads,writes,progress,cancel_after;bool read_fail,write_fail,duplicate;uint32_t done;};
static bool read_page(void *context,const struct qlp_request *request,struct qlp_page *page){
    struct fixture *f=context;if(f->read_fail&&f->reads++)return false;f->reads++;
    memset(page,0,sizeof(*page));page->offset=request->offset;page->total=901;page->retained_total=4096;
    page->returned=request->offset+300<=901?300:901-request->offset;page->next_offset=page->offset+page->returned;page->has_more=page->next_offset<page->total;
    strcpy(page->generation,"0123456789abcdef0123456789abcdef");strcpy(page->anchor,"4096");assert(qlp_filter_key(&request->filter,page->query_key));
    if(request->offset)assert(!strcmp(request->query_key,page->query_key)&&!strcmp(request->anchor,page->anchor));
    for(unsigned i=0;i<page->returned;i++){struct qlp_row *row=&page->rows[i];row->timestamp=1000;row->uid=-1;row->action=1;row->family=6;row->type=0;row->status=200;strcpy(row->host,"same.example");strcpy(row->path,"/image");snprintf(row->sequence,sizeof(row->sequence),"%u",4096-request->offset-i);}
    if(f->duplicate&&request->offset)snprintf(page->rows[0].sequence,sizeof(page->rows[0].sequence),"%u",4096-request->offset+1);
    return true;
}
static bool write_bytes(void *context,const char *bytes,size_t length){struct fixture *f=context;assert(bytes&&length);f->writes++;return !f->write_fail;}
static bool cancelled(void *context){struct fixture *f=context;return f->cancel_after&&f->writes>=f->cancel_after;}
static void progress(void *context,uint32_t done,uint32_t total){struct fixture *f=context;assert(total==901&&done>f->done);f->done=done;f->progress++;}
static void exports(void){struct qlp_request request={0};request.filter.enabled=true;struct fixture f={0};
 assert(qlx_export(request,&f,read_page,write_bytes,cancelled,progress));assert(f.done==901&&f.progress==4);
 memset(&f,0,sizeof(f));f.read_fail=true;assert(!qlx_export(request,&f,read_page,write_bytes,cancelled,progress));assert(f.done==300);
 memset(&f,0,sizeof(f));f.write_fail=true;assert(!qlx_export(request,&f,read_page,write_bytes,cancelled,progress));
 memset(&f,0,sizeof(f));f.cancel_after=30;assert(!qlx_export(request,&f,read_page,write_bytes,cancelled,progress));
 memset(&f,0,sizeof(f));f.duplicate=true;assert(!qlx_export(request,&f,read_page,write_bytes,cancelled,progress));
}
int main(void){parser();exports();puts("PASS: v1 history request/key/capability, DENY response evidence, privacy and complete-snapshot export/cancel/failure");return 0;}
