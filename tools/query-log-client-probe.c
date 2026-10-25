/* Actual bounded desktop response/page parser used by the loopback fixture. */
#include "query_log_page.h"
#include <stdio.h>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif
int main(int argc, char **argv) {
    static char response[192 * 1024];
    struct qlp_request request;
    struct mg_str body;
    uint64_t offset = 0;
    if (argc != 2 && argc != 4) return 1;
    bool filtered = argc == 4 && strcmp(argv[1], "--v1") == 0;
    bool stats_mode = argc == 2 && strcmp(argv[1], "--stats") == 0;
    memset(&request, 0, sizeof(request));
    if (!stats_mode && (!qlp_decimal_digits(filtered ? argv[2] : argv[1], strlen(filtered ? argv[2] : argv[1]), &offset) || offset > QLP_MAX_TOTAL)) return 1;
    request.offset = (uint32_t)offset;
    if (filtered) {
        struct mg_str filters=mg_str(argv[3]);request.filter.enabled=true;
        const char *names[]={"$.action","$.family","$.type","$.uid"};
        bool *present[]={&request.filter.has_action,&request.filter.has_family,&request.filter.has_type,&request.filter.has_uid};
        int *values[]={&request.filter.action,&request.filter.family,&request.filter.type,&request.filter.uid};
        for(unsigned i=0;i<4;++i)if(mg_json_get_tok(filters,names[i]).len){
            bool negative=false;uint64_t magnitude;
            if(!qlp_json_integer(mg_json_get_tok(filters,names[i]),true,&negative,&magnitude)||(negative?magnitude!=1:magnitude>INT_MAX))return 1;
            *present[i]=true;*values[i]=negative?-1:(int)magnitude;
        }
        if(mg_json_get_tok(filters,"$.q").len){if(!qlp_string_escapes_supported(filters,"$.q"))return 1;size_t n=mg_json_unescape(filters,"$.q",request.filter.query,sizeof(request.filter.query));if(n>=sizeof(request.filter.query))return 1;}
        if(mg_json_get_tok(filters,"$.generation").len){
            if(!qlp_read_generation(filters,request.generation)||!qlp_read_anchor(filters,request.anchor)||!qlp_string_escapes_supported(filters,"$.queryKey")||mg_json_unescape(filters,"$.queryKey",request.query_key,sizeof(request.query_key))!=64)return 1;
        }
    } else if (argc == 4) {
        if (strlen(argv[2]) >= sizeof(request.generation) || strlen(argv[3]) >= sizeof(request.anchor)) return 1;
        memcpy(request.generation, argv[2], strlen(argv[2]) + 1);
        memcpy(request.anchor, argv[3], strlen(argv[3]) + 1);
    }
#ifdef _WIN32
    if (_setmode(_fileno(stdin), _O_BINARY) < 0) return 1;
#endif
    size_t length = fread(response, 1, sizeof(response), stdin);
    if (ferror(stdin) || length == sizeof(response) || !dashboard_response_body(response, length, &body)) return 2;
    mg_log_set(MG_LL_NONE);
    if (stats_mode) {
        if (!dashboard_stats_valid(body)) return 2;
        puts("valid-stats");
        return 0;
    }
    struct qlp_page *page = (struct qlp_page *)calloc(1, sizeof(*page));
    if (!page) return 1;
    if (!qlp_parse(body, &request, page)) { free(page); return 2; }
    printf("%u,%u,%u,%u,%d,%s,%s\n", page->offset, page->returned, page->next_offset,
           page->total, page->has_more ? 1 : 0, page->generation, page->anchor);
    if(filtered)printf("v1,%u,%s\n",page->retained_total,page->query_key);
    for (uint32_t i = 0; i < page->returned; i++) puts(page->rows[i].host);
    free(page);
    return 0;
}
