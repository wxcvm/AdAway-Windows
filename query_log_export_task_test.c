#include "query_log_export_task.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    struct qlp_request live = {0};
    struct qln_page page = {0};
    live.offset=300;live.filter.enabled=true;strcpy(live.filter.query,"ads");
    strcpy(page.generation,"0123456789abcdef0123456789abcdef");
    strcpy(page.anchor,"123");
    assert(qlp_filter_key(&live.filter,page.query_key));
    page.total=333;page.retained_total=4096;
    struct qlx_query_snapshot frozen;
    assert(qlx_query_capture(&frozen,&live,&page));
    /* The modal loop may process new navigation/results. It cannot alter this value. */
    strcpy(live.filter.query,"new query");strcpy(page.anchor,"999");page.total=0;
    assert(frozen.request.offset==0);
    assert(!strcmp(frozen.request.filter.query,"ads"));
    assert(!strcmp(frozen.request.anchor,"123"));
    assert(frozen.total==333&&frozen.retained==4096);
    wchar_t path[MAX_PATH]=L"C:/临时/请求.csv";
    struct qlx_export_task task;
    assert(qlx_task_confirm(&task,7,&frozen,path));
    memset(&frozen,0,sizeof(frozen));path[3]=L'X';
    assert(task.id==7&&task.query.total==333);
    assert(!wcscmp(task.target,L"C:/临时/请求.csv"));
    struct qlx_export_task worker=task;
    task.query.total=1;task.target[3]=L'Y';
    assert(worker.query.total==333&&worker.target[3]!=L'Y');
    struct qlx_export_progress progress;
    qlx_progress_begin(&progress,7,333);
    assert(qlx_progress_update(&progress,7,300,333));
    assert(!qlx_progress_update(&progress,6,333,333));
    assert(!qlx_progress_update(&progress,7,299,333));
    assert(!qlx_progress_update(&progress,7,334,333));
    assert(!qlx_progress_update(&progress,7,301,334));
    qlx_progress_begin(&progress,8,0);
    assert(!qlx_progress_finish(&progress,7,ERROR_READ_FAULT,ERROR_ACCESS_DENIED,L"old-stage"));
    assert(progress.error==0&&progress.cleanup_error==0&&!progress.stage[0]);
    assert(!qlx_progress_update(&progress,7,333,333));
    assert(qlx_progress_update(&progress,8,0,0));
    assert(qlx_progress_finish(&progress,8,ERROR_RETRY,ERROR_ACCESS_DENIED,L"owned-stage"));
    assert(!wcscmp(progress.stage,L"owned-stage"));
    assert(qlx_progress_finish(&progress,8,0,0,NULL));
    assert(!progress.stage[0]);
    assert(!qlx_task_confirm(&task,0,&worker.query,L"file.csv"));
    assert(!qlx_task_confirm(&task,9,&worker.query,L""));
    wchar_t long_path[MAX_PATH+1];
    for(size_t i=0;i<MAX_PATH;++i)long_path[i]=L'x';
    long_path[MAX_PATH]=0;
    assert(!qlx_task_confirm(&task,9,&worker.query,long_path));
    live.filter=worker.query.request.filter;
    page= (struct qln_page){0};
    assert(!qlx_query_capture(&frozen,&live,&page));
    memcpy(page.generation,worker.query.request.generation,sizeof(page.generation));
    memcpy(page.anchor,worker.query.request.anchor,sizeof(page.anchor));
    memcpy(page.query_key,worker.query.request.query_key,sizeof(page.query_key));
    assert(qlx_query_capture(&frozen,&live,&page)); /* zero matches is valid */
    page.total=1;assert(!qlx_query_capture(&frozen,&live,&page));
    page.total=0;page.retained_total=QLP_MAX_TOTAL+1;
    assert(!qlx_query_capture(&frozen,&live,&page));
    puts("PASS: frozen modal query, copied task/path, zero matches, stale task isolation and bounds");
    return 0;
}
