#include "query_log_export_state.h"
#include <stdio.h>
#include <stdlib.h>
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#c); exit(1); } } while(0)
struct race { volatile LONG phase, cancelled, committed; HANDLE start; };
static DWORD WINAPI cancel_worker(void *opaque) {
    struct race *r=opaque; CHECK(WaitForSingleObject(r->start,3000)==WAIT_OBJECT_0);
    if(qlx_phase_cancel(&r->phase))InterlockedIncrement(&r->cancelled);
    return 0;
}
static DWORD WINAPI commit_worker(void *opaque) {
    struct race *r=opaque; CHECK(WaitForSingleObject(r->start,3000)==WAIT_OBJECT_0);
    if(qlx_phase_commit(&r->phase))InterlockedIncrement(&r->committed);
    return 0;
}
int main(void) {
    volatile LONG phase=QLX_IDLE;
    CHECK(qlx_phase_begin(&phase)); CHECK(!qlx_phase_begin(&phase));
    CHECK(!qlx_phase_cancel(&phase)); CHECK(!qlx_phase_commit(&phase));
    for(int p=QLX_CHOOSING;p<=QLX_COMMITTING;p++) {
        InterlockedExchange(&phase,p); CHECK(qlx_phase_busy(qlx_phase_get(&phase)));
        CHECK(!qlx_phase_begin(&phase));
    }
    InterlockedExchange(&phase,QLX_QUEUED); CHECK(qlx_phase_cancel(&phase));
    CHECK(qlx_phase_cancel(&phase)); CHECK(!qlx_phase_commit(&phase));
    InterlockedExchange(&phase,QLX_RUNNING); CHECK(qlx_phase_commit(&phase));
    CHECK(!qlx_phase_cancel(&phase)); CHECK(!qlx_phase_commit(&phase));
    for(int p=QLX_SUCCEEDED;p<=QLX_DIALOG_FAILED;p++) {
        InterlockedExchange(&phase,p);
        CHECK(qlx_phase_begin(&phase)==(p!=QLX_CLEANUP_FAILED));
    }
    InterlockedExchange(&phase,QLX_CLEANUP_FAILED);
    CHECK(!qlx_phase_begin(&phase)); CHECK(!qlx_phase_cancel(&phase));
    CHECK(qlx_phase_cleanup_resolved(&phase)); CHECK(qlx_phase_begin(&phase));
    CHECK(!qlx_phase_cleanup_resolved(&phase));
    for(int i=0;i<1000;i++) {
        struct race r={QLX_RUNNING,0,0,NULL}; r.start=CreateEventW(NULL,TRUE,FALSE,NULL); CHECK(r.start);
        HANDLE workers[2]={CreateThread(NULL,0,cancel_worker,&r,0,NULL),CreateThread(NULL,0,commit_worker,&r,0,NULL)};
        CHECK(workers[0]&&workers[1]); CHECK(SetEvent(r.start));
        CHECK(WaitForMultipleObjects(2,workers,TRUE,5000)==WAIT_OBJECT_0);
        CHECK(r.cancelled+r.committed==1);
        CHECK(qlx_phase_get(&r.phase)==(r.cancelled?QLX_CANCEL_REQUESTED:QLX_COMMITTING));
        CHECK(!qlx_phase_begin(&r.phase));
        CHECK(CloseHandle(workers[0])&&CloseHandle(workers[1])&&CloseHandle(r.start));
    }
    puts("PASS: export phases, cleanup failure gate and 1000 real-thread cancel/commit races");
    return 0;
}
