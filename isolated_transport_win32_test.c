#include "isolated_transport_win32.h"
#include <assert.h>
#include <stdio.h>
struct test_run { struct it_options options; struct it_result result; };
static DWORD WINAPI run_thread(void *opaque) {
    struct test_run *run=opaque; isolated_transport_run(&run->options,&run->result); return 0;
}
static void clean(const struct it_result *result) {
    assert(result->cleanup_ok); assert(result->sockets_opened==result->sockets_closed);
}
int main(void) {
    for (unsigned family=4;family<=6;family+=2) {
        for (unsigned cycle=0;cycle<8;cycle++) {
            struct it_options options={family,1000,NULL,NULL,IT_NORMAL}; struct it_result result;
            isolated_transport_run(&options,&result);
            if (result.status!=IT_OK) fprintf(stderr,"family=%u cycle=%u status=%d elapsed=%u opened=%u closed=%u error=%u stage=%u\n",family,cycle,result.status,result.elapsed_ms,result.sockets_opened,result.sockets_closed,result.error,result.stage);
            assert(result.status==IT_OK); clean(&result);
        }
        for (enum it_fixture fault=IT_SILENT;fault<=IT_BAD_PACKET;fault++) {
            struct it_options options={family,fault==IT_SILENT?100u:1000u,NULL,NULL,fault}; struct it_result result;
            isolated_transport_run(&options,&result); assert(result.status==(fault==IT_SILENT?IT_TIMEOUT:IT_INVALID)); clean(&result);
        }
        for (unsigned cycle=0;cycle<4;cycle++) {
            HANDLE cancel=CreateEventW(NULL,TRUE,FALSE,NULL),ready=CreateEventW(NULL,TRUE,FALSE,NULL); assert(cancel && ready);
            struct test_run run={{family,1200,cancel,ready,IT_SILENT},{0}};
            HANDLE thread=CreateThread(NULL,0,run_thread,&run,0,NULL); assert(thread);
            assert(WaitForSingleObject(ready,1000)==WAIT_OBJECT_0); SetEvent(cancel);
            assert(WaitForSingleObject(thread,1000)==WAIT_OBJECT_0); assert(run.result.status==IT_CANCELLED); clean(&run.result);
            CloseHandle(thread); CloseHandle(ready); CloseHandle(cancel);
            run.options.cancel=NULL;run.options.ready=NULL;run.options.fixture=IT_NORMAL;
            isolated_transport_run(&run.options,&run.result); assert(run.result.status==IT_OK); clean(&run.result);
        }
    }
    puts("Both IP families: actual packet ingress/relay/reply, timeout, malformed/stale rejection, in-flight cancellation, cleanup and fresh restart passed");
    return 0;
}
