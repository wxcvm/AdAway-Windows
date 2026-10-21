#include "isolated_tcp_win32.h"
#include <assert.h>
#include <stdio.h>
static struct it_result run(unsigned family,enum tcp_fixture fixture) {
    struct tcp_options options={family,1200,NULL,NULL,fixture};struct it_result result;
    isolated_tcp_run(&options,&result);
    assert(result.cleanup_ok && result.sockets_closed==result.sockets_opened);
    return result;
}
struct cancel_test { struct tcp_options options;struct it_result result; };
static DWORD WINAPI pending(void *opaque) {
    struct cancel_test *test=opaque;isolated_tcp_run(&test->options,&test->result);return 0;
}
int main(void) {
    for(unsigned family=4;family<=6;family+=2) {
        for(unsigned cycle=0;cycle<3;cycle++) {
            struct it_result normal=run(family,TCP_NORMAL);
            printf("TCP/%u cycle %u status %u stage %u sockets %u/%u error %u\n",family,cycle,normal.status,normal.stage,normal.sockets_closed,normal.sockets_opened,normal.error);
            fflush(stdout);
            assert(normal.status==IT_OK && normal.sockets_opened==6);
        }
        for(enum tcp_fixture fixture=TCP_STALE;fixture<=TCP_OVERSIZE;fixture++) {
            struct it_result rejected=run(family,fixture);assert(rejected.status==IT_INVALID);
            if(fixture==TCP_BAD_AUTH || fixture==TCP_BAD_TARGET)assert(rejected.sockets_opened==4);
        }
        struct tcp_options silent={family,150,NULL,NULL,TCP_SILENT};struct it_result timeout;
        isolated_tcp_run(&silent,&timeout);assert(timeout.status==IT_TIMEOUT && timeout.cleanup_ok);
        struct cancel_test test={{family,1200,NULL,NULL,TCP_SILENT},{0}};
        test.options.cancel=CreateEventW(NULL,TRUE,FALSE,NULL);test.options.ready=CreateEventW(NULL,TRUE,FALSE,NULL);
        assert(test.options.cancel && test.options.ready);
        HANDLE thread=CreateThread(NULL,0,pending,&test,0,NULL);assert(thread);
        assert(WaitForSingleObject(test.options.ready,1000)==WAIT_OBJECT_0);SetEvent(test.options.cancel);
        assert(WaitForSingleObject(thread,1000)==WAIT_OBJECT_0);assert(test.result.status==IT_CANCELLED && test.result.cleanup_ok);
        assert(test.result.sockets_opened==test.result.sockets_closed);
        assert(CloseHandle(thread) && CloseHandle(test.options.cancel) && CloseHandle(test.options.ready));
        assert(run(family,TCP_NORMAL).status==IT_OK);
        HANDLE cancel=CreateEventW(NULL,TRUE,TRUE,NULL);assert(cancel);
        struct tcp_options stopped={family,1200,cancel,NULL,TCP_NORMAL};struct it_result result;
        isolated_tcp_run(&stopped,&result);assert(result.status==IT_CANCELLED && result.sockets_opened==0 && result.cleanup_ok);assert(CloseHandle(cancel));
    }
    struct it_result invalid;isolated_tcp_run(NULL,&invalid);assert(invalid.status==IT_INVALID && invalid.sockets_opened==0);
    struct tcp_options bad={4,1201,NULL,NULL,TCP_NORMAL};isolated_tcp_run(&bad,&invalid);assert(invalid.status==IT_INVALID);
    puts("Windows dual-stack authenticated TCP partial-I/O, half-close, rejection, timeout, cancellation and restart passed");return 0;
}
