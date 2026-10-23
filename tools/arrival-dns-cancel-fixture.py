"""Compile the actual DNS wait/ownership code with a deliberately stalled OS resolver."""
import importlib.util
from pathlib import Path
import sys

root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('core_hooks',root/'tools/build-rule-core.py')
hooks=importlib.util.module_from_spec(spec)
spec.loader.exec_module(hooks)
source=(root/'listener_arrival_win32.c').read_text(encoding='utf-8')

def extract(marker):
    left,right=hooks.function_span(source,marker)
    return source[left:right]

out=r'''
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "listener_arrival_win32.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while (0)
static HANDLE resolver_entered,resolver_release,cancel_event;
static volatile LONG resolver_calls;
static int controlled_resolver(PCWSTR name,PCWSTR service,const ADDRINFOW *hints,PADDRINFOW *answers) {
    (void)service; CHECK(hints->ai_family==AF_UNSPEC);
    CHECK(!wcscmp(name,L"dns-fixture.invalid."));
    InterlockedIncrement(&resolver_calls); SetEvent(resolver_entered);
    CHECK(WaitForSingleObject(resolver_release,5000)==WAIT_OBJECT_0);
    /* This read happens after the caller cancelled and returned. Its context
       must still be owned by the outstanding resolver thread. */
    CHECK(!wcscmp(name,L"dns-fixture.invalid.")); *answers=NULL;
    return WSAHOST_NOT_FOUND;
}
#define GetAddrInfoW controlled_resolver
'''
out+=extract('struct ac_dns_work {')+';\nstatic volatile LONG ac_dns_active;\n'
for marker in ('static void ac_dns_release(', 'static DWORD WINAPI ac_dns_worker(', 'static int ac_resolve('):
    out+=extract(marker)+'\n'
out+=r'''
#undef GetAddrInfoW
static bool cancelled(void *event) { return WaitForSingleObject((HANDLE)event,0)==WAIT_OBJECT_0; }
static DWORD WINAPI call_resolver(void *opaque) {
    int *status=(int *)opaque; ADDRINFOW *answers=NULL;
    struct arrival_cancel cancel={cancelled,cancel_event,NULL};
    *status=ac_resolve("dns-fixture.invalid",&answers,&cancel); CHECK(!answers); return 0;
}
int main(void) {
    WSADATA data; CHECK(!WSAStartup(MAKEWORD(2,2),&data));
    resolver_entered=CreateEventW(NULL,TRUE,FALSE,NULL);
    resolver_release=CreateEventW(NULL,TRUE,FALSE,NULL);
    cancel_event=CreateEventW(NULL,TRUE,FALSE,NULL);
    CHECK(resolver_entered && resolver_release && cancel_event);
    int status=0; HANDLE caller=CreateThread(NULL,0,call_resolver,&status,0,NULL); CHECK(caller);
    CHECK(WaitForSingleObject(resolver_entered,2000)==WAIT_OBJECT_0);
    ULONGLONG start=GetTickCount64(); SetEvent(cancel_event);
    CHECK(WaitForSingleObject(caller,1000)==WAIT_OBJECT_0);
    CHECK(status==WSA_OPERATION_ABORTED && GetTickCount64()-start<800);
    CHECK(ac_dns_active==1 && resolver_calls==1);
    ADDRINFOW *answers=NULL;
    CHECK(ac_resolve("dns-fixture.invalid",&answers,NULL)==WSAEINPROGRESS);
    CHECK(!answers && resolver_calls==1); /* Retry never launches a second DNS worker. */
    SetEvent(resolver_release);
    start=GetTickCount64(); while (ac_dns_active && GetTickCount64()-start<1000) Sleep(10);
    CHECK(!ac_dns_active); Sleep(50);
    CloseHandle(caller); CloseHandle(cancel_event); CloseHandle(resolver_release); CloseHandle(resolver_entered);
    WSACleanup();
    puts("PASS: actual DNS cancellation returns promptly; outstanding resolver retains heap ownership and sole global slot until completion");
    return 0;
}
'''
target=Path(sys.argv[1]); target.parent.mkdir(parents=True,exist_ok=True)
target.write_text(out,encoding='utf-8',newline='\n')
