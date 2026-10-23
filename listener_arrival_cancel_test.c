#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "listener_arrival_task_win32.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while (0)
struct fixture { SOCKET listener; const char *ip; int port; };
static struct fixture listen_local(int family) {
    struct fixture f={INVALID_SOCKET,family==6 ? "::1" : "127.0.0.1",0};
    f.listener=socket(family==6 ? AF_INET6 : AF_INET,SOCK_STREAM,IPPROTO_TCP); CHECK(f.listener!=INVALID_SOCKET);
    if (family==6) { DWORD only=1; CHECK(!setsockopt(f.listener,IPPROTO_IPV6,IPV6_V6ONLY,(char *)&only,sizeof(only))); }
    SOCKADDR_STORAGE address; memset(&address,0,sizeof(address));
    int size;
    if (family==6) { struct sockaddr_in6 *v6=(struct sockaddr_in6 *)&address; v6->sin6_family=AF_INET6;
        CHECK(inet_pton(AF_INET6,f.ip,&v6->sin6_addr)==1); size=sizeof(*v6);
    } else { struct sockaddr_in *v4=(struct sockaddr_in *)&address; v4->sin_family=AF_INET;
        CHECK(inet_pton(AF_INET,f.ip,&v4->sin_addr)==1); size=sizeof(*v4); }
    CHECK(!bind(f.listener,(struct sockaddr *)&address,size)); CHECK(!listen(f.listener,4));
    CHECK(!getsockname(f.listener,(struct sockaddr *)&address,&size));
    f.port=ntohs(family==6 ? ((struct sockaddr_in6 *)&address)->sin6_port : ((struct sockaddr_in *)&address)->sin_port);
    return f;
}
static SOCKET accepted(struct fixture *f) {
    fd_set ready; FD_ZERO(&ready); FD_SET(f->listener,&ready); struct timeval limit={3,0};
    CHECK(select(0,&ready,NULL,NULL,&limit)==1);
    SOCKET peer=accept(f->listener,NULL,NULL); CHECK(peer!=INVALID_SOCKET);
    return peer;
}
static bool event_cancelled(void *event) { return WaitForSingleObject((HANDLE)event,0)==WAIT_OBJECT_0; }
struct probe { struct fixture fixture; HANDLE cancel,done; bool tls,received; enum arrival_tls_state tls_state; };
static DWORD WINAPI run_probe(void *opaque) {
    struct probe *p=(struct probe *)opaque;
    struct arrival_cancel cancel={event_cancelled,p->cancel,NULL};
    if (p->tls) p->tls_state=arrival_tls_cancel(p->fixture.ip,p->fixture.port,"localhost",&cancel).state;
    else p->received=arrival_receipt_cancel(p->fixture.ip,p->fixture.port,&cancel);
    SetEvent(p->done); return 0;
}
static void no_extra_connection(struct fixture *f) {
    fd_set ready; FD_ZERO(&ready); FD_SET(f->listener,&ready); struct timeval limit={0,100000};
    CHECK(select(0,&ready,NULL,NULL,&limit)==0);
}
static void test_socket_cancel(int family,bool tls) {
    struct probe p={0}; p.fixture=listen_local(family); p.tls=tls;
    p.cancel=CreateEventW(NULL,TRUE,FALSE,NULL); p.done=CreateEventW(NULL,TRUE,FALSE,NULL); CHECK(p.cancel && p.done);
    HANDLE thread=CreateThread(NULL,0,run_probe,&p,0,NULL); CHECK(thread);
    SOCKET peer=accepted(&p.fixture); /* A real connected peer sends no reply. */
    ULONGLONG start=GetTickCount64(); CHECK(SetEvent(p.cancel));
    CHECK(WaitForSingleObject(p.done,1000)==WAIT_OBJECT_0);
    CHECK(GetTickCount64()-start<800);
    CHECK(tls ? p.tls_state==ARRIVAL_TLS_CANCELLED : !p.received);
    CHECK(WaitForSingleObject(thread,1000)==WAIT_OBJECT_0);
    no_extra_connection(&p.fixture);
    closesocket(peer); closesocket(p.fixture.listener); CloseHandle(thread); CloseHandle(p.cancel); CloseHandle(p.done);
}
static void test_close_detach_and_retry(int family) {
    struct fixture f=listen_local(family);
    struct arrival_config config={0}; config.pair=true; config.http=f.port; config.https=f.port;
    snprintf(family==6 ? config.ipv6 : config.ip,64,"%s",f.ip);
    enum arrival_task_status status;
    struct arrival_task *task=arrival_task_start(&config,"ads.cancel.invalid","hosts.cancel.invalid",&status);
    CHECK(task && status==ARRIVAL_TASK_OK);
    SOCKET peer=accepted(&f);
    wchar_t progress[384]; arrival_task_progress(task,progress,384);
    CHECK(wcsstr(progress,L"HTTP") && wcsstr(progress,family==6 ? L"IPv6" : L"IPv4"));
    struct arrival_task *parallel=arrival_task_start(&config,"","",&status);
    CHECK(!parallel && status==ARRIVAL_TASK_BUSY);
    ULONGLONG start=GetTickCount64();
    arrival_task_cancel(task); arrival_task_release(task); /* Window closes now. */
    task=NULL;
    while (GetTickCount64()-start<1000) {
        task=arrival_task_start(&config,"bad","",&status);
        if (task) break;
        CHECK(status==ARRIVAL_TASK_BUSY); Sleep(10);
    }
    CHECK(task && GetTickCount64()-start<800);
    while (!arrival_task_done(task) && GetTickCount64()-start<1500) Sleep(10);
    CHECK(arrival_task_done(task)); CHECK(wcsstr(arrival_task_result(task),L"请输入"));
    arrival_task_release(task);
    no_extra_connection(&f); /* Cancelled report did not start TLS or DNS stage. */
    closesocket(peer); closesocket(f.listener);
}
int main(int argc,char **argv) {
    WSADATA winsock; CHECK(WSAStartup(MAKEWORD(2,2),&winsock)==0);
    bool include_tls=!(argc==2 && !strcmp(argv[1],"--http-only"));
    for (int i=0;i<2;i++) {
        int family=i ? 6 : 4;
        test_socket_cancel(family,false);
        if (include_tls) test_socket_cancel(family,true);
        test_close_detach_and_retry(family);
    }
    DWORD before=0,after=0; CHECK(GetProcessHandleCount(GetCurrentProcess(),&before));
    for (int i=0;i<12;i++) test_close_detach_and_retry(i%2 ? 6 : 4);
    Sleep(100); CHECK(GetProcessHandleCount(GetCurrentProcess(),&after)); CHECK(after<=before+2);
    WSACleanup();
    FILE *evidence=fopen("arrival-cancel-results.json","wb"); CHECK(evidence);
    fprintf(evidence,"{\"passed\":true,\"realDualStackHttpCancellation\":true,\"realDualStackTlsCancellation\":%s,\"progress\":true,\"closeDetachRetry\":true,\"singleTask\":true,\"handleCleanup\":true,\"hostNetworkChanges\":false}\n",include_tls ? "true" : "false");
    CHECK(!fclose(evidence));
    printf("PASS: real dual-stack stalled HTTP%s cancellation, stage progress, close/detach, no later probes, single task, retry and handle cleanup\n",include_tls ? "/TLS" : " (TLS not exercised)");
    return 0;
}
