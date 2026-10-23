#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "listener_arrival_task_win32.h"

struct arrival_task {
    LONG references;
    HANDLE cancel,done;
    struct arrival_config config;
    char adblock[256],hosts[256];
    wchar_t result[6144];
    SRWLOCK progress_lock;
    wchar_t progress[384];
};
static volatile LONG arrival_task_active;

static bool task_cancelled(void *opaque) {
    const struct arrival_task *task=(const struct arrival_task *)opaque;
    return WaitForSingleObject(task->cancel,0)==WAIT_OBJECT_0;
}

static void task_progress(void *opaque,enum arrival_stage stage,const char *target,int port) {
    struct arrival_task *task=(struct arrival_task *)opaque;
    AcquireSRWLockExclusive(&task->progress_lock);
    switch (stage) {
        case ARRIVAL_STAGE_MANAGEMENT: swprintf(task->progress,384,L"正在检查管理回执 [%hs]:%d",target,port); break;
        case ARRIVAL_STAGE_HTTP: swprintf(task->progress,384,L"正在检查 IPv%d HTTP [%hs]:%d",strchr(target,':') ? 6 : 4,target,port); break;
        case ARRIVAL_STAGE_HTTPS: swprintf(task->progress,384,L"正在检查 IPv%d HTTPS [%hs]:%d",strchr(target,':') ? 6 : 4,target,port); break;
        case ARRIVAL_STAGE_DNS: swprintf(task->progress,384,L"正在等待系统 DNS：%hs",target); break;
        case ARRIVAL_STAGE_UDP: swprintf(task->progress,384,L"正在读取 %hs UDP/%d 占用",target,port); break;
        case ARRIVAL_STAGE_DONE: wcscpy(task->progress,L"检测完成"); break;
        case ARRIVAL_STAGE_CANCELLED: wcscpy(task->progress,L"检测已取消"); break;
        default: wcscpy(task->progress,L"正在开始检测…"); break;
    }
    task->progress[383]=0;
    ReleaseSRWLockExclusive(&task->progress_lock);
}

void arrival_task_release(struct arrival_task *task) {
    if (!task || InterlockedDecrement(&task->references)!=0) return;
    CloseHandle(task->cancel); CloseHandle(task->done); free(task);
}

static DWORD WINAPI task_work(void *opaque) {
    struct arrival_task *task=(struct arrival_task *)opaque;
    struct arrival_cancel cancel={task_cancelled,task,task_progress};
    (void)arrival_report_cancel(&task->config,task->adblock,task->hosts,task->result,6144,&cancel);
    /* No dialog pointer, HWND, or posted completion can outlive the window.
       All probe/result writes finish before releasing the global run slot. */
    InterlockedExchange(&arrival_task_active,0);
    SetEvent(task->done);
    arrival_task_release(task);
    return 0;
}

struct arrival_task *arrival_task_start(const struct arrival_config *config,const char *adblock,
    const char *hosts,enum arrival_task_status *status) {
    if (status) *status=ARRIVAL_TASK_UNAVAILABLE;
    if (!config || !adblock || !hosts || strlen(adblock)>254 || strlen(hosts)>254) return NULL;
    if (InterlockedCompareExchange(&arrival_task_active,1,0)!=0) {
        if (status) *status=ARRIVAL_TASK_BUSY;
        return NULL;
    }
    struct arrival_task *task=(struct arrival_task *)calloc(1,sizeof(*task));
    if (!task) { InterlockedExchange(&arrival_task_active,0); return NULL; }
    task->references=1; task->config=*config; InitializeSRWLock(&task->progress_lock);
    memcpy(task->adblock,adblock,strlen(adblock)+1); memcpy(task->hosts,hosts,strlen(hosts)+1);
    task->cancel=CreateEventW(NULL,TRUE,FALSE,NULL); task->done=CreateEventW(NULL,TRUE,FALSE,NULL);
    if (!task->cancel || !task->done) {
        if (task->cancel) CloseHandle(task->cancel);
        if (task->done) CloseHandle(task->done);
        free(task); InterlockedExchange(&arrival_task_active,0); return NULL;
    }
    InterlockedIncrement(&task->references);
    HANDLE thread=CreateThread(NULL,0,task_work,task,0,NULL);
    if (!thread) {
        arrival_task_release(task); arrival_task_release(task);
        InterlockedExchange(&arrival_task_active,0); return NULL;
    }
    CloseHandle(thread);
    if (status) *status=ARRIVAL_TASK_OK;
    return task;
}

void arrival_task_cancel(struct arrival_task *task) { if (task) SetEvent(task->cancel); }
bool arrival_task_done(const struct arrival_task *task) { return task && WaitForSingleObject(task->done,0)==WAIT_OBJECT_0; }
bool arrival_task_cancelled(const struct arrival_task *task) { return task && WaitForSingleObject(task->cancel,0)==WAIT_OBJECT_0; }
const wchar_t *arrival_task_result(const struct arrival_task *task) { return arrival_task_done(task) ? task->result : NULL; }
void arrival_task_progress(struct arrival_task *task,wchar_t *out,size_t cap) {
    if (!out || !cap) return;
    out[0]=0; if (!task) return;
    AcquireSRWLockShared(&task->progress_lock);
    wcsncpy(out,task->progress,cap-1); out[cap-1]=0;
    ReleaseSRWLockShared(&task->progress_lock);
}
