#include "query_log_export_file_win32.h"
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#c); exit(1); } } while (0)

enum fault { NONE, CREATE_FAIL, OPEN_FAIL, WRITE_FAIL, FLUSH_FAIL, SYNC_FAIL, CLOSE_FAIL, REPLACE_FAIL, CLEANUP_FAIL };
struct fixture {
    const struct qlx_file_ops *base;
    struct qlx_file_ops ops;
    struct qlx_file_transaction tx;
    volatile LONG phase;
    enum fault fault;
    unsigned flushes, syncs, closes, replacements, notices;
    bool cancel_after_close, cancel_in_replace;
    HANDLE entered, release;
    bool gate_replace;
};
static FILE *create(void *opaque,const wchar_t *target,wchar_t *stage,DWORD *error) {
    struct fixture *f=opaque;
    if(f->fault==CREATE_FAIL){*error=ERROR_PATH_NOT_FOUND;return NULL;}
    FILE *file=f->base->create(NULL,target,stage,error);
    if(file&&f->fault==OPEN_FAIL){CHECK(!fclose(file));*error=ERROR_OPEN_FAILED;return NULL;}
    return file;
}
static size_t write_bytes(void *opaque,FILE *file,const char *bytes,size_t count) {
    struct fixture *f=opaque;
    return f->base->write(NULL,file,bytes,f->fault==WRITE_FAIL&&count?count-1:count);
}
static int flush(void *opaque,FILE *file) {
    struct fixture *f=opaque;f->flushes++;
    int result=f->base->flush(NULL,file);
    return f->fault==FLUSH_FAIL?EOF:result;
}
static int sync_file(void *opaque,FILE *file) {
    struct fixture *f=opaque;f->syncs++;
    return f->fault==SYNC_FAIL?-1:f->base->sync(NULL,file);
}
static int close_file(void *opaque,FILE *file) {
    struct fixture *f=opaque;f->closes++;
    int result=f->base->close(NULL,file);
    return f->fault==CLOSE_FAIL?EOF:result;
}
static bool replace(void *opaque,const wchar_t *stage,const wchar_t *target,DWORD *error) {
    struct fixture *f=opaque;f->replacements++;
    CHECK(qlx_phase_get(&f->phase)==QLX_COMMITTING);
    if(f->cancel_in_replace)CHECK(!qlx_phase_cancel(&f->phase));
    if(f->entered&&f->gate_replace) {
        CHECK(SetEvent(f->entered));CHECK(WaitForSingleObject(f->release,5000)==WAIT_OBJECT_0);
    }
    if(f->fault==REPLACE_FAIL){*error=ERROR_SHARING_VIOLATION;return false;}
    return f->base->replace(NULL,stage,target,error);
}
static bool remove_stage(void *opaque,const wchar_t *stage,DWORD *error) {
    struct fixture *f=opaque;
    if(f->fault==CLEANUP_FAIL){*error=ERROR_ACCESS_DENIED;return false;}
    return f->base->remove(NULL,stage,error);
}
static bool cancelled(void *opaque) {
    struct fixture *f=opaque;
    if(f->entered&&!f->gate_replace) {
        CHECK(f->closes==1);CHECK(SetEvent(f->entered));
        CHECK(WaitForSingleObject(f->release,5000)==WAIT_OBJECT_0);
    }
    return f->cancel_after_close;
}
static void notice(void *opaque) {
    struct fixture *f=opaque;CHECK(qlx_phase_get(&f->phase)==QLX_COMMITTING);f->notices++;
}
static void init(struct fixture *f,enum fault fault) {
    memset(f,0,sizeof(*f));f->base=qlx_file_default_ops();f->phase=QLX_RUNNING;f->fault=fault;
    f->ops=(struct qlx_file_ops){create,write_bytes,flush,sync_file,close_file,replace,remove_stage};
    qlx_file_init(&f->tx,&f->ops,f);
}
static void seed(const wchar_t *target) {
    FILE *file=_wfopen(target,L"wb");CHECK(file);
    CHECK(fwrite("original",1,8,file)==8);CHECK(!fclose(file));
}
static void contents(const wchar_t *target,const char *expected) {
    char buffer[64]={0};FILE *file=_wfopen(target,L"rb");CHECK(file);
    size_t count=fread(buffer,1,sizeof(buffer),file);
    CHECK(!ferror(file)&&!fclose(file));CHECK(count==strlen(expected));
    CHECK(!memcmp(buffer,expected,count));
}
static bool exists(const wchar_t *path) { return GetFileAttributesW(path)!=INVALID_FILE_ATTRIBUTES; }
static enum qlx_phase finish(struct fixture *f,const wchar_t *target,bool ok) {
    return qlx_file_finish(&f->tx,target,ok,&f->phase,cancelled,notice,f);
}
struct worker {struct fixture *f;const wchar_t *target;enum qlx_phase result;};
static DWORD WINAPI finish_worker(void *opaque) {
    struct worker *w=opaque;w->result=finish(w->f,w->target,true);return 0;
}
int wmain(int argc,wchar_t **argv) {
    CHECK(argc==2);
    wchar_t root[MAX_PATH],base[MAX_PATH],target[MAX_PATH],foreign[MAX_PATH];
    CHECK(GetFullPathNameW(argv[1],MAX_PATH,base,NULL)>0);
    CHECK(swprintf(root,MAX_PATH,L"%ls\\export-tx-%lu",base,(unsigned long)GetCurrentProcessId())>0);
    CHECK(CreateDirectoryW(root,NULL)); /* Never reuse or delete a preexisting directory. */
    CHECK(swprintf(target,MAX_PATH,L"%ls\\导出证据.csv",root)>0);
    CHECK(swprintf(foreign,MAX_PATH,L"%ls\\qle-foreign.tmp",root)>0);seed(foreign);
    unsigned cases=0;
    for(int fault=NONE;fault<=REPLACE_FAIL;fault++) {
        seed(target);struct fixture f;init(&f,(enum fault)fault);
        bool opened=qlx_file_open(&f.tx,target);
        CHECK(opened==(fault!=CREATE_FAIL&&fault!=OPEN_FAIL));
        bool written=opened&&qlx_file_write(&f.tx,"new-result",10);
        CHECK(written==(opened&&fault!=WRITE_FAIL));
        enum qlx_phase result=finish(&f,target,written);
        CHECK(result==(fault==NONE?QLX_SUCCEEDED:QLX_FAILED));
        CHECK(!f.tx.file&&!f.tx.owned&&!f.tx.cleanup_error);
        if(f.tx.stage[0])CHECK(!exists(f.tx.stage));
        CHECK(f.closes==(unsigned)opened&&f.flushes==(unsigned)opened);
        CHECK(f.replacements==(unsigned)(fault==NONE||fault==REPLACE_FAIL));
        CHECK(f.notices==f.replacements);
        if(fault!=NONE)CHECK(f.tx.error!=0&&f.tx.failed_at!=QLX_FILE_NONE);
        if(fault==WRITE_FAIL)CHECK(f.tx.failed_at==QLX_FILE_WRITE);
        if(fault==FLUSH_FAIL)CHECK(f.tx.failed_at==QLX_FILE_FLUSH&&!f.syncs);
        if(fault==SYNC_FAIL)CHECK(f.tx.failed_at==QLX_FILE_SYNC);
        if(fault==CLOSE_FAIL)CHECK(f.tx.failed_at==QLX_FILE_CLOSE);
        if(fault==REPLACE_FAIL)CHECK(f.tx.error==ERROR_SHARING_VIOLATION);
        contents(target,fault==NONE?"new-result":"original");contents(foreign,"original");cases++;
    }
    /* Read failure: partial bytes can never become a complete export. */
    {struct fixture f;init(&f,NONE);seed(target);CHECK(qlx_file_open(&f.tx,target));
     CHECK(qlx_file_write(&f.tx,"partial",7));CHECK(finish(&f,target,false)==QLX_FAILED);
     CHECK(!f.replacements&&!exists(f.tx.stage));contents(target,"original");cases++;}
    /* Cancellation after close (e.g. application exit during flush) is rechecked. */
    {struct fixture f;init(&f,NONE);seed(target);CHECK(qlx_file_open(&f.tx,target));
     CHECK(qlx_file_write(&f.tx,"new-result",10));f.cancel_after_close=true;
     CHECK(finish(&f,target,true)==QLX_CANCELLED);CHECK(!f.replacements&&!exists(f.tx.stage));
     contents(target,"original");cases++;}
    /* Cancellation before any staging creation owns/deletes nothing. */
    {struct fixture f;init(&f,NONE);f.phase=QLX_CANCEL_REQUESTED;
     CHECK(finish(&f,target,false)==QLX_CANCELLED);CHECK(!f.tx.stage[0]&&!f.closes);
     contents(foreign,"original");cases++;}
    /* Once COMMITTING wins, even cancellation inside actual replace cannot undo it. */
    {struct fixture f;init(&f,NONE);seed(target);CHECK(qlx_file_open(&f.tx,target));
     CHECK(qlx_file_write(&f.tx,"new-result",10));f.cancel_in_replace=true;
     CHECK(finish(&f,target,true)==QLX_SUCCEEDED);contents(target,"new-result");cases++;}
    /* Actual sharing violation, not only a stubbed return code. */
    {struct fixture f;init(&f,NONE);seed(target);
     HANDLE lock=CreateFileW(target,GENERIC_READ,0,NULL,OPEN_EXISTING,0,NULL);CHECK(lock!=INVALID_HANDLE_VALUE);
     CHECK(qlx_file_open(&f.tx,target));CHECK(qlx_file_write(&f.tx,"new-result",10));
     CHECK(finish(&f,target,true)==QLX_FAILED);CHECK(f.tx.failed_at==QLX_FILE_REPLACE);
     CHECK(!exists(f.tx.stage));CHECK(CloseHandle(lock));contents(target,"original");cases++;}
    /* Failed cleanup remains owned and blocks a second task until recovery. */
    {struct fixture f;init(&f,CLEANUP_FAIL);seed(target);CHECK(qlx_file_open(&f.tx,target));
     CHECK(qlx_file_write(&f.tx,"partial",7));CHECK(finish(&f,target,false)==QLX_CLEANUP_FAILED);
     CHECK(f.tx.cleanup_error==ERROR_ACCESS_DENIED&&f.tx.owned&&exists(f.tx.stage));
     InterlockedExchange(&f.phase,QLX_CLEANUP_FAILED);CHECK(!qlx_phase_begin(&f.phase));
     contents(target,"original");contents(foreign,"original");CHECK(DeleteFileW(f.tx.stage));
     CHECK(qlx_phase_cleanup_resolved(&f.phase)&&qlx_phase_begin(&f.phase));cases++;}
    /* Deterministic real-file commit races, no timing-only sleeps. */
    for(unsigned committed=0;committed<2;committed++) {
        struct fixture f;init(&f,NONE);seed(target);CHECK(qlx_file_open(&f.tx,target));
        CHECK(qlx_file_write(&f.tx,"new-result",10));f.gate_replace=committed!=0;
        f.entered=CreateEventW(NULL,TRUE,FALSE,NULL);f.release=CreateEventW(NULL,TRUE,FALSE,NULL);
        CHECK(f.entered&&f.release);
        struct worker w={&f,target,QLX_IDLE};HANDLE thread=CreateThread(NULL,0,finish_worker,&w,0,NULL);CHECK(thread);
        CHECK(WaitForSingleObject(f.entered,5000)==WAIT_OBJECT_0);
        CHECK(qlx_phase_cancel(&f.phase)==!committed);CHECK(SetEvent(f.release));
        CHECK(WaitForSingleObject(thread,5000)==WAIT_OBJECT_0);
        CHECK(w.result==(committed?QLX_SUCCEEDED:QLX_CANCELLED));
        contents(target,committed?"new-result":"original");CHECK(!exists(f.tx.stage));
        CHECK(CloseHandle(thread)&&CloseHandle(f.entered)&&CloseHandle(f.release));cases++;
    }
    contents(foreign,"original");CHECK(DeleteFileW(target)&&DeleteFileW(foreign));CHECK(RemoveDirectoryW(root));
    printf("PASS: %u real-file transaction cases (I/O faults, cleanup, ownership, cancellation and gated commit races)\n",cases);
    return 0;
}
