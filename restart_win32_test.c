/* Real processes and a named guard reproduce the old restart race deterministically. */
#include "restart_win32.h"
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line %d: %s (win=%lu)\n",__LINE__,#x,(unsigned long)GetLastError()); exit(1); } } while (0)
static const wchar_t *resource=L"D:\\AdAway test\\参数 & [x]\\";
static const wchar_t *guard=L"Local\\AdAwayRestartRegression";
static DWORD spawn(struct restart_command *command) {
    STARTUPINFOW startup; PROCESS_INFORMATION process;
    ZeroMemory(&startup,sizeof(startup)); ZeroMemory(&process,sizeof(process)); startup.cb=sizeof(startup);
    CHECK(CreateProcessW(command->executable,command->command,NULL,NULL,FALSE,0,NULL,NULL,&startup,&process));
    CloseHandle(process.hThread); CHECK(WaitForSingleObject(process.hProcess,5000)==WAIT_OBJECT_0);
    DWORD code=0; CHECK(GetExitCodeProcess(process.hProcess,&code)); CloseHandle(process.hProcess); return code;
}
int main(void) {
    int argc=0; wchar_t **argv=CommandLineToArgvW(GetCommandLineW(),&argc); CHECK(argv);
    if (argc>1) {
        CHECK(argc==3 && !wcscmp(argv[1],L"--resources") && !wcscmp(argv[2],resource));
        HANDLE single=CreateMutexW(NULL,FALSE,guard); CHECK(single);
        if (GetLastError()==ERROR_ALREADY_EXISTS) { CloseHandle(single); LocalFree(argv); return 42; }
        Sleep(2500); CloseHandle(single); LocalFree(argv); return 0;
    }
    LocalFree(argv);
    char utf8[1024]; CHECK(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,resource,-1,utf8,sizeof(utf8),NULL,NULL));
    struct restart_command *command=NULL;
    CHECK(!restart_prepare(utf8,false,&command));
    HANDLE single=CreateMutexW(NULL,FALSE,guard); CHECK(single && GetLastError()!=ERROR_ALREADY_EXISTS);
    /* Old ordering holds the guard while launching. The real child rejects it. */
    CHECK(spawn(command)==42); free(command);
    struct restart_command *invalid=NULL; CHECK(restart_prepare("\xff",false,&invalid)==ERROR_NO_UNICODE_TRANSLATION && !invalid);
    HANDLE probe=OpenMutexW(SYNCHRONIZE,FALSE,guard); CHECK(probe); CloseHandle(probe);
    CHECK(!restart_prepare(utf8,false,&command));
    DWORD child=0; CHECK(!restart_launch(command,&single,&child)); CHECK(!single && child && child!=GetCurrentProcessId()); free(command);
    HANDLE process=OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,child); CHECK(process);
    CHECK(WaitForSingleObject(process,3000)==WAIT_OBJECT_0); DWORD code=99; CHECK(GetExitCodeProcess(process,&code) && !code); CloseHandle(process);
    CHECK(!restart_prepare(utf8,false,&command));
    wcscpy(command->executable,L"Z:\\AdAway-nonexistent-restart-fixture.exe");
    child=999; CHECK(restart_launch(command,&single,&child)!=ERROR_SUCCESS && !child); free(command);
    single=CreateMutexW(NULL,FALSE,guard); CHECK(single && GetLastError()!=ERROR_ALREADY_EXISTS);
    HANDLE no_guard=NULL; CHECK(!restart_prepare(utf8,false,&command));
    child=999; CHECK(restart_launch(command,&no_guard,&child)==ERROR_PROCESS_ABORTED && !child);
    CloseHandle(single); single=NULL; free(command);
    CHECK(!restart_prepare(utf8,true,&command));
    argv=CommandLineToArgvW(command->command,&argc); CHECK(argv && argc==4 && !wcscmp(argv[2],resource) && !wcscmp(argv[3],L"--minimized")); LocalFree(argv); free(command);
    FILE *evidence=fopen("restart-process-results.json","wb"); CHECK(evidence);
    CHECK(fputs("{\"passed\":true,\"baselineChildRejectedHeldGuard\":42,\"newPidAcquiredReleasedGuard\":true,\"utf8TrailingBackslashRoundTrip\":true,\"invalidUtf8RetainsGuard\":true,\"launchFailureReported\":true,\"hostNetworkChanges\":false}\n",evidence)>=0); CHECK(!fclose(evidence));
    puts("PASS: real old-order child exit 42; fixed child acquires guard; UTF8/trailing slash; preparation and launch failures"); return 0;
}
