#include "restart_win32.h"
#include <stdlib.h>
#include <wchar.h>

static bool append(wchar_t *out, size_t *used, wchar_t c) {
    if (*used >= RESTART_COMMAND_CAPACITY-1) return false;
    out[(*used)++]=c; out[*used]=0; return true;
}
/* Windows CRT argv quoting: trailing backslashes must be doubled inside quotes. */
static bool quote(wchar_t *out,size_t *used,const wchar_t *arg) {
    if (!append(out,used,L'"')) return false;
    for (;;) {
        size_t slashes=0;
        while (*arg==L'\\') { ++slashes; ++arg; }
        size_t count=(*arg==L'"' || !*arg) ? slashes*2 : slashes;
        while (count--) if (!append(out,used,L'\\')) return false;
        if (!*arg) break;
        if (*arg==L'"' && !append(out,used,L'\\')) return false;
        if (!append(out,used,*arg++)) return false;
    }
    return append(out,used,L'"');
}
DWORD restart_prepare(const char *resources,bool minimized,struct restart_command **out) {
    if (!out || !resources) return ERROR_INVALID_PARAMETER;
    *out=NULL;
    int count=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,resources,-1,NULL,0);
    if (!count) return GetLastError();
    wchar_t *path=calloc((size_t)count,sizeof(*path));
    struct restart_command *command=calloc(1,sizeof(*command));
    if (!path || !command) { free(path); free(command); return ERROR_NOT_ENOUGH_MEMORY; }
    DWORD error=ERROR_SUCCESS;
    DWORD length=GetModuleFileNameW(NULL,command->executable,RESTART_COMMAND_CAPACITY);
    if (!length || length>=RESTART_COMMAND_CAPACITY) error=length ? ERROR_INSUFFICIENT_BUFFER : GetLastError();
    if (!error && !MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,resources,-1,path,count)) error=GetLastError();
    size_t used=0;
    if (!error && !quote(command->command,&used,command->executable)) error=ERROR_INSUFFICIENT_BUFFER;
    const wchar_t *option=L" --resources ";
    while (!error && *option) if (!append(command->command,&used,*option++)) error=ERROR_INSUFFICIENT_BUFFER;
    if (!error && !quote(command->command,&used,path)) error=ERROR_INSUFFICIENT_BUFFER;
    option=minimized ? L" --minimized" : L"";
    while (!error && *option) if (!append(command->command,&used,*option++)) error=ERROR_INSUFFICIENT_BUFFER;
    free(path);
    if (error) free(command); else *out=command;
    return error;
}
DWORD restart_launch(struct restart_command *command,HANDLE *single,DWORD *child_pid) {
    if (child_pid) *child_pid=0;
    if (!command || !command->executable[0] || !command->command[0] || !single) return ERROR_INVALID_PARAMETER;
    if (*single) {
        if (!CloseHandle(*single)) return GetLastError();
        *single=NULL;
    }
    STARTUPINFOW startup; PROCESS_INFORMATION process;
    ZeroMemory(&startup,sizeof(startup)); ZeroMemory(&process,sizeof(process));
    startup.cb=sizeof(startup); startup.dwFlags=STARTF_USESHOWWINDOW; startup.wShowWindow=SW_SHOWNORMAL;
    if (!CreateProcessW(command->executable,command->command,NULL,NULL,FALSE,0,NULL,NULL,&startup,&process)) return GetLastError();
    CloseHandle(process.hThread);
    DWORD wait=WaitForSingleObject(process.hProcess,1000);
    DWORD error=wait==WAIT_OBJECT_0 ? ERROR_PROCESS_ABORTED : wait==WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
    if (!error && child_pid) *child_pid=process.dwProcessId;
    CloseHandle(process.hProcess);
    return error;
}
