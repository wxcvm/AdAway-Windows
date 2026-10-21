#include <windows.h>
#include <stdio.h>
#include <wchar.h>
/* Disposable CI executable: never listens, changes settings or installs anything. */
int main(void) {
    wchar_t path[MAX_PATH];
    if(!GetModuleFileNameW(NULL,path,MAX_PATH)) return 3;
    wchar_t *last=wcsrchr(path,L'\\'); if(!last) return 4;
    wcscpy(last+1,L"fail-startup");
    if(GetFileAttributesW(path)!=INVALID_FILE_ATTRIBUTES) return 7;
    wcscpy(last+1,L"started.pid");
    FILE *file=_wfopen(path,L"wb"); if(!file) return 5;
    fprintf(file,"%lu",(unsigned long)GetCurrentProcessId());
    if(fclose(file)) return 6;
    Sleep(90000);
    return 0;
}
