#define _WIN32_WINNT 0x0600
#include "listener_conflict_win32.h"
int main(int argc,char **argv) {
    if (argc!=3) return 2;
    WSADATA data; if (WSAStartup(MAKEWORD(2,2),&data)) return 3;
    DWORD owner; int status=listener_status(argv[1],la_port(argv[2]),&owner);
    printf("{\"status\":%d,\"pid\":%lu}\n",status,(unsigned long)owner);
    WSACleanup(); return 0;
}
