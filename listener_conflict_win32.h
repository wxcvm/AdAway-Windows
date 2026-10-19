#ifndef ADBLOCK_LISTENER_CONFLICT_WIN32_H
#define ADBLOCK_LISTENER_CONFLICT_WIN32_H
#include "listen_address.h"
#include <iphlpapi.h>
/* Only an overlapping LISTEN row counts. Never terminate another process. */
static inline DWORD listener_owner(const char *ip, int port, int *known) {
    char normalized[64]; int version=la_normalize(ip,normalized);
    DWORD size=0, owner=0; *known=0;
    ULONG family=version==6 ? AF_INET6 : AF_INET;
    DWORD rc=GetExtendedTcpTable(NULL,&size,FALSE,family,TCP_TABLE_OWNER_PID_LISTENER,0);
    if (rc!=ERROR_INSUFFICIENT_BUFFER) return 0;
    void *buffer=malloc(size); if (!buffer) return 0;
    rc=GetExtendedTcpTable(buffer,&size,FALSE,family,TCP_TABLE_OWNER_PID_LISTENER,0);
    if (rc==NO_ERROR) {
        *known=1;
        if (version==4) {
            struct in_addr address; inet_pton(AF_INET,ip,&address);
            MIB_TCPTABLE_OWNER_PID *table=(MIB_TCPTABLE_OWNER_PID *)buffer;
            for (DWORD i=0;i<table->dwNumEntries;i++) {
                MIB_TCPROW_OWNER_PID row=table->table[i];
                if (ntohs((u_short)row.dwLocalPort)==port &&
                    (!row.dwLocalAddr || !address.s_addr || row.dwLocalAddr==address.s_addr)) {
                    owner=row.dwOwningPid; if (owner!=GetCurrentProcessId()) break;
                }
            }
        } else {
            unsigned char address[16], zero[16]={0}; inet_pton(AF_INET6,ip,address);
            MIB_TCP6TABLE_OWNER_PID *table=(MIB_TCP6TABLE_OWNER_PID *)buffer;
            for (DWORD i=0;i<table->dwNumEntries;i++) {
                MIB_TCP6ROW_OWNER_PID row=table->table[i];
                if (ntohs((u_short)row.dwLocalPort)==port &&
                    (!memcmp(row.ucLocalAddr,zero,16) || !memcmp(address,zero,16) || !memcmp(row.ucLocalAddr,address,16))) {
                    owner=row.dwOwningPid; if (owner!=GetCurrentProcessId()) break;
                }
            }
        }
    }
    free(buffer); return owner;
}

/* 0 available, 6 this process, 1 another owner, or la_probe status. */
static inline int listener_status(const char *ip,int port,DWORD *owner) {
    int known=0,error=0; *owner=listener_owner(ip,port,&known);
    if (*owner) return *owner==GetCurrentProcessId() ? 6 : 1;
    return la_probe(ip,port,&error);
}
#endif
