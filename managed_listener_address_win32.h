#ifndef ADBLOCK_MANAGED_LISTENER_ADDRESS_WIN32_H
#define ADBLOCK_MANAGED_LISTENER_ADDRESS_WIN32_H
#include "listen_address.h"
#include <ws2ipdef.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>

/* One private /32 or /128 on the software loopback. Never change DHCP, DNS,
 * gateways, physical adapters or persistent system network configuration. */
#define MA_REGISTRY L"SOFTWARE\\AdAway\\ListenerAddresses"
#define MA_CLEANUP_FAILED 60001u
#define MA_PORT_CONFLICT 60002u
struct ma_receipt { ULONGLONG luid; LONGLONG created; };

static inline int ma_address(const char *ip, SOCKADDR_INET *address) {
    char normalized[64]; int version=la_normalize(ip,normalized);
    unsigned char raw[16]={0};
    if (!version || inet_pton(version==4 ? AF_INET : AF_INET6,normalized,raw)!=1) return 0;
    if (version==4) {
        if (!(raw[0]==127 || raw[0]==10 || (raw[0]==172 && raw[1]>=16 && raw[1]<=31)
                || (raw[0]==192 && raw[1]==168))) return 0;
    } else if ((raw[0]&0xfe)!=0xfc) return 0;
    memset(address,0,sizeof(*address)); address->si_family=version==4 ? AF_INET : AF_INET6;
    if (version==4) memcpy(&address->Ipv4.sin_addr,raw,4);
    else memcpy(&address->Ipv6.sin6_addr,raw,16);
    return version;
}

static inline int ma_equal(const SOCKADDR_INET *a,const SOCKADDR_INET *b) {
    if (a->si_family!=b->si_family) return 0;
    return a->si_family==AF_INET ? !memcmp(&a->Ipv4.sin_addr,&b->Ipv4.sin_addr,4)
            : !memcmp(&a->Ipv6.sin6_addr,&b->Ipv6.sin6_addr,16);
}

static inline DWORD ma_find(const SOCKADDR_INET *address,MIB_UNICASTIPADDRESS_ROW *row) {
    MIB_UNICASTIPADDRESS_TABLE *table=NULL;
    DWORD status=GetUnicastIpAddressTable(address->si_family,&table);
    if (status!=NO_ERROR) return status;
    status=ERROR_NOT_FOUND;
    for (ULONG i=0;i<table->NumEntries;i++) if (ma_equal(address,&table->Table[i].Address)) {
        *row=table->Table[i]; status=NO_ERROR; break;
    }
    FreeMibTable(table); return status;
}

static inline void ma_name(const char *ip,wchar_t name[64]) {
    char normalized[64]; la_normalize(ip,normalized);
    MultiByteToWideChar(CP_UTF8,0,normalized,-1,name,64);
}

static inline DWORD ma_store(const char *ip,const MIB_UNICASTIPADDRESS_ROW *row) {
    HKEY key; DWORD status=RegCreateKeyExW(HKEY_LOCAL_MACHINE,MA_REGISTRY,0,NULL,0,KEY_SET_VALUE,NULL,&key,NULL);
    if (status!=ERROR_SUCCESS) return status;
    wchar_t name[64]; ma_name(ip,name);
    struct ma_receipt receipt={row->InterfaceLuid.Value,row->CreationTimeStamp.QuadPart};
    status=RegSetValueExW(key,name,0,REG_BINARY,(const BYTE *)&receipt,sizeof(receipt));
    if (status==ERROR_SUCCESS) status=RegFlushKey(key);
    RegCloseKey(key); return status;
}

static inline DWORD ma_owned(const char *ip,MIB_UNICASTIPADDRESS_ROW *row) {
    SOCKADDR_INET address; if (!ma_address(ip,&address)) return ERROR_INVALID_PARAMETER;
    DWORD status=ma_find(&address,row); if (status!=NO_ERROR) return status;
    struct ma_receipt receipt; DWORD bytes=sizeof(receipt),type=0; wchar_t name[64]; ma_name(ip,name);
    status=RegGetValueW(HKEY_LOCAL_MACHINE,MA_REGISTRY,name,RRF_RT_REG_BINARY,&type,&receipt,&bytes);
    if (status!=ERROR_SUCCESS) return status;
    if (bytes!=sizeof(receipt) || receipt.luid!=row->InterfaceLuid.Value
            || receipt.created!=row->CreationTimeStamp.QuadPart || !row->SkipAsSource
            || row->OnLinkPrefixLength!=(address.si_family==AF_INET ? 32 : 128)) return ERROR_ACCESS_DENIED;
    MIB_IF_ROW2 interface_row; memset(&interface_row,0,sizeof(interface_row));
    interface_row.InterfaceLuid=row->InterfaceLuid;
    status=GetIfEntry2(&interface_row);
    return status ? status : interface_row.Type==IF_TYPE_SOFTWARE_LOOPBACK ? NO_ERROR : ERROR_ACCESS_DENIED;
}

static inline DWORD ma_remove(const char *ip) {
    MIB_UNICASTIPADDRESS_ROW row; DWORD status=ma_owned(ip,&row);
    if (status!=NO_ERROR) return status;
    status=DeleteUnicastIpAddressEntry(&row);
    if (status==NO_ERROR) {
        HKEY key; wchar_t name[64]; ma_name(ip,name);
        status=RegOpenKeyExW(HKEY_LOCAL_MACHINE,MA_REGISTRY,0,KEY_SET_VALUE,&key);
        if (status==ERROR_SUCCESS) { status=RegDeleteValueW(key,name); RegCloseKey(key); }
    }
    return status;
}

static inline DWORD ma_add(const char *ip) {
    SOCKADDR_INET address; int version=ma_address(ip,&address);
    if (!version) return ERROR_INVALID_PARAMETER;
    MIB_UNICASTIPADDRESS_ROW row; DWORD status=ma_find(&address,&row);
    if (status==NO_ERROR) return ERROR_OBJECT_ALREADY_EXISTS;
    if (status!=ERROR_NOT_FOUND) return status;
    MIB_IF_TABLE2 *interfaces=NULL; status=GetIfTable2(&interfaces);
    if (status!=NO_ERROR) return status;
    NET_LUID luid; luid.Value=0;
    for (ULONG i=0;i<interfaces->NumEntries;i++) if (interfaces->Table[i].Type==IF_TYPE_SOFTWARE_LOOPBACK) {
        luid=interfaces->Table[i].InterfaceLuid; break;
    }
    FreeMibTable(interfaces); if (!luid.Value) return ERROR_NOT_FOUND;
    InitializeUnicastIpAddressEntry(&row);
    row.Address=address; row.InterfaceLuid=luid; row.OnLinkPrefixLength=version==4 ? 32 : 128;
    row.SkipAsSource=TRUE; row.DadState=IpDadStatePreferred;
    status=CreateUnicastIpAddressEntry(&row);
    if (status!=NO_ERROR) return status; /* Includes races: never claim an existing address. */
    status=GetUnicastIpAddressEntry(&row);
    if (status==NO_ERROR) status=ma_store(ip,&row);
    if (status!=NO_ERROR) return DeleteUnicastIpAddressEntry(&row)==NO_ERROR ? status : MA_CLEANUP_FAILED;
    for (int i=0;i<40;i++) {
        status=GetUnicastIpAddressEntry(&row);
        if (status!=NO_ERROR || row.DadState==IpDadStateDuplicate || row.DadState==IpDadStateInvalid) break;
        if (row.DadState==IpDadStatePreferred) return NO_ERROR;
        Sleep(100);
    }
    return ma_remove(ip)==NO_ERROR ? ERROR_ADDRESS_NOT_ASSOCIATED : MA_CLEANUP_FAILED;
}

/* Runs before service resources, CA, mutexes or GUI are initialized. No arbitrary commands or paths. */
static inline int ma_cli(int argc,char **argv) {
    int create=argc>1 && !strcmp(argv[1],"--create-listener-address");
    int remove=argc>1 && !strcmp(argv[1],"--remove-listener-address");
    if (!create && !remove) return -1;
    if ((create && argc!=5) || (remove && argc!=3)) return ERROR_INVALID_PARAMETER;
    SOCKADDR_INET address;
    if (!ma_address(argv[2],&address)) return ERROR_INVALID_PARAMETER;
    int http=create ? la_port(argv[3]) : 0,https=create ? la_port(argv[4]) : 0;
    if (create && (!http || !https || http==https || http==8686 || https==8686)) return ERROR_INVALID_PARAMETER;
    WSADATA data; if (WSAStartup(MAKEWORD(2,2),&data)) return ERROR_NOT_SUPPORTED;
    DWORD status=remove ? ma_remove(argv[2]) : ma_add(argv[2]);
    if (create && status==NO_ERROR) {
        int native_error=0;
        if (la_probe(argv[2],http,&native_error) || la_probe(argv[2],https,&native_error))
            status=ma_remove(argv[2])==NO_ERROR ? MA_PORT_CONFLICT : MA_CLEANUP_FAILED;
    }
    WSACleanup(); return (int)status;
}
#endif
