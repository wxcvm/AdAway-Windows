#define _WIN32_WINNT 0x0A00
#define UNICODE
#define _UNICODE
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "listener_arrival_dialog_win32.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while (0)
struct scenario { SOCKET listener; HANDLE begin,finished; HWND owner; DWORD ui_thread; int phase; };
static void save_window(HWND window,const wchar_t *name) {
    RECT rect; CHECK(GetWindowRect(window,&rect)); int width=rect.right-rect.left,height=rect.bottom-rect.top;
    CHECK(width>0 && height>0 && width<=4096 && height<=4096);
    HDC screen=GetDC(NULL),memory=CreateCompatibleDC(screen); CHECK(screen && memory);
    HBITMAP bitmap=CreateCompatibleBitmap(screen,width,height); CHECK(bitmap);
    HGDIOBJ old=SelectObject(memory,bitmap); CHECK(PrintWindow(window,memory,0)); SelectObject(memory,old);
    BITMAPINFO info; memset(&info,0,sizeof(info)); info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth=width; info.bmiHeader.biHeight=height; info.bmiHeader.biPlanes=1; info.bmiHeader.biBitCount=32;
    DWORD bytes=(DWORD)width*(DWORD)height*4; void *pixels=malloc(bytes); CHECK(pixels);
    CHECK(GetDIBits(memory,bitmap,0,(UINT)height,pixels,&info,DIB_RGB_COLORS));
    CreateDirectoryW(L"ui-review",NULL); wchar_t path[256]; swprintf(path,256,L"ui-review/%ls.bmp",name);
    FILE *file=_wfopen(path,L"wb"); CHECK(file);
    BITMAPFILEHEADER header; memset(&header,0,sizeof(header)); header.bfType=0x4d42;
    header.bfOffBits=(DWORD)(sizeof(header)+sizeof(info.bmiHeader)); header.bfSize=header.bfOffBits+bytes;
    CHECK(fwrite(&header,sizeof(header),1,file)==1 && fwrite(&info.bmiHeader,sizeof(info.bmiHeader),1,file)==1 && fwrite(pixels,bytes,1,file)==1);
    CHECK(!fclose(file)); free(pixels); DeleteObject(bitmap); DeleteDC(memory); ReleaseDC(NULL,screen);
}
static void send_message(HWND window,UINT message,WPARAM wp,LPARAM lp) {
    DWORD_PTR result=0;
    CHECK(SendMessageTimeoutW(window,message,wp,lp,SMTO_ABORTIFHUNG,2000,&result));
}
static void read_control(HWND window,int id,wchar_t *text,size_t cap) {
    send_message(GetDlgItem(window,id),WM_GETTEXT,(WPARAM)cap,(LPARAM)text);
}
static SOCKET accept_request(struct scenario *s) {
    fd_set ready; FD_ZERO(&ready); FD_SET(s->listener,&ready); struct timeval wait={3,0};
    CHECK(select(0,&ready,NULL,NULL,&wait)==1);
    SOCKET peer=accept(s->listener,NULL,NULL); CHECK(peer!=INVALID_SOCKET); return peer;
}
static void run(HWND window) {
    send_message(window,WM_COMMAND,2003,0);
    CHECK(IsWindowEnabled(GetDlgItem(window,IDCANCEL)));
}
static void wait_enabled(HWND window,int id) {
    ULONGLONG deadline=GetTickCount64()+2000;
    while (!IsWindowEnabled(GetDlgItem(window,id)) && GetTickCount64()<deadline) Sleep(10);
    CHECK(IsWindowEnabled(GetDlgItem(window,id)));
}
static void reply_receipt(SOCKET peer) {
    DWORD timeout=2000; CHECK(!setsockopt(peer,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(timeout)));
    char request[1024]={0}; int used=0;
    while (!strstr(request,"\r\n\r\n") && used<(int)sizeof(request)-1) {
        int count=recv(peer,request+used,(int)sizeof(request)-1-used,0); CHECK(count>0); used+=count; request[used]=0;
    }
    const char *prefix="GET /adaway-listener-probe/"; CHECK(!strncmp(request,prefix,strlen(prefix)));
    char nonce[33]; memcpy(nonce,request+strlen(prefix),32); nonce[32]=0;
    char response[256]; int count=snprintf(response,sizeof(response),
        "HTTP/1.1 200 OK\r\nContent-Length: 48\r\nX-AdAway-Listener-Probe: %s\r\nConnection: close\r\n\r\nadaway-listener:%s",nonce,nonce);
    CHECK(send(peer,response,count,0)==count); closesocket(peer);
}
static DWORD WINAPI control_dialog(void *opaque) {
    struct scenario *s=(struct scenario *)opaque;
    for (int phase=0;phase<3;phase++) {
        CHECK(WaitForSingleObject(s->begin,3000)==WAIT_OBJECT_0);
        HWND dialog=NULL; ULONGLONG deadline=GetTickCount64()+2000;
        while (GetTickCount64()<deadline) { dialog=FindWindowW(L"AdAwayArrivalCheck",NULL); if (dialog && GetDlgItem(dialog,2013) && GetDlgItem(dialog,2006)) break; Sleep(10); }
        CHECK(dialog && GetDlgItem(dialog,2013) && GetDlgItem(dialog,2006));
        CHECK(SetWindowPos(dialog,NULL,0,0,620,560,SWP_NOMOVE|SWP_NOZORDER));
        send_message(GetDlgItem(dialog,2001),WM_SETTEXT,0,(LPARAM)L"");
        send_message(GetDlgItem(dialog,2002),WM_SETTEXT,0,(LPARAM)L"");
        if (!phase) {
            run(dialog); reply_receipt(accept_request(s)); wait_enabled(dialog,2003);
            wchar_t completed[6400],current[6600]; read_control(dialog,2004,completed,6400);
            CHECK(wcsstr(completed,L"HTTP 请求已到达 AdAway"));
            save_window(dialog,L"arrival-completed-minimum");
            run(dialog); SOCKET peer=accept_request(s);
            CHECK(IsWindowEnabled(GetDlgItem(dialog,2006)));
            read_control(dialog,2004,current,6600); CHECK(!wcscmp(completed,current));
            wchar_t progress[384]; deadline=GetTickCount64()+1000;
            do { read_control(dialog,2013,progress,384); if (wcsstr(progress,L"HTTP")) break; Sleep(10); } while (GetTickCount64()<deadline);
            CHECK(wcsstr(progress,L"IPv4 HTTP"));
            save_window(dialog,L"arrival-running-minimum");
            send_message(dialog,WM_COMMAND,2006,0); wait_enabled(dialog,2003);
            read_control(dialog,2004,current,6600);
            CHECK(wcsstr(current,L"检测已取消") && wcsstr(current,completed)); closesocket(peer);
            save_window(dialog,L"arrival-cancelled-preserved");
        }
        if (phase==1) save_window(dialog,L"arrival-reopened-minimum");
        /* The newly reopened dialog may briefly see the cancelled predecessor
           draining. A deliberate retry must start one task, never two. */
        deadline=GetTickCount64()+1500;
        do { run(dialog); if (!IsWindowEnabled(GetDlgItem(dialog,2003))) break; Sleep(20); } while (GetTickCount64()<deadline);
        CHECK(!IsWindowEnabled(GetDlgItem(dialog,2003)));
        SOCKET peer=accept_request(s);
        ULONGLONG close_at=GetTickCount64();
        if (phase==2) CHECK(PostThreadMessageW(s->ui_thread,WM_QUIT,42,0));
        else CHECK(PostMessageW(dialog,WM_CLOSE,0,0));
        while (IsWindow(dialog) && GetTickCount64()-close_at<1000) Sleep(10);
        CHECK(!IsWindow(dialog) && GetTickCount64()-close_at<800);
        closesocket(peer); SetEvent(s->finished);
    }
    return 0;
}
int main(void) {
    WSADATA winsock; CHECK(!WSAStartup(MAKEWORD(2,2),&winsock));
    struct scenario s; memset(&s,0,sizeof(s)); s.ui_thread=GetCurrentThreadId();
    s.listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); CHECK(s.listener!=INVALID_SOCKET);
    struct sockaddr_in address; memset(&address,0,sizeof(address)); address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    CHECK(!bind(s.listener,(struct sockaddr *)&address,sizeof(address))); CHECK(!listen(s.listener,4));
    int size=sizeof(address); CHECK(!getsockname(s.listener,(struct sockaddr *)&address,&size));
    s.begin=CreateEventW(NULL,FALSE,FALSE,NULL); s.finished=CreateEventW(NULL,FALSE,FALSE,NULL); CHECK(s.begin && s.finished);
    s.owner=CreateWindowExW(0,L"STATIC",L"Arrival cancellation fixture",WS_OVERLAPPEDWINDOW,0,0,800,700,NULL,NULL,GetModuleHandleW(NULL),NULL); CHECK(s.owner);
    struct arrival_config config={0}; config.pair=true; config.http=ntohs(address.sin_port); strcpy(config.ip,"127.0.0.1");
    HANDLE controller=CreateThread(NULL,0,control_dialog,&s,0,NULL); CHECK(controller);
    for (s.phase=0;s.phase<3;s.phase++) {
        SetEvent(s.begin); gui_show_arrival_dialog(s.owner,&config);
        CHECK(WaitForSingleObject(s.finished,2000)==WAIT_OBJECT_0); CHECK(IsWindowEnabled(s.owner));
    }
    MSG message; CHECK(PeekMessageW(&message,NULL,WM_QUIT,WM_QUIT,PM_REMOVE) && message.wParam==42);
    CHECK(WaitForSingleObject(controller,2000)==WAIT_OBJECT_0);
    CloseHandle(controller); CloseHandle(s.begin); CloseHandle(s.finished); DestroyWindow(s.owner); closesocket(s.listener); WSACleanup();
    FILE *evidence=fopen("arrival-dialog-results.json","wb"); CHECK(evidence);
    CHECK(fputs("{\"passed\":true,\"actualProductionDialog\":true,\"stageProgress\":true,\"lastReportPreserved\":true,\"cancelRetry\":true,\"closeReopen\":true,\"wmQuitCleanup\":true,\"ownerRestored\":true,\"minimumWidth\":620,\"screenshots\":4,\"hostNetworkChanges\":false}\n",evidence)>=0);
    CHECK(!fclose(evidence));
    puts("PASS: production modal GUI stage progress, last completed report, cancel/retry, immediate close/reopen, WM_QUIT cleanup and owner restoration");
    return 0;
}
