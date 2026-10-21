#define _WIN32_WINNT 0x0A00
#define UNICODE
#define _UNICODE
#include "isolated_transport_win32.h"
#include "isolated_tcp_win32.h"
#include <stdio.h>
#include <string.h>
#define IT_RUN 2101
#define IT_STOP 2102
#define IT_REPORT 2103
#define IT_DONE (WM_APP+95)
struct it_dialog { HWND window; HFONT font; HANDLE cancel,thread; bool running,closing; wchar_t report[4096]; };
static DWORD WINAPI it_dialog_work(void *opaque) {
    struct it_dialog *state=opaque; struct it_result results[4];
    for (unsigned i=0;i<2;i++) {
        struct it_options udp={i?6:4,900,state->cancel,NULL,IT_NORMAL};
        struct tcp_options tcp={i?6:4,1200,state->cancel,NULL,TCP_NORMAL};
        isolated_transport_run(&udp,&results[i]);
        isolated_tcp_run(&tcp,&results[i+2]);
    }
    size_t at=0;bool clean=true;
    for(unsigned i=0;i<4;i++) {
        struct it_result *r=&results[i];clean=clean && r->cleanup_ok;
        int written=swprintf(state->report+at,4096-at,
            L"%ls/IPv%u：%ls · %u ms · 已关闭 %u/%u 个套接字 · 阶段 %u / 错误 %u\r\n",
            i<2?L"UDP":L"TCP",r->family,isolated_transport_status(r->status),r->elapsed_ms,r->sockets_closed,r->sockets_opened,r->stage,r->error);
        if(written<0) { state->report[0]=0;break; }
        at+=(size_t)written;
    }
    swprintf(state->report+at,4096-at,
        L"\r\n清理：%ls\r\n\r\n"
        L"UDP：本机原始 IP 报文 → 严格校验 → 固定回环端点 → 校验回包。\r\n"
        L"TCP：临时回环端点 → 随机凭据认证 → 固定目标 CONNECT → 分片读写与半关闭 → 校验回复。\r\n"
        L"每次使用新的端点与请求标识；停止后释放资源，可重新测试。\r\n\r\n"
        L"TCP 结果仅验证后端，尚未接入 TUN 中的 TCP 报文。Windows TUN/WFP、系统路由、外部网络、TLS 与 QUIC 尚未验证。没有修改系统网络、DNS、证书或 AdGuard。",
        clean?L"本次资源均已释放":L"失败，请保留本报告");
    PostMessageW(state->window,IT_DONE,0,0); return 0;
}
static void it_layout(HWND window) {
    RECT area;GetClientRect(window,&area); int dpi=(int)GetDpiForWindow(window);
    int pad=MulDiv(18,dpi,96),line=MulDiv(28,dpi,96),gap=MulDiv(10,dpi,96);
    SetWindowPos(GetDlgItem(window,2110),NULL,pad,pad,area.right-2*pad,3*line,SWP_NOZORDER);
    int top=pad+3*line+gap;
    SetWindowPos(GetDlgItem(window,IT_REPORT),NULL,pad,top,area.right-2*pad,area.bottom-top-2*pad-line,SWP_NOZORDER);
    SetWindowPos(GetDlgItem(window,IT_RUN),NULL,pad,area.bottom-pad-line,MulDiv(200,dpi,96),line,SWP_NOZORDER);
    SetWindowPos(GetDlgItem(window,IT_STOP),NULL,pad+MulDiv(210,dpi,96),area.bottom-pad-line,MulDiv(120,dpi,96),line,SWP_NOZORDER);
    SetWindowPos(GetDlgItem(window,IDCANCEL),NULL,area.right-pad-MulDiv(100,dpi,96),area.bottom-pad-line,MulDiv(100,dpi,96),line,SWP_NOZORDER);
}
static LRESULT CALLBACK it_window(HWND window,UINT message,WPARAM wp,LPARAM lp) {
    struct it_dialog *state=(struct it_dialog *)GetWindowLongPtrW(window,GWLP_USERDATA);
    if (message==WM_CREATE) {
        state=((CREATESTRUCTW *)lp)->lpCreateParams;state->window=window;SetWindowLongPtrW(window,GWLP_USERDATA,(LONG_PTR)state);
        state->font=CreateFontW(-MulDiv(15,(int)GetDpiForWindow(window),96),0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Microsoft YaHei UI");
        const struct { int id;const wchar_t *kind,*text;DWORD style; } controls[]={
            {2110,L"STATIC",L"验证 IPv4 / IPv6 的隔离 UDP 回包与 TCP 后端。测试仅在本机回环端点之间运行，不需要管理员权限，也不启用全机接管。点击开始后才会创建临时套接字。",SS_LEFT},
            {IT_REPORT,L"EDIT",L"尚未运行。点击“测试双栈转发”后分别显示 UDP/TCP 的 IPv4、IPv6 和资源清理结果。",WS_BORDER|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL|WS_VSCROLL|WS_TABSTOP},
            {IT_RUN,L"BUTTON",L"测试双栈转发",BS_DEFPUSHBUTTON|WS_TABSTOP},
            {IT_STOP,L"BUTTON",L"停止测试",BS_PUSHBUTTON|WS_TABSTOP},
            {IDCANCEL,L"BUTTON",L"关闭",BS_PUSHBUTTON|WS_TABSTOP}
        };
        for (size_t i=0;i<sizeof(controls)/sizeof(controls[0]);i++) {
            HWND child=CreateWindowExW(0,controls[i].kind,controls[i].text,WS_CHILD|WS_VISIBLE|controls[i].style,0,0,1,1,window,(HMENU)(INT_PTR)controls[i].id,GetModuleHandleW(NULL),NULL);
            SendMessageW(child,WM_SETFONT,(WPARAM)state->font,TRUE);
        }
        EnableWindow(GetDlgItem(window,IT_STOP),FALSE);it_layout(window);return 0;
    }
    if (!state) return DefWindowProcW(window,message,wp,lp);
    if (message==WM_SIZE) { it_layout(window);return 0; }
    if (message==WM_GETMINMAXINFO) {
        MINMAXINFO *limits=(MINMAXINFO *)lp;int dpi=(int)GetDpiForWindow(window);
        limits->ptMinTrackSize.x=MulDiv(620,dpi,96);limits->ptMinTrackSize.y=MulDiv(440,dpi,96);return 0;
    }
    if (message==WM_COMMAND && LOWORD(wp)==IT_RUN && !state->running) {
        ResetEvent(state->cancel);state->running=true;state->closing=false;
        EnableWindow(GetDlgItem(window,IT_RUN),FALSE);EnableWindow(GetDlgItem(window,IT_STOP),TRUE);
        SetDlgItemTextW(window,IT_REPORT,L"正在测试本机 IPv4 / IPv6 隔离转发…可以随时停止。");
        state->thread=CreateThread(NULL,0,it_dialog_work,state,0,NULL);
        if (!state->thread) {
            state->running=false;EnableWindow(GetDlgItem(window,IT_RUN),TRUE);EnableWindow(GetDlgItem(window,IT_STOP),FALSE);
            SetDlgItemTextW(window,IT_REPORT,L"无法创建测试任务，尚未创建网络资源。可重试。");
        }
        return 0;
    }
    if (message==IT_DONE) {
        WaitForSingleObject(state->thread,INFINITE);CloseHandle(state->thread);state->thread=NULL;state->running=false;
        if (state->closing) { DestroyWindow(window);return 0; }
        SetDlgItemTextW(window,IT_REPORT,state->report);EnableWindow(GetDlgItem(window,IT_RUN),TRUE);EnableWindow(GetDlgItem(window,IT_STOP),FALSE);return 0;
    }
    if (message==WM_COMMAND && LOWORD(wp)==IT_STOP && state->running) {
        SetEvent(state->cancel);EnableWindow(GetDlgItem(window,IT_STOP),FALSE);return 0;
    }
    if (message==WM_CLOSE || (message==WM_COMMAND && LOWORD(wp)==IDCANCEL)) {
        if (state->running) { state->closing=true;SetEvent(state->cancel);SetDlgItemTextW(window,IT_REPORT,L"正在取消并清理本次测试资源…"); }
        else DestroyWindow(window);
        return 0;
    }
    if (message==WM_DESTROY) { if (state->font) DeleteObject(state->font);return 0; }
    return DefWindowProcW(window,message,wp,lp);
}
void gui_show_transport_dialog(HWND owner) {
    WNDCLASSW kind;memset(&kind,0,sizeof(kind));kind.lpfnWndProc=it_window;kind.hInstance=GetModuleHandleW(NULL);
    kind.hCursor=LoadCursorW(NULL,IDC_ARROW);kind.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);kind.lpszClassName=L"AdAwayIsolatedTransport";RegisterClassW(&kind);
    struct it_dialog state;memset(&state,0,sizeof(state));state.cancel=CreateEventW(NULL,TRUE,FALSE,NULL);
    if (!state.cancel) return;
    int dpi=(int)GetDpiForWindow(owner);
    HWND window=CreateWindowExW(WS_EX_DLGMODALFRAME,kind.lpszClassName,L"双栈转发与恢复验证",WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,CW_USEDEFAULT,MulDiv(740,dpi,96),MulDiv(540,dpi,96),owner,NULL,kind.hInstance,&state);
    if (!window) { CloseHandle(state.cancel);return; }
    EnableWindow(owner,FALSE);ShowWindow(window,SW_SHOW);
    MSG message;memset(&message,0,sizeof(message));int rc=1;
    while (IsWindow(window) && (rc=GetMessageW(&message,NULL,0,0))>0)
        if (!IsDialogMessageW(window,&message)) { TranslateMessage(&message);DispatchMessageW(&message); }
    if (state.running) { SetEvent(state.cancel);WaitForSingleObject(state.thread,INFINITE);CloseHandle(state.thread); }
    if (IsWindow(window)) DestroyWindow(window);
    CloseHandle(state.cancel);EnableWindow(owner,TRUE);SetActiveWindow(owner);
    if (rc==0) PostQuitMessage((int)message.wParam);
}
