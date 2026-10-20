#define _WIN32_WINNT 0x0A00
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "listener_arrival_dialog_win32.h"
#define AC_RUN 2003
#define AC_COPY 2005
#define AC_DONE (WM_APP+94)
struct ac_dialog {
    struct arrival_config config;
    HWND window; HFONT font; bool running;
    char adblock[256],hosts[256]; wchar_t result[6144];
};
static DWORD WINAPI ac_work(void *opaque) {
    struct ac_dialog *state=(struct ac_dialog *)opaque;
    arrival_report(&state->config,state->adblock,state->hosts,state->result,6144);
    PostMessageW(state->window,AC_DONE,0,0); return 0;
}
static void ac_controls(struct ac_dialog *state,bool enabled) {
    for (int id=2001;id<=2003;id++) EnableWindow(GetDlgItem(state->window,id),enabled);
    EnableWindow(GetDlgItem(state->window,IDCANCEL),enabled);
    EnableWindow(GetDlgItem(state->window,AC_COPY),enabled);
}
static void ac_copy(HWND window) {
    HWND report=GetDlgItem(window,2004); int count=GetWindowTextLengthW(report)+1;
    HGLOBAL memory=GlobalAlloc(GMEM_MOVEABLE,(size_t)count*sizeof(wchar_t));
    if (!memory) return;
    wchar_t *text=(wchar_t *)GlobalLock(memory);
    if (!text) { GlobalFree(memory); return; }
    GetWindowTextW(report,text,count); GlobalUnlock(memory);
    bool copied=false;
    if (OpenClipboard(window)) {
        if (EmptyClipboard() && SetClipboardData(CF_UNICODETEXT,memory)) copied=true;
        CloseClipboard();
    }
    if (!copied) { GlobalFree(memory); MessageBoxW(window,L"剪贴板暂不可用，请稍后重试。",L"复制结果",MB_OK|MB_ICONINFORMATION); }
}
static void ac_place(HWND window) {
    RECT client; GetClientRect(window,&client); int width=client.right,height=client.bottom;
    int dpi=(int)GetDpiForWindow(window),pad=MulDiv(18,dpi,96),line=MulDiv(26,dpi,96),gap=MulDiv(10,dpi,96);
    SetWindowPos(GetDlgItem(window,2010),NULL,pad,pad,width-2*pad,3*line,SWP_NOZORDER);
    SetWindowPos(GetDlgItem(window,2011),NULL,pad,pad+3*line+gap,width-2*pad,line,SWP_NOZORDER);
    SetWindowPos(GetDlgItem(window,2001),NULL,pad,pad+4*line+gap,width-2*pad,line,SWP_NOZORDER);
    SetWindowPos(GetDlgItem(window,2012),NULL,pad,pad+5*line+2*gap,width-2*pad,line,SWP_NOZORDER);
    SetWindowPos(GetDlgItem(window,2002),NULL,pad,pad+6*line+2*gap,width-2*pad,line,SWP_NOZORDER);
    int top=pad+7*line+3*gap;
    SetWindowPos(GetDlgItem(window,2004),NULL,pad,top,width-2*pad,height-top-2*pad-line,SWP_NOZORDER);
    SetWindowPos(GetDlgItem(window,AC_RUN),NULL,pad,height-pad-line,MulDiv(240,dpi,96),line,SWP_NOZORDER);
    SetWindowPos(GetDlgItem(window,AC_COPY),NULL,pad+MulDiv(250,dpi,96),height-pad-line,MulDiv(120,dpi,96),line,SWP_NOZORDER);
    SetWindowPos(GetDlgItem(window,IDCANCEL),NULL,width-pad-MulDiv(100,dpi,96),height-pad-line,MulDiv(100,dpi,96),line,SWP_NOZORDER);
}
static LRESULT CALLBACK ac_window(HWND window,UINT message,WPARAM wp,LPARAM lp) {
    struct ac_dialog *state=(struct ac_dialog *)GetWindowLongPtrW(window,GWLP_USERDATA);
    if (message==WM_CREATE) {
        state=(struct ac_dialog *)((CREATESTRUCTW *)lp)->lpCreateParams; state->window=window;
        SetWindowLongPtrW(window,GWLP_USERDATA,(LONG_PTR)state);
        state->font=CreateFontW(-MulDiv(15,(int)GetDpiForWindow(window),96),0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Microsoft YaHei UI");
        const struct { int id; const wchar_t *type,*text; DWORD style; } controls[]={
            {2010,L"STATIC",L"按本次实际启动配置检测 HTTP、HTTPS 与 UDP 占用；保存待重启的配置尚不生效。AdGuard 两类 DNS 模式的自定义 IP 可分别指向本机监听。测试域名可修改或留空，不保证命中当前规则。检测不修改网络或证书。",SS_LEFT},
            {2011,L"STATIC",L"广告规则测试域名（ASCII / xn--，可修改或留空）",SS_LEFT},
            {2001,L"EDIT",L"ad.doubleclick.net",WS_BORDER|ES_AUTOHSCROLL|WS_TABSTOP},
            {2012,L"STATIC",L"Hosts 规则测试域名（可选，命中类别以 AdGuard 日志为准）",SS_LEFT},
            {2002,L"EDIT",L"",WS_BORDER|ES_AUTOHSCROLL|WS_TABSTOP},
            {2004,L"EDIT",L"点击检测后分别显示 DNS、HTTP、HTTPS 与 UDP 占用。只连接匹配监听的本机地址，不访问公网广告源站；HTTPS 会严格校验证书并检测加密回执；QUIC / HTTP/3 当前未实现。",WS_BORDER|ES_MULTILINE|ES_READONLY|WS_VSCROLL|ES_AUTOVSCROLL|WS_TABSTOP},
            {AC_RUN,L"BUTTON",L"检测 DNS 与请求到达",BS_DEFPUSHBUTTON|WS_TABSTOP},
            {AC_COPY,L"BUTTON",L"复制结果",BS_PUSHBUTTON|WS_TABSTOP},
            {IDCANCEL,L"BUTTON",L"关闭",BS_PUSHBUTTON|WS_TABSTOP}
        };
        for (size_t i=0;i<sizeof(controls)/sizeof(controls[0]);i++) {
            HWND child=CreateWindowExW(0,controls[i].type,controls[i].text,WS_CHILD|WS_VISIBLE|controls[i].style,0,0,1,1,window,(HMENU)(INT_PTR)controls[i].id,GetModuleHandleW(NULL),NULL);
            SendMessageW(child,WM_SETFONT,(WPARAM)state->font,TRUE);
        }
        SendDlgItemMessageW(window,2001,EM_SETLIMITTEXT,253,0); SendDlgItemMessageW(window,2002,EM_SETLIMITTEXT,253,0);
        ac_place(window); return 0;
    }
    if (!state) return DefWindowProcW(window,message,wp,lp);
    if (message==WM_GETMINMAXINFO) {
        MINMAXINFO *limits=(MINMAXINFO *)lp;
        limits->ptMinTrackSize.x=MulDiv(620,(int)GetDpiForWindow(window),96);
        limits->ptMinTrackSize.y=MulDiv(560,(int)GetDpiForWindow(window),96); return 0;
    }
    if (message==WM_SIZE) { ac_place(window); return 0; }
    if (message==WM_COMMAND && LOWORD(wp)==AC_RUN && !state->running) {
        GetDlgItemTextA(window,2001,state->adblock,256); GetDlgItemTextA(window,2002,state->hosts,256);
        if ((*state->adblock && !arrival_domain_valid(state->adblock)) || (*state->hosts && !arrival_domain_valid(state->hosts))) {
            SetDlgItemTextW(window,2004,L"请输入完整 ASCII / xn-- 域名，不含 URL、路径、IP、端口或空白。尚未开始检测。"); return 0;
        }
        state->running=true; ac_controls(state,false); SetDlgItemTextW(window,2004,L"正在检查本机回执与系统 DNS，请稍候…");
        HANDLE thread=CreateThread(NULL,0,ac_work,state,0,NULL);
        if (thread) CloseHandle(thread);
        else { state->running=false; ac_controls(state,true); SetDlgItemTextW(window,2004,L"无法启动检测任务，配置未改变。"); }
        return 0;
    }
    if (message==AC_DONE) { state->running=false; ac_controls(state,true); SetDlgItemTextW(window,2004,state->result); return 0; }
    if (message==WM_COMMAND && LOWORD(wp)==AC_COPY && !state->running) { ac_copy(window); return 0; }
    if (message==WM_CLOSE || (message==WM_COMMAND && LOWORD(wp)==IDCANCEL)) {
        if (!state->running) DestroyWindow(window);
        return 0;
    }
    if (message==WM_DESTROY) { if (state->font) DeleteObject(state->font); return 0; }
    return DefWindowProcW(window,message,wp,lp);
}
void gui_show_arrival_dialog(HWND owner,const struct arrival_config *config) {
    WNDCLASSW type; memset(&type,0,sizeof(type)); type.lpfnWndProc=ac_window; type.hInstance=GetModuleHandleW(NULL);
    type.hCursor=LoadCursorW(NULL,IDC_ARROW); type.hbrBackground=(HBRUSH)(COLOR_WINDOW+1); type.lpszClassName=L"AdAwayArrivalCheck";
    RegisterClassW(&type);
    struct ac_dialog state; memset(&state,0,sizeof(state)); state.config=*config;
    UINT dpi=GetDpiForWindow(owner);
    HWND window=CreateWindowExW(WS_EX_DLGMODALFRAME,type.lpszClassName,L"HTTP / HTTPS / AdGuard 诊断",WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,CW_USEDEFAULT,MulDiv(720,(int)dpi,96),MulDiv(650,(int)dpi,96),owner,NULL,type.hInstance,&state);
    if (!window) { MessageBoxW(owner,L"无法打开请求检测窗口。",L"AdGuard 检测",MB_OK|MB_ICONERROR); return; }
    EnableWindow(owner,FALSE); ShowWindow(window,SW_SHOW); UpdateWindow(window);
    MSG message; memset(&message,0,sizeof(message)); int result=1;
    while (IsWindow(window) && (result=GetMessageW(&message,NULL,0,0))>0) {
        if (!IsDialogMessageW(window,&message)) { TranslateMessage(&message); DispatchMessageW(&message); }
    }
    EnableWindow(owner,TRUE); SetActiveWindow(owner);
    if (result==0) PostQuitMessage((int)message.wParam);
}
