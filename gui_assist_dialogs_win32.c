#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "gui_assist_dialogs_win32.h"
#include "adguard_home_plan.h"
#include "windows_network_inventory_win32.h"

/* Dialog code extracted from the dashboard's 3700-line message/UI module.
 * Stateful inputs are passed explicitly; no network configuration writes. */

/* A read-only/manual AdGuard Home setup wizard. No settings are pushed into
 * another application, no firewall rules changed, and no successful DNS
 * interception is inferred from process presence or open listeners. */
void gui_show_adguard_home_wizard(HWND hwnd,
                                  const struct gui_adguard_runtime *state,
                                  gui_lookup_lan_ipv4 find_lan_ipv4) {
    if (!state) return;
    int answer = MessageBoxW(hwnd,
        L"请选择 AdGuard Home DNS 客户端与本程序的关系：\n\n"
        L"【是】AdGuard Home 与本程序运行在同一台 Windows 电脑\n"
        L"【否】AdGuard Home 的 DNS 客户端包含其他设备（手机、路由器等）\n\n"
        L"此向导只检查配置、给出提示，不会修改 AdGuard、路由或证书。",
        L"AdGuard Home · 协同配置", MB_YESNOCANCEL | MB_ICONQUESTION);
    if (answer != IDYES && answer != IDNO) return;

    const bool remote = (answer == IDNO);
    char lan[64] = {0};
    const bool has_lan = ((find_lan_ipv4 != NULL && find_lan_ipv4(lan, sizeof(lan)) == 0));
    wchar_t ipv4[80] = L"不可用：尚未找到合适的局域网 IPv4";
    if (!remote) {
        wcscpy(ipv4, L"127.0.0.1");
    } else if (has_lan) {
        MultiByteToWideChar(CP_UTF8, 0, lan, -1, ipv4,
                            (int)(sizeof(ipv4) / sizeof(ipv4[0])));
        ipv4[(sizeof(ipv4) / sizeof(ipv4[0])) - 1] = 0;
    }
    const struct adguard_home_inputs input = {
        .remote_clients = remote,
        .bind_all = state->bind_all,
        .listener_responding = state->listener_responding,
        .lan_address_available = has_lan,
        .ca_trusted_for_user = state->ca_trusted_for_user,
        .http_port = state->http_port,
        .https_port = state->https_port
    };
    unsigned warnings = adguard_home_preflight(&input);
    wchar_t report[4096];
    swprintf(report, sizeof(report) / sizeof(report[0]),
        L"仅适用于 AdGuard Home，不适用于 AdGuard Windows/Android 客户端。\n\n"
        L"建议在 AdGuard Home 的 DNS 阻断设置中选择 custom_ip：\n"
        L"blocking_ipv4 = %ls\n"
        L"当前本程序 HTTP 端口：%d（DNS 目标一般需要 80）\n"
        L"当前本程序 HTTPS 端口：%d（DNS 目标一般需要 443）\n"
        L"监听所有网卡：%ls\n\n"
        L"检查结果：%ls\n",
        ipv4, state->http_port, state->https_port, state->bind_all ? L"是" : L"否",
        (warnings & ADGUARD_HOME_SERVER_UNVERIFIED)
            ? L"本地管理服务暂不可达" : L"本地管理服务可达（不是 DNS 验证）");

    size_t remaining = sizeof(report) / sizeof(report[0]) - wcslen(report) - 1;
    wchar_t *tail = report + wcslen(report);
    if (warnings & (ADGUARD_HOME_HTTP_PORT | ADGUARD_HOME_HTTPS_PORT)) {
        swprintf(tail, remaining,
            L"· DNS 返回 IP 不包含端口，请配置 HTTP 80 / HTTPS 443 并验证端口可用。\n");
        tail = report + wcslen(report);
        remaining = sizeof(report) / sizeof(report[0]) - wcslen(report) - 1;
    }
    if (warnings & ADGUARD_HOME_LAN_BIND) {
        swprintf(tail, remaining,
            L"· 跨设备访问需要显式允许局域网监听，并评估防火墙和代理暴露风险。\n");
        tail = report + wcslen(report);
        remaining = sizeof(report) / sizeof(report[0]) - wcslen(report) - 1;
    }
    if (warnings & ADGUARD_HOME_LAN_IP) {
        swprintf(tail, remaining,
            L"· 未找到合适的局域网 IPv4，不要使用 127.0.0.1 给其他设备作目标。\n");
        tail = report + wcslen(report);
        remaining = sizeof(report) / sizeof(report[0]) - wcslen(report) - 1;
    }
    if (warnings & ADGUARD_HOME_CA_TRUST) {
        swprintf(tail, remaining,
            L"· 本机当前用户的 CA 信任尚未验证；其他设备需分别信任对应 CA。\n");
        tail = report + wcslen(report);
        remaining = sizeof(report) / sizeof(report[0]) - wcslen(report) - 1;
    }
    swprintf(tail, remaining,
        L"· 尚未验证 DNS → 本服务的端到端路径；HTTPS 还可能受到证书固定限制。\n"
        L"· 不要为跨设备协同暴露未经鉴权的通用代理。\n\n"
        L"是否复制建议的 IPv4 地址到剪贴板？");
    int copy = MessageBoxW(hwnd, report, L"AdGuard Home 配置检查",
                           MB_YESNO | MB_ICONINFORMATION);
    if (copy != IDYES || (remote && !has_lan)) return;

    const size_t bytes = (wcslen(ipv4) + 1) * sizeof(wchar_t);
    HGLOBAL data = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!data) return;
    void *ptr = GlobalLock(data);
    if (!ptr) { GlobalFree(data); return; }
    memcpy(ptr, ipv4, bytes);
    GlobalUnlock(data);
    if (!OpenClipboard(hwnd)) { GlobalFree(data); return; }
    if (!EmptyClipboard() || !SetClipboardData(CF_UNICODETEXT, data)) {
        CloseClipboard();
        GlobalFree(data);
        return;
    }
    CloseClipboard();  /* Clipboard now owns the allocation. */
}

void gui_show_network_baseline(HWND hwnd) {
    const struct windows_network_inventory v = windows_network_inventory_read();
    wchar_t info[1024];
    swprintf(info, sizeof(info)/sizeof(info[0]),
        L"Windows 当前网络基线（只读）：\n\n"
        L"IPv4 路由条数：%u\nIPv4 默认路由数：%u\nIPv6 网关候选数：%u（非路由表）\n"
        L"已连接网卡：%u\n这些网卡列出的 DNS 服务器数：%u\n\n"
        L"路由查询：%ls（错误码 %lu）\n网卡查询：%ls（错误码 %lu）\n\n"
        L"这里只查看概况，不会修改配置。\n"
        L"计数不是可恢复的路由/DNS 快照；\n"
        L"全局接管及自动恢复仍未开放。",
        v.route_count, v.default_ipv4, v.ipv6_gateway_candidates,
        v.active_adapters, v.dns_servers,
        v.route_error == NO_ERROR ? L"成功" : L"失败",
        (unsigned long)v.route_error,
        v.adapter_error == NO_ERROR ? L"成功" : L"失败",
        (unsigned long)v.adapter_error);
    MessageBoxW(hwnd, info, L"网络基线检查", MB_OK | MB_ICONINFORMATION);
}

