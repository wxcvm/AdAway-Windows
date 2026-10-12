#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <tlhelp32.h>
#include <wchar.h>
#include "traffic_observer_win32.h"

/* Read-only process enumeration: an AdGuard executable may be installed but
 * idle. We deliberately do not infer VPN/proxy/WFP ownership or change any
 * other application's settings based on this signal. */
enum adguard_process_signal adguard_process_probe(void) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return ADGUARD_PROCESS_UNKNOWN;
    }
    PROCESSENTRY32W process;
    ZeroMemory(&process, sizeof(process));
    process.dwSize = sizeof(process);
    if (!Process32FirstW(snapshot, &process)) {
        CloseHandle(snapshot);
        return ADGUARD_PROCESS_UNKNOWN;
    }
    do {
        if (_wcsicmp(process.szExeFile, L"Adguard.exe") == 0 ||
            _wcsicmp(process.szExeFile, L"AdguardSvc.exe") == 0) {
            CloseHandle(snapshot);
            return ADGUARD_PROCESS_PRESENT;
        }
    } while (Process32NextW(snapshot, &process));
    CloseHandle(snapshot);
    return ADGUARD_PROCESS_ABSENT;
}
