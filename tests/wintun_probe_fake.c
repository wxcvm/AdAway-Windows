#include <windows.h>

/* A regression trap: any DLL entry point execution writes a test-owned marker. */
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance; (void)reason; (void)reserved;
    wchar_t path[MAX_PATH];
    if (GetEnvironmentVariableW(L"ADBLOCK_WINTUN_TEST_MARKER", path, MAX_PATH)) {
        HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    }
    return TRUE;
}
#define EXPORT(name) __declspec(dllexport) DWORD WINAPI name(void) { return 0; }
#ifndef WINTUN_TEST_FORWARD_ONLY
EXPORT(WintunOpenAdapter)
EXPORT(WintunCloseAdapter)
EXPORT(WintunCreateAdapter)
EXPORT(WintunGetAdapterLuid)
EXPORT(WintunStartSession)
EXPORT(WintunEndSession)
EXPORT(WintunGetReadWaitEvent)
EXPORT(WintunReceivePacket)
EXPORT(WintunReleaseReceivePacket)
EXPORT(WintunAllocateSendPacket)
EXPORT(WintunSendPacket)
EXPORT(WintunGetRunningDriverVersion)
#endif
#ifdef WINTUN_TEST_DEPENDENCY
EXPORT(WintunTestDependency)
#endif
