"""Count-checked Windows restart fix; portable core pin remains unchanged."""
def prepare_restart(source):
    include='#include "gui_win32.h"      /* native dashboard + autostart (Windows) */'
    old='''        if (win32_restart_requested()) {
            LOG_INFO("Restart requested - relaunching with the new settings...");
            wchar_t exeW[MAX_PATH], argsW[2048];
            if (GetModuleFileNameW(NULL, exeW, MAX_PATH) > 0) {
                swprintf(argsW, 2048, L"--resources \\"%hs\\"", s.resource_dir);
                ShellExecuteW(NULL, L"open", exeW, argsW, NULL, SW_SHOWNORMAL);
            }
        }'''
    if source.count(include)!=1 or source.count(old)!=1:
        raise ValueError("upstream restart block changed; review before rebasing")
    source=source.replace(include,include+'\n#include "restart_win32.h"',1)
    restart='''        if (win32_restart_requested()) {
            struct restart_command *command = NULL;
            DWORD child_pid = 0;
            DWORD restart_error = restart_prepare(s.resource_dir, false, &command);
            if (!restart_error) restart_error = restart_launch(command, &single, &child_pid);
            free(command);
            if (restart_error) {
                wchar_t failure[256];
                swprintf(failure, 256, L"设置已保存，但重新打开本安装失败（错误 %lu）。请手动打开 AdAway。", (unsigned long)restart_error);
                LOG_ERROR("Restart launch failed: %lu", (unsigned long)restart_error);
                MessageBoxW(NULL, failure, L"AdAway 重新启动失败", MB_OK | MB_ICONERROR);
                return EXIT_FAILURE;
            }
            LOG_INFO("Restart process created: PID %lu; readiness is verified by the new instance", (unsigned long)child_pid);
        }'''
    source=source.replace(old,restart,1)
    attached='''        int rc = adblock_gui_run(&args);
        if (rc != 0)
            LOG_FATAL("Dashboard window could not be created (exit code %d).", rc);
        return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;'''
    if source.count(attached)!=1:
        raise ValueError("upstream dashboard-only return changed")
    # No server thread belongs to this dashboard; never stop the attached process.
    return source.replace(attached,attached.replace('        return rc == 0',restart+'\n        return rc == 0'),1)
