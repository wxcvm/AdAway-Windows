#ifndef ADAWAY_RESTART_WIN32_H
#define ADAWAY_RESTART_WIN32_H
#include <windows.h>
#include <stdbool.h>
#define RESTART_COMMAND_CAPACITY 32768
struct restart_command {
    wchar_t executable[RESTART_COMMAND_CAPACITY];
    wchar_t command[RESTART_COMMAND_CAPACITY];
};
/* Preparation never releases the running instance guard. Caller frees with free(). */
DWORD restart_prepare(const char *resources, bool minimized, struct restart_command **out);
/* Called only after the old server has stopped. Consumes *single before launch. */
DWORD restart_launch(struct restart_command *command, HANDLE *single, DWORD *child_pid);
#endif
