#define _WIN32_WINNT 0x0A00
#include <stdbool.h>
#include "listener_startup_win32.h"
#include <assert.h>
int main(void) {
    char *none[]={"test"}; assert(ms_cli(1,none)==-1);
    char *missing[]={"test","--ensure-listener-addresses","127.0.0.1"};
    assert(ms_cli(3,missing)==ERROR_INVALID_PARAMETER);
    char *wrong[]={"test","--ensure-listener-addresses","::1","-","30080","30443"};
    assert(ms_cli(6,wrong)==ERROR_INVALID_PARAMETER);
    char *empty[]={"test","--ensure-listener-addresses","-","-","30080","30443"};
    assert(ms_cli(6,empty)==ERROR_INVALID_PARAMETER);
    char *overlap[]={"test","--ensure-listener-addresses","127.0.0.1","::1","30080","30080"};
    assert(ms_cli(6,overlap)==ERROR_INVALID_PARAMETER);
    puts("Restricted startup arguments and protocol boundaries passed without address mutations");
    return 0;
}
