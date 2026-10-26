/* Test-only owner process. Links the unmodified production adblock_gui_run.
 * No listener creation, updater, network change or certificate operation is invoked.
 * The controller can only operate windows belonging to this process. */
#include "gui_win32.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
bool win32_server_alive(void) { return true; }
void win32_log_line(const char *format,...) {
    FILE *file=fopen("webserver.log","a");if(!file)return;
    va_list args;va_start(args,format);vfprintf(file,format,args);va_end(args);
    fputc('\n',file);fclose(file);
}
int main(int argc,char **argv) {
    if(argc!=5)return 2;
    struct adblock_gui_args args={0};
    args.resource_dir=argv[1];args.http_port=atoi(argv[2]);
    args.https_port=atoi(argv[3]);args.stats_port=atoi(argv[4]);
    args.bind_ip="127.0.0.1";args.bind_ipv6="::1";args.explicit_pair=true;
    args.owns_server=false;
    return adblock_gui_run(&args);
}
