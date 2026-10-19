#ifndef ADBLOCK_CONTROL_HTTP_RESULT_H
#define ADBLOCK_CONTROL_HTTP_RESULT_H
#include <string.h>
/* A completed status line/header is required; sending bytes is not acknowledgement. */
static inline int control_http_status(const char *response) {
    if (!response || strlen(response)<14 || !strstr(response,"\r\n\r\n")) return 0;
    if (strncmp(response,"HTTP/1.0 ",9) && strncmp(response,"HTTP/1.1 ",9)) return 0;
    if (response[9]<'1' || response[9]>'5' || response[10]<'0' || response[10]>'9' ||
        response[11]<'0' || response[11]>'9' || (response[12]!=' ' && response[12]!='\r')) return 0;
    return (response[9]-'0')*100+(response[10]-'0')*10+response[11]-'0';
}
#endif
