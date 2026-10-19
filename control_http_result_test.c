#include "control_http_result.h"
#include <assert.h>
#include <stdio.h>
int main(void) {
    assert(control_http_status("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")==200);
    assert(control_http_status("HTTP/1.0 403 Forbidden\r\n\r\n")==403);
    assert(control_http_status("HTTP/1.1 409 Wait\r\n\r\n")==409);
    assert(control_http_status("HTTP/1.1 500 Error\r\n\r\n")==500);
    const char *invalid[]={"","sent successfully","HTTP/1.1 200 OK\r\n","HTTP/1.1 20x OK\r\n\r\n","HTTP/1.1 2000 OK\r\n\r\n","HTTP/1.1 999 X\r\n\r\n"};
    for (size_t i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++) assert(!control_http_status(invalid[i]));
    puts("Control acknowledgement: success/rejection/error and partial/malformed response cases passed"); return 0;
}
