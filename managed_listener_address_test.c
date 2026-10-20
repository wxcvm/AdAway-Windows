#include "managed_listener_address_win32.h"
#include <assert.h>
int main(void) {
    WSADATA data; assert(WSAStartup(MAKEWORD(2,2),&data)==0);
    SOCKADDR_INET address;
    const char *allowed[]={"10.4.3.2","172.16.0.2","192.168.4.2","127.0.0.2","fd6b:2a91:84f0::2"};
    for (size_t i=0;i<sizeof(allowed)/sizeof(allowed[0]);i++) assert(ma_address(allowed[i],&address));
    const char *rejected[]={"8.8.8.8","2001:db8::2","fe80::2","::1","::","0.0.0.0","ff02::2","::ffff:10.4.3.2","fd12::2;whoami","[fd12::2]"};
    for (size_t i=0;i<sizeof(rejected)/sizeof(rejected[0]);i++) assert(!ma_address(rejected[i],&address));
    char *invalid[]={"webserver","--create-listener-address","fd12::2","80","80"};
    assert(ma_cli(5,invalid)==ERROR_INVALID_PARAMETER);
    char *normal[]={"webserver","--resources","fixture"}; assert(ma_cli(3,normal)==-1);
    /* Never call mutating APIs on the developer machine. Actual add/remove is tested in disposable CI. */
    puts("Managed listener private-address policy and CLI side-effect guards passed");
    WSACleanup(); return 0;
}
