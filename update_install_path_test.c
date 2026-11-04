/* Same-volume portable copies must not be mistaken for the installed copy. */
#include "update_install_path.h"
#include <stdio.h>
#include <stdlib.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)

int main(void) {
    /* The former implementation stopped at the first path separator. */
    CHECK(!update_install_path_equal(L"D:\\ADBlock", L"D:\\Downloads\\ADBlock"));
    CHECK(!update_install_path_equal(L"C:\\ADBlock", L"C:\\ADBlockPortable"));
    CHECK(!update_install_path_equal(L"D:\\ADBlock", L"E:\\ADBlock"));
    CHECK(!update_install_path_equal(L"D:\\ADBlock", L"D:\\ADBlock\\other"));
    CHECK(!update_install_path_equal(L"C:", L"C:\\"));
    CHECK(!update_install_path_equal(L"", L""));
    CHECK(!update_install_path_equal(NULL, L"D:\\ADBlock"));
    CHECK(update_install_path_equal(L"D:\\ADBlock", L"d:/adblock/"));
    CHECK(update_install_path_equal(L"C:\\Users\\中文\\ADBlock",
                                    L"c:/Users/中文/ADBLOCK/"));
    CHECK(update_install_path_equal(L"\\\\server\\share\\ADBlock",
                                    L"//server/share/adblock/"));
    CHECK(update_install_path_equal(L"C:\\", L"c:/"));
    puts("PASS: full Windows install path identity, separators, Unicode, roots and portable siblings");
    return 0;
}
