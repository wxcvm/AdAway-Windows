#include "query_log_view.h"
#include <stdio.h>
#include <stdlib.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); exit(1); } } while (0)

int main(void) {
    struct qlv_view first = {0}, second = {0};
    CHECK(qlv_same_view(&first, &second));
    first.offset = 300;
    CHECK(!qlv_same_view(&first, &second)); /* paging goes to top */
    second.offset = 300;
    CHECK(qlv_same_view(&first, &second));
    first.generation[0] = 'a';
    CHECK(!qlv_same_view(&first, &second)); /* server restarted */
    second.generation[0] = 'a';
    CHECK(qlv_same_view(&first, &second));
    first.query_key[0] = 'a';
    CHECK(!qlv_same_view(&first, &second)); /* filter changed */
    second.query_key[0] = 'a';
    CHECK(qlv_same_view(&first, &second));
    second.apps = true;
    CHECK(!qlv_same_view(&first, &second)); /* switch to apps resets */
    first.apps = true;
    CHECK(qlv_same_view(&first, &second));
    first.offset = 999;
    CHECK(qlv_same_view(&first, &second)); /* app summary is not paged */
    first.ranking = true;
    CHECK(!qlv_same_view(&first, &second)); /* switch to ranking resets */
    second.ranking = true;
    CHECK(qlv_same_view(&first, &second)); /* ranking doesn't paginate */
    first.apps = false;
    CHECK(!qlv_same_view(&first, &second));
    second.apps = false;
    CHECK(qlv_same_view(&first, &second));
    first.external = true;
    CHECK(!qlv_same_view(&first,&second)); /* imported vs local sources */
    second.external = true;
    CHECK(qlv_same_view(&first,&second));
    CHECK(!qlv_same_view(NULL, &second));
    puts("PASS: scroll is retained on the same view, reset for different history/filter and tabs");
    return 0;
}
