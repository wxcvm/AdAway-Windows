#include "query_log_navigation.h"
#include <stdio.h>
#include <stdlib.h>
#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "FAIL %d: %s\n", __LINE__, #condition); exit(1); } } while (0)

int main(void) {
    struct qln_state state;
    memset(&state, 0, sizeof(state));
    qln_refresh(&state);
    struct qln_page page = {0, 197, 600, true, "0123456789abcdef0123456789abcdef", "600"};
    uint64_t revision = state.revision;
    CHECK(qln_freeze(&state, &page, revision));
    CHECK(!qln_next(&state, &page, revision)); /* Retired request cannot navigate. */
    CHECK(!qln_freeze(&state, &page, state.revision));
    CHECK(qln_next(&state, &page, state.revision));
    CHECK(state.request.offset == 197 && state.depth == 1);
    CHECK(strcmp(state.request.anchor, "600") == 0);
    page.offset = 197;
    page.next_offset = 480; /* Actual server progress, not requested page size. */
    CHECK(qln_next(&state, &page, state.revision));
    CHECK(state.request.offset == 480 && state.depth == 2);
    CHECK(qln_previous(&state) && state.request.offset == 197);
    CHECK(qln_previous(&state) && state.request.offset == 0);
    CHECK(!qln_previous(&state));
    CHECK(strcmp(state.request.generation, page.generation) == 0);
    revision = state.revision;
    qln_refresh(&state);
    CHECK(!state.request.generation[0] && !state.request.anchor[0] && state.depth == 0);
    CHECK(!qln_next(&state, &page, revision));
    page.offset = 0; page.next_offset = 600; page.has_more = false;
    CHECK(!qln_next(&state, &page, state.revision));
    puts("PASS: log cursor freezing, actual page offsets, previous, refresh and stale request rejection");
    return 0;
}
