#include "query_log_order.h"
#include <stdio.h>
#include <stdlib.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); exit(1); } } while (0)
int main(void) {
    const struct qlo_time_row events[] = {{125}, {100}, {130}, {130}, {0}, {120}};
    const size_t expected[] = {2, 3, 0, 5, 1, 4};
    size_t order[6] = {0};
    qlo_descending_time_order(events, 6, order);
    for (size_t i = 0; i < 6; ++i) CHECK(order[i] == expected[i]);
    const struct qlo_time_row ties[] = {{42}, {42}, {42}};
    size_t original[3] = {3, 3, 3};
    qlo_descending_time_order(ties, 3, original);
    for (size_t i = 0; i < 3; ++i) CHECK(original[i] == i);
    puts("PASS: stable descending display timestamp order");
    return 0;
}
