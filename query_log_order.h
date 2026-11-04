#ifndef ADBLOCK_QUERY_LOG_ORDER_H
#define ADBLOCK_QUERY_LOG_ORDER_H
#include <stddef.h>
#include <stdint.h>

/* Stable timestamp-descending order within a displayed page only.
 * Does not change the server's sequence cursor, retention or CSV export. */
struct qlo_time_row { uint64_t timestamp; };
static inline void qlo_descending_time_order(
    const struct qlo_time_row *rows, size_t count, size_t *order) {
    if (!rows || !order) return;
    for (size_t i = 0; i < count; ++i) {
        size_t j = i;
        while (j > 0 && rows[order[j - 1]].timestamp < rows[i].timestamp) {
            order[j] = order[j - 1];
            --j;
        }
        order[j] = i;
    }
}
#endif
