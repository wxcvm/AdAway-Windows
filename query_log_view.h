#ifndef ADBLOCK_QUERY_LOG_VIEW_H
#define ADBLOCK_QUERY_LOG_VIEW_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* Retain the scroll position only while the user is still viewing the same
 * history page and filter, or the same application summary.  The result rows
 * may change without changing this identity; the list should not jump back
 * to the top during periodic stats refresh. */
struct qlv_view {
    bool apps;
    uint32_t offset;
    char generation[33];
    char query_key[65];
};

static inline bool qlv_same_view(const struct qlv_view *before,
                                 const struct qlv_view *after) {
    if (!before || !after || before->apps != after->apps) return false;
    if (before->apps) return true;
    return before->offset == after->offset &&
           memcmp(before->generation, after->generation,
                  sizeof(before->generation)) == 0 &&
           memcmp(before->query_key, after->query_key,
                  sizeof(before->query_key)) == 0;
}

#endif
