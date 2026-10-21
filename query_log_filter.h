#ifndef ADBLOCK_QUERY_LOG_FILTER_H
#define ADBLOCK_QUERY_LOG_FILTER_H
#include <stdbool.h>
#include <stddef.h>
#include <wchar.h>
#include <wctype.h>

/* Filtering is deliberately local to the loaded page, never advertised as a
 * search of retained history. It never changes the cursor or rule decisions. */
static inline bool qlf_matches(const wchar_t *host, int action,
                               const wchar_t *query, int filter) {
    if (!host || !query || (filter >= 0 && filter != action)) return false;
    if (!*query) return true;
    for (const wchar_t *start = host; *start; ++start) {
        const wchar_t *left = start, *right = query;
        while (*left && *right && towlower(*left) == towlower(*right)) {
            ++left; ++right;
        }
        if (!*right) return true;
    }
    return false;
}
#endif
