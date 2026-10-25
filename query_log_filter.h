#ifndef ADBLOCK_QUERY_LOG_FILTER_H
#define ADBLOCK_QUERY_LOG_FILTER_H
#include <stdbool.h>
#include <stddef.h>
#include <wchar.h>
#include <wctype.h>

#define QLF_FAMILY_UNKNOWN 10
#define QLF_IPV4 14
#define QLF_IPV6 16
#define QLF_TYPE_UNKNOWN 99
#define QLF_TYPE_BASE 100

/* Legacy in-memory matcher retained for compatibility tests only. Production
 * GUI filtering uses versioned server history requests, not this matcher. */
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

/* One existing combo selects one dimension at a time; search combines with it.
 * Response classifications are not rule types and family is not DNS A/AAAA. */
static inline int qlf_filter_for_choice(int choice) {
    static const int filters[] = {-1, 1, 2, 0, QLF_IPV4, QLF_IPV6, QLF_FAMILY_UNKNOWN,
        100, 101, 102, 103, 104, 105, 106, 107, 108, 109, QLF_TYPE_UNKNOWN, 3};
    return choice >= 0 && (size_t)choice < sizeof(filters) / sizeof(filters[0]) ? filters[choice] : -1;
}

static inline bool qlf_matches_entry(const wchar_t *host, int action, int type, int family,
                                     const wchar_t *query, int filter) {
    int action_filter = filter >= -1 && filter <= 2 ? filter : -1;
    if (!qlf_matches(host, action, query, action_filter)) return false;
    if (filter == QLF_IPV4) return family == 4;
    if (filter == QLF_IPV6) return family == 6;
    if (filter == QLF_FAMILY_UNKNOWN) return family == 0;
    if (filter == QLF_TYPE_UNKNOWN) return action == 1 && (type < 0 || type >= 10);
    if (filter >= QLF_TYPE_BASE && filter < QLF_TYPE_BASE + 10)
        return action == 1 && type == filter - QLF_TYPE_BASE;
    return filter >= -1 && filter <= 2;
}
#endif
