#ifndef ADAWAY_ADGUARD_WINDOW_COMPARE_H
#define ADAWAY_ADGUARD_WINDOW_COMPARE_H
/* Compare independently observed event counts over a user-selected time
 * window. There is deliberately no correlation or combined block rate: a
 * common hostname/timestamp cannot prove the same network transaction. */
#include "adguard_filter_import.h"

struct ag_window_compare {
    int64_t since, until; /* inclusive UTC seconds; anchored to latest import */
    size_t imported, imported_blocked, imported_dns;
    size_t local, local_blocked; /* caller supplies ONLY visible local page */
};
static inline bool ag_window_compare_begin(struct ag_window_compare *stats,
                                           const struct ag_import *imported,
                                           int64_t seconds) {
    if (!stats || !imported || !imported->count || !seconds || seconds < 0)
        return false;
    memset(stats, 0, sizeof(*stats));
    int64_t latest=imported->events[0].unix_seconds;
    for (size_t i=1; i<imported->count; ++i)
        if (imported->events[i].unix_seconds > latest)
            latest=imported->events[i].unix_seconds;
    stats->until=latest;
    stats->since=latest-seconds+1;
    for (size_t i=0; i<imported->count; ++i) {
        const struct ag_event *event=&imported->events[i];
        if (event->unix_seconds < stats->since || event->unix_seconds > latest)
            continue;
        ++stats->imported;
        if (event->log_type==0) ++stats->imported_blocked;
        if (strcmp(event->protocol, "Dns")==0) ++stats->imported_dns;
    }
    return true;
}
static inline void ag_window_compare_local(struct ag_window_compare *stats,
                                            int64_t timestamp, int action) {
    if (!stats || timestamp < stats->since || timestamp > stats->until)
        return;
    ++stats->local;
    if (action==1) ++stats->local_blocked;
}
#endif
