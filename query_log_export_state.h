#ifndef ADAWAY_QUERY_LOG_EXPORT_STATE_H
#define ADAWAY_QUERY_LOG_EXPORT_STATE_H
#include <windows.h>
#include <stdbool.h>

/* One state is shared by the UI and its existing poll worker. The CAS into
 * COMMITTING is the cancellation boundary: a cancellation that wins before
 * it cannot replace the destination; after it, saving is no longer abortable.
 * Terminal states are published only after closing/cleaning owned resources. */
enum qlx_phase {
    QLX_IDLE, QLX_CHOOSING, QLX_QUEUED, QLX_RUNNING, QLX_CANCEL_REQUESTED,
    QLX_COMMITTING, QLX_SUCCEEDED, QLX_CANCELLED, QLX_FAILED,
    QLX_CLEANUP_FAILED, QLX_DIALOG_FAILED
};
static inline enum qlx_phase qlx_phase_get(volatile LONG *state) {
    return (enum qlx_phase)InterlockedCompareExchange(state,0,0);
}
static inline bool qlx_phase_busy(enum qlx_phase phase) {
    return phase>=QLX_CHOOSING && phase<=QLX_COMMITTING;
}
static inline bool qlx_phase_begin(volatile LONG *state) {
    LONG old=InterlockedCompareExchange(state,0,0);
    while(!qlx_phase_busy((enum qlx_phase)old) && old!=QLX_CLEANUP_FAILED) {
        LONG found=InterlockedCompareExchange(state,QLX_CHOOSING,old);
        if(found==old)return true;
        old=found;
    }
    return false;
}
/* Only call after confirming that the recorded staging path no longer exists.
 * A cleanup failure is not permission to lose that path by starting a new job. */
static inline bool qlx_phase_cleanup_resolved(volatile LONG *state) {
    return InterlockedCompareExchange(state,QLX_FAILED,QLX_CLEANUP_FAILED)==QLX_CLEANUP_FAILED;
}
static inline bool qlx_phase_cancel(volatile LONG *state) {
    LONG old=InterlockedCompareExchange(state,0,0);
    while(old==QLX_QUEUED||old==QLX_RUNNING) {
        LONG found=InterlockedCompareExchange(state,QLX_CANCEL_REQUESTED,old);
        if(found==old)return true;
        old=found;
    }
    return old==QLX_CANCEL_REQUESTED;
}
static inline bool qlx_phase_commit(volatile LONG *state) {
    return InterlockedCompareExchange(state,QLX_COMMITTING,QLX_RUNNING)==QLX_RUNNING;
}
#endif
