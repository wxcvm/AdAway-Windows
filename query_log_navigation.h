#ifndef ADBLOCK_QUERY_LOG_NAVIGATION_H
#define ADBLOCK_QUERY_LOG_NAVIGATION_H
#include "query_log_page.h"
#include <stdint.h>
#include <string.h>

/* Only the UI thread changes history; the poll worker takes a request/revision
 * copy under the dashboard mutex. Bounds follow the existing server contract. */
struct qln_state {
    struct qlp_request request;
    uint64_t revision;
    unsigned depth;
    uint32_t previous[10000];
};

struct qln_page {
    uint32_t offset, next_offset, total;
    bool has_more;
    char generation[33], anchor[21];
};

static inline void qln_refresh(struct qln_state *state) {
    memset(&state->request, 0, sizeof(state->request));
    state->depth = 0;
    state->revision++;
}

static inline bool qln_freeze(struct qln_state *state, const struct qln_page *page,
                              uint64_t revision) {
    if (revision != state->revision || page->offset != state->request.offset ||
        state->request.generation[0]) return false;
    memcpy(state->request.generation, page->generation, sizeof(page->generation));
    memcpy(state->request.anchor, page->anchor, sizeof(page->anchor));
    state->revision++;
    return true;
}

static inline bool qln_next(struct qln_state *state, const struct qln_page *page,
                            uint64_t revision) {
    if (revision != state->revision || page->offset != state->request.offset ||
        !page->has_more || page->next_offset <= page->offset ||
        page->next_offset >= page->total || state->depth >= 10000) return false;
    state->previous[state->depth++] = page->offset;
    state->request.offset = page->next_offset;
    memcpy(state->request.generation, page->generation, sizeof(page->generation));
    memcpy(state->request.anchor, page->anchor, sizeof(page->anchor));
    state->revision++;
    return true;
}

static inline bool qln_previous(struct qln_state *state) {
    if (!state->depth) return false;
    state->request.offset = state->previous[--state->depth];
    state->revision++;
    return true;
}
#endif
