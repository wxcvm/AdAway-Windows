#ifndef ADAWAY_QUERY_LOG_EXPORT_TASK_H
#define ADAWAY_QUERY_LOG_EXPORT_TASK_H
#include "query_log_request.h"
#include <windows.h>
#include <wchar.h>

/* Value objects: capture before a modal dialog; never refer to live navigation. */
struct qlx_query_snapshot {
    struct qlp_request request;
    uint32_t total, retained;
};
struct qlx_export_task {
    uint64_t id;
    struct qlx_query_snapshot query;
    wchar_t target[MAX_PATH];
};
/* Mutable progress is published only under the dashboard mutex. */
struct qlx_export_progress {
    uint64_t id;
    uint32_t done, total;
    DWORD error, cleanup_error;
    wchar_t stage[MAX_PATH];
};
static inline bool qlx_query_capture(struct qlx_query_snapshot *out,
        const struct qlp_request *request, const struct qlp_page *page) {
    if (!out || !request || !page || !request->filter.enabled ||
        !page->generation[0] || !page->anchor[0] || !page->query_key[0] ||
        page->total > page->retained_total || page->retained_total > QLP_MAX_TOTAL) return false;
    struct qlx_query_snapshot copy = {0};
    copy.request = *request;
    copy.request.offset = 0;
    memcpy(copy.request.generation, page->generation, sizeof(copy.request.generation));
    memcpy(copy.request.anchor, page->anchor, sizeof(copy.request.anchor));
    memcpy(copy.request.query_key, page->query_key, sizeof(copy.request.query_key));
    char path[1200];
    if (!qlp_request_path(&copy.request, path, sizeof(path))) return false;
    copy.total = page->total; copy.retained = page->retained_total;
    *out = copy;
    return true;
}
static inline bool qlx_task_confirm(struct qlx_export_task *out, uint64_t id,
        const struct qlx_query_snapshot *query, const wchar_t *target) {
    if (!out || !id || !query || !target) return false;
    size_t length = 0;
    while (length < MAX_PATH && target[length]) ++length;
    if (!length || length >= MAX_PATH) return false;
    struct qlx_export_task copy = {0};
    copy.id = id; copy.query = *query;
    memcpy(copy.target, target, (length + 1) * sizeof(wchar_t));
    *out = copy;
    return true;
}
static inline void qlx_progress_begin(struct qlx_export_progress *state,
        uint64_t id, uint32_t total) {
    memset(state, 0, sizeof(*state)); state->id = id; state->total = total;
}
static inline bool qlx_progress_update(struct qlx_export_progress *state,
        uint64_t id, uint32_t done, uint32_t total) {
    if (!id || state->id != id || total != state->total ||
        done < state->done || done > total) return false;
    state->done = done;
    return true;
}
static inline bool qlx_progress_finish(struct qlx_export_progress *state,
        uint64_t id, DWORD error, DWORD cleanup_error, const wchar_t *owned_stage) {
    if (!id || state->id != id) return false;
    state->error = error; state->cleanup_error = cleanup_error;
    if (cleanup_error && owned_stage) {
        wcsncpy(state->stage, owned_stage, MAX_PATH - 1);
        state->stage[MAX_PATH - 1] = 0;
    } else state->stage[0] = 0;
    return true;
}
#endif
