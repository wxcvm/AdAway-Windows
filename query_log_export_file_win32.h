#ifndef ADAWAY_QUERY_LOG_EXPORT_FILE_WIN32_H
#define ADAWAY_QUERY_LOG_EXPORT_FILE_WIN32_H
#include "query_log_export_state.h"
#include <stdio.h>

/* File operations are injected for deterministic failure/race tests. Production
 * always uses the default operations: there are no environment/test switches. */
struct qlx_file_ops {
    FILE *(*create)(void *, const wchar_t *, wchar_t *, DWORD *);
    size_t (*write)(void *, FILE *, const char *, size_t);
    int (*flush)(void *, FILE *);
    int (*sync)(void *, FILE *);
    int (*close)(void *, FILE *);
    bool (*replace)(void *, const wchar_t *, const wchar_t *, DWORD *);
    bool (*remove)(void *, const wchar_t *, DWORD *);
};
enum qlx_file_failure {
    QLX_FILE_NONE, QLX_FILE_CREATE, QLX_FILE_WRITE, QLX_FILE_FLUSH,
    QLX_FILE_SYNC, QLX_FILE_CLOSE, QLX_FILE_REPLACE
};
struct qlx_file_transaction {
    FILE *file;
    wchar_t stage[MAX_PATH];
    bool owned;
    DWORD error, cleanup_error;
    enum qlx_file_failure failed_at;
    const struct qlx_file_ops *ops;
    void *io_context;
};
const struct qlx_file_ops *qlx_file_default_ops(void);
void qlx_file_init(struct qlx_file_transaction *, const struct qlx_file_ops *, void *);
bool qlx_file_open(struct qlx_file_transaction *, const wchar_t *);
bool qlx_file_write(struct qlx_file_transaction *, const char *, size_t);
/* Returns a terminal phase only after closing/cleaning. Caller publishes it
 * after its UI error/path snapshot. cancel is rechecked AFTER flush/close and
 * immediately before the shared phase CAS; notice runs only after CAS wins. */
enum qlx_phase qlx_file_finish(struct qlx_file_transaction *, const wchar_t *, bool,
    volatile LONG *, bool (*cancel)(void *), void (*notice)(void *), void *);
#endif
