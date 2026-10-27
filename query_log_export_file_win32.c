#include "query_log_export_file_win32.h"
#include <io.h>
#include <string.h>
#include <wchar.h>

static FILE *file_create(void *context, const wchar_t *target, wchar_t *stage, DWORD *error) {
    (void)context;
    wchar_t directory[MAX_PATH];
    size_t length = target ? wcslen(target) : 0;
    if (!length || length >= MAX_PATH) { *error = ERROR_INVALID_NAME; return NULL; }
    wcscpy(directory, target);
    wchar_t *back = wcsrchr(directory, L'\\'), *forward = wcsrchr(directory, L'/');
    wchar_t *slash = back;
    if (forward && (!slash || forward > slash)) slash = forward;
    if (slash) slash[1] = 0; else wcscpy(directory, L".");
    if (!GetTempFileNameW(directory, L"qle", 0, stage)) {
        *error = GetLastError(); stage[0] = 0; return NULL;
    }
    /* stage is ours even if reopening fails; finish must still clean it. */
    FILE *file = _wfopen(stage, L"wb");
    if (!file) *error = ERROR_OPEN_FAILED;
    return file;
}
static size_t file_write(void *context, FILE *file, const char *bytes, size_t length) {
    (void)context; return fwrite(bytes, 1, length, file);
}
static int file_flush(void *context, FILE *file) { (void)context; return fflush(file); }
static int file_sync(void *context, FILE *file) { (void)context; return _commit(_fileno(file)); }
static int file_close(void *context, FILE *file) { (void)context; return fclose(file); }
static bool file_replace(void *context, const wchar_t *stage, const wchar_t *target, DWORD *error) {
    (void)context;
    if (MoveFileExW(stage, target, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) return true;
    *error = GetLastError(); return false;
}
static bool file_remove(void *context, const wchar_t *stage, DWORD *error) {
    (void)context;
    if (DeleteFileW(stage)) return true;
    DWORD code = GetLastError();
    if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) return true;
    *error = code; return false;
}
static const struct qlx_file_ops DEFAULT_OPS = {
    file_create, file_write, file_flush, file_sync, file_close, file_replace, file_remove
};
const struct qlx_file_ops *qlx_file_default_ops(void) { return &DEFAULT_OPS; }
void qlx_file_init(struct qlx_file_transaction *tx, const struct qlx_file_ops *ops, void *context) {
    memset(tx, 0, sizeof(*tx)); tx->ops = ops ? ops : &DEFAULT_OPS; tx->io_context = context;
}
static void fail(struct qlx_file_transaction *tx, enum qlx_file_failure at, DWORD error) {
    if (!tx->error) { tx->error = error ? error : ERROR_WRITE_FAULT; tx->failed_at = at; }
}
bool qlx_file_open(struct qlx_file_transaction *tx, const wchar_t *target) {
    if (tx->file || tx->owned) return false;
    DWORD error = 0;
    tx->file = tx->ops->create(tx->io_context, target, tx->stage, &error);
    tx->owned = tx->stage[0] != 0;
    if (!tx->file) fail(tx, QLX_FILE_CREATE, error ? error : ERROR_OPEN_FAILED);
    return tx->file != NULL;
}
bool qlx_file_write(struct qlx_file_transaction *tx, const char *bytes, size_t length) {
    if (!tx->file || tx->error) return false;
    if (tx->ops->write(tx->io_context, tx->file, bytes, length) == length) return true;
    fail(tx, QLX_FILE_WRITE, ERROR_WRITE_FAULT); return false;
}
enum qlx_phase qlx_file_finish(struct qlx_file_transaction *tx, const wchar_t *target, bool content_ok,
        volatile LONG *phase, bool (*cancel)(void *), void (*notice)(void *), void *context) {
    bool ok = content_ok && tx->file && !tx->error;
    if (tx->file) {
        if (tx->ops->flush(tx->io_context, tx->file) != 0) {
            ok = false; fail(tx, QLX_FILE_FLUSH, ERROR_WRITE_FAULT);
        }
        if (ok && tx->ops->sync(tx->io_context, tx->file) != 0) {
            ok = false; fail(tx, QLX_FILE_SYNC, ERROR_WRITE_FAULT);
        }
        if (tx->ops->close(tx->io_context, tx->file) != 0) {
            ok = false; fail(tx, QLX_FILE_CLOSE, ERROR_WRITE_FAULT);
        }
        tx->file = NULL;
    }
    if (cancel && cancel(context)) qlx_phase_cancel(phase);
    if (ok && qlx_phase_commit(phase)) {
        if (notice) notice(context);
        DWORD error = 0;
        ok = tx->ops->replace(tx->io_context, tx->stage, target, &error);
        if (ok) tx->owned = false; else fail(tx, QLX_FILE_REPLACE, error);
    } else ok = false;
    if (tx->owned) {
        DWORD error = 0;
        if (!tx->ops->remove(tx->io_context, tx->stage, &error))
            tx->cleanup_error = error ? error : ERROR_ACCESS_DENIED;
        else tx->owned = false;
    }
    return tx->cleanup_error ? QLX_CLEANUP_FAILED : ok ? QLX_SUCCEEDED :
        qlx_phase_get(phase) == QLX_CANCEL_REQUESTED ? QLX_CANCELLED : QLX_FAILED;
}
