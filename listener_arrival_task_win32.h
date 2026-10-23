#ifndef ADAWAY_LISTENER_ARRIVAL_TASK_WIN32_H
#define ADAWAY_LISTENER_ARRIVAL_TASK_WIN32_H
#include "listener_arrival_win32.h"

struct arrival_task;
enum arrival_task_status { ARRIVAL_TASK_OK, ARRIVAL_TASK_BUSY, ARRIVAL_TASK_UNAVAILABLE };
struct arrival_task *arrival_task_start(const struct arrival_config *config,const char *adblock,
    const char *hosts,enum arrival_task_status *status);
void arrival_task_cancel(struct arrival_task *task);
bool arrival_task_done(const struct arrival_task *task);
bool arrival_task_cancelled(const struct arrival_task *task);
/* The returned immutable text stays alive while the caller owns its task ref. */
const wchar_t *arrival_task_result(const struct arrival_task *task);
void arrival_task_progress(struct arrival_task *task,wchar_t *out,size_t cap);
void arrival_task_release(struct arrival_task *task);
#endif
