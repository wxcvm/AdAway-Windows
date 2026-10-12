#ifndef ADBLOCK_WINDOWS_NETWORK_JOURNAL_H
#define ADBLOCK_WINDOWS_NETWORK_JOURNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * A tiny in-memory MODEL of a future compensating-action journal.
 *
 * It NEVER mutates Windows networking. Once the real backend is implemented,
 * every action needs a persisted, fsync'd intent record before the OS write,
 * explicit ownership, idempotent undo, startup recovery, and conflict checks.
 * This is only the deterministic reverse-order logic and failure behavior.
 */
#define NETWORK_JOURNAL_MAX 32u
enum network_action_kind {
    NETWORK_ACTION_ROUTE_ADD = 1,
    NETWORK_ACTION_DNS_CHANGE,
    NETWORK_ACTION_ADAPTER_CREATE
};
struct network_undo_entry {
    enum network_action_kind kind;
    uint64_t token;
    bool active;
};
struct network_journal {
    struct network_undo_entry entries[NETWORK_JOURNAL_MAX];
    unsigned count;
};
typedef bool (*network_journal_undo_fn)(enum network_action_kind kind,
                                         uint64_t token, void *context);

bool network_journal_record(struct network_journal *journal,
                             enum network_action_kind kind, uint64_t token);

/* Returns count of failed undo calls. Successful entries are made inactive.
 * Failures stay active for subsequent retry. */
unsigned network_journal_rollback(struct network_journal *journal,
                                  network_journal_undo_fn undo, void *context);

bool network_journal_is_clean(const struct network_journal *journal);

#endif
