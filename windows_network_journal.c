#include "windows_network_journal.h"

bool network_journal_record(struct network_journal *j,
                            enum network_action_kind kind, uint64_t token) {
    if (!j || token == 0 || kind < NETWORK_ACTION_ROUTE_ADD ||
            kind > NETWORK_ACTION_ADAPTER_CREATE ||
            j->count >= NETWORK_JOURNAL_MAX) return false;
    j->entries[j->count].kind = kind;
    j->entries[j->count].token = token;
    j->entries[j->count].active = true;
    ++j->count;
    return true;
}

unsigned network_journal_rollback(struct network_journal *j,
                                 network_journal_undo_fn undo, void *context) {
    if (!j || !undo) return 1;
    unsigned failed = 0;
    for (unsigned i = j->count; i > 0; --i) {
        struct network_undo_entry *entry = &j->entries[i-1];
        if (!entry->active) continue;
        if (undo(entry->kind, entry->token, context))
            entry->active = false;
        else ++failed;
    }
    return failed;
}

bool network_journal_is_clean(const struct network_journal *j) {
    if (!j) return false;
    for (unsigned i = 0; i < j->count; ++i)
        if (j->entries[i].active) return false;
    return true;
}
