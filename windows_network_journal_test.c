#include "windows_network_journal.h"
#include <assert.h>
#include <stdio.h>

struct calls { int count; uint64_t seen[3]; bool fail_second; };
static bool fake_undo(enum network_action_kind kind, uint64_t token, void *ctx) {
    (void)kind;
    struct calls *calls = (struct calls *)ctx;
    if (calls->count < 3) calls->seen[calls->count] = token;
    calls->count++;
    return !(calls->fail_second && token == 2);
}

int main(void) {
    struct network_journal journal = {0};
    struct calls calls = {0};
    assert(network_journal_is_clean(&journal));
    assert(!network_journal_record(NULL, NETWORK_ACTION_ROUTE_ADD, 1));
    assert(!network_journal_record(&journal, NETWORK_ACTION_ROUTE_ADD, 0));
    assert(network_journal_record(&journal, NETWORK_ACTION_ADAPTER_CREATE, 1));
    assert(network_journal_record(&journal, NETWORK_ACTION_DNS_CHANGE, 2));
    assert(network_journal_record(&journal, NETWORK_ACTION_ROUTE_ADD, 3));
    calls.fail_second = true;
    assert(network_journal_rollback(&journal, fake_undo, &calls) == 1);
    assert(calls.count == 3 && calls.seen[0] == 3
            && calls.seen[1] == 2 && calls.seen[2] == 1);
    assert(!network_journal_is_clean(&journal));
    calls.count = 0;
    calls.fail_second = false;
    assert(network_journal_rollback(&journal, fake_undo, &calls) == 0);
    assert(calls.count == 1 && calls.seen[0] == 2);
    assert(network_journal_is_clean(&journal));
    calls.count = 0;
    assert(network_journal_rollback(&journal, fake_undo, &calls) == 0);
    assert(calls.count == 0);
    assert(network_journal_rollback(NULL, fake_undo, &calls) == 1);
    puts("Network undo journal: reverse order, retry and idempotence passed");
    return 0;
}
