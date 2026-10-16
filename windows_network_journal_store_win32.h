#ifndef ADBLOCK_WINDOWS_NETWORK_JOURNAL_STORE_WIN32_H
#define ADBLOCK_WINDOWS_NETWORK_JOURNAL_STORE_WIN32_H

#include <stdbool.h>
#include <wchar.h>
#include "windows_network_journal.h"

/*
 * Disk persistence for the MODEL of future compensating actions.
 *
 * WARNING: no system networking APIs are called. This is NOT yet a safe
 * persistent recovery engine: it lacks an exclusive interprocess owner,
 * real rollback commands, startup replay and OS-state conflict checking.
 *
 * Format is fixed-width LE with version, FNV-1a corruption detection,
 * validated kinds/tokens, and atomic replace after FlushFileBuffers.
 * FNV is NOT cryptographic integrity/authentication.
 */
bool network_journal_save_file(const wchar_t *path,
                               const struct network_journal *journal);
bool network_journal_load_file(const wchar_t *path,
                               struct network_journal *journal);

#endif
