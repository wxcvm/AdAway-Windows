#ifndef ADBLOCK_WINDOWS_NETWORK_JOURNAL_STORE_WIN32_H
#define ADBLOCK_WINDOWS_NETWORK_JOURNAL_STORE_WIN32_H

#include <stdbool.h>
#include <wchar.h>
#include "windows_network_journal.h"

/*
 * Disk persistence for the MODEL of future compensating actions.
 *
 * WARNING: no system networking APIs are called. This is NOT yet a safe
 * persistent recovery engine: it lacks original/new OS values, real rollback
 * commands, durable transaction ownership, startup replay and conflict checking.
 *
 * Format v2 wraps model data and a random HMAC key with current-user DPAPI;
 * HMAC-SHA256 covers the complete DPAPI blob including provider metadata,
 * a protected user/SYSTEM file DACL, exclusive per-operation file lock, and
 * atomic replace after FlushFileBuffers. Legacy plaintext v1 is rejected.
 * This protects model storage; it cannot make a model an OS recovery snapshot.
 */
bool network_journal_save_file(const wchar_t *path,
                               const struct network_journal *journal);
bool network_journal_load_file(const wchar_t *path,
                               struct network_journal *journal);

#endif
