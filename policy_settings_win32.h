#ifndef ADBLOCK_POLICY_SETTINGS_WIN32_H
#define ADBLOCK_POLICY_SETTINGS_WIN32_H
#include <stddef.h>
#include <wchar.h>

#define POLICY_SETTINGS_COUNT 10
struct policy_setting {
    const char *reply_key;
    const char *mode_key;
    int mode;
};

/* Same ten keys and mode values as the existing UI. Publish one complete UTF-8
 * file under an exclusive writer lock. Failure preserves the previous file. */
int policy_settings_save(const wchar_t *directory,
                         const struct policy_setting *settings, size_t count);
#endif
