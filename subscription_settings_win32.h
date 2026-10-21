#ifndef ADAWAY_SUBSCRIPTION_SETTINGS_WIN32_H
#define ADAWAY_SUBSCRIPTION_SETTINGS_WIN32_H
#include "subscription_update_win32.h"
#define SUBSCRIPTION_STATUS_CAPACITY 160
#define SUBSCRIPTION_NAME_CAPACITY 96

/* UTF-8 legacy line format; a failed write leaves the previous file intact. */
int subscription_settings_save_urls(const wchar_t *directory,
        const wchar_t urls[][SUBSCRIPTION_URL_CAPACITY], unsigned count);
int subscription_settings_save_status(const wchar_t *directory,
        const wchar_t urls[][SUBSCRIPTION_URL_CAPACITY],
        const wchar_t status[][SUBSCRIPTION_STATUS_CAPACITY], unsigned count);
/* Names are legacy-compatible # name: comments immediately before their URL.
 * One atomic file publishes both; status and imported rules stay independent.
 * Load stages the complete bounded file; failure leaves all outputs untouched. */
int subscription_settings_save_sources(const wchar_t *directory,
        const wchar_t urls[][SUBSCRIPTION_URL_CAPACITY],
        const wchar_t names[][SUBSCRIPTION_NAME_CAPACITY], unsigned count);
int subscription_settings_load_sources(const wchar_t *directory,
        wchar_t urls[][SUBSCRIPTION_URL_CAPACITY],
        wchar_t names[][SUBSCRIPTION_NAME_CAPACITY], unsigned *count);
int subscription_settings_name_valid(const wchar_t *name);
#endif
