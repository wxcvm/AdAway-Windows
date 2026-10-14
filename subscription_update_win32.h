#ifndef ADAWAY_SUBSCRIPTION_UPDATE_WIN32_H
#define ADAWAY_SUBSCRIPTION_UPDATE_WIN32_H
#include <windows.h>
#include <stddef.h>
#define SUBSCRIPTION_MAX_SOURCES 32
#define SUBSCRIPTION_URL_CAPACITY 1024
enum subscription_update_status { SUB_UPDATE_OK, SUB_UPDATE_LOCKED, SUB_UPDATE_DOWNLOAD_FAILED,
    SUB_UPDATE_PARSE_FAILED, SUB_UPDATE_PUBLISH_FAILED, SUB_UPDATE_IO_FAILED };
struct subscription_update_result {
    enum subscription_update_status status;
    size_t entries, unsupported, source_entries[SUBSCRIPTION_MAX_SOURCES];
    unsigned failed_source;
};
typedef int (*subscription_download)(const wchar_t *url, const wchar_t *file,
                                     unsigned long long max_bytes, unsigned budget_ms, void *context);
struct subscription_update_result subscription_update(const wchar_t *directory,
        const wchar_t urls[][SUBSCRIPTION_URL_CAPACITY], unsigned count,
        subscription_download download, void *context);
#endif
