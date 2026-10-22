#ifndef ADAWAY_SUBSCRIPTION_DISPLAY_WIN32_H
#define ADAWAY_SUBSCRIPTION_DISPLAY_WIN32_H
#include <stddef.h>
#include <wchar.h>
/* Presentation only: no network, IDN normalization or subscription mutation.
 * Invalid inputs use constant fallbacks, never the private address. */
int subscription_display_url(const wchar_t *url, wchar_t *out, size_t capacity);
int subscription_display_name(const wchar_t *url, const wchar_t *custom,
                              wchar_t *out, size_t capacity);
#endif
