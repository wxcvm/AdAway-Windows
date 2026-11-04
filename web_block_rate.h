#ifndef ADBLOCK_WEB_BLOCK_RATE_H
#define ADBLOCK_WEB_BLOCK_RATE_H
#include <stdbool.h>
#include <stdint.h>

/* This is the share of counted local Web requests that the response server
 * classified as blocked, NOT the fraction of whole-PC traffic protected.
 * Return unavailable for no traffic and inconsistent persisted counters.
 * Use one decimal place without ever rounding 99.95% up to 100.0%. */
struct wbr_result {
    bool valid;
    unsigned tenths_percent;   /* 0..1000, where 1000 == exactly 100.0% */
    uint64_t not_blocked;     /* counted requests not classified as blocked */
};
static inline struct wbr_result wbr_compute(int64_t requests, int64_t blocked) {
    struct wbr_result result = {0};
    if (requests <= 0 || blocked < 0 || blocked > requests) return result;
    result.valid = true;
    result.not_blocked = (uint64_t)(requests - blocked);
    if (requests == blocked) {
        result.tenths_percent = 1000;
    } else {
        double percentage_tenths = ((double)blocked / (double)requests) * 1000.0;
        unsigned tenths = (unsigned)percentage_tenths;
        result.tenths_percent = tenths < 1000 ? tenths : 999;
    }
    return result;
}
#endif
