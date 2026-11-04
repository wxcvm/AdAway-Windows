#include "web_block_rate.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)

int main(void) {
    struct wbr_result r = wbr_compute(10, 7);
    CHECK(r.valid && r.tenths_percent == 700 && r.not_blocked == 3);
    r = wbr_compute(100, 100);
    CHECK(r.valid && r.tenths_percent == 1000 && r.not_blocked == 0);
    r = wbr_compute(100000, 99999);
    CHECK(r.valid && r.tenths_percent == 999 && r.not_blocked == 1);
    r = wbr_compute(2, 0);
    CHECK(r.valid && r.tenths_percent == 0 && r.not_blocked == 2);
    r = wbr_compute(0, 0);
    CHECK(!r.valid);
    r = wbr_compute(20, 21);
    CHECK(!r.valid);
    r = wbr_compute(-5, 0);
    CHECK(!r.valid);
    r = wbr_compute(8, -1);
    CHECK(!r.valid);
    r = wbr_compute(INT64_MAX, INT64_MAX - 1);
    CHECK(r.valid && r.tenths_percent == 999 && r.not_blocked == 1);
    puts("PASS: local Web-block share, unknown denominator, and truthful near-100% display");
    return 0;
}
