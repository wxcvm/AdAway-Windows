"""Extract production counter derivation and verify raw count preservation."""
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
start = source.index("    uint64_t req = s_stats.total_requests;")
end = source.index("    uint64_t daily_peak = 0;", start)
body = source[start:end]
assert source.count("    uint64_t req = s_stats.total_requests;") == 1
out = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL: %s\n",#x); exit(1); } } while(0)
static struct { uint64_t total_requests, tls_handshakes, sni_cache_hits; } s_stats;
static uint64_t blocked;
static uint64_t stats_total_blocked(void) { return blocked; }
static void check(uint64_t requests, uint64_t raw, double expected) {
    s_stats.total_requests = requests;
    blocked = raw;
''' + body + r'''
    CHECK(blk == raw);
    CHECK(block_rate == expected);
    (void)hit_rate;
}
int main(void) {
    check(10, 7, 70.0);
    check(10, 10, 100.0);
    check(10, 11, 0.0);
    check(0, 0, 0.0);
    check(0, 1, 0.0);
    puts("PASS: production counter derivation preserves raw values");
    return 0;
}
'''
pathlib.Path(sys.argv[2]).write_text(out, encoding="utf-8")
