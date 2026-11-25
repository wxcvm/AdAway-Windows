"""Exercise the actual generated cooldown helpers, not a second implementation."""
import importlib.util
import pathlib
import sys

spec = importlib.util.spec_from_file_location("core", pathlib.Path(__file__).with_name("build-rule-core.py"))
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)
source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
functions = []
for signature in ("static void pin_policy_reload(", "static bool pin_mode_deny(",
                  "static bool pin_uid_bypassed(", "static bool pin_record_cooldown("):
    start, end = core.function_span(source, signature)
    functions.append(source[start:end])
out = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); exit(1); } } while(0)
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#define APP_STATS_MAX 2
#define PIN_POLICY_FILE "pin_policy.txt"
#define PIN_BYPASS_MS 600000u
typedef unsigned int uid_t;
static char s_pin_mode[8] = "off";
static uint64_t s_pin_mode_loaded_ms, clock_ms;
static struct { uid_t uid; uint64_t until_ms; } s_pin_bypass[APP_STATS_MAX];
static int s_pin_bypass_count;
static uint64_t mg_millis(void) { return clock_ms; }
''' + "\n".join(functions) + r'''
int main(int argc, char **argv) {
    CHECK(argc == 2);
    char path[PATH_MAX];
    CHECK(snprintf(path,sizeof(path),"%s/%s",argv[1],PIN_POLICY_FILE) > 0);
    FILE *fp = fopen(path,"w"); CHECK(fp != NULL);
    CHECK(fputs("mode=deny\n",fp) >= 0); CHECK(fclose(fp) == 0);
    clock_ms = 1000;
    pin_policy_reload(argv[1]);
    CHECK(pin_mode_deny());
    CHECK(pin_record_cooldown(1, clock_ms));
    CHECK(pin_record_cooldown(2, clock_ms+1));
    CHECK(!pin_record_cooldown(3,clock_ms+2));
    CHECK(pin_uid_bypassed(1));
    clock_ms += PIN_BYPASS_MS;
    CHECK(pin_record_cooldown(3,clock_ms));
    CHECK(!pin_uid_bypassed(1) && pin_uid_bypassed(3));
    CHECK(s_pin_bypass_count==2);
    fp=fopen(path,"w"); CHECK(fp != NULL);
    CHECK(fputs("mode=off\n",fp) >= 0); CHECK(fclose(fp)==0);
    pin_policy_reload(argv[1]);
    CHECK(!pin_mode_deny() && s_pin_bypass_count==0 && !pin_uid_bypassed(3));
    fp=fopen(path,"w"); CHECK(fp != NULL);
    CHECK(fputs("mode=deny\n",fp) >= 0); CHECK(fclose(fp)==0);
    clock_ms+=1000; pin_policy_reload(argv[1]);
    CHECK(pin_mode_deny() && pin_record_cooldown(4,clock_ms));
    CHECK(remove(path)==0);
    clock_ms+=1000; pin_policy_reload(argv[1]);
    CHECK(!pin_mode_deny() && s_pin_bypass_count==0);
    puts("PASS: production CONNECT cooldown reuse and disable lifecycle");
    return 0;
}
'''
pathlib.Path(sys.argv[2]).write_text(out, encoding="utf-8")
