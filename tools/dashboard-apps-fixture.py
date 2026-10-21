"""Compile and exercise the actual GUI app-row decoder without a GUI process."""
import importlib.util
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("core_hooks", root/"tools/build-rule-core.py")
hooks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hooks)
source = (root/"gui_win32.c").read_text(encoding="utf-8")
def extract(marker):
    left, right = hooks.function_span(source, marker)
    return source[left:right]

result = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <limits.h>
#ifdef _MSC_VER
#include <malloc.h>
#undef alloca
#endif
#include "mongoose/mongoose.h"
#define GUI_APP_MAX 12
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
'''
result += extract("struct app_row {")+";\n"
result += "struct snapshot { int app_count; struct app_row apps[GUI_APP_MAX]; };\n"
result += extract("static long long json_num(")+"\n"
result += extract("static void json_apps(")+"\n"
result += r'''
int main(void) {
    struct snapshot snapshot;
    mg_log_set(MG_LL_NONE);
    json_apps("{\"apps\":[{\"uid\":17,\"name\":\"first.exe\",\"requests\":650,\"connections\":12,\"blocked\":649,\"hosts\":[{\"h\":\"a.example\",\"n\":1},{\"h\":\"b.example\",\"n\":2},{\"h\":\"c.example\",\"n\":3}],\"pin_refused\":true},{\"uid\":18,\"name\":\"second.exe\",\"requests\":900,\"hosts\":[],\"pin_refused\":false}],\"recent_tls\":[{\"uid\":0}]}",&snapshot);
    CHECK(snapshot.app_count==2);
    CHECK(snapshot.apps[0].requests==900 && wcscmp(snapshot.apps[0].name,L"second.exe")==0);
    CHECK(snapshot.apps[1].requests==650 && snapshot.apps[1].connections==12 && snapshot.apps[1].blocked==649);
    CHECK(snapshot.apps[1].pin_refused==1 && wcscmp(snapshot.apps[1].name,L"first.exe")==0);
    json_apps("{\"apps\":[],\"recent_tls\":[{\"uid\":0}]}",&snapshot);
    CHECK(snapshot.app_count==0);
    json_apps("{\"other\":[{\"uid\":0}]}",&snapshot);
    CHECK(snapshot.app_count==0);
    json_apps("{\"apps\":[{\"uid\":17,\"requests\":9223372036854775807}]}",&snapshot);
    CHECK(snapshot.app_count==1 && snapshot.apps[0].requests==LLONG_MAX && wcscmp(snapshot.apps[0].name,L"id 17")==0);
    puts("PASS: actual GUI app decoder preserves full rows, nested hosts, counters, flags, order and array boundaries");
    return 0;
}
'''
output = Path(sys.argv[1])
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(result, encoding="utf-8", newline="\n")
