"""Exercise the production GUI publication code without starting a GUI or server."""
import importlib.util
from pathlib import Path
import re
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('core_hooks', root / 'tools/build-rule-core.py')
hooks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hooks)
source = (root / 'gui_win32.c').read_text(encoding='utf-8')
baseline = len(sys.argv) == 4 and sys.argv[2] == '--baseline'

def extract(marker):
    left, right = hooks.function_span(source, marker)
    return source[left:right]

poll = extract('static void *stats_poll_thread(')
assert 'if (tmp.valid) snapshot_read_page' not in poll, 'Log reads must not depend on stats JSON'
assert 'snapshot_read_page(&tmp, &request, revision);' in poll
result = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <time.h>
#include "query_log_navigation.h"
#include <windows.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while (0)
'''
for name in ('HIST_MAX', 'LISTENER_MAX_GUI', 'GUI_APP_MAX', 'GUI_QLOG_MAX', 'GUI_TOP_MAX'):
    result += re.search(r'^#define ' + name + r'\s+\d+', source, re.M).group(0) + '\n'
for name in ('listener_info', 'histogram', 'app_row', 'qlog_row', 'top_row', 'snapshot'):
    result += extract('struct ' + name + ' {') + ';\n'
result += extract('static void snapshot_copy_log(') + '\n'
if baseline:
    old = subprocess.check_output(['git', 'show', sys.argv[3] + ':gui_win32.c'], cwd=root).decode('utf-8')
    left = old.index('        if (!tmp.valid && g_snap_next.has_data) {')
    right = old.index('        /* Compare every rendered field', left)
    body = old[left:right].replace('g_snap_next', '(*published)').replace('g_log_nav.revision', 'current_revision')
    body = body.replace('revision', 'requested_revision').replace('current_requested_revision', 'current_revision')
    body = body.replace('&tmp', 'incoming').replace('tmp.', 'incoming->').replace('tmp =', '*incoming =')
    result += 'static bool snapshot_publish(struct snapshot *published, struct snapshot *incoming, uint64_t requested_revision, uint64_t current_revision) {\n'
    result += body + '\n*published = *incoming; return true;\n}\n'
else:
    result += extract('static bool snapshot_publish(') + '\n'
for marker in ('static long long json_num(', 'static const char *json_array_end(',
               'static void json_qlog_key(', 'static void json_qlog('):
    result += extract(marker) + '\n'
result += r'''
static struct snapshot previous, incoming;
static void initial(void) {
    memset(&previous,0,sizeof(previous)); memset(&incoming,0,sizeof(incoming));
    previous.valid=previous.has_data=previous.qlog_ready=1;
    previous.total_requests=101; previous.total_blocked=41; previous.hist[0].requests=21;
    previous.updated_at=60; previous.listener_count=1; previous.listeners[0].bound=1;
    previous.qlog_count=1; previous.qlog_revision=5; previous.qlog_page.total=1;
    wcscpy(previous.qlog[0].host,L"old.example");
}
static void fresh_log(void) {
    incoming.qlog_ready=1; incoming.qlog_count=1; incoming.qlog_revision=5;
    incoming.qlog_page.total=2; wcscpy(incoming.qlog[0].host,L"fresh.example");
}
int main(void) {
    initial(); fresh_log();
    CHECK(snapshot_publish(&previous,&incoming,5,5));
    CHECK(!previous.valid && previous.has_data && previous.total_requests==101 && previous.total_blocked==41);
    CHECK(previous.hist[0].requests==21 && previous.updated_at==60 && previous.listeners[0].bound);
    CHECK(previous.qlog_ready && !previous.qlog_error && !wcscmp(previous.qlog[0].host,L"fresh.example"));

    memset(&previous,0,sizeof(previous)); memset(&incoming,0,sizeof(incoming)); fresh_log();
    CHECK(snapshot_publish(&previous,&incoming,5,5));
    CHECK(!previous.has_data && previous.qlog_ready && !wcscmp(previous.qlog[0].host,L"fresh.example"));

    initial(); incoming.valid=incoming.has_data=1; incoming.total_requests=102; incoming.qlog_error=1;
    CHECK(snapshot_publish(&previous,&incoming,5,5));
    CHECK(previous.valid && previous.total_requests==102 && previous.qlog_error==1);
    CHECK(!wcscmp(previous.qlog[0].host,L"old.example"));

    initial(); incoming.qlog_error=1;
    CHECK(snapshot_publish(&previous,&incoming,5,5));
    CHECK(!previous.valid && previous.total_requests==101 && previous.qlog_error==1);
    CHECK(!wcscmp(previous.qlog[0].host,L"old.example"));
    memset(&incoming,0,sizeof(incoming)); incoming.qlog_error=1;
    CHECK(!snapshot_publish(&previous,&incoming,5,5));

    initial(); previous.qlog_ready=0; incoming.qlog_error=1;
    CHECK(snapshot_publish(&previous,&incoming,5,5));
    CHECK(previous.total_requests==101 && previous.qlog_count==1 && !previous.qlog_ready);
    CHECK(!wcscmp(previous.qlog[0].host,L"old.example"));

    initial(); fresh_log(); incoming.valid=incoming.has_data=1; incoming.total_requests=102;
    CHECK(snapshot_publish(&previous,&incoming,5,6));
    CHECK(previous.total_requests==102 && previous.qlog_error==3 && previous.qlog_revision==5);
    CHECK(!wcscmp(previous.qlog[0].host,L"old.example"));

    memset(&previous,0,sizeof(previous)); memset(&incoming,0,sizeof(incoming)); fresh_log();
    CHECK(snapshot_publish(&previous,&incoming,5,6));
    CHECK(!previous.qlog_ready && !previous.qlog_count && previous.qlog_error==3);

    initial(); fresh_log(); incoming.qlog_error=2;
    CHECK(snapshot_publish(&previous,&incoming,5,5));
    CHECK(previous.qlog_error==2 && previous.total_requests==101);

    json_qlog("{\"query_log\":[{\"host\":\"ipv6.example\",\"family\":6},{\"host\":\"::1\",\"family\":4},{\"host\":\"legacy.example\"},{\"host\":\"bad.example\",\"family\":5}]}",&incoming);
    CHECK(incoming.qlog_count==3 && incoming.qlog[0].family==6 && incoming.qlog[1].family==4 && incoming.qlog[2].family==0);
    puts("PASS: production publication keeps stats and logs independently, cold-start logs, failures, expiry and stale navigation");
    return 0;
}
'''
output = Path(sys.argv[1])
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(result, encoding='utf-8', newline='\n')
