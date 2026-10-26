"""Disposable Windows GUI acceptance: real production dashboard and Save dialog.
No global input injection: every HWND is checked against the child PID and owner.
No production hooks; HTTP pauses are implemented only in this local fixture.
"""
import argparse
import csv
import ctypes as c
from ctypes import wintypes as w
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

u = c.WinDLL('user32', use_last_error=True)
k = c.WinDLL('kernel32', use_last_error=True)
CALLBACK = c.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
for name, restype, args in [
    ('EnumWindows', w.BOOL, [CALLBACK, w.LPARAM]),
    ('EnumChildWindows', w.BOOL, [w.HWND, CALLBACK, w.LPARAM]),
    ('GetWindowThreadProcessId', w.DWORD, [w.HWND, c.POINTER(w.DWORD)]),
    ('GetClassNameW', c.c_int, [w.HWND, w.LPWSTR, c.c_int]),
    ('GetWindowTextW', c.c_int, [w.HWND, w.LPWSTR, c.c_int]),
    ('GetDlgItem', w.HWND, [w.HWND, c.c_int]),
    ('GetAncestor', w.HWND, [w.HWND, w.UINT]),
    ('GetWindow', w.HWND, [w.HWND, w.UINT]),
    ('SetForegroundWindow', w.BOOL, [w.HWND]),
    ('GetForegroundWindow', w.HWND, []),
    ('GetWindowRect', w.BOOL, [w.HWND,c.POINTER(w.RECT)]),
    ('IsWindow', w.BOOL, [w.HWND]),
    ('IsWindowEnabled', w.BOOL, [w.HWND]),
    ('IsWindowVisible', w.BOOL, [w.HWND]),
    ('GetDlgCtrlID', c.c_int, [w.HWND]),
    ('PostMessageW', w.BOOL, [w.HWND, w.UINT, w.WPARAM, w.LPARAM]),
    ('SendMessageTimeoutW', w.LPARAM, [w.HWND, w.UINT, w.WPARAM, w.LPARAM, w.UINT, w.UINT, c.POINTER(c.c_size_t)]),
]:
    fn = getattr(u, name); fn.restype = restype; fn.argtypes = args
k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
k.CreateFileW.restype = w.HANDLE
k.CloseHandle.argtypes = [w.HANDLE]; k.CloseHandle.restype = w.BOOL


def wait(test, message, seconds=15):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        result = test()
        if result:
            return result
        time.sleep(.025)
    raise AssertionError(message)


class Gui:
    def __init__(self, driver, root, resources, ports):
        self.root = root; self.root.mkdir()
        self.exe = root / driver.name
        shutil.copy2(driver, self.exe)
        for dll in driver.parent.glob('*.dll'):
            shutil.copy2(dll, root / dll.name)
        (root / 'webserver.ini').write_text('[settings]\nautomatic_update=0\n', encoding='utf8')
        self.output = (root / 'gui-output.log').open('wb')
        self.process = subprocess.Popen([str(self.exe), str(resources), *map(str, ports)], cwd=root,
                                        stdout=self.output, stderr=self.output,
                                        creationflags=subprocess.CREATE_NO_WINDOW)
        self.main = wait(lambda: self.find('ADBlockDashWin11'), 'owned dashboard not found')
        self.send(self.main, 0x111, 47001)  # Existing production navigation command.
        self.button = self.child(self.main, 1219)
        wait(lambda: u.IsWindowEnabled(self.button), 'server page did not enable export')

    def owned(self, hwnd):
        pid = w.DWORD()
        assert hwnd and u.IsWindow(hwnd) and u.GetWindowThreadProcessId(hwnd, c.byref(pid))
        assert pid.value == self.process.pid, 'refusing to operate another process window'
        return hwnd

    def text(self, hwnd):
        self.owned(hwnd)
        buf = c.create_unicode_buffer(4096)
        # WM_GETTEXT supports child controls in another process without injecting input.
        self.send(hwnd, 0xD, len(buf), c.addressof(buf))
        return buf.value

    def find(self, class_name, owner=None):
        matches = []
        @CALLBACK
        def visit(hwnd, _):
            pid = w.DWORD(); u.GetWindowThreadProcessId(hwnd, c.byref(pid))
            cls = c.create_unicode_buffer(256); u.GetClassNameW(hwnd, cls, 256)
            if pid.value == self.process.pid and cls.value == class_name and u.IsWindowVisible(hwnd):
                if owner is None or u.GetAncestor(hwnd, 3) == owner:
                    matches.append(hwnd)
            return True
        u.EnumWindows(visit, 0)
        return matches[0] if matches else None

    def child(self, parent, control):
        self.owned(parent)
        found=u.GetDlgItem(parent, control)
        if not found:
            matches=[]
            @CALLBACK
            def visit(hwnd,_):
                pid=w.DWORD();u.GetWindowThreadProcessId(hwnd,c.byref(pid))
                if pid.value==self.process.pid and u.GetDlgCtrlID(hwnd)==control and u.IsWindowVisible(hwnd):
                    matches.append(hwnd)
                return True
            u.EnumChildWindows(parent,visit,0)
            assert len(matches)==1, f'owned control {control} missing or ambiguous'
            found=matches[0]
        return self.owned(found)

    def activate(self, window):
        self.owned(window)
        u.SetForegroundWindow(window)
        wait(lambda:u.GetForegroundWindow()==window,'owned dialog could not be activated',3)

    def capture(self, name, window=None):
        window=self.owned(window or self.main)
        rect=w.RECT(); assert u.GetWindowRect(window,c.byref(rect))
        assert 0 < rect.right-rect.left <= 4096 and 0 < rect.bottom-rect.top <= 4096
        from PIL import ImageGrab
        ImageGrab.grab(bbox=(rect.left,rect.top,rect.right,rect.bottom),all_screens=True).save(self.root/f'{name}.png')

    def click(self, parent, control):
        # BM_CLICK on an inactive native dialog is not a reliable user action.
        # Activate only this owned window and verify activation, no global keys.
        self.activate(parent)
        button=self.child(parent,control)
        assert u.IsWindowEnabled(button), f'owned control {control} is disabled'
        self.post(button,0xF5)  # BM_CLICK includes the native button HWND notification.

    def send(self, hwnd, message, wp=0, lp=0):
        self.owned(hwnd); result = c.c_size_t()
        assert u.SendMessageTimeoutW(hwnd, message, wp, lp, 2, 3000, c.byref(result)), 'owned window stopped responding'
        return result.value

    def post(self, hwnd, message, wp=0):
        self.owned(hwnd); assert u.PostMessageW(hwnd, message, wp, 0)

    def dialog(self):
        self.post(self.button,0xF5)
        dialog = wait(lambda: self.find('#32770', self.main), 'owned Save dialog not shown')
        assert u.GetAncestor(dialog, 3) == self.main
        self.activate(dialog)
        return dialog

    def choose(self, dialog, path):
        self.owned(dialog)
        assert u.GetAncestor(dialog, 3) == self.main
        controls = []
        @CALLBACK
        def visit(hwnd, _):
            pid = w.DWORD(); u.GetWindowThreadProcessId(hwnd, c.byref(pid))
            if pid.value == self.process.pid:
                cls = c.create_unicode_buffer(256); u.GetClassNameW(hwnd, cls, 256)
                controls.append(dict(hwnd=int(hwnd), id=u.GetDlgCtrlID(hwnd), cls=cls.value))
            return True
        u.EnumChildWindows(dialog, visit, 0)
        (self.root/'save-controls.json').write_text(json.dumps(controls,indent=2),encoding='utf8')
        # Explorer hosts the compatibility controls in a child dialog on some
        # Windows builds. Never assume GetDlgItem(top-level) is sufficient.
        # Captured CI hierarchy: the DirectUI file name is native Edit 1001
        # inside its combo, while the address bar's 1001 is ToolbarWindow32.
        edits = [x for x in controls if x['id'] in (0x480,1001) and x['cls']=='Edit']
        combos = [x for x in controls if x['id']==0x47C and x['cls'] in ('ComboBox','ComboBoxEx32')]
        candidates = edits or combos
        assert len(candidates)<=1, 'ambiguous native file name controls'
        if candidates:
            edit = self.owned(candidates[0]['hwnd'])
            value = c.create_unicode_buffer(str(path))
            self.send(edit, 0xC, 0, c.addressof(value))
            assert self.text(edit)==str(path), 'file name text was not applied'
        else:
            # Modern Common Item Dialog uses DirectUI; use its documented UIA
            # value pattern, bounded to this exact same-PID dialog, no SendKeys.
            script=Path(__file__).with_name('set-export-dialog-path.ps1')
            result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-WindowStyle','Hidden',
                '-ExecutionPolicy','Bypass',
                '-File',str(script),'-ProcessId',str(self.process.pid),'-Dialog',str(int(dialog)),
                '-MainWindow',str(int(self.main)),'-Path',str(path),
                '-EvidencePath',str(self.root/'save-uia.json')],capture_output=True,text=True,
                encoding='utf-8',errors='replace',timeout=12,creationflags=subprocess.CREATE_NO_WINDOW)
            (self.root/'save-uia-output.json').write_text(json.dumps(dict(code=result.returncode,
                stdout=result.stdout,stderr=result.stderr),indent=2),encoding='utf8')
            assert result.returncode==0, result.stderr or result.stdout or 'UIA path setter failed; see owned fixture evidence'
        self.capture('save-before-click',dialog)
        self.click(dialog,1)

    def confirmation(self, chooser):
        matches = []
        @CALLBACK
        def visit(hwnd, _):
            pid = w.DWORD(); u.GetWindowThreadProcessId(hwnd, c.byref(pid))
            cls = c.create_unicode_buffer(256); u.GetClassNameW(hwnd, cls, 256)
            if (pid.value == self.process.pid and hwnd != chooser and
                cls.value == '#32770' and u.GetAncestor(hwnd, 3) == self.main and
                u.IsWindowVisible(hwnd) and u.GetDlgItem(hwnd, 6) and u.GetDlgItem(hwnd, 7)):
                matches.append(hwnd)
            return True
        u.EnumWindows(visit, 0)
        assert len(matches) <= 1, 'ambiguous owned overwrite confirmation'
        return matches[0] if matches else None

    def ready(self):
        wait(lambda: not self.find('#32770', self.main) and self.text(self.button) in ('导出全部匹配', '检查暂存清理') and u.IsWindowEnabled(self.button),
             'export did not finish cleanup', 20)

    def stages(self):
        return list(self.root.glob('qle*.tmp'))

    def close(self):
        if self.process.poll() is None:
            # Preserve the last actual dialog/page, including a timeout failure.
            self.capture('last-owned-window',self.find('#32770',self.main) or self.main)
            self.post(self.main, 0x402)  # Existing production WM_APP_EXIT, not WM_CLOSE-to-tray.
            self.process.wait(timeout=12)
        assert self.process.returncode == 0, self.process.returncode
        self.output.close()


class Controlled:
    def __init__(self):
        self.count = 601; self.expired = False; self.hold = False
        self.entered = threading.Event(); self.release = threading.Event(); self.requests = []
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                parsed = urlsplit(self.path); q = parse_qs(parsed.query, keep_blank_values=True)
                code = 200
                if parsed.path == '/internal-stats':
                    body = dict(uptime_seconds=10, total_requests=owner.count, total_connections=owner.count,
                                blocked_images=owner.count, top_blocked=[], apps=[], query_log=[])
                elif parsed.path == '/internal-qlog':
                    offset = int(q.get('offset', ['0'])[0]); frozen = 'generation' in q
                    owner.requests.append(dict(offset=offset, frozen=frozen, query=q))
                    if frozen and owner.expired:
                        code, body = 409, {}
                    else:
                        if frozen and offset and owner.hold:
                            owner.entered.set()
                            assert owner.release.wait(10), 'controller did not release held export'
                        canonical = 'qlog-filter-v1\n' + '\n'.join(f'{key}={q.get(key,["*"])[0]}' for key in ('action','family','type','uid'))
                        canonical += '\nq=' + q.get('q', [''])[0].translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'))
                        key = hashlib.sha256(canonical.encode()).hexdigest()
                        rows = [dict(ts=1000, uid=-1, action=1, type=0, mode=0, family=6,
                                     host='same.example', path=f'/image-{i}.png', status=200,
                                     pathTruncated=False, sequence=str(owner.count-i))
                                for i in range(offset, min(offset+150, owner.count))]
                        body = dict(offset=offset,limit=300,total=owner.count,retainedTotal=owner.count,
                                    returned=len(rows),nextOffset=offset+len(rows),hasMore=offset+len(rows)<owner.count,
                                    generation='0123456789abcdef0123456789abcdef',anchor=str(owner.count),
                                    filterVersion=1,queryKey=key,entries=rows)
                else:
                    code, body = 404, {}
                payload = json.dumps(body,separators=(',',':')).encode()
                self.send_response(code); self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(payload))); self.send_header('Connection','close'); self.end_headers()
                try:
                    self.wfile.write(payload)
                except (ConnectionError, OSError):
                    pass  # A cancelled owned client may close its socket.
        self.server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True); self.thread.start()
        self.port = self.server.server_address[1]
    def close(self):
        self.release.set(); self.server.shutdown(); self.server.server_close(); self.thread.join(3)


def exported(path, expected):
    raw = path.read_bytes()
    rows = list(csv.DictReader(io.StringIO(raw.decode('utf8'))))
    assert len(rows)==expected, (len(rows),expected)
    assert len({(r['generation'],r['sequence']) for r in rows})==expected
    return raw


def run(driver, exe, probe, evidence):
    if os.environ.get('GITHUB_ACTIONS')!='true':
        raise RuntimeError('GUI activation is restricted to a disposable GitHub runner, never the daily host')
    spec = importlib.util.spec_from_file_location('real_server', Path(__file__).with_name('test-query-log-server.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    evidence.mkdir(parents=True,exist_ok=True)
    results=[]
    def record(value):
        results.append(value)
        (evidence/'completed-cases.json').write_text(json.dumps(results,indent=2),encoding='utf8')
    # Retained under the CI temp directory for failure logs; never a user's profile.
    root=Path(tempfile.mkdtemp(prefix='AdAwayExportGui-',dir=os.environ.get('RUNNER_TEMP')))
    (evidence/'fixture-path.txt').write_text(str(root),encoding='utf8')
    fixture=module.Fixture(exe,probe,root)
    fixture.start()
    try:
        fixture.batch(1,601)
        gui=Gui(driver,root/'production-gui',fixture.resources,(fixture.http,fixture.https,fixture.stats))
        try:
            before=fixture.exchange(fixture.stats,'/internal-qlog?filterVersion=1&offset=0&limit=300&q=')[1]
            total=json.loads(before)['total']; assert total==601
            # Cancel native chooser: no export request or staging file.
            dialog=gui.dialog(); gui.click(dialog,2); gui.ready(); assert not gui.stages()
            record('native-dialog-cancel')
            target=gui.root/'完整 导出-IPv6.csv'
            dialog=gui.dialog(); gui.choose(dialog,target)
            wait(target.exists,'production export did not publish'); gui.ready()
            initial=exported(target,total); assert not gui.stages()
            record('real-production-multipage-unicode-save')
            # Native overwrite rejection must retain the original bytes.
            dialog=gui.dialog(); gui.choose(dialog,target)
            confirm=wait(lambda:gui.confirmation(dialog),'owned overwrite prompt missing')
            gui.click(confirm,7)
            wait(lambda:u.IsWindow(dialog),'save dialog vanished after refusing overwrite')
            gui.click(dialog,2); gui.ready(); assert target.read_bytes()==initial
            record('native-overwrite-rejected')
            dialog=gui.dialog(); gui.choose(dialog,target)
            confirm=wait(lambda:gui.confirmation(dialog),'overwrite confirmation missing'); gui.click(confirm,6)
            wait(lambda:not u.IsWindow(dialog),'chooser did not finish'); gui.ready()
            assert exported(target,total)==initial
            record('native-overwrite-confirmed')
            handle=k.CreateFileW(str(target),0x80000000,1,None,3,0,None)
            assert handle != c.c_void_p(-1).value
            try:
                dialog=gui.dialog(); gui.choose(dialog,target)
                confirm=wait(lambda:gui.confirmation(dialog),'locked-target overwrite prompt missing')
                gui.click(confirm,6)
                wait(lambda:not u.IsWindow(dialog),'locked-target chooser still open'); gui.ready()
                assert target.read_bytes()==initial and not gui.stages()
                log=gui.root/'webserver.log'
                assert '[export] failed before publication' in log.read_text(encoding='utf8')
                record('locked-destination-preserves-original-and-cleans-stage')
            finally:
                assert k.CloseHandle(handle)

        finally:
            gui.close()
    finally:
        fixture.stop()
    controlled=Controlled()
    try:
        gui=Gui(driver,root/'controlled-gui',fixture.resources,(controlled.port,controlled.port,controlled.port))
        try:
            target=gui.root/'cancelled.csv'; target.write_bytes(b'old bytes')
            controlled.hold=True
            dialog=gui.dialog(); gui.choose(dialog,target)
            confirm=wait(lambda:gui.confirmation(dialog),'overwrite confirmation missing'); gui.click(confirm,6)
            assert controlled.entered.wait(8),'export never reached a held later page'
            gui.post(gui.button,0xF5)
            wait(lambda:gui.text(gui.button)=='正在取消并清理','cancel request not acknowledged')
            assert not u.IsWindowEnabled(gui.button), 'second export enabled before cleanup'
            controlled.release.set(); gui.ready()
            assert target.read_bytes()==b'old bytes' and not gui.stages()
            record('held-later-page-cancel-preserves-target')
            # Prevent deletion of this task's own staging file while a later
            # HTTP page is held. This is a real sharing violation, not a hook.
            controlled.entered.clear(); controlled.release.clear()
            dialog=gui.dialog(); gui.choose(dialog,target)
            confirm=wait(lambda:gui.confirmation(dialog),'overwrite confirmation missing'); gui.click(confirm,6)
            assert controlled.entered.wait(8)
            stages=gui.stages(); assert len(stages)==1
            stage=stages[0]; assert stage.resolve().parent==gui.root.resolve()
            handle=k.CreateFileW(str(stage),0x80000000,3,None,3,0,None)
            assert handle != c.c_void_p(-1).value
            try:
                gui.post(gui.button,0xF5)
                wait(lambda:gui.text(gui.button)=='正在取消并清理','cancel not acknowledged')
                controlled.release.set(); gui.ready()
                assert gui.text(gui.button)=='检查暂存清理'
                assert target.read_bytes()==b'old bytes' and stage.exists()
                gui.post(gui.button,0xF5)
                warning=wait(lambda:gui.find('#32770',gui.main),'cleanup failure warning missing')
                assert not u.GetDlgItem(warning,0x480) and not u.GetDlgItem(warning,0x47C)
                gui.click(warning,1); gui.ready()
                assert stage.exists() and gui.text(gui.button)=='检查暂存清理'
            finally:
                assert k.CloseHandle(handle)
            stage.unlink()  # Only this job's known path inside its unique temp directory.
            controlled.hold=False
            dialog=gui.dialog(); gui.click(dialog,2); gui.ready()
            assert gui.text(gui.button)=='导出全部匹配' and not gui.stages()
            record('cleanup-failure-blocks-second-export-until-owned-stage-is-gone')
            # Pin history BEFORE opening the actual file chooser, then expire it.
            target=gui.root/'expired.csv'; dialog=gui.dialog(); controlled.expired=True
            gui.choose(dialog,target); wait(lambda:not u.IsWindow(dialog),'chooser still open'); gui.ready()
            assert not target.exists() and not gui.stages()
            assert any(x['frozen'] for x in controlled.requests)
            record('history-expires-during-file-selection')
        finally:
            gui.close()
        # Reopen actual dashboard: no stale busy state is inherited.
        controlled.expired=False; controlled.count=0
        gui=Gui(driver,root/'reopened-gui',fixture.resources,(controlled.port,controlled.port,controlled.port))
        try:
            target=gui.root/'empty.csv'; dialog=gui.dialog(); gui.choose(dialog,target)
            wait(target.exists,'zero-match export did not publish'); gui.ready()
            exported(target,0); assert not gui.stages()
            record('reopen-and-zero-match-header-only')
        finally:
            gui.close()
    finally:
        controlled.close()
    (evidence/'results.json').write_text(json.dumps(dict(cases=results,ownerPidChecked=True,
        nativeSaveDialog=True,productionGui=True,hostNetworkChanges=False,fixtureRoot=str(root)),indent=2),encoding='utf8')
    print(json.dumps(results))


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('driver',type=Path);parser.add_argument('server',type=Path)
    parser.add_argument('probe',type=Path);parser.add_argument('evidence',type=Path)
    args=parser.parse_args()
    run(args.driver.resolve(),args.server.resolve(),args.probe.resolve(),args.evidence.resolve())
