"""Real exe, HTTP, desktop parser and restart. Disposable CI runner only.
All listeners are loopback; files and the spawned process belong to this test.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import argparse
import json
import shutil
import socket
import subprocess
import tempfile
import time


def host(number):
    return f"q-{number:05d}." + "a" * 50 + "." + "b" * 50 + "." + "c" * 40 + ".example.test"


class Fixture:
    def __init__(self, exe, probe, root):
        self.exe, self.probe, self.root = exe, probe, root
        self.resources = root / "resources"
        shutil.copytree(exe.parent / "resources", self.resources)
        sockets = [socket.socket() for _ in range(3)]
        try:
            for item in sockets:
                item.bind(("127.0.0.1", 0))
            self.http, self.https, self.stats = [item.getsockname()[1] for item in sockets]
        finally:
            for item in sockets:
                item.close()
        self.process, self.log = None, None

    def start(self):
        self.log = (self.root / "server-output.log").open("ab")
        self.process = subprocess.Popen([
            str(self.exe), "--resources", str(self.resources), "--no-gui",
            "--http-port", str(self.http), "--https-port", str(self.https),
            "--stats-port", str(self.stats), "--listen-ipv4", "127.0.0.1", "--listen-ipv6", "-"],
            cwd=self.exe.parent, stdout=self.log, stderr=self.log,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("Server exited during fixture startup")
            try:
                if self.exchange(self.stats, "/internal-stats")[0] == 200:
                    return
            except (OSError, AssertionError):
                pass
            time.sleep(0.05)
        raise RuntimeError("Loopback fixture did not become ready")

    def stop(self):
        if self.process is not None:
            if self.process.poll() is None:
                try:
                    self.control("shutdown")
                    self.process.wait(timeout=8)
                except (OSError, AssertionError, subprocess.TimeoutExpired):
                    self.process.terminate()
                    self.process.wait(timeout=5)
            self.process = None
        if self.log is not None:
            self.log.close()
            self.log = None

    def exchange(self, port, path, hostname="127.0.0.1", body=None, token=None):
        method = "POST" if body is not None else "GET"
        headers = f"{method} {path} HTTP/1.0\r\nHost: {hostname}\r\nConnection: close\r\n"
        if token is not None:
            headers += f"X-ADBlock-Token: {token}\r\n"
        if body is not None:
            headers += f"Content-Length: {len(body)}\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
            connection.sendall(headers.encode("ascii") + b"\r\n" + (body or b""))
            chunks, length = [], 0
            while True:
                chunk = connection.recv(16384)
                if not chunk:
                    break
                length += len(chunk)
                assert length < 192 * 1024, "Response exceeds actual desktop buffer"
                chunks.append(chunk)
                received = b"".join(chunks)
                if b"\r\n\r\n" in received:
                    head, payload = received.split(b"\r\n\r\n", 1)
                    lengths = [int(line.split(b":", 1)[1].strip()) for line in head.split(b"\r\n")[1:]
                               if line.lower().startswith(b"content-length:")]
                    assert len(lengths) == 1, "Expected one native Content-Length"
                    if len(payload) >= lengths[0]:
                        assert len(payload) == lengths[0], "Surplus native response bytes"
                        break
        raw = b"".join(chunks)
        head, payload = raw.split(b"\r\n\r\n", 1)
        return int(head.split(b" ", 2)[1]), payload, raw

    def add(self, number):
        assert self.exchange(self.http, "/query-log-fixture.gif", host(number))[0] in (200, 204)

    def batch(self, first, last):
        with ThreadPoolExecutor(max_workers=12) as pool:
            list(pool.map(self.add, range(first, last + 1)))

    def page(self, offset=0, cursor=None, status=200):
        path = f"/internal-qlog?offset={offset}&limit=300"
        args = [str(self.probe), str(offset)]
        if cursor:
            generation, anchor = cursor
            path += f"&generation={generation}&anchor={anchor}"
            args.extend(cursor)
        actual, body, raw = self.exchange(self.stats, path)
        assert actual == status, (actual, status)
        client = subprocess.run(args, input=raw, capture_output=True, timeout=10)
        if status != 200:
            assert client.returncode == 2
            return None
        assert client.returncode == 0, client.stderr.decode("utf-8", errors="replace")
        page = json.loads(body)
        lines = client.stdout.decode("utf-8").splitlines()
        expected = [str(page[key]) for key in ("offset", "returned", "nextOffset", "total")]
        expected += [str(int(page["hasMore"])), page["generation"], page["anchor"]]
        assert lines[0].split(",") == expected
        assert lines[1:] == [entry["host"] for entry in page["entries"]]
        return page

    def all_pages(self, first=None):
        page = first or self.page()
        cursor = (page["generation"], page["anchor"])
        rows = list(page["entries"])
        while page["hasMore"]:
            page = self.page(page["nextOffset"], cursor)
            rows.extend(page["entries"])
        assert len(rows) == page["total"]
        return rows, cursor

    def control(self, command):
        token = (self.resources / "control_token.txt").read_text(encoding="ascii").strip()
        assert self.exchange(self.stats, "/control", body=("cmd=" + command).encode("ascii"), token=token)[0] == 200


def run(exe, probe):
    with tempfile.TemporaryDirectory(prefix="adaway-qlog-") as directory:
        fixture = Fixture(exe, probe, Path(directory))
        try:
            fixture.start()
            assert fixture.page()["total"] == 0
            fixture.batch(1, 600)
            first = fixture.page()
            assert first["total"] == 600 and 0 < first["returned"] < 300
            old_cursor = (first["generation"], first["anchor"])
            fixture.batch(601, 625)
            rows, _ = fixture.all_pages(first)
            assert {entry["host"] for entry in rows} == {host(i) for i in range(1, 601)}
            fixture.batch(626, 4850)
            fixture.page(0, old_cursor, status=409)
            full, before_restart = fixture.all_pages()
            assert len(full) == 4096 and len({entry["host"] for entry in full}) == 4096
            fixture.exchange(fixture.stats, "/internal-stats") # Commit the actual ring.
            fixture.stop()
            fixture.start()
            fixture.page(0, before_restart, status=409)
            restored, restored_cursor = fixture.all_pages()
            assert restored == full, "Restart lost committed log order/metadata"
            fixture.control("clear_query_log")
            fixture.page(0, restored_cursor, status=409)
            assert fixture.page()["total"] == 0
            assert fixture.exchange(fixture.stats, "/internal-qlog?limit=301000")[0] == 400
            return dict(retention=4096, originalRows=600, concurrentWrites=25,
                        actualShortPage=first["returned"], overwriteExpired=True,
                        restartOrderAndMetadata=True, clearExpired=True,
                        productionClientParser=True, hostNetworkChanges=False)
        finally:
            fixture.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("exe", type=Path)
    parser.add_argument("probe", type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.exe.resolve(), args.probe.resolve()), indent=2))
