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
import hashlib
from urllib.parse import urlencode


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
            "--stats-port", str(self.stats), "--listen-ipv4", "127.0.0.1", "--listen-ipv6", "::1"],
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
                except (OSError, AssertionError):
                    # The frozen core can exit before flushing this reply.
                    # Verify the owned process actually exits normally below.
                    pass
                try:
                    self.process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    self.process.terminate()
                    self.process.wait(timeout=5)
                    raise AssertionError("Server needed forced shutdown")
                assert self.process.returncode == 0, "Server exited abnormally"
            self.process = None
        if self.log is not None:
            self.log.close()
            self.log = None

    def exchange(self, port, path, hostname="127.0.0.1", body=None, token=None, family=4):
        method = "POST" if body is not None else "GET"
        headers = f"{method} {path} HTTP/1.0\r\n"
        if hostname is not None:
            headers += f"Host: {hostname}\r\n"
        headers += "Connection: close\r\n"
        if token is not None:
            headers += f"X-ADBlock-Token: {token}\r\n"
        if body is not None:
            headers += f"Content-Length: {len(body)}\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        with socket.create_connection(("::1" if family == 6 else "127.0.0.1", port), timeout=5) as connection:
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
        assert b"\r\n\r\n" in raw, "Response ended before complete headers"
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
        # Fresh fixture rows always carry their observed socket family. Legacy
        # unknown-family migration is covered by the shared persistence tests.
        assert all(entry.get("family") in (4, 6) for entry in page["entries"])
        lines = client.stdout.decode("utf-8").splitlines()
        expected = [str(page[key]) for key in ("offset", "returned", "nextOffset", "total")]
        expected += [str(int(page["hasMore"])), page["generation"], page["anchor"]]
        assert lines[0].split(",") == expected
        assert lines[1:] == [entry["host"] for entry in page["entries"]]
        return page

    def filtered_page(self, filters=None, offset=0, cursor=None):
        filters = dict(filters or {})
        if cursor:
            filters.update(generation=cursor[0], anchor=cursor[1], queryKey=cursor[2])
        path = "/internal-qlog?" + urlencode(dict(filterVersion=1, offset=offset, limit=300, **filters))
        status, body, raw = self.exchange(self.stats, path)
        assert status == 200, (status, body)
        page = json.loads(body)
        assert page["filterVersion"] == 1 and page["retainedTotal"] >= page["total"]
        canonical = "qlog-filter-v1" + "".join("\n" + name + "=" + str(filters.get(name, "*")) for name in ("action", "family", "type", "uid"))
        canonical += "\nq=" + str(filters.get("q", "")).translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"))
        assert page["queryKey"] == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        client = subprocess.run([str(self.probe), "--v1", str(offset), json.dumps(filters, ensure_ascii=False)], input=raw, capture_output=True, timeout=10)
        assert client.returncode == 0, client.stderr
        lines=client.stdout.decode("utf-8").splitlines()
        assert lines[1] == f"v1,{page['retainedTotal']},{page['queryKey']}"
        assert lines[2:] == [entry["host"] for entry in page["entries"]]
        sequence=[int(entry["sequence"]) for entry in page["entries"]]
        assert sequence == sorted(set(sequence), reverse=True)
        assert all(entry["path"] == "/query-log-fixture.gif" and entry["status"] in (200,204) and not entry["pathTruncated"] for entry in page["entries"])
        return page

    def verify_filtered_history(self):
        target=self.filtered_page(dict(q="Q-00001.",action=1,family=4,type=0))
        assert target["total"]==1 and target["retainedTotal"]==600 and target["entries"][0]["host"]==host(1)
        page=self.filtered_page(dict(q="query-log-fixture"));cursor=(page["generation"],page["anchor"],page["queryKey"])
        rows=list(page["entries"])
        while page["hasMore"]:
            page=self.filtered_page(dict(q="query-log-fixture"),page["nextOffset"],cursor);rows.extend(page["entries"])
        assert len(rows)==600 and len({entry["sequence"] for entry in rows})==600
        bad=dict(filterVersion=1,offset=0,limit=300,generation=cursor[0],anchor=cursor[1],queryKey=cursor[2],q="different")
        assert self.exchange(self.stats,"/internal-qlog?"+urlencode(bad))[0]==400
        for query in ("filterVersion=1&action=1&action=1", "filterVersion=1&q=%FF", "filterVersion=1&q=%00", "filterVersion=1&q="+"x"*192):
            assert self.exchange(self.stats,"/internal-qlog?"+query)[0]==400
        return len(rows)

    def all_pages(self, first=None):
        page = first or self.page()
        cursor = (page["generation"], page["anchor"])
        rows = list(page["entries"])
        while page["hasMore"]:
            page = self.page(page["nextOffset"], cursor)
            rows.extend(page["entries"])
        assert len(rows) == page["total"]
        return rows, cursor

    def validate_stats(self, minimum_requests):
        status, body, raw = self.exchange(self.stats, "/internal-stats")
        assert status == 200
        document = json.loads(body)
        assert document["total_requests"] >= minimum_requests
        assert all(isinstance(document[name], list) for name in ("apps", "top_blocked", "query_log", "listeners"))
        assert all(entry.get("family") in (4, 6) for entry in document["query_log"])
        client = subprocess.run([str(self.probe), "--stats"], input=raw, capture_output=True, timeout=10)
        assert client.returncode == 0 and client.stdout.strip() == b"valid-stats"
        return document

    def control(self, command):
        token = (self.resources / "control_token.txt").read_text(encoding="ascii").strip()
        result = self.exchange(self.stats, "/control", body=("cmd=" + command).encode("ascii"), token=token)
        assert result[0] == 200, (result[0], result[1])

    def verify_control_authentication(self):
        # Use a harmless flush to verify real header/body clients and rejection.
        token = (self.resources / "control_token.txt").read_text(encoding="ascii").strip()
        command = b"cmd=flush_stats"
        assert self.exchange(self.stats, "/control", body=command)[0] == 403
        assert self.exchange(self.stats, "/control", body=command, token="wrong")[0] == 403
        assert self.exchange(self.stats, "/control", body=command, token=token)[0] == 200
        assert self.exchange(self.stats, "/control", body=command + b"&token=" + token.encode("ascii"))[0] == 200
        # An explicitly wrong body token must not be rescued by a valid header.
        assert self.exchange(self.stats, "/control", body=command + b"&token=wrong", token=token)[0] == 403


def run(exe, probe):
    with tempfile.TemporaryDirectory(prefix="adaway-qlog-") as directory:
        fixture = Fixture(exe, probe, Path(directory))
        try:
            fixture.start()
            fixture.verify_control_authentication()
            fixture.control("clear_query_log")
            assert fixture.page()["total"] == 0
            fixture.batch(1, 600)
            fixture.validate_stats(600)
            fixture.verify_filtered_history()
            first = fixture.page()
            assert first["total"] == 600 and 0 < first["returned"] < 300
            old_cursor = (first["generation"], first["anchor"])
            fixture.batch(601, 625)
            rows, _ = fixture.all_pages(first)
            assert {entry["host"] for entry in rows} == {host(i) for i in range(1, 601)}
            assert all(entry["family"] == 4 for entry in rows), "IPv4 requests must report observed socket family"
            fixture.batch(626, 4850)
            fixture.page(0, old_cursor, status=409)
            full, before_restart = fixture.all_pages()
            assert len(full) == 4096 and len({entry["host"] for entry in full}) == 4096
            fixture.validate_stats(4850) # Validate the actual document and commit the ring.
            fixture.stop()
            fixture.start()
            fixture.validate_stats(4850)
            fixture.page(0, before_restart, status=409)
            restored, restored_cursor = fixture.all_pages()
            assert restored == full, "Restart lost committed log order/metadata"
            fixture.control("clear_query_log")
            fixture.page(0, restored_cursor, status=409)
            assert fixture.page()["total"] == 0
            assert fixture.exchange(fixture.stats, "/internal-qlog?limit=301000")[0] == 400
            # These requests use the real server entrypoint after the original
            # retention/restart assertions, so the established row counts stay
            # unchanged. No URL path or query may substitute for a missing Host.
            assert fixture.exchange(fixture.http, "/private?token=secret", hostname="[::1]:8443")[0] in (200, 204)
            assert fixture.exchange(fixture.http, "/private/secret", hostname=None)[0] in (200, 204)
            authority_page = fixture.page()
            assert authority_page["total"] == 2
            assert [entry["host"] for entry in authority_page["entries"]] == ["(unknown host)", "::1"]
            assert [entry["family"] for entry in authority_page["entries"]] == [4, 4], "IPv6-looking Host must not relabel IPv4 transport"
            assert fixture.exchange(fixture.http, "/family-fixture", hostname="127.0.0.1", family=6)[0] in (200, 204)
            family_page = fixture.page()
            assert family_page["entries"][0]["family"] == 6 and family_page["entries"][0]["host"] == "127.0.0.1"
            assert fixture.validate_stats(4853)["query_log"][0]["family"] == 6
            fixture.stop()
            fixture.start()
            assert fixture.page()["entries"] == family_page["entries"], "Restart lost actual dual-stack metadata"
            return dict(fullRetainedHistoryFiltering=True, fixedQueryKeyAndSequences=True, retention=4096, originalRows=600, concurrentWrites=25,
                        actualShortPage=first["returned"], overwriteExpired=True,
                        restartOrderAndMetadata=True, clearExpired=True,
                        productionClientParser=True, controlAuthentication=True,
                        longHostStatsComplete=True,
                        ipv6AuthorityAndMissingHostPrivacy=True,
                        ipv4AndIpv6LogRecords=True, socketFamilyNotInferredFromHost=True,
                        hostNetworkChanges=False)
        finally:
            fixture.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("exe", type=Path)
    parser.add_argument("probe", type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.exe.resolve(), args.probe.resolve()), indent=2))
