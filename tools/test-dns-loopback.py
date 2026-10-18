#!/usr/bin/env python3
"""Exercise the shipped diagnostic CLI and real importer with loopback-only fixtures."""
import json
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


def exact(stream, size):
    result = b''
    while len(result) < size:
        part = stream.recv(size - len(result))
        if not part:
            raise EOFError('incomplete query')
        result += part
    return result


class Fixture:
    def __init__(self, mode):
        self.mode, self.stop, self.errors = mode, threading.Event(), []
        self.udp_count = self.tcp_count = 0
        self.tcp = socket.socket(); self.tcp.bind(('127.0.0.1', 0)); self.tcp.listen(1)
        self.port = self.tcp.getsockname()[1]
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); self.udp.bind(('127.0.0.1', self.port))
        self.tcp.settimeout(.1); self.udp.settimeout(.1)
        self.peers = []
        self.workers = [threading.Thread(target=self.guard, args=(self.serve_udp,)), threading.Thread(target=self.guard, args=(self.serve_tcp,))]
        for worker in self.workers:
            worker.start()

    def guard(self, task):
        try:
            task()
        except (BrokenPipeError, ConnectionResetError):
            pass  # Client closes immediately when its deadline/frame validation fails.
        except OSError as error:
            if not self.stop.is_set():
                self.errors.append(repr(error))
        except Exception as error:
            self.errors.append(repr(error))

    def serve_udp(self):
        while not self.stop.is_set():
            try:
                query, peer = self.udp.recvfrom(513)
            except socket.timeout:
                continue
            self.udp_count += 1
            answer = bytearray(query); answer[2] = 0x81 if self.mode == 'udp' else 0x83
            if self.mode == 'bad-udp':
                answer[0] ^= 1
            if self.mode == 'slow':
                time.sleep(.14)
            if self.mode != 'silent':
                self.udp.sendto(answer, peer)
            return

    def serve_tcp(self):
        while not self.stop.is_set():
            try:
                peer, address = self.tcp.accept()
            except socket.timeout:
                continue
            self.peers.append(peer); self.tcp_count += 1
            with peer:
                peer.settimeout(2)
                size, = struct.unpack('!H', exact(peer, 2))
                assert size == 29
                answer = bytearray(exact(peer, size)); answer[2] = 0x81
                if self.mode == 'bad-id':
                    answer[0] ^= 1
                if self.mode == 'tcp-tc':
                    answer[2] |= 2
                if self.mode == 'oversize':
                    peer.sendall(b'\x02\x01'); return
                if self.mode == 'short':
                    peer.sendall(struct.pack('!H', size) + answer[:5]); return
                if self.mode == 'slow':
                    time.sleep(.08)
                prefix = struct.pack('!H', size)
                peer.sendall(prefix[:1]); peer.sendall(prefix[1:])
                if self.mode == 'slow':
                    time.sleep(.1)
                for byte in answer:
                    peer.sendall(bytes([byte]))
                return

    def close(self):
        self.stop.set(); self.udp.close(); self.tcp.close()
        for peer in self.peers:
            peer.close()
        for worker in self.workers:
            worker.join(3)
            assert not worker.is_alive(), 'fixture thread leaked'
        assert not self.errors, self.errors


def run(executable):
    records = []
    cases = [('udp', '', 0, 0), ('tcp', '', 0, 1), ('bad-udp', '', 4, 0),
             ('bad-id', '', 4, 1), ('tcp-tc', '', 4, 1), ('oversize', '', 4, 1),
             ('short', '', 3, 1), ('slow', '', 2, 1), ('silent', '', 2, 0),
             ('tcp', '||example.com^\n', 0, 0), ('tcp', '192.0.2.7 example.com\n', 0, 0),
             ('tcp', '||example.com^\n@@||example.com^\n', 0, 1)]
    with tempfile.TemporaryDirectory(prefix='dns probe ') as root:
        source = Path(root) / '规则 source.txt'
        for mode, rules, status, tcp_used in cases:
            source.write_text(rules, encoding='utf-8')
            fixture = Fixture(mode)
            try:
                begin = time.monotonic()
                completed = subprocess.run([str(executable), str(source), str(fixture.port), '230' if mode in ('slow','silent') else '1000'],
                                           capture_output=True, text=True, timeout=5)
                elapsed = time.monotonic()-begin
                result = json.loads(completed.stdout)
                assert result['status'] == status, (mode, result, completed.stderr)
                assert result['transport'] == ('local' if rules and not tcp_used else 'tcp' if tcp_used else 'udp'), result
                assert completed.returncode == (0 if status == 0 else 1)
                assert fixture.tcp_count == tcp_used, (mode, fixture.tcp_count)
                if rules and not tcp_used:
                    assert fixture.udp_count == 0 and result['source'] == 2 and result['generation'] == 1
                    assert result['rule_action'] in (1,4)
                if status:
                    assert result['bytes'] == 0
                if mode in ('slow','silent'):
                    assert elapsed < 1.1, elapsed
                records.append({'case': mode, 'rule_hit': bool(rules), 'result': result})
            finally:
                fixture.close()
    print(json.dumps({'loopback_only': True, 'cases': records}, indent=2))


if __name__ == '__main__':
    run(Path(sys.argv[1]).resolve())
