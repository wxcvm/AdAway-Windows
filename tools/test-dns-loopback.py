#!/usr/bin/env python3
"""Exercise the shipped diagnostic CLI and real importer with loopback-only fixtures."""
import json
import errno
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
    def __init__(self, mode, query_type=1, ip_version=4):
        self.mode, self.stop, self.errors = mode, threading.Event(), []
        self.query_type = query_type
        self.udp_count = self.tcp_count = 0
        self.tcp_query_received = False
        family = socket.AF_INET6 if ip_version == 6 else socket.AF_INET
        host = '::1' if ip_version == 6 else '127.0.0.1'
        # TCP port zero does not reserve the same UDP port. Retry setup only
        # on a real port collision; never reuse somebody else's listener.
        for attempt in range(16):
            self.tcp = socket.socket(family, socket.SOCK_STREAM)
            self.udp = None
            try:
                self.udp = socket.socket(family, socket.SOCK_DGRAM)
                if ip_version == 6:
                    self.tcp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    self.udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                self.tcp.bind((host, 0)); self.port = self.tcp.getsockname()[1]
                self.udp.bind((host, self.port)); self.tcp.listen(1)
                break
            except OSError as error:
                self.tcp.close()
                if self.udp is not None:
                    self.udp.close()
                if (error.errno != errno.EADDRINUSE and getattr(error, 'winerror', None) != 10048) or attempt == 15:
                    raise
        self.tcp.settimeout(.1); self.udp.settimeout(.1)
        self.peers = []
        self.workers = [threading.Thread(target=self.guard, args=(self.serve_udp,)), threading.Thread(target=self.guard, args=(self.serve_tcp,))]
        for worker in self.workers:
            worker.start()

    def guard(self, task):
        try:
            task()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError) as error:
            # Windows may report WSAECONNABORTED instead of a reset after the
            # client rejects a reply or expires its deadline. Only these TCP
            # fixtures expect that close, after receiving the complete query.
            if not (task == self.serve_tcp and self.tcp_query_received and
                    self.mode in ('bad-id', 'tcp-tc', 'oversize', 'slow', 'wrong-type-tcp')):
                self.errors.append(f'{self.mode}: {error!r}')
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
            assert len(query) == 29 and struct.unpack('!H', query[25:27])[0] == self.query_type
            answer = bytearray(query); answer[2] = 0x81 if self.mode == 'udp' else 0x83
            if self.mode == 'bad-udp':
                answer[0] ^= 1
            if self.mode == 'wrong-type-udp':
                answer[26] = 28 if self.query_type == 1 else 1
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
                assert struct.unpack('!H', answer[25:27])[0] == self.query_type
                self.tcp_query_received = True
                if self.mode == 'bad-id':
                    answer[0] ^= 1
                if self.mode == 'tcp-tc':
                    answer[2] |= 2
                if self.mode == 'wrong-type-tcp':
                    answer[26] = 28 if self.query_type == 1 else 1
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


def run(executable, policy_vectors, ip_version):
    records = []
    cases = [('udp', '', 0, 0), ('tcp', '', 0, 1), ('bad-udp', '', 4, 0),
             ('bad-id', '', 4, 1), ('tcp-tc', '', 4, 1), ('oversize', '', 4, 1),
             ('short', '', 3, 1), ('slow', '', 2, 1), ('silent', '', 2, 0),
             ('tcp', '||example.com^\n', 0, 0), ('tcp', '192.0.2.7 example.com\n', 0, 0),
             ('tcp', '||example.com^\n@@||example.com^\n', 0, 1),
             ('wrong-type-udp', '', 4, 0), ('wrong-type-tcp', '', 4, 1)]
    # Preserve the original A cases and exercise every transport failure with AAAA.
    cases = [(mode, rules, status, tcp, 1, None) for mode, rules, status, tcp in cases]
    cases += [(mode, rules, status, tcp, 28, None) for mode, rules, status, tcp, _, _ in cases if not rules]
    vector_count = 0
    for line in policy_vectors.read_text(encoding='utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        fields = line.split('\t')
        rules = '' if fields[2] == '-' else fields[2].replace('\\n', '\n')
        cases.append(('tcp', rules, 0, 1 if fields[6] == '-' else 0, int(fields[1]), fields))
        vector_count += 1
    assert vector_count == 16
    with tempfile.TemporaryDirectory(prefix='dns probe ') as root:
        source = Path(root) / '规则 source.txt'
        for mode, rules, status, tcp_used, query_type, vector in cases:
            source.write_text(rules, encoding='utf-8')
            fixture = Fixture(mode, query_type, ip_version)
            try:
                begin = time.monotonic()
                arguments = [str(executable), str(source), str(fixture.port)]
                # Keep the original shortest CLI invocation under regression:
                # omitting both optional arguments still means A / 1200 ms.
                if not (mode == 'udp' and query_type == 1 and vector is None and ip_version == 4):
                    arguments += ['230' if mode in ('slow','silent') else '1000',
                                  'A' if query_type == 1 else 'AAAA', 'ipv6' if ip_version == 6 else 'ipv4']
                completed = subprocess.run(arguments, capture_output=True, text=True, timeout=5)
                elapsed = time.monotonic()-begin
                result = json.loads(completed.stdout)
                assert result['status'] == status, (mode, result, completed.stderr)
                assert result['transport'] == ('local' if rules and not tcp_used else 'tcp' if tcp_used else 'udp'), result
                assert completed.returncode == (0 if status == 0 else 1)
                assert result['query_type'] == query_type
                assert result['upstream_ip_version'] == ip_version
                assert fixture.tcp_count == tcp_used, (mode, fixture.tcp_count)
                if rules and not tcp_used:
                    assert fixture.udp_count == 0 and result['source'] == 2 and result['generation'] == 1
                    assert result['rule_action'] in (1,4)
                if status:
                    assert result['bytes'] == 0 and result['response_hex'] == ''
                if vector:
                    assert result['rule_action'] == int(vector[3]), (vector[0], result)
                    assert result['source'] == int(vector[4]), (vector[0], result)
                    assert result['scope'] == int(vector[5]), (vector[0], result)
                    assert result['generation'] == 1
                    expected = vector[6]
                    if expected == '-':
                        reply = bytearray.fromhex('535301000001000000000000076578616d706c6503636f6d0000010001')
                        reply[26] = query_type; reply[2] = 0x81; expected = reply.hex()
                    assert result['response_hex'] == expected, (vector[0], result)
                    assert result['bytes'] == len(bytes.fromhex(expected))
                if mode in ('slow','silent'):
                    assert elapsed < 1.1, elapsed
                records.append({'case': vector[0] if vector else mode, 'query_type': query_type,
                                'upstream_ip_version': ip_version, 'rule_hit': bool(rules), 'result': result})
            finally:
                fixture.close()
        fixture = Fixture('tcp', ip_version=ip_version)
        try:
            for invalid in ('MX', 'AAAAA', '', '28'):
                failed = subprocess.run([str(executable), str(source), str(fixture.port), '1000', invalid,
                                         'ipv6' if ip_version == 6 else 'ipv4'],
                                        capture_output=True, text=True, timeout=5)
                assert failed.returncode == 2 and not failed.stdout
            for invalid in ('ipv5', '::1', ''):
                failed = subprocess.run([str(executable), str(source), str(fixture.port), '1000', 'A', invalid],
                                        capture_output=True, text=True, timeout=5)
                assert failed.returncode == 2 and not failed.stdout
            assert fixture.udp_count == 0 and fixture.tcp_count == 0
        finally:
            fixture.close()
    assert len(records) == 41
    return records


if __name__ == '__main__':
    executable = Path(sys.argv[1]).resolve()
    vectors = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(__file__).resolve().parents[1] / 'dns-contract' / 'diagnostic_dns_policy_vectors.tsv'
    records = run(executable,vectors,4) + run(executable,vectors,6)
    assert len(records) == 82
    print(json.dumps({'loopback_only': True, 'ip_versions': [4,6], 'policy_vectors': 16,
                      'invalid_types_rejected': 8, 'invalid_ip_versions_rejected': 6, 'cases': records}, indent=2))
