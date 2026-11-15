#!/usr/bin/env python3
"""Same-machine SOCKS5 DIRECT/SS download comparison, with byte integrity.

All traffic stays on loopback; CPU is child user+system time including startup,
and peak RSS comes from wait4 (macOS/Linux). This is not a WAN protocol claim.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BLOCK = bytes(range(256)) * 256


def free_port():
    with socket.socket() as stream:
        stream.bind(('127.0.0.1', 0))
        return stream.getsockname()[1]


def exact(stream, count):
    data = bytearray()
    while len(data) < count:
        chunk = stream.recv(count - len(data))
        if not chunk:
            raise RuntimeError('unexpected EOF')
        data.extend(chunk)
    return bytes(data)


def socks(port, origin):
    stream = socket.create_connection(('127.0.0.1', port), timeout=10)
    stream.sendall(b'\x05\x01\x00')
    if exact(stream, 2) != b'\x05\x00':
        stream.close()
        raise RuntimeError('SOCKS authentication failed')
    stream.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + struct.pack('>H', origin))
    response = exact(stream, 4)
    if response[1] != 0:
        stream.close()
        raise RuntimeError('SOCKS connect failed: ' + repr(response))
    size = {1: 4, 4: 16}.get(response[3])
    if size is None:
        size = exact(stream, 1)[0]
    exact(stream, size + 2)
    return stream


def ready(process, port):
    for _ in range(200):
        if process.poll() is not None:
            raise RuntimeError('reference process exited during startup')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                return
        except OSError:
            time.sleep(.025)
    raise TimeoutError('proxy did not become ready')


def stop(process):
    process.terminate()
    _, status, usage = os.wait4(process.pid, 0)
    process.returncode = os.waitstatus_to_exitcode(status)
    return usage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mihomo', required=True, type=Path)
    parser.add_argument('--sing-box', required=True, type=Path)
    parser.add_argument('--mib', type=int, default=32)
    parser.add_argument('--samples', type=int, default=5)
    parser.add_argument('--output', default='bin/benchmark.json')
    args = parser.parse_args()
    amount = args.mib * 1048576
    if args.mib < 1 or args.samples < 2:
        parser.error('use positive MiB and at least two samples')
    expected = hashlib.sha256(BLOCK * (amount // len(BLOCK))).hexdigest()
    class Origin(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                exact(self.request, 1)
                for _ in range(amount // len(BLOCK)):
                    self.request.sendall(BLOCK)
            except (OSError,RuntimeError):
                pass
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
    origin = Server(('127.0.0.1', 0), Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    results = []
    versions = dict(reka=subprocess.check_output([str(ROOT / 'bin/reka'), '-version'], text=True).strip(), mihomo=subprocess.check_output([str(args.mihomo.resolve()), '-v'], text=True).strip(), sing_box=subprocess.check_output([str(args.sing_box.resolve()), 'version'], text=True).strip())
    with tempfile.TemporaryDirectory(prefix='reka-comparison-') as folder:
        temp = Path(folder)
        ssport = free_port()
        with (temp / 'ss.log').open('w') as log:
            ss = subprocess.Popen([str(ROOT / 'bin/benchserver'), '-listen', '127.0.0.1:' + str(ssport)], stdout=log, stderr=log)
            ready(ss, ssport)
            try:
                for protocol in ('direct', 'shadowsocks'):
                    for core in ('reka', 'mihomo', 'sing-box'):
                        stage = temp / (core + '-' + protocol)
                        stage.mkdir()
                        port = free_port()
                        node = dict(server='127.0.0.1', port=ssport, password='reka-controlled-benchmark')
                        if core == 'reka':
                            outbound = dict(id='node', type='shadowsocks', method='aes-128-gcm', **node) if protocol == 'shadowsocks' else dict(id='node', type='direct')
                            # JSON is a YAML subset.
                            (stage / 'profile.yaml').write_text(json.dumps({'schema-version': 1, 'log': {'level': 'error'}, 'outbounds': [outbound], 'rules': [{'match': {'all': True}, 'outbound': 'node'}]}))
                            (stage / 'local.yaml').write_text(json.dumps({'listeners': [{'id': 'mixed', 'type': 'mixed', 'listen': '127.0.0.1:' + str(port)}]}))
                            command = [str(ROOT / 'bin/reka'), '-state-root', str(stage / 'state'), '-profile', str(stage / 'profile.yaml'), '-local', str(stage / 'local.yaml'), '-control', '-', '-edit-dir', '-']
                        elif core == 'mihomo':
                            proxies = [dict(name='node', type='ss', cipher='aes-128-gcm', **node)] if protocol == 'shadowsocks' else []
                            config = {'mixed-port': port, 'bind-address': '127.0.0.1', 'mode': 'rule', 'log-level': 'silent', 'proxies': proxies, 'rules': ['MATCH,' + ('node' if proxies else 'DIRECT')]}
                            (stage / 'config.yaml').write_text(json.dumps(config))
                            command = [str(args.mihomo.resolve()), '-d', str(stage), '-f', str(stage / 'config.yaml')]
                        else:
                            outbound = dict(type='shadowsocks', tag='node', server='127.0.0.1', server_port=ssport, method='aes-128-gcm', password=node['password']) if protocol == 'shadowsocks' else dict(type='direct', tag='node')
                            config = {'log': {'level': 'error'}, 'inbounds': [{'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': port}], 'outbounds': [outbound], 'route': {'final': 'node'}}
                            (stage / 'config.json').write_text(json.dumps(config))
                            command = [str(args.sing_box.resolve()), 'run', '-D', str(stage), '-c', str(stage / 'config.json')]
                        durations = []
                        with (stage / 'process.log').open('w') as process_log:
                            process = subprocess.Popen(command, stdout=process_log, stderr=process_log)
                            try:
                                ready(process, port)
                                # Reka binds listeners during transaction preparation;
                                # wait for an actual route before timing any sample.
                                for attempt in range(200):
                                    try:
                                        probe=socks(port,origin.server_address[1]);probe.close();break
                                    except (OSError,RuntimeError):
                                        time.sleep(.025)
                                else:
                                    raise RuntimeError('proxy bound but route never activated')
                                idle_rss = int(subprocess.check_output(['ps', '-o', 'rss=', '-p', str(process.pid)]).strip()) * 1024
                                for index in range(args.samples + 2):
                                    digest = hashlib.sha256()
                                    start = time.monotonic()
                                    with socks(port, origin.server_address[1]) as stream:
                                        stream.sendall(b'x')
                                        count = 0
                                        while count < amount:
                                            chunk = stream.recv(min(262144, amount - count))
                                            if not chunk:
                                                raise RuntimeError('short download')
                                            count += len(chunk)
                                            digest.update(chunk)
                                    if digest.hexdigest() != expected:
                                        raise RuntimeError('byte integrity mismatch')
                                    if index >= 2:
                                        durations.append(time.monotonic() - start)
                            except Exception:
                                print(core,protocol,(stage / "process.log").read_text(),flush=True)
                                raise
                            finally:
                                usage = stop(process)
                        result = dict(core=core, protocol=protocol, samples=args.samples, mib_per_sample=args.mib, elapsed_seconds=durations, mib_per_second=[round(args.mib / n, 2) for n in durations], child_cpu_seconds_including_startup=round(usage.ru_utime + usage.ru_stime, 4), idle_rss_bytes=idle_rss, peak_rss_bytes=int(usage.ru_maxrss * (1 if platform.system() == 'Darwin' else 1024)), sha256_verified=True)
                        results.append(result)
                        print(core, protocol, result['mib_per_second'], flush=True)
            finally:
                stop(ss)
                origin.shutdown()
    build_info={name:subprocess.check_output(['go','version','-m',str(path.resolve())],text=True) for name,path in [('reka',ROOT/'bin/reka'),('mihomo',args.mihomo),('sing_box',args.sing_box)]}
    document = dict(reference_source_versions={'mihomo':'v1.19.34','sing-box':'v1.14.4'},build_info=build_info,machine=dict(os=platform.system(), arch=platform.machine(), go=subprocess.check_output(['go', 'version'], text=True).strip()), versions=versions, workload='SOCKS5 TCP download; 2 warmups; fixed bytes; localhost only; child CPU includes startup', results=results)
    path = ROOT / args.output
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + '\n')


if __name__ == '__main__':
    main()
