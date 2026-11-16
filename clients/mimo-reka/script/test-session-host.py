#!/usr/bin/env python3
"""Test session-host promotion and ownership without root or OS takeover.

Compiles a separate MIMO_REKA_HOST_TESTING binary whose paths are confined to
the supplied temporary tree. The shipped SwiftPM target never sets this flag.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = Path(__file__).resolve().parents[3]
CORE = Path(os.environ.get('MIMO_REKA_KERNEL_BINARY', REPO / 'bin/releases/1.0.0/reka-1.0.0-darwin-arm64/reka'))


def rpc(path, method, params=None):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(5)
        stream.connect(str(path))
        def exact(size):
            data = b''
            while len(data) < size:
                block = stream.recv(size-len(data))
                if not block:
                    raise RuntimeError('unexpected control EOF')
                data += block
            return data
        def call(identifier, name, parameters):
            data = json.dumps({'id': identifier, 'method': name, 'params': parameters}, sort_keys=True).encode()
            stream.sendall(struct.pack('>I', len(data)) + data)
            response = json.loads(exact(struct.unpack('>I', exact(4))[0]))
            if 'error' in response:
                raise RuntimeError(response['error'])
            return response['result']
        call(1, 'Hello', {'versions': [1], 'client': 'mimo-reka-host-tests'})
        return call(2, method, params or {})


def host_command(path, command):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(5)
        stream.connect(str(path))
        stream.sendall((command+'\n').encode())
        return stream.recv(256).decode().strip()


def wait(predicate, seconds=12):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        try:
            if predicate():
                return
        except (OSError, ValueError, RuntimeError):
            pass
        time.sleep(.05)
    raise AssertionError('timed out waiting for session state')


def main():
    root = Path(tempfile.mkdtemp(prefix='mr-host-', dir='/tmp'))
    processes = []
    server = None
    try:
        binary = root / 'MimoRekaHost-testing'
        env = os.environ | {'DEVELOPER_DIR': '/Applications/Xcode.app/Contents/Developer'}
        subprocess.run(['xcrun', 'swiftc', '-D', 'MIMO_REKA_HOST_TESTING', '-parse-as-library', '-swift-version', '5', '-module-cache-path', str(root/'module-cache'), str(REPO/'clients/mimo-reka/Sources/MimoRekaHost/HostMain.swift'), '-o', str(binary)], env=env, check=True)
        assert CORE.is_file(), CORE
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        normal = root/'normal'
        normal.mkdir(mode=0o700)
        (normal/'profile.yaml').write_text('schema-version: 1\nrules:\n - {id: final, match: {all: true}, outbound: direct}\n')
        (normal/'local.yaml').write_text('listeners:\n - {id: mixed, type: mixed, listen: "127.0.0.1:%d"}\nnetwork: {mode: off}\n' % port)
        child = subprocess.Popen([str(binary), '--supervise', str(CORE), str(normal), str(normal/'control.sock'), str(normal/'profile.yaml'), str(normal/'local.yaml')], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        processes.append(child)
        wait(lambda: (normal/'control.sock').exists())

        class Subscription(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'proxies: [{name: SessionNode, type: socks5, server: 127.0.0.1, port: 9}]\n'
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *_):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Subscription)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        current = rpc(normal/'control.sock', 'GetConfiguration')
        configured = rpc(normal/'control.sock', 'ConfigureSubscription', {'source_id':'locked', 'base_revision':current['revision'], 'subscription':{'url':'http://127.0.0.1:%d/sub' % server.server_port, 'format':'clash', 'interval':3600, 'nodes_only':True}})
        assert configured['state']=='committed', configured
        fetched = rpc(normal/'control.sock', 'RefreshSubscription', {'source_id':'locked', 'wait':True})
        assert fetched['state']=='current', fetched
        current = rpc(normal/'control.sock', 'GetConfiguration', {'reveal':True})
        blobs = list((normal/'resources/sha256').iterdir())
        assert blobs, 'subscription must create an immutable locked body'
        staging = root/'promotion'
        staging.mkdir(mode=0o700)
        (staging/'sha256').mkdir(mode=0o700)
        for blob in blobs:
            assert hashlib.sha256(blob.read_bytes()).hexdigest()==blob.name
            shutil.copyfile(blob, staging/'sha256'/blob.name)
            (staging/'sha256'/blob.name).chmod(0o600)
        bundle = {'documents':{field:current[field] for field in ('profile','local','sources','overlay')},'resources':[blob.name for blob in blobs]}
        payload = staging/'bootstrap.json'
        payload.write_text(json.dumps(bundle))
        payload.chmod(0o600)
        child.stdin.close()
        child.stdin = None
        output = child.communicate(timeout=10)[0]
        assert child.returncode==0, output
        print('Normal lifetime EOF cleanly stops its own Reka child: PASS')

        uid = os.getuid()
        key = uuid.uuid4().hex
        token = str(uuid.uuid4())
        env['MIMO_REKA_HOST_TEST_ROOT'] = str(root)
        session = subprocess.Popen([str(binary),'--privileged',str(uid),str(os.getpid()),key,str(CORE),token,str(payload)],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        processes.append(session)
        controls=root/'run'/str(uid)/key
        wait(lambda: int(host_command(controls/'host.sock','status '+token)) > 0)
        status=rpc(controls/'control.sock','GetStatus')
        assert status['runtime']['network']['mode']=='off'
        migrated=rpc(controls/'control.sock','GetConfiguration')
        assert 'locked' in migrated['sources']
        for blob in blobs:
            target=root/'state'/str(uid)/key/'state/resources/sha256'/blob.name
            assert target.read_bytes()==blob.read_bytes()
        assert host_command(controls/'host.sock','stop invalid-token').startswith('error')
        assert host_command(controls/'host.sock','stop '+token)=='ok'
        session.communicate(timeout=10)
        assert session.returncode==0
        print('Promotion preserves locked resources, network off, authenticated session stop: PASS')

        # A retry supplies fresh documents to an existing private state. It
        # must apply them before announcing ready, rather than ignoring them.
        bundle['documents']['profile']='schema-version: 1\ngroups:\n - {id: proof, type: select, members: [direct], selected: direct}\nrules:\n - {id: final, match: {all: true}, outbound: proof}\n'
        payload.write_text(json.dumps(bundle)); payload.chmod(0o600)
        token=str(uuid.uuid4())
        session=subprocess.Popen([str(binary),'--privileged',str(uid),str(os.getpid()),key,str(CORE),token,str(payload)],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        processes.append(session)
        wait(lambda: int(host_command(controls/'host.sock','status '+token)) > 0)
        assert 'proof' in rpc(controls/'control.sock','GetConfiguration')['profile']
        host_command(controls/'host.sock','stop '+token)
        session.communicate(timeout=10)
        print('Retry promotion applies fresh documents to existing private state: PASS')

        # The watched surrogate is killed; its session host must then restore
        # off and terminate even though no GUI stop command can be sent.
        surrogate=root/'surrogate.py'
        watchdogKey=uuid.uuid4().hex
        watchdogToken=str(uuid.uuid4())
        # Build the command without shell interpolation or inherited life fd.
        surrogate.write_text('import os, subprocess, time\nargs='+repr([str(binary),'--privileged',str(uid),'PARENT',watchdogKey,str(CORE),watchdogToken,str(payload)])+'\nargs[3]=str(os.getpid())\np=subprocess.Popen(args)\nwhile True: time.sleep(1)\n')
        parent=subprocess.Popen(['/usr/bin/python3',str(surrogate)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        processes.append(parent)
        watchdogControls=root/'run'/str(uid)/watchdogKey
        wait(lambda: int(host_command(watchdogControls/'host.sock','status '+watchdogToken)) > 0)
        parent.kill(); parent.wait(timeout=5)
        wait(lambda: not (watchdogControls/'host.sock').exists())
        assert not (watchdogControls/'control.sock').exists()
        print('Exact GUI process-exit watchdog stops its owned session: PASS')
        print('Tests used loopback-only network.mode=off; no system proxy/TUN changed.')
    finally:
        for process in processes:
            if process.poll() is None:
                if process.stdin:
                    process.stdin.close(); process.stdin=None
                process.terminate()
                try: process.communicate(timeout=10)
                except subprocess.TimeoutExpired: pass
        if server:
            server.shutdown(); server.server_close()
        shutil.rmtree(root, ignore_errors=True)


if __name__=='__main__':
    main()
