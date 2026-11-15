#!/usr/bin/env python3
"""Authorized macOS system-proxy and launchd acceptance, staged outside Desktop.

Stage reka, examples/gui/client.py and packaging/macos/{install,uninstall}.sh
under --stage, then run this tool as root. It never enables a network mode in
the installed service; proxy mutations use a separate temporary state root.
"""
import argparse
import http.server
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', type=Path, required=True)
    parser.add_argument('--owner', type=int, required=True)
    parser.add_argument('--service', default='Wi-Fi')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0, 'administrator privileges required'
    stage = args.stage.resolve()
    spec = importlib.util.spec_from_file_location('reka_client', stage / 'examples/gui/client.py')
    client_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(client_module)

    def run(*command, timeout=30):
        return subprocess.check_output([str(x) for x in command], text=True,
                                       stderr=subprocess.STDOUT, timeout=timeout, cwd=stage).strip()

    def snapshot():
        return {k: run('/usr/sbin/networksetup', '-get' + k, args.service)
                for k in ('dnsservers', 'webproxy', 'securewebproxy', 'socksfirewallproxy')}

    def connect(address, process=None):
        last = None
        for _ in range(100):
            if process and process.poll() is not None:
                raise RuntimeError('daemon exited: ' + str(process.returncode))
            try:
                return client_module.Client(address)
            except (OSError, ConnectionError) as error:
                last = error
                time.sleep(.1)
        raise RuntimeError('control unavailable: ' + str(last))

    def commit_local(client, local):
        change = dict(base_revision=client.call('GetStatus')['revision'], local=local)
        plan = client.call('PlanConfiguration', change)
        result = client.call('CommitConfiguration', dict(change, plan_hash=plan['plan_hash']))
        assert result['state'] == 'committed', result

    before = snapshot()
    report = dict(proxy=False, crash_recovery=False, launchd=False)
    daemon = client = server = None
    installed = False
    label = 'org.mimoproxy.reka.' + str(args.owner)
    plist = Path('/Library/LaunchDaemons/' + label + '.plist')
    assert not plist.exists(), 'existing service must be preserved'
    try:
        with tempfile.TemporaryDirectory(prefix='reka-proxy-', dir='/private/tmp') as folder:
            root = Path(folder)
            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    body = b'REKA_SYSTEM_PROXY_PASS'
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, *unused):
                    pass

            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            profile = root / 'profile.yaml'
            profile.write_text('schema-version: 1\ndns:\n nameserver: [223.5.5.5]\n'
                               ' default-nameserver: [223.5.5.5]\n use-hosts: true\n'
                               ' hosts: [{id: fixture.reka.test, addresses: [127.0.0.1]}]\n'
                               'rules: [{id: final, match: {all: true}, outbound: direct}]\n')
            local = ('listeners: [{id: mixed, type: mixed, listen: "127.0.0.1:%d"}]\n'
                     'network:\n mode: system-proxy\n proxy-listener: mixed\n service: %s\n') % (port, json.dumps(args.service))
            local_path = root / 'local.yaml'
            local_path.write_text(local)
            address = 'unix://' + str(root / 'control.sock')
            command = [str(stage / 'reka'), '-state-root', str(root / 'state'),
                       '-control', address, '-profile', str(profile), '-local',
                       str(local_path), '-edit-dir', '-']
            with (stage / 'proxy-daemon.log').open('w') as log:
                try:
                    daemon = subprocess.Popen(command, stdout=log, stderr=log)
                    client = connect(address, daemon)
                    status = client.call('GetStatus')
                    assert not status.get('start_error'), status
                    assert status['runtime']['network']['state'] == 'Running', status
                    active = snapshot()
                    for key in ('webproxy', 'securewebproxy', 'socksfirewallproxy'):
                        assert 'Enabled: Yes' in active[key] and ('Port: ' + str(port)) in active[key], active
                    swift = root / 'request.swift'
                    swift.write_text('''import Foundation
import Dispatch
let done = DispatchSemaphore(value: 0)
let task = URLSession.shared.dataTask(with: URL(string: CommandLine.arguments[1])!) { data, _, error in
    guard let data = data else { fputs("\\(String(describing: error))\\n", stderr); exit(1) }
    print(String(data: data, encoding: .utf8)!)
    done.signal()
}
task.resume()
if done.wait(timeout: .now() + 15) == .timedOut { exit(2) }
''')
                    run('/usr/bin/swiftc', swift, '-o', root / 'request', timeout=90)
                    body = run(root / 'request', 'http://fixture.reka.test:%d/' % server.server_port)
                    assert body == 'REKA_SYSTEM_PROXY_PASS', body
                    report.update(proxy=True, native_client='Foundation URLSession; no explicit proxy', active=active)
                    commit_local(client, 'network: {mode: off}\n')
                    assert snapshot() == before, 'graceful restoration differs'
                    commit_local(client, local)
                    client.close()
                    client = None
                    daemon.kill()
                    daemon.wait(timeout=15)
                    assert snapshot() == active, 'crash did not leave owned settings for recovery test'
                    daemon = subprocess.Popen(command, stdout=log, stderr=log)
                    client = connect(address, daemon)
                    commit_local(client, 'network: {mode: off}\n')
                    assert snapshot() == before, 'restart recovery did not preserve original settings'
                    report['crash_recovery'] = True
                finally:
                    try:
                        if client:
                            try:
                                commit_local(client, 'network: {mode: off}\n')
                            finally:
                                client.close()
                    finally:
                        if daemon and daemon.poll() is None:
                            daemon.terminate()
                            daemon.wait(timeout=30)
            run('/bin/sh', stage / 'packaging/macos/install.sh', args.owner)
            installed = True
            service_address = 'unix:///var/run/reka/%d/control.sock' % args.owner
            client = connect(service_address)
            status = client.call('GetStatus')
            client.close()
            client = None
            assert status['runtime']['network']['mode'] == 'off', status
            owner_probe = ('import sys;sys.path.insert(0,%r);from client import Client;'
                           'c=Client(%r);assert c.call("GetStatus")["runtime"]["network"]["mode"]=="off";c.close();print("OWNER_PASS")') % (
                               str(stage / 'examples/gui'), service_address)
            assert run('/usr/bin/sudo', '-u', '#' + str(args.owner), '/usr/bin/python3', '-c', owner_probe) == 'OWNER_PASS'
            first = run('/bin/launchctl', 'print', 'system/' + label)
            run('/bin/launchctl', 'kill', 'SIGKILL', 'system/' + label)
            time.sleep(7)
            client = connect(service_address)
            client.call('GetStatus')
            client.close()
            client = None
            second = run('/bin/launchctl', 'print', 'system/' + label)
            def pid(text):
                return next(line.strip() for line in text.splitlines() if line.strip().startswith('pid ='))
            assert pid(first) != pid(second), 'launchd did not replace killed process'
            report.update(launchd=True, owner_control=True, pid_before=pid(first), pid_after=pid(second))
    except Exception as error:
        report['error'] = str(error)
        if isinstance(error, subprocess.CalledProcessError):
            report['command_output'] = error.output
    finally:
        if server:
            server.shutdown()
        if installed:
            run('/bin/sh', stage / 'packaging/macos/uninstall.sh', args.owner)
        report['after'] = snapshot()
        report['before'] = before
        report['settings_restored'] = report['after'] == before
        report['service_uninstalled'] = not plist.exists()
        report['passed'] = all(report[k] for k in ('proxy', 'crash_recovery', 'launchd', 'settings_restored', 'service_uninstalled'))
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        os.chown(args.output, args.owner, -1)
        print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
