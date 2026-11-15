#!/usr/bin/env python3
"""Verify the independent example client against an isolated production daemon."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('example_client', ROOT / 'examples/gui/client.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def main():
    with tempfile.TemporaryDirectory(prefix='reka-client-') as folder:
        root = Path(folder)
        profile = root / 'profile.yaml'
        profile.write_text('schema-version: 1\nlog: {level: error}\nrules: [{id: final, match: {all: true}, outbound: direct}]\n')
        address = 'unix://' + str(root / 'control.sock')
        with (root / 'daemon.log').open('w') as log:
            daemon = subprocess.Popen([str(ROOT / 'bin/reka'), '-state-root', str(root / 'state'), '-control', address, '-profile', str(profile), '-edit-dir', '-'], stdout=log, stderr=log)
            a = b = None
            try:
                for _ in range(100):
                    if (root / 'control.sock').exists():
                        break
                    if daemon.poll() is not None:
                        raise RuntimeError((root / 'daemon.log').read_text())
                    time.sleep(.05)
                a, b = module.Client(address), module.Client(address)
                caps = a.call('GetCapabilities')
                assert caps['api_version'] == 1
                cfg = a.call('GetConfiguration')
                a.call('Subscribe')
                change = dict(base_revision=cfg['revision'], patch=[dict(op='set', path='/log/level', value='warn')])
                plan = a.call('PlanConfiguration', change)
                request = dict(change, plan_hash=plan['plan_hash'], operation_id='client-operation')
                result = a.call('CommitConfiguration', request)
                assert result['state'] == 'committed', result
                assert a.call('CommitConfiguration', request) == result
                assert b.call('CommitConfiguration', dict(change, operation_id='stale-operation'))['error']['code'] == 'conflict'
                event = a.events.get(timeout=3)
                assert event['type'] in ('snapshot', 'config.committed', 'operation', 'runtime.generation')
                assert daemon.poll() is None
                status = a.call('GetStatus')
                assert status['revision'] == result['revision']
                a.close()
                try:
                    a.call('GetStatus')
                    raise AssertionError('offline client accepted a call')
                except ConnectionError:
                    pass
                print(json.dumps(dict(pass_=True, client='independent Python framed JSON', hello=True, capabilities=True, planned_commit=True, idempotent_retry=True, stale_conflict=True, events=True, offline_disabled=True, status=status), indent=2))
            finally:
                if a:
                    a.close()
                if b:
                    b.close()
                daemon.terminate()
                try:
                    daemon.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait()


if __name__ == '__main__':
    main()
