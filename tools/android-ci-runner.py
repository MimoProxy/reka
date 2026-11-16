#!/usr/bin/env python3
"""Run one explicitly selected Android CI job on an ephemeral local runner.

Requires the pinned official runner archive, a local SDK, and existing gh auth.
Uses a random exclusive label and no default labels, checks out the dispatched
commit, runs exactly once, and removes registration in finally. No service is
installed. A running idle-power measurement prevents any device CI startup.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
VERSION = '2.338.2'
SHA256 = '25a065af409ffa317ab4d5a3b614dd15fc9c40f2172bc1b35a1b1258e919a388'


def gh(*args):
    return subprocess.check_output(['gh', *args], text=True, cwd=ROOT, timeout=60)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--ref', required=True)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--repository', default='MimoProxy/reka')
    parser.add_argument('--output', type=Path, default=ROOT / 'bin/android/device-ci.json')
    args = parser.parse_args()
    os.umask(0o077)
    if not re.fullmatch(r'[\w.:-]+', args.serial):
        parser.error('invalid adb serial')
    adb = args.sdk / 'platform-tools/adb'
    live = subprocess.run([str(adb), '-s', args.serial, 'shell', 'cat', '/sdcard/Android/data/org.mimoproxy.reka.test/files/power-report.json'], capture_output=True, text=True, timeout=30)
    running = subprocess.run([str(adb), '-s', args.serial, 'shell', 'pidof', 'org.mimoproxy.reka.test'], capture_output=True, text=True, timeout=30).stdout.split()
    try:
        receipt=json.loads(live.stdout)
        if str(receipt.get('pid')) in running and receipt.get('state') in ('baseline', 'vpn', 'waiting_for_unplug', 'waiting_for_screen_off'):
            raise SystemExit('Power measurement is active; device CI must wait')
    except ValueError:
        if running:
            raise SystemExit('Cannot verify the running device app power-test state; inspect the device before CI')
    archive = ROOT / 'bin/toolchains' / ('actions-runner-osx-arm64-' + VERSION + '.tar.gz')
    if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise SystemExit('Official runner archive checksum mismatch')
    label = 'reka-device-' + uuid.uuid4().hex
    home = ROOT / 'bin/device-ci-runners' / label
    home.mkdir(parents=True)
    with tarfile.open(archive) as source:
        for entry in source.getmembers():
            if not (home / entry.name).resolve().is_relative_to(home.resolve()):
                raise SystemExit('Unsafe runner archive path')
        source.extractall(home)
    env = dict(os.environ, ANDROID_HOME=str(args.sdk), PATH=str(args.sdk / 'platform-tools') + os.pathsep + os.environ['PATH'])
    token = json.loads(gh('api', '-X', 'POST', 'repos/' + args.repository + '/actions/runners/registration-token'))['token']
    configure = dict(env, ACTIONS_RUNNER_INPUT_TOKEN=token)
    report = {'repository': args.repository, 'ref': args.ref, 'label': label, 'ephemeral': True, 'default_labels': False}
    try:
        with (home / 'configure.log').open('w') as log:
            subprocess.run([str(home / 'config.sh'), '--unattended', '--ephemeral', '--no-default-labels', '--url', 'https://github.com/' + args.repository, '--name', label, '--labels', label], cwd=home, env=configure, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=90)
        del configure['ACTIONS_RUNNER_INPUT_TOKEN']
        token = None
        # The workflow uses the random runner label as its run name. This
        # identifies our dispatch even if another maintainer dispatches one.
        gh('workflow', 'run', 'android-runtime.yml', '--repo', args.repository, '--ref', args.ref, '-f', 'serial=' + args.serial, '-f', 'runner_label=' + label)
        run_id = None
        for _ in range(30):
            runs = json.loads(gh('run', 'list', '--repo', args.repository, '--workflow', 'android-runtime.yml', '--event', 'workflow_dispatch', '--limit', '20', '--json', 'databaseId,displayTitle,url'))
            matches = [r for r in runs if r['displayTitle'] == label]
            if matches:
                run_id = matches[0]['databaseId']
                report['workflow_url'] = matches[0]['url']
                report['workflow_run_id'] = run_id
                break
            time.sleep(2)
        if run_id is None:
            raise RuntimeError('Cannot identify the dispatched device workflow')
        with (home / 'runner.log').open('w') as log:
            process = subprocess.Popen([str(home / 'run.sh')], cwd=home, env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                report['runner_exit'] = process.wait(timeout=1200)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=30)
                raise RuntimeError('One-shot device CI exceeded its bounded duration')
        report['runner_finished'] = True
        for _ in range(60):
            run = json.loads(gh('run', 'view', str(run_id), '--repo', args.repository, '--json', 'status,conclusion,headSha'))
            if run['status'] == 'completed':
                report['workflow_conclusion'] = run['conclusion']
                report['head_sha'] = run['headSha']
                break
            time.sleep(2)
        if report.get('workflow_conclusion') != 'success':
            raise RuntimeError('Device workflow did not complete successfully')
    finally:
        runners = json.loads(gh('api', 'repos/' + args.repository + '/actions/runners'))['runners']
        for runner in runners:
            if runner['name'] == label:
                gh('api', '-X', 'DELETE', 'repos/' + args.repository + '/actions/runners/' + str(runner['id']))
        report['registration_removed'] = True
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        # Ephemeral credentials should not remain in the local diagnostics.
        for name in ('.credentials', '.credentials_rsaparams', '.runner'):
            (home / name).unlink(missing_ok=True)
    print(json.dumps(report))
    return 0 if report.get('runner_exit') == 0 and report.get('workflow_conclusion') == 'success' and report.get('registration_removed') else 1


if __name__ == '__main__':
    raise SystemExit(main())
