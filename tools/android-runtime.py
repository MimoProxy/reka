#!/usr/bin/env python3
"""Run the production JNI acceptance on one explicitly selected Android device."""
import argparse
import json
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--adb', default='adb')
    parser.add_argument('--apk', default='bin/android/reka-libtest.apk')
    parser.add_argument('--skip-install', action='store_true', help='use the already installed acceptance APK')
    parser.add_argument('--vpn', action='store_true')
    parser.add_argument('--full', action='store_true', help='VPN test: use both default routes; requires explicit host authorization')
    parser.add_argument('--grant-vpn', action='store_true', help='test devices only: grant this test package VPN appop')
    parser.add_argument('--output', default='bin/android/runtime.json')
    args = parser.parse_args()
    if args.full and not args.vpn:
        parser.error('--full requires --vpn')
    adb = [args.adb, '-s', args.serial]
    def run(*command):
        return subprocess.check_output(adb + list(command), text=True, stderr=subprocess.STDOUT, timeout=30)
    package = 'org.mimoproxy.reka.test'
    if not args.skip_install:
        run('install', '-r', args.apk)
    run('shell', 'am', 'force-stop', package)
    if args.grant_vpn:
        run('shell', 'appops', 'set', package, 'ACTIVATE_VPN', 'allow')
    command = ['shell', 'am', 'start', '-W', '-n', package + '/.MainActivity']
    if args.vpn:
        command += ['--ez', 'vpn', 'true']
    if args.full:
        command += ['--ez', 'full', 'true']
    launch = run(*command)
    pid = ''
    for _ in range(20):
        try:
            pid = run('shell', 'pidof', package).strip()
        except subprocess.CalledProcessError:
            pass
        if pid:
            break
        time.sleep(.2)
    if not pid:
        raise RuntimeError('acceptance activity did not start')
    tag = 'RekaVPNTest' if args.vpn else 'RekaTest'
    log = ''
    for _ in range(120):
        log = run('logcat', '-d', '--pid=' + pid, '-v', 'raw', '-s', tag + ':I', '*:S')
        if 'RESULT PASS' in log or 'RESULT FAIL' in log:
            break
        time.sleep(1)
    result = dict(mode='vpn' if args.vpn else 'loopback', full_default_routes=args.full, api=run('shell', 'getprop', 'ro.build.version.sdk').strip(), abi=run('shell', 'getprop', 'ro.product.cpu.abi').strip(), model=run('shell', 'getprop', 'ro.product.model').strip(), emulator=run('shell', 'getprop', 'ro.kernel.qemu').strip() == '1', passed='RESULT PASS' in log, launch=launch, pid=pid, log=log)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(log)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
