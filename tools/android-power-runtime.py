#!/usr/bin/env python3
"""Start/observe the test APK's diagnostic or uncharged idle A/B run."""
import argparse
import json
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', default='adb')
    parser.add_argument('--serial', required=True)
    parser.add_argument('--start', action='store_true')
    parser.add_argument('--minutes', type=int, default=30)
    parser.add_argument('--diagnostic', action='store_true', help='15-second phases; permits charging, never counts as power acceptance')
    parser.add_argument('--wait', type=int, default=0, help='maximum seconds to observe; zero reads once')
    parser.add_argument('--output', default='bin/android/power.json')
    args = parser.parse_args()
    adb = [args.adb, '-s', args.serial]

    def run(*command):
        return subprocess.check_output(adb + list(command), text=True, stderr=subprocess.STDOUT, timeout=30)

    if args.start:
        run('shell', 'am', 'force-stop', 'org.mimoproxy.reka.test')
        command = ['shell', 'am', 'start', '-W', '-n', 'org.mimoproxy.reka.test/.MainActivity', '--ei', 'battery-minutes', str(args.minutes)]
        if args.diagnostic:
            command += ['--ez', 'diagnostic', 'true', '--ei', 'seconds', '15']
        print(run(*command).strip(), flush=True)
    pid = run('shell', 'pidof', 'org.mimoproxy.reka.test').strip()
    if args.start and args.wait == 0:
        print('started pid=' + pid + '; read the current report separately to confirm preflight and phase', flush=True)
        return 0
    deadline = time.monotonic() + args.wait
    last = None
    while True:
        try:
            raw = run('shell', 'cat', '/sdcard/Android/data/org.mimoproxy.reka.test/files/power-report.json')
            result = json.loads(raw)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError) as error:
            if time.monotonic() >= deadline:
                print('report unavailable: ' + str(type(error).__name__), flush=True)
                return 2
            time.sleep(2)
            continue
        if str(result.get('pid')) == pid:
            path = Path(args.output)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(result, indent=2) + '\n')
            state = result.get('state')
            if state != last:
                print('state=' + str(state), flush=True)
                last = state
            if state in ('complete', 'failed'):
                if state == 'failed':
                    print(result.get('error'), flush=True)
                return 0 if state == 'complete' else 1
        if time.monotonic() >= deadline:
            return 2
        time.sleep(2)


if __name__ == '__main__':
    raise SystemExit(main())
