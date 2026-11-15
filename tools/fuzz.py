#!/usr/bin/env python3
"""Run each fuzz target in a separate process; preserve logs and exact commands."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
TAGS = 'with_gvisor,with_utls,badlinkname,tfogo_checklinkname0,reka_minimal'
TARGETS = [('internal/config/model', 'FuzzDocuments'), ('internal/config/importer', 'FuzzSubscriptions'), ('internal/rulesdata', 'FuzzRuleResources'), ('internal/rulesdata', 'FuzzDecodeMRS'), ('internal/dns', 'FuzzDNSMessages'), ('internal/control', 'FuzzFrames')]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, default=30)
    parser.add_argument('--output', default='bin/fuzz')
    args = parser.parse_args()
    if args.seconds < 1:
        parser.error('seconds must be positive')
    output = ROOT / args.output
    output.mkdir(parents=True, exist_ok=True)
    overlay=subprocess.check_output(["python3",str(ROOT/"tools/build-overlay.py")],cwd=ROOT,text=True).strip()
    results = []
    for package, target in TARGETS:
        command = ['go', 'test', '-modfile', str(ROOT/'bin/build.mod'), '-overlay', overlay, '-tags', TAGS, '-ldflags', '-checklinkname=0', '-run=^$', '-fuzz=^' + target + '$', '-fuzztime=' + str(args.seconds) + 's', '-parallel=2', './' + package]
        start = time.monotonic()
        with (output / (target + '.log')).open('w') as log:
            result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, env=dict(os.environ, CGO_ENABLED='1'), timeout=args.seconds + 180)
        results.append(dict(target=target, command=command, seconds=round(time.monotonic() - start, 2), passed=result.returncode == 0))
        print(target, 'PASS' if result.returncode == 0 else 'FAIL', flush=True)
    (output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    return 0 if all(result['passed'] for result in results) else 1

if __name__ == '__main__':
    raise SystemExit(main())
