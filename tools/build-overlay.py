#!/usr/bin/env python3
"""Generate the pinned Go build overlay that drops unused upstream ECH code.

Go refuses overlays for files inside the module cache, so this script
copies the locked sing-box module to bin/upstream/sing-box, verifies the
copy byte for byte, points a separate bin/build.mod at it, and writes an
overlay that replaces one file of the copy. The checked-in go.mod and the
module cache are never modified.

It fails closed: a different sing-box version, a changed upstream file or
a modified copy stops the build until the overlay is reviewed again. It
prints the overlay path for the Makefile.
"""
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PINNED_VERSION = 'v1.14.4'
PINNED_ECH_SHA256 = '0687c20186a1a8f9a7c6cbf091c6e0461e61f9c93193a61bf3d89df1f1c622e6'
ECH_FILE = 'common/tls/ech.go'
REPLACEMENT = ROOT / 'internal/backend/sagernet/buildoverlay/ech.go.txt'


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_hashes(root):
    return {str(p.relative_to(root)): sha256(p) for p in root.rglob('*') if p.is_file()}


def main():
    info = json.loads(subprocess.check_output(
        ['go', 'list', '-m', '-json', 'github.com/sagernet/sing-box'], cwd=ROOT))
    if info.get('Version') != PINNED_VERSION or info.get('Replace'):
        raise SystemExit('Review the Reka ECH overlay before changing the pinned sing-box version')
    original = Path(info['Dir'])
    if sha256(original / ECH_FILE) != PINNED_ECH_SHA256:
        raise SystemExit('Pinned ECH source changed; review the overlay before building')

    copy = ROOT / 'bin/upstream/sing-box'
    if not copy.exists():
        copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(original, copy)
    if tree_hashes(original) != tree_hashes(copy):
        raise SystemExit('Generated upstream copy differs from the locked module; remove bin/upstream and retry')
    source = copy / ECH_FILE
    if sha256(source) != PINNED_ECH_SHA256:
        raise SystemExit('Generated upstream copy changed; remove bin/upstream and retry')

    modfile = ROOT / 'bin/build.mod'
    modfile.write_text((ROOT / 'go.mod').read_text()
                       + '\nreplace github.com/sagernet/sing-box => ' + json.dumps('./bin/upstream/sing-box') + '\n')
    shutil.copyfile(ROOT / 'go.sum', ROOT / 'bin/build.sum')

    target = ROOT / 'bin/build-overlay.json'
    target.parent.mkdir(exist_ok=True)
    target.write_text(json.dumps({'Replace': {str(source): str(REPLACEMENT)}}) + '\n')
    print(target)


if __name__ == '__main__':
    main()
