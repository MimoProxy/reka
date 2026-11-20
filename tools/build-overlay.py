#!/usr/bin/env python3
"""Generate pinned overlays for scoped ECH and component lifetime corrections.

Go refuses overlays for files inside the module cache, so this script
copies the locked sing-box module to bin/upstream/sing-box, verifies the
copy byte for byte, points a separate bin/build.mod at it, and writes an
overlay that replaces selected files of the copy. The checked-in go.mod and the
module cache are never modified.

It fails closed: a different sing-box version, a changed upstream file or
a modified copy stops the build until the overlay is reviewed again. It
prints the overlay path for the Makefile.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from upstream_patches import MODULES

ROOT = Path(__file__).resolve().parents[1]
PINNED_VERSION = 'v1.14.4'
PINNED_ECH_SHA256 = '0687c20186a1a8f9a7c6cbf091c6e0461e61f9c93193a61bf3d89df1f1c622e6'
ECH_FILE = 'common/tls/ech.go'
REPLACEMENT = ROOT / 'internal/backend/sagernet/buildoverlay/ech.go.txt'
TROJAN_FILE = 'transport/trojan/service.go'
PINNED_TROJAN_SHA256 = '6ffe5d2408d4b391b2e625de0777debecbd02c1a01c1b079f46c18fcac114edf'


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_hashes(root):
    return {str(p.relative_to(root)): sha256(p) for p in root.rglob('*') if p.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'bin')
    output = parser.parse_args().output_dir.resolve()

    def module_path(path):
        return './' + path.relative_to(ROOT).as_posix() if output == ROOT / 'bin' else str(path)

    # Inspect the root lockfile, even when called from a build already using
    # the generated modfile/overlay. Otherwise our own replacements look like
    # unreviewed changes to the source dependency pins.
    module_env = dict(os.environ, GOFLAGS='')
    info = json.loads(subprocess.check_output(
        ['go', 'list', '-m', '-json', 'github.com/sagernet/sing-box'], cwd=ROOT, env=module_env))
    if info.get('Version') != PINNED_VERSION or info.get('Replace'):
        raise SystemExit('Review the Reka ECH overlay before changing the pinned sing-box version')
    if 'Dir' not in info:
        # A fresh checkout (CI) has not downloaded the module yet.
        info = json.loads(subprocess.check_output(
            ['go', 'mod', 'download', '-json', 'github.com/sagernet/sing-box@' + PINNED_VERSION], cwd=ROOT, env=module_env))
    original = Path(info['Dir'])
    if sha256(original / ECH_FILE) != PINNED_ECH_SHA256:
        raise SystemExit('Pinned ECH source changed; review the overlay before building')
    if sha256(original / TROJAN_FILE) != PINNED_TROJAN_SHA256:
        raise SystemExit('Pinned Trojan source changed; review the overlay before building')

    copy = output / 'upstream/sing-box'
    if not copy.exists():
        copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(original, copy)
    if tree_hashes(original) != tree_hashes(copy):
        raise SystemExit('Generated upstream copy differs from the locked module; remove bin/upstream and retry')
    source = copy / ECH_FILE
    if sha256(source) != PINNED_ECH_SHA256:
        raise SystemExit('Generated upstream copy changed; remove bin/upstream and retry')

    replacements = {'github.com/sagernet/sing-box': module_path(copy)}
    extra_overlays = {}
    patches = output / 'upstream-patches'
    patches.mkdir(exist_ok=True)
    for name, (version, files) in MODULES.items():
        module = json.loads(subprocess.check_output(['go', 'list', '-m', '-json', name], cwd=ROOT, env=module_env))
        if module.get('Version') != version or module.get('Replace'):
            raise SystemExit('Review pinned component patches before changing ' + name)
        if 'Dir' not in module:
            module = json.loads(subprocess.check_output(['go', 'mod', 'download', '-json', name + '@' + version], cwd=ROOT, env=module_env))
        module_root = Path(module['Dir'])
        module_copy = output / 'upstream' / name.rsplit('/', 1)[1]
        if not module_copy.exists():
            shutil.copytree(module_root, module_copy)
        if tree_hashes(module_root) != tree_hashes(module_copy):
            raise SystemExit('Generated upstream copy differs from locked ' + name)
        for filename, (digest, transform) in files.items():
            source_file = module_copy / filename
            if sha256(source_file) != digest:
                raise SystemExit('Pinned source changed; review patch for ' + name + '/' + filename)
            patched_file = patches / (name.rsplit('/', 1)[1] + '-' + filename.replace('/', '-') + '.txt')
            patched_file.write_text(transform(source_file.read_text()))
            subprocess.check_call(['gofmt', '-w', str(patched_file)])
            extra_overlays[str(source_file)] = str(patched_file)
        replacements[name] = module_path(module_copy)
    modfile = output / 'build.mod'
    modfile.write_text((ROOT / 'go.mod').read_text() + ''.join('\nreplace ' + name + ' => ' + json.dumps(path) + '\n' for name, path in replacements.items()))
    shutil.copyfile(ROOT / 'go.sum', output / 'build.sum')

    target = output / 'build-overlay.json'
    target.parent.mkdir(exist_ok=True)
    # Reka's loopback test/tool node uses this inbound. A single stream Read
    # may return a partial authentication key (notably an HTTPUpgrade cache).
    # Keep the locked source copy intact and generate the two-line correction.
    trojan = (copy / TROJAN_FILE).read_text()
    trojan = trojan.replace('"encoding/binary"\n', '"encoding/binary"\n\t"io"\n', 1)
    trojan = trojan.replace('n, err := conn.Read(key[:])', 'n, err := io.ReadFull(conn, key[:])', 1)
    patched = output / 'trojan-service-overlay.go.txt'
    patched.write_text(trojan)
    target.write_text(json.dumps({'Replace': {str(source): str(REPLACEMENT), str(copy / TROJAN_FILE): str(patched), **extra_overlays}}) + '\n')
    print(target)


if __name__ == '__main__':
    main()
