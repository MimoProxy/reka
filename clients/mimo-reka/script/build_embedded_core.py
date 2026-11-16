#!/usr/bin/env python3
"""Build this workspace's native core with pinned release flags and provenance."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[3]
DEST = ROOT / 'clients/mimo-reka/.build/core'

def run(args, **kwargs):
    return subprocess.check_output(args, cwd=ROOT, **kwargs).decode().strip()

def main():
    spec = importlib.util.spec_from_file_location('reka_release', ROOT/'tools/release.py')
    release = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(release)
    arch = {'arm64': 'arm64', 'x86_64': 'amd64'}[platform.machine()]
    paths = ['cmd', 'internal', 'go.mod', 'go.sum', 'tools/build-overlay.py', 'tools/upstream_patches.py']
    commit = run(['git', 'log', '-1', '--format=%H', '--', *paths])
    files = run(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '--', *paths]).splitlines()
    hashes = {p: hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in files if (ROOT/p).is_file()}
    source_hash = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
    version = '1.0.0+' + commit[:7]
    dirty = bool(run(['git', 'status', '--porcelain', '--', *paths]))
    identity = dict(commit=commit, source_sha256=source_hash, version=version, target='darwin/'+arch,
                    tags=release.TAGS, go=run(['go', 'version']), dirty=dirty)
    DEST.mkdir(parents=True, exist_ok=True)
    metadata = DEST/'BUILD.json'
    if metadata.exists() and (DEST/'reka').exists():
        previous = json.loads(metadata.read_text())
        if all(previous.get(k) == v for k,v in identity.items()) and previous.get('sha256') == hashlib.sha256((DEST/'reka').read_bytes()).hexdigest():
            print(DEST/'reka'); return
    overlay = run(['python3', 'tools/build-overlay.py'])
    flags = ['-modfile', str(ROOT/'bin/build.mod'), '-overlay', overlay]
    env = os.environ | {'CGO_ENABLED': '0', 'GOOS': 'darwin', 'GOARCH': arch}
    subprocess.run(['go','build',*flags,'-trimpath','-tags',release.TAGS,'-ldflags',release.LDFLAGS+' -X main.version='+version,'-o',str(DEST/'reka'),'./cmd/reka'], cwd=ROOT, env=env, check=True)
    shutil.rmtree(DEST/'licenses', ignore_errors=True)
    release.licenses(DEST, env, flags, ['./cmd/reka'])
    shutil.copyfile(ROOT/'internal/compat/xhttp/ORIGIN.md', DEST/'licenses/XHTTP-ORIGIN.md')
    identity['sha256'] = hashlib.sha256((DEST/'reka').read_bytes()).hexdigest()
    identity['source_files'] = hashes
    metadata.write_text(json.dumps(identity, indent=2)+'\n')
    print(DEST/'reka')

if __name__ == '__main__': main()
