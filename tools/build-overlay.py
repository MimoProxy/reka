#!/usr/bin/env python3
"""Generate a pinned, fail-closed Go build overlay; never edit module caches."""
import hashlib
import json
from pathlib import Path
import subprocess
import shutil
ROOT=Path(__file__).resolve().parents[1]
info=json.loads(subprocess.check_output(['go','list','-m','-json','github.com/sagernet/sing-box'],cwd=ROOT))
if info.get('Version')!='v1.14.4' or info.get('Replace'):
    raise SystemExit('Review the Reka ECH overlay before changing the pinned sing-box version')
source=Path(info['Dir'])/'common/tls/ech.go'
if hashlib.sha256(source.read_bytes()).hexdigest()!='0687c20186a1a8f9a7c6cbf091c6e0461e61f9c93193a61bf3d89df1f1c622e6':
    raise SystemExit('Pinned ECH source changed; review the overlay before building')
# Go deliberately forbids overlays inside GOMODCACHE. Work from an exact
# generated copy and a separate modfile; the checked-in module is unchanged.
copy=ROOT/'bin/upstream/sing-box'
if not copy.exists():
    copy.parent.mkdir(parents=True,exist_ok=True)
    shutil.copytree(info['Dir'],copy)
original=Path(info['Dir'])
expected={str(p.relative_to(original)):hashlib.sha256(p.read_bytes()).hexdigest() for p in original.rglob('*') if p.is_file()}
actual={str(p.relative_to(copy)):hashlib.sha256(p.read_bytes()).hexdigest() for p in copy.rglob('*') if p.is_file()}
if expected!=actual:
    raise SystemExit('Generated upstream copy differs from the locked module; remove bin/upstream and retry')
source=copy/'common/tls/ech.go'
if hashlib.sha256(source.read_bytes()).hexdigest()!='0687c20186a1a8f9a7c6cbf091c6e0461e61f9c93193a61bf3d89df1f1c622e6':
    raise SystemExit('Generated upstream copy changed; remove bin/upstream and retry')
modfile=ROOT/'bin/build.mod'
modfile.write_text((ROOT/'go.mod').read_text()+'\nreplace github.com/sagernet/sing-box => '+json.dumps('./bin/upstream/sing-box')+'\n')
shutil.copyfile(ROOT/'go.sum',ROOT/'bin/build.sum')
target=ROOT/'bin/build-overlay.json'
target.parent.mkdir(exist_ok=True)
target.write_text(json.dumps({'Replace':{str(source):str(ROOT/'internal/backend/sagernet/buildoverlay/ech.go.txt')}})+'\n')
print(target)
