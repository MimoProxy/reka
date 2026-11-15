#!/usr/bin/env python3
"""Record an Android library's build invocation and bind it to exact bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('library',type=Path)
parser.add_argument('--version',required=True)
args=parser.parse_args()
if not re.fullmatch(r'[0-9A-Za-z][0-9A-Za-z.+_-]{0,79}',args.version):parser.error('invalid version')
info=subprocess.check_output(['go','version','-m',str(args.library)],text=True)
settings={}
for line in info.splitlines():
    fields=line.strip().split('\t')
    if len(fields)==2 and fields[0]=='build' and '=' in fields[1]:
        key,value=fields[1].split('=',1);settings[key]=value
if settings.get('GOOS')!='android' or settings.get('GOARCH')!='arm64':raise SystemExit('expected android/arm64 library')
result=dict(version=args.version,sha256=hashlib.sha256(args.library.read_bytes()).hexdigest(),source_revision=settings.get('vcs.revision'),dirty=settings.get('vcs.modified')=='true',target='android/arm64',build_info=info)
args.library.with_suffix('.build.json').write_text(json.dumps(result,indent=2)+'\n')
