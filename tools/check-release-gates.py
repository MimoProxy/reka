#!/usr/bin/env python3
"""Report formal release readiness; staging builds remain available separately."""
import json
from pathlib import Path
source=Path(__file__).resolve().parents[1]/'docs/release-gates.json'
if not source.exists():
    # Gates are kept with the maintainers' release records, not in the
    # repository; without them nothing counts as release-ready.
    print(json.dumps({'formal_release_ready':False,'pending':{'release_gates':'missing '+str(source)}},indent=2))
    raise SystemExit(1)
gates=json.loads(source.read_text())
pending={key:value for key,value in gates['checks'].items() if value!='passed'}
print(json.dumps({'formal_release_ready':not pending and gates['formal_release_ready'],'pending':pending},indent=2))
raise SystemExit(0 if not pending and gates['formal_release_ready'] else 1)
