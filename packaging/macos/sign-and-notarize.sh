#!/bin/sh
# Run only for an explicitly authorized distribution, after release gates pass.
set -eu
STAGE=${1:?unpacked darwin distribution directory required}
VERSION=${2:?release version required}
OUTPUT=${3:?output pkg path required}
: "${REKA_SIGN_IDENTITY:?Developer ID Application identity required}"
: "${REKA_INSTALLER_IDENTITY:?Developer ID Installer identity required}"
: "${REKA_NOTARY_PROFILE:?notarytool keychain profile required}"
case "$VERSION" in ''|*[!0-9.]*) echo 'pkg version must contain digits and dots' >&2; exit 1;; esac
for NAME in reka rekactl; do
  codesign --force --sign "$REKA_SIGN_IDENTITY" --options runtime --timestamp "$STAGE/$NAME"
  codesign --verify --strict --verbose=2 "$STAGE/$NAME"
done
python3 - "$STAGE" <<'PYCODE'
import hashlib,json,sys
from pathlib import Path
stage=Path(sys.argv[1]);path=stage/'BUILD.json'
metadata=json.loads(path.read_text());metadata['signed']=True
metadata['notarization_scope']='outer installer package; see receipt'
for name in ('reka','rekactl'):
    binary=stage/name
    metadata['binaries'][name]={'bytes':binary.stat().st_size,'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
path.write_text(json.dumps(metadata,indent=2)+'\n')
PYCODE
pkgbuild --root "$STAGE" --identifier org.mimoproxy.reka --version "$VERSION" \
  --ownership recommended --install-location '/Library/Application Support/Reka/distribution' \
  --sign "$REKA_INSTALLER_IDENTITY" "$OUTPUT"
pkgutil --check-signature "$OUTPUT"
xcrun notarytool submit "$OUTPUT" --keychain-profile "$REKA_NOTARY_PROFILE" --wait
xcrun stapler staple "$OUTPUT"
xcrun stapler validate "$OUTPUT"
spctl --assess --type install --verbose=4 "$OUTPUT"

python3 - "$OUTPUT" <<'PYCODE'
import hashlib,json,sys
from pathlib import Path
path=Path(sys.argv[1]);path.with_suffix('.notarization.json').write_text(json.dumps({'package':path.name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'accepted':True,'stapled':True},indent=2)+'\n')
PYCODE
