#!/usr/bin/env python3
"""Fetch the pinned official Kotlin command-line compiler into bin/toolchains."""
import hashlib
from pathlib import Path
import shutil
import urllib.request
import zipfile

VERSION = '2.4.21'
SHA256 = '7cc140e76daf416a0424a5557f99afd7ca89ebd463ea1101261e3e01c33e75cd'
ROOT = Path(__file__).resolve().parents[1] / 'bin/toolchains'


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    archive = ROOT / ('kotlin-compiler-' + VERSION + '.zip')
    if not archive.exists():
        temporary = archive.with_suffix('.download')
        with urllib.request.urlopen('https://github.com/JetBrains/kotlin/releases/download/v' + VERSION + '/' + archive.name, timeout=60) as response, temporary.open('wb') as output:
            shutil.copyfileobj(response, output)
        temporary.replace(archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise SystemExit('Kotlin compiler archive checksum mismatch: ' + str(archive))
    destination = ROOT / ('kotlin-' + VERSION)
    if not (destination / 'kotlinc/bin/kotlinc').exists():
        destination.mkdir(exist_ok=True)
        with zipfile.ZipFile(archive) as source:
            for item in source.infolist():
                target = (destination / item.filename).resolve()
                if not target.is_relative_to(destination.resolve()):
                    raise SystemExit('Unsafe compiler archive path')
            source.extractall(destination)
        for path in (destination / 'kotlinc/bin').iterdir():
            if path.is_file():
                path.chmod(0o755)
    print(destination / 'kotlinc')


if __name__ == '__main__':
    main()
