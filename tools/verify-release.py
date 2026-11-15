#!/usr/bin/env python3
"""Validate staged archives without executing or extracting their contents."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import struct
import subprocess
import tarfile
import zipfile


def contents(path):
    if path.suffix == '.zip':
        with zipfile.ZipFile(path) as archive:
            return {name: archive.read(name) for name in archive.namelist() if not name.endswith('/')}
    with tarfile.open(path, 'r:gz') as archive:
        return {entry.name: archive.extractfile(entry).read() for entry in archive if entry.isfile()}


def elf_headers(data):
    assert data[:6] == b'\x7fELF\x02\x01', 'expected little-endian ELF64'
    offset, size, count = struct.unpack_from('<Q', data, 32)[0], struct.unpack_from('<H', data, 54)[0], struct.unpack_from('<H', data, 56)[0]
    return [struct.unpack_from('<IIQQQQQQ', data, offset + index * size) for index in range(count)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    checks = []
    for line in (args.directory / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split('  ', 1)
        path = args.directory / name
        assert path.parent == args.directory and path.name == name
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, name
        if path.suffix=='.pkg':
            listing=subprocess.check_output(['pkgutil','--payload-files',str(path)],text=True)
            assert './reka' in listing and './rekactl' in listing
            checks.append(dict(archive=name,target='unsigned macOS installer',passed=True))
            continue
        raw = contents(path)
        assert all(not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts for name in raw)
        prefixes = {PurePosixPath(name).parts[0] for name in raw}
        assert len(prefixes) == 1
        prefix = next(iter(prefixes)) + '/'
        files = {name[len(prefix):]: data for name, data in raw.items()}
        assert 'LICENSE' in files
        if 'SOURCE.json' in files:
            source = json.loads(files['SOURCE.json'])
            for filename, value in source['files'].items():
                assert hashlib.sha256(files[filename]).hexdigest() == value
            dependencies = json.loads(files['DEPENDENCY-SOURCES.json'])
            assert dependencies and any(name.startswith('module-cache/') and name.endswith('.zip') for name in files)
            checks.append(dict(archive=name, source_files=len(source['files']), dependency_sources=len(dependencies), passed=True))
            continue
        assert 'licenses/Go-LICENSE' in files
        metadata = json.loads(files['BUILD.json'])
        assert metadata['signed'] is False, 'staging archives must honestly declare signing status'
        for module in json.loads(files['MODULES.json']):
            assert module['notices'] and all(notice in files for notice in module['notices'])
        target = metadata['target']
        for filename, info in metadata.get('binaries', {}).items():
            assert len(files[filename]) == info['bytes']
            assert hashlib.sha256(files[filename]).hexdigest() == info['sha256']
            data = files[filename]
            if target.startswith('linux/'):
                assert all(header[0] != 3 for header in elf_headers(data)), 'Linux binary has a dynamic interpreter'
                assert struct.unpack_from('<H', data, 18)[0] == (183 if target.endswith('arm64') else 62)
            elif target.startswith('windows/'):
                assert data[:2] == b'MZ'
                pe = struct.unpack_from('<I', data, 60)[0]
                assert data[pe:pe+4] == b'PE\0\0'
                assert struct.unpack_from('<H', data, pe + 4)[0] == (0xaa64 if target.endswith('arm64') else 0x8664)
            elif target.startswith('darwin/'):
                assert data[:4] == b'\xcf\xfa\xed\xfe'
                assert struct.unpack_from('<I', data, 4)[0] == (0x100000c if target.endswith('arm64') else 0x1000007)
        if target.startswith('windows/'):
            assert 'packaging/windows/WINTUN-LICENSE.txt' in files
        if target == 'android/arm64':
            data = files['jniLibs/arm64-v8a/libreka.so']
            assert hashlib.sha256(data).hexdigest() == metadata['library_sha256']
            assert struct.unpack_from('<H', data, 18)[0] == 183
            assert all(header[7] >= 16384 for header in elf_headers(data) if header[0] == 1), 'Android PT_LOAD alignment below 16 KiB'
        checks.append(dict(archive=name, target=target, passed=True))
    print(json.dumps(checks, indent=2))


if __name__ == '__main__':
    main()
