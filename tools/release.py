#!/usr/bin/env python3
"""Build reviewable local distribution archives, checksums and exact sources.

No upload, signing or release creation is performed by this command.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TAGS = 'with_gvisor,with_utls,badlinkname,tfogo_checklinkname0,reka_minimal'
LDFLAGS = '-X runtime.godebugDefault=multipathtcp=0,tlssha1=1 -checklinkname=0 -s -w -buildid='
TARGETS = ['darwin/arm64', 'darwin/amd64', 'windows/amd64', 'windows/arm64', 'linux/amd64', 'linux/arm64']


def run(args, **kwargs):
    return subprocess.check_output(args, cwd=ROOT, **kwargs)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def copy_public_docs(destination):
    """Ship repository documentation, excluding local maintainer evidence."""
    for raw in run(['git', 'ls-files', '-z', '--', 'docs']).split(b'\0'):
        if not raw:
            continue
        source = ROOT / os.fsdecode(raw)
        target = destination / source.relative_to(ROOT / 'docs')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def json_objects(raw):
    text = raw.decode()
    decoder = json.JSONDecoder()
    while text.strip():
        value, end = decoder.raw_decode(text.lstrip())
        yield value
        text = text.lstrip()[end:]


def licenses(stage, env, flags, packages=None):
    modules = {}
    raw = run(['go', 'list', *flags, '-tags', TAGS, '-deps', '-json', *(packages or ['./cmd/reka', './cmd/rekactl'])], env=env)
    for package in json_objects(raw):
        module = package.get('Module')
        if module and not module.get('Main'):
            modules[module['Path']] = module
    records = []
    destination = stage / 'licenses'
    destination.mkdir()
    goroot=Path(run(["go","env","GOROOT"]).decode().strip())
    license_file=next((p for p in (goroot/"LICENSE",goroot.parent/"LICENSE") if p.exists()),None)
    if license_file is None: raise RuntimeError("Go toolchain license not found")
    shutil.copyfile(license_file,destination/"Go-LICENSE")
    for name, module in sorted(modules.items()):
        directory = Path(module.get('Replace', module)['Dir'])
        files = []
        for file in sorted(directory.iterdir()):
            if file.is_file() and file.name.upper().startswith(('LICENSE', 'COPYING', 'NOTICE')):
                target = destination / (name.replace('/', '_') + '__' + file.name)
                shutil.copyfile(file, target)
                files.append(str(target.relative_to(stage)))
        if not files:
            raise RuntimeError('missing license for linked module: ' + name)
        records.append(dict(path=name, version=module.get('Version'), notices=files))
    (stage / 'MODULES.json').write_text(json.dumps(records, indent=2) + '\n')


def archive(stage, path, epoch):
    files = sorted(p for p in stage.rglob('*') if p.is_file())
    if path.suffix == '.zip':
        with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as output:
            for file in files:
                info = zipfile.ZipInfo(str(Path(stage.name) / file.relative_to(stage)), time.gmtime(max(epoch, 315532800))[:6])
                info.external_attr = (file.stat().st_mode & 0xffff) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                output.writestr(info, file.read_bytes())
    else:
        with path.open('wb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=epoch) as compressed, tarfile.open(fileobj=compressed, mode='w') as output:
            for file in files:
                info = output.gettarinfo(str(file), arcname=str(Path(stage.name) / file.relative_to(stage)))
                info.uid = info.gid = 0
                info.uname = info.gname = ''
                info.mtime = epoch
                with file.open('rb') as contents:
                    output.addfile(info, contents)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default='1.0.0-dev')
    parser.add_argument('--targets', nargs='+', default=TARGETS, choices=TARGETS)
    parser.add_argument('--android-library', type=Path, help='freshly built arm64 libreka.so to package')
    parser.add_argument('--output', default='bin/dist')
    parser.add_argument('--macos-pkg', action='store_true', help='also build unsigned macOS installer packages (macOS host only)')
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9A-Za-z][0-9A-Za-z.+_-]{0,79}', args.version):
        parser.error('invalid version')
    pkg_version = args.version.split('-', 1)[0].split('+', 1)[0]
    if args.macos_pkg and not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', pkg_version):
        parser.error('macOS packages require a numeric major.minor.patch version')
    output = ROOT / args.output / args.version
    output.mkdir(parents=True, exist_ok=True)
    overlay = run(['python3', 'tools/build-overlay.py']).decode().strip()
    flags = ['-modfile', str(ROOT / 'bin/build.mod'), '-overlay', overlay]
    commit = run(['git', 'rev-parse', 'HEAD']).decode().strip()
    epoch = int(os.environ.get('SOURCE_DATE_EPOCH', run(['git', 'show', '-s', '--format=%ct', 'HEAD']).decode().strip()))
    dirty = bool(run(['git', 'status', '--porcelain']))
    built = []
    source_modules = set()
    for target in args.targets:
        goos, goarch = target.split('/')
        name = 'reka-' + args.version + '-' + target.replace('/', '-')
        stage = output / name
        if stage.exists():
            shutil.rmtree(stage)
        stage.mkdir()
        env = dict(os.environ, GOOS=goos, GOARCH=goarch, CGO_ENABLED='0')
        for command in ('reka', 'rekactl'):
            filename = command + ('.exe' if goos == 'windows' else '')
            run(['go', 'build', *flags, '-trimpath', '-tags', TAGS, '-ldflags', LDFLAGS + ' -X main.version=' + args.version, '-o', str(stage / filename), './cmd/' + command], env=env)
        copy_public_docs(stage / 'docs')
        shutil.copytree(ROOT / 'examples', stage / 'examples', ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copytree(ROOT / 'packaging', stage / 'packaging')
        for file in ('LICENSE', 'README.md', 'README.zh-CN.md'):
            shutil.copyfile(ROOT / file, stage / file)
        licenses(stage, env, flags)
        source_modules.update((m['path'], m['version']) for m in json.loads((stage / 'MODULES.json').read_text()))
        metadata = dict(version=args.version, target=target, commit=commit, dirty=dirty, go=run(['go', 'version']).decode().strip(), tags=TAGS, signed=False, notarized=False, source_archive='reka-' + args.version + '-source.tar.gz', binaries={file.name: dict(bytes=file.stat().st_size, sha256=sha(file)) for file in stage.iterdir() if file.is_file() and file.name.startswith(('reka.exe', 'rekactl.exe', 'reka', 'rekactl'))})
        (stage / 'BUILD.json').write_text(json.dumps(metadata, indent=2) + '\n')
        extension = '.zip' if goos == 'windows' else '.tar.gz'
        path = output / (name + extension)
        archive(stage, path, epoch)
        built.append(path)
        print(path.relative_to(ROOT), flush=True)
        if args.macos_pkg and goos=='darwin':
            package=output/(name+'.pkg')
            pkg_namespace = 'staging.' if '-' in args.version else 'distribution.'
            run(['pkgbuild','--root',str(stage),'--identifier','org.mimoproxy.reka.'+pkg_namespace+goarch,'--version',pkg_version,'--ownership','recommended','--install-location','/Library/Application Support/Reka/distribution',str(package)])
            built.append(package)
            print(package.relative_to(ROOT),flush=True)
    if args.android_library:
        library = args.android_library.resolve()
        library_info=json.loads(library.with_suffix('.build.json').read_text())
        if library_info['version']!=args.version or library_info['sha256']!=sha(library):
            raise RuntimeError('Android library metadata/version mismatch; rebuild with REKA_VERSION='+args.version)
        if library_info['source_revision']!=commit:
            raise RuntimeError('Android library is from another source commit; rebuild before packaging')
        stage = output / ('reka-' + args.version + '-android-arm64')
        if stage.exists():
            shutil.rmtree(stage)
        (stage / 'jniLibs/arm64-v8a').mkdir(parents=True)
        shutil.copyfile(library, stage / 'jniLibs/arm64-v8a/libreka.so')
        shutil.copyfile(library.with_suffix('.build.json'),stage/'LIBRARY-BUILD.json')
        shutil.copyfile(ROOT/'mobile/android/consumer-rules.pro',stage/'consumer-rules.pro')
        for folder in ('java', 'kotlin'):
            shutil.copytree(ROOT / 'mobile/android' / folder, stage / folder)
        copy_public_docs(stage / 'docs')
        sdk=Path(os.environ.get('ANDROID_HOME',str(Path.home()/'Library/Android/sdk')))
        ndk=Path(os.environ['ANDROID_NDK_HOME']) if os.environ.get('ANDROID_NDK_HOME') else sorted((sdk/'ndk').iterdir(),key=lambda p:tuple(map(int,p.name.split('.'))))[-1]
        host=next((ndk/'toolchains/llvm/prebuilt').iterdir())
        android_env=dict(os.environ,GOOS='android',GOARCH='arm64',CGO_ENABLED='1',CC=str(host/'bin/aarch64-linux-android26-clang'))
        licenses(stage,android_env,flags,['./mobile/jni'])
        source_modules.update((m['path'],m['version']) for m in json.loads((stage/'MODULES.json').read_text()))
        shutil.copyfile(ROOT / 'LICENSE', stage / 'LICENSE')
        (stage / 'BUILD.json').write_text(json.dumps(dict(version=args.version, commit=commit, dirty=dirty, target='android/arm64', library_sha256=sha(library), signed=False, abi='arm64-v8a', min_api=26, source_archive='reka-' + args.version + '-source.tar.gz'), indent=2) + '\n')
        path = output / (stage.name + '.zip')
        archive(stage, path, epoch)
        built.append(path)
    # Include the exact working source, including new files; no credentials,
    # ignored build output or module caches enter the corresponding source.
    stage = output / ('reka-' + args.version + '-source')
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir()
    files = run(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard']).decode().split('\0')
    hashes = {}
    for name in files:
        if not name:
            continue
        source = ROOT / name
        if source.is_file() and not source.is_relative_to(output):
            destination = stage / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            destination.chmod(source.stat().st_mode)
            hashes[name] = sha(source)
    # Include cached upstream module source archives for every linked module,
    # plus available graph metadata. These are usable as a local GOPROXY.
    cache=Path(run(['go','env','GOMODCACHE']).decode().strip())/'cache/download'
    def escaped(path):
        return ''.join('!'+c.lower() if c.isupper() else c for c in path)
    for module,version in sorted(source_modules):
        if not version:
            raise RuntimeError('missing pinned source version: '+module)
        relative=Path(escaped(module))/'@v'
        for extension in ('.zip','.mod','.info'):
            original=cache/relative/(version+extension)
            if not original.exists():
                raise RuntimeError('missing corresponding source archive: '+str(original))
            target=stage/'module-cache'/relative/original.name
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(original,target)
    # Local replacements expose graph metadata that package builds can prune.
    # Allow Go to record those .mod checksums in the generated build.sum;
    # listing modules downloads metadata, not unlinked platform library zips.
    # The checked-in go.mod/go.sum remain untouched.
    for metadata in json_objects(run(['go','list','-mod=mod','-modfile',str(ROOT/'bin/build.mod'),'-m','-json','all'])):
        version=metadata.get('Version')
        if not version:
            continue
        relative=Path(escaped(metadata['Path']))/'@v'
        for extension in ('.mod','.info'):
            original=cache/relative/(version+extension)
            target=stage/'module-cache'/relative/original.name
            if original.exists() and not target.exists():
                target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(original,target)
    (stage/'DEPENDENCY-SOURCES.json').write_text(json.dumps([dict(path=m,version=v) for m,v in sorted(source_modules)],indent=2)+'\n')
    (stage / 'SOURCE.json').write_text(json.dumps(dict(commit=commit, dirty=dirty, files=hashes), indent=2) + '\n')
    path = output / (stage.name + '.tar.gz')
    archive(stage, path, epoch)
    built.append(path)
    (output / 'SHA256SUMS').write_text(''.join(sha(path) + '  ' + path.name + '\n' for path in built))
    (output / 'artifacts.json').write_text(json.dumps([dict(file=path.name, bytes=path.stat().st_size, sha256=sha(path)) for path in built], indent=2) + '\n')


if __name__ == '__main__':
    main()
