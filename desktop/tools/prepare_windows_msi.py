"""Bounded offline WiX 4 assembly preparation. Never executes WiX or an installer.

Inputs are a private, quiescent DATA directory and a separately reviewed binding.
This is NOT a Windows ACL/handle validator or native transaction authority.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import uuid
import xml.etree.ElementTree as ET

TARGET = 'x86_64-pc-windows-msvc'
SHELL = 'mobile-release-kit-desktop.exe'
PUBLISHER = 'mrk-windows-runtime-publish.exe'
NAMESPACE = uuid.UUID('40694ebf-3ae5-568c-b89a-d4d46075a688')
UPGRADE_CODE = str(uuid.uuid5(NAMESPACE, 'dev.mobile-release-kit.desktop:msi:x64')).upper()
NS = 'http://wixtoolset.org/schemas/v4/wxs'
LIMIT = 512 * 1024 * 1024
TOTAL = 1024 * 1024 * 1024
SOURCE_REQUIRED = {
    'desktop/github-ca.pem',
    'desktop/src-tauri/src/lib.rs',
    'desktop/src-tauri/src/lib_windows_packaging.rs',
    'desktop/src-tauri/src/runtime_manifest_data.rs',
    'desktop/src-tauri/src/runtime_hash_data.rs',
    'desktop/src-tauri/src/runtime_windows_version.rs',
    'desktop/src-tauri/src/runtime_publication_inputs.rs',
    'desktop/src-tauri/src/protocol.rs',
    'desktop/src-tauri/src/protocol_version.rs',
    'desktop/src-tauri/src/protocol_json.rs',
    'desktop/src-tauri/src/runtime_paths.rs',
    'desktop/src-tauri/src/error.rs',
    'desktop/tools/prepare_windows_embedded_payload.py',
    'desktop/tools/prepare_runtime.py',
    'desktop/src-tauri/src/runtime.rs', 'desktop/src-tauri/src/shell_windows.rs',
    'desktop/src-tauri/src/installed_runtime_windows.rs',
    'desktop/src-tauri/src/runtime_publication_windows.rs',
    'desktop/src-tauri/src/bin/windows_runtime_publish.rs',
    'desktop/native/windows-installed-native/src/publication.rs',
    'desktop/native/windows-installed-native/src/publication_exclusion.rs',
    'desktop/native/windows-installed-native/src/lib.rs',
    'desktop/src-tauri/build.rs', 'desktop/src-tauri/Cargo.toml',
    'desktop/src-tauri/Cargo.lock', 'desktop/src-tauri/tauri.conf.json',
}
# Exact cumulative successor implementation inputs; source/tree remains authoritative.
SOURCE_REQUIRED |= {
    'desktop/native/windows-installed-native/src/lib.rs',
    'desktop/native/windows-installed-native/src/publication.rs',
    'desktop/native/windows-installed-native/src/publication_exclusion.rs',
    'desktop/packaging/windows/native-transaction/CMakeLists.txt',
    'desktop/packaging/windows/native-transaction/Invoke-Lifecycle.ps1',
    'desktop/packaging/windows/native-transaction/native_tests.cpp',
    'desktop/packaging/windows/native-transaction/transaction.cpp',
    'desktop/src-tauri/src/apple_provisioning_windows_closed.rs',
    'desktop/src-tauri/src/application_project_binding_data.rs',
    'desktop/src-tauri/src/application_service.rs',
    'desktop/src-tauri/src/application_service_error_data.rs',
    'desktop/src-tauri/src/application_service_host_windows_closed.rs',
    'desktop/src-tauri/src/application_service_windows_closed.rs',
    'desktop/src-tauri/src/application_state_data.rs',
    'desktop/src-tauri/src/application_state_store.rs',
    'desktop/src-tauri/src/application_state_windows_closed.rs',
    'desktop/src-tauri/src/asset_commands.rs',
    'desktop/src-tauri/src/asset_session.rs',
    'desktop/src-tauri/src/asset_session_apple_key_material.rs',
    'desktop/src-tauri/src/asset_session_apple_p12_material.rs',
    'desktop/src-tauri/src/asset_session_apple_profile_material.rs',
    'desktop/src-tauri/src/asset_session_apple_windows_closed.rs',
    'desktop/src-tauri/src/asset_session_application_service.rs',
    'desktop/src-tauri/src/asset_session_application_service_windows_data.rs',
    'desktop/src-tauri/src/asset_session_vault_windows_closed.rs',
    'desktop/src-tauri/src/asset_source.rs',
    'desktop/src-tauri/src/bin/windows_runtime_publish.rs',
    'desktop/src-tauri/src/installed_runtime.rs',
    'desktop/src-tauri/src/installed_runtime_data.rs',
    'desktop/src-tauri/src/lib.rs',
    'desktop/src-tauri/src/lib_application.rs',
    'desktop/src-tauri/src/lib_platform_data.rs',
    'desktop/src-tauri/src/lib_ubuntu_packaging.rs',
    'desktop/src-tauri/src/lib_windows_packaging.rs',
    'desktop/src-tauri/src/protocol.rs',
    'desktop/src-tauri/src/protocol_json.rs',
    'desktop/src-tauri/src/protocol_json_common.rs',
    'desktop/src-tauri/src/protocol_version.rs',
    'desktop/src-tauri/src/runtime.rs',
    'desktop/src-tauri/src/runtime_hash_data.rs',
    'desktop/src-tauri/src/runtime_manifest_data.rs',
    'desktop/src-tauri/src/runtime_publication_inputs.rs',
    'desktop/src-tauri/src/runtime_publication_windows.rs',
    'desktop/src-tauri/src/runtime_windows_version.rs',
    'desktop/src-tauri/src/saved_command_apple_key.rs',
    'desktop/src-tauri/src/saved_command_apple_key_private.rs',
    'desktop/src-tauri/src/saved_command_apple_p12.rs',
    'desktop/src-tauri/src/saved_command_apple_p12_private.rs',
    'desktop/src-tauri/src/saved_command_apple_profile_private.rs',
    'desktop/src-tauri/src/saved_command_apple_signing.rs',
    'desktop/src-tauri/src/version_allocation_windows_data.rs',
    'desktop/tools/build_windows_transaction.py',
    'desktop/tools/ci_foundation.py',
    'desktop/tools/create_windows_validation_transform.py',
    'desktop/tools/prepare_windows_embedded_payload.py',
    'desktop/tools/prepare_windows_msi.py',
    'desktop/tools/prepare_windows_transaction_run.py',
    'desktop/tools/windows_build_command.py',
    'desktop/tools/windows_msi_transaction.py',
    'tests/desktop/test_windows_msi_preparation.py',
    'tests/desktop/test_windows_native_transaction.py',
}

class Refused(ValueError): pass

def need(ok, message):
    if not ok: raise Refused(message)

def digest(data): return hashlib.sha256(data).hexdigest()

def hex_value(value, length=64):
    need(isinstance(value, str) and re.fullmatch('[0-9a-f]{%d}' % length, value), 'invalid digest')
    return value

def relative(value):
    need(isinstance(value, str) and len(value) <= 240, 'path bound')
    need(all(re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', p) and p not in ('.', '..')
             and not p.endswith('.') for p in value.split('/')), 'unsafe path')
    need(str(PurePosixPath(value)) == value, 'noncanonical path')
    return value

def regular(path):
    path = Path(os.path.abspath(path))
    for parent in reversed((path, *path.parents)):
        s = parent.lstat()
        need(not stat.S_ISLNK(s.st_mode), 'symlink refused')
        need(not getattr(s, 'st_file_attributes', 0) & 0x400, 'reparse refused')
    s = path.stat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, 'single-link regular file required')
    return s

def stable_metadata(value):
    """Identity and mutation-sensitive metadata; a read may advance atime.

    Keep mode/owner/link and platform flags in addition to nanosecond clocks.
    This DATA check is not native Windows DACL, ADS or custody qualification.
    Content is independently SHA256-checked by every admission/copy caller.
    """
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
              'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_birthtime_ns',
              'st_birthtime', 'st_flags', 'st_gen', 'st_file_attributes',
              'st_reparse_tag')
    return tuple(getattr(value, name, None) for name in fields)

def unchanged(before, after):
    return stable_metadata(before) == stable_metadata(after)

def read(path, limit):
    before = regular(path)
    need(0 < before.st_size <= limit, 'file size bound')
    with Path(path).open('rb') as f:
        opened = os.fstat(f.fileno())
        need(unchanged(before, opened), 'input replaced')
        data = f.read(limit + 1)
        after = os.fstat(f.fileno())
    need(len(data) == before.st_size and unchanged(before, after), 'input changed')
    need(unchanged(before, regular(path)), 'input pathname changed')
    return data

def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate JSON key')
        result[key] = value
    return result

def decode(data): return json.loads(data, object_pairs_hook=unique)

def version(value):
    need(isinstance(value, str) and re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value), 'three numeric version fields required')
    parts = tuple(map(int, value.split('.')))
    need(parts[0] <= 255 and parts[1] <= 255 and parts[2] <= 65535, 'MSI version overflow')
    return value

def roster(source):
    body = read(source / 'desktop/native/windows-installed-native/src/publication.rs', 256 * 1024).decode()
    match = re.search(r'pub const PUBLICATION_PAYLOADS: \[&str; 65\] = \[(.*?)\];', body, re.S)
    need(match is not None, 'fixed publisher roster missing')
    paths = re.findall(r'"([^"]+)"', match[1])
    need(len(paths) == len(set(paths)) == 65, 'publisher roster count')
    return [relative(p) for p in paths]

def validate(source, inputs, binding, expected):
    raw = read(binding, 256 * 1024)
    need(digest(raw) == hex_value(expected), 'binding digest mismatch')
    b = decode(raw)
    need(set(b) == {'schema', 'sourceCommit', 'sourceTree', 'version', 'target', 'manifestSha256', 'protocolSha256', 'sourceFiles', 'files'}, 'binding schema')
    need(type(b['schema']) is int and b['schema'] == 1 and b['target'] == TARGET, 'binding target/schema')
    hex_value(b['sourceCommit'], 40); hex_value(b['sourceTree'], 40)
    version(b['version']); hex_value(b['manifestSha256']); hex_value(b['protocolSha256'])
    need(isinstance(b['sourceFiles'], dict) and SOURCE_REQUIRED <= b['sourceFiles'].keys() and len(b['sourceFiles']) <= 128, 'source inventory')
    source_total = 0
    for name, sha in b['sourceFiles'].items():
        data = read(source / relative(name), 4 * 1024 * 1024)
        source_total += len(data)
        need(source_total <= 32 * 1024 * 1024, 'source aggregate bound')
        need(digest(data) == hex_value(sha), 'source digest mismatch: ' + name)
    config = decode(read(source / 'desktop/src-tauri/tauri.conf.json', 65536))
    need(config['version'] == b['version'] and config['identifier'] == 'dev.mobile-release-kit.desktop' and config['bundle']['active'] is False, 'product mapping')
    expected_paths = {SHELL, PUBLISHER} | {'runtime/' + p for p in roster(source)}
    need(isinstance(b['files'], dict) and set(b['files']) == expected_paths, 'exact 67 input files required')
    actual = set()
    # Bounded traversal; no recursive symlink following, hidden extras or empty directories.
    for root, dirs, files in os.walk(inputs, followlinks=False):
        need(len(dirs) + len(files) <= 67, 'directory entry bound')
        for name in dirs:
            p = Path(root) / name
            rel = p.relative_to(inputs).as_posix()
            need(rel in {'runtime', 'runtime/python'} and not p.is_symlink()
                 and not getattr(p.lstat(), 'st_file_attributes', 0) & 0x400, 'unexpected directory')
        for name in files:
            actual.add((Path(root) / name).relative_to(inputs).as_posix())
            need(len(actual) <= 67, 'input count bound')
    need(actual == expected_paths, 'unexpected or missing input file')
    total = 0
    for name in sorted(expected_paths):
        row = b['files'][name]
        need(set(row) == {'size', 'sha256'} and type(row['size']) is int and 0 < row['size'] <= LIMIT, 'file record')
        total += row['size']
        need(total <= TOTAL, 'input aggregate bound')
        # Read one file at a time; bounded chunks, no whole runtime buffering.
        path = inputs / name
        s = regular(path)
        need(s.st_size == row['size'], 'input size mismatch')
        h = hashlib.sha256()
        with path.open('rb') as f:
            need(unchanged(s, os.fstat(f.fileno())), 'input replaced')
            count = 0
            while True:
                chunk = f.read(65536)
                if not chunk: break
                count += len(chunk); need(count <= row['size'], 'input grew')
                h.update(chunk)
            need(unchanged(s, os.fstat(f.fileno())), 'input changed')
        need(unchanged(s, regular(path)), 'input pathname changed')
        need(count == row['size'] and h.hexdigest() == hex_value(row['sha256']), 'input hash mismatch: ' + name)
    need(b['files']['runtime/manifest.json']['sha256'] == b['manifestSha256'], 'manifest binding')
    manifest = decode(read(inputs / 'runtime/manifest.json', 1024 * 1024))
    need(manifest.get('protocolSha256') == b['protocolSha256'] and manifest.get('target') == TARGET, 'manifest protocol/target')
    need(sum(b['files'][p]['size'] for p in expected_paths if p.startswith('runtime/')) * 2 <= TOTAL, 'publisher source/readback budget')
    return b

def identity(b):
    # ProductCode changes with version. Assembly binding covers reviewed signed
    # inputs; the real PackageCode must be extracted after WiX generates it.
    canonical = json.dumps(b, sort_keys=True, separators=(',', ':')).encode()
    return {'upgradeCode': UPGRADE_CODE,
            'productCode': str(uuid.uuid5(NAMESPACE, 'product:' + b['version'])).upper(),
            'assemblyBindingSha256': digest(canonical), 'packageCode': None}

def assembly(b):
    ET.register_namespace('', NS)
    def add(parent, tag, **attrs): return ET.SubElement(parent, '{'+NS+'}'+tag, attrs)
    root = ET.Element('{'+NS+'}Wix')
    ids = identity(b)
    package = add(root, 'Package', Name='Mobile Release Kit', Manufacturer='Mobile Release Kit', Version=b['version'],
                  ProductCode=ids['productCode'], UpgradeCode=ids['upgradeCode'],
                  Scope='perMachine', InstallerVersion='500', Compressed='yes')
    # Deliberate constant, not a public MSI property an operator can override.
    add(package, 'Launch', Condition='0', Message='NONSHIPPING: native transaction owner and Windows installed consumer are unqualified.')
    add(package, 'MediaTemplate', EmbedCab='yes')
    pf = add(package, 'StandardDirectory', Id='ProgramFiles64Folder')
    app = add(pf, 'Directory', Id='MRKApp', Name='Mobile Release Kit')
    ri = add(app, 'Directory', Id='MRKInput', Name='runtime-input')
    target = add(ri, 'Directory', Id='MRKTarget', Name=TARGET)
    manifest_dir = add(target, 'Directory', Id='MRKManifest', Name=b['manifestSha256'])
    python = add(manifest_dir, 'Directory', Id='MRKPython', Name='python')
    feature = add(package, 'Feature', Id='Main', Title='Mobile Release Kit', Level='1')
    for name in sorted(b['files']):
        parent = python if name.startswith('runtime/python/') else manifest_dir if name.startswith('runtime/') else app
        key = 'F' + digest(name.encode())[:24]
        # Path-stable GUIDs; manifest directory is part of the runtime-input identity.
        dest = name if not name.startswith('runtime/') else b['manifestSha256'] + '/' + name
        component = add(parent, 'Component', Id='C'+key, Guid=str(uuid.uuid5(NAMESPACE, 'component:'+dest)).upper(), Bitness='always64')
        add(component, 'File', Id=key, Name=PurePosixPath(name).name, Source='payload/' + name, KeyPath='yes')
        add(feature, 'ComponentRef', Id='C'+key)
    # Unscheduled until a native owner can hold originals through exit and block
    # maintenance after parent death. No registry receipt can supply that proof.
    add(package, 'CustomAction', Id='PublishFixedRuntime', FileRef='F'+digest(PUBLISHER.encode())[:24],
        ExeCommand='', Execute='deferred', Impersonate='no', Return='check')
    ET.indent(root)
    return ET.tostring(root, encoding='unicode', xml_declaration=True) + '\n'

def prepare(source, inputs, binding, expected, output):
    source, inputs, output = map(lambda p: Path(os.path.abspath(p)), (source, inputs, output))
    for a, c in ((output, source), (output, inputs), (source, inputs)):
        need(a != c and a not in c.parents and c not in a.parents, 'roots must be disjoint')
    need(not output.exists() and not output.is_symlink(), 'fresh output required')
    b = validate(source, inputs, binding, expected)
    for parent in output.parents:
        if parent.exists():
            need(not parent.is_symlink() and not getattr(parent.lstat(), 'st_file_attributes', 0) & 0x400, 'unsafe output ancestor')
    output.mkdir(mode=0o700)
    for name, row in sorted(b['files'].items()):
        src = inputs / name
        before = regular(src)
        dst = output / 'payload' / name
        dst.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        h = hashlib.sha256(); count = 0
        with src.open('rb') as reader, dst.open('xb') as writer:
            need(unchanged(before, os.fstat(reader.fileno())), 'copy source replaced')
            while True:
                chunk = reader.read(65536)
                if not chunk: break
                count += len(chunk); need(count <= row['size'], 'copy source grew')
                need(writer.write(chunk) == len(chunk), 'short stage write')
                h.update(chunk)
            need(unchanged(before, os.fstat(reader.fileno())), 'copy source changed')
        need(unchanged(before, regular(src)), 'copy pathname changed')
        need(count == row['size'] and h.hexdigest() == row['sha256'], 'copy digest mismatch')
    # Any failed copy leaves its exclusive output occupied for diagnosis; no cleanup.
    # Bytes are staged as DATA; signature/PE/ACL checks remain native gates.
    (output / 'Package.wxs').write_text(assembly(b))
    (output / 'binding.json').write_text(json.dumps(b, indent=2) + '\n')
    (output / 'assembly.json').write_text(json.dumps({'status':'NONSHIPPING_ASSEMBLY_ONLY', **identity(b),
        'target': TARGET, 'wixArchitecture': 'x64', 'version': b['version'],
        'inputBindingSha256': expected, 'compilerExecuted': False, 'installerExists': False,
        'payloadLayout': 'payload/<binding files keys>', 'nativeTransactionOwnerQualified': False,
        'installedConsumerQualified': False}, indent=2) + '\n')
    return b

def require_build_qualification():
    # No --qualified override: both native integration and admission are absent.
    raise Refused('MSI build refused: native original-owner/maintenance integration and installed Windows session inputs are unqualified')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build', action='store_true')
    for name in ('source', 'inputs', 'binding', 'binding-sha256', 'output'): p.add_argument('--'+name)
    a = p.parse_args()
    try:
        if a.build: require_build_qualification()
        need(all((a.source, a.inputs, a.binding, a.binding_sha256, a.output)), 'preparation arguments required')
        prepare(Path(a.source), Path(a.inputs), Path(a.binding), a.binding_sha256, Path(a.output))
    except (Refused, OSError, ValueError, KeyError, TypeError) as e:
        p.exit(2, 'WINDOWS_MSI_REFUSED: '+str(e)+'\n')
if __name__ == '__main__': main()
