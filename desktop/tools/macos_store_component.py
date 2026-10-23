"""Archive/restore fixed Ruby components and retain an original signed ZIP.

Actions owns original job/artifact identity. A retained signed ZIP additionally
requires an independent SOURCE pin of its original service bytes, not a new
signing claim from its carrier. Extraction is bounded DATA work, never payload
execution, signing, installation or Store authority.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from types import SimpleNamespace
import tarfile
import zipfile

REPOSITORY = 'Apdelrahman1911/mobile-release-kit'
WORKFLOW = '.github/workflows/desktop-macos-store-runtime.yml'
BRANCH = 'verify/desktop-macos-store-runtime'
ASSEMBLY_BRANCH = 'task/ci-simplification-20261015'
VERSIONS = {'ruby': '3.3.12', 'openssl': '3.5.8', 'libyaml': '0.2.5', 'deploymentTarget': '26.0'}
LIMIT = 512 * 1024 * 1024
ROOT = Path(__file__).resolve().parents[2]
RETAINED_SELECTION = 'macos-installed-inputs/store-signed-retained-transport.json'
RETAINED_SELECTION_LIMIT = 4096
RETAINED_WORKFLOW = '.github/workflows/desktop-macos-components.yml'
RETAINED_BRANCH = 'verify/desktop-macos-store-retention'
RETAINED_JOB = 'Retain signed Store runtime (arm64)'
ORIGINAL_ZIP = 'store-original.zip'
ZIP_LIMIT = LIMIT + 1024 * 1024
RETAINED_ZIP_LIMIT = ZIP_LIMIT + 1024 * 1024
# Native recipe DATA, consumed by the builder; unrelated assembly/tooling code
# is deliberately not hashed. Bump recipeVersion for native build logic changes
# not described by these actual inputs/options.
NATIVE_RECIPE = {
    'recipeVersion': 1, 'deployment': '26.0', 'cflags': '-O2',
    'ruby': ['--enable-load-relative', '--disable-shared', '--disable-install-doc',
             '--disable-yjit', '--disable-rjit', '--without-git'],
    'openssl': ['no-shared', 'no-module', 'no-tests'],
    'yaml': ['--disable-shared', '--enable-static'],
}


def native_inputs():
    spec = importlib.util.spec_from_file_location('mrk_store_public_inputs',
                                                 ROOT / 'desktop/tools/prepare_macos_store_inputs.py')
    source = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(source)  # First-party constants only; main not run.
    lock = json.loads((ROOT / 'desktop/macos-cpython-source-inputs/source-lock.json').read_bytes())
    openssl, = [row for row in lock['archiveSelections'] if row['id'] == 'openssl']
    archives = {row['directory']: {'bytes': row['bytes'], 'sha256': row['sha256']}
                for row in source.SOURCES}
    archives['openssl-' + openssl['version']] = {'bytes': openssl['bytes'], 'sha256': openssl['sha256']}
    ca = (ROOT / 'desktop/cpython-source-inputs/github-ca.pem').read_bytes()
    return {'recipe': NATIVE_RECIPE, 'archives': archives, 'caSha256': hashlib.sha256(ca).hexdigest()}


def write_build_config(output):
    output.mkdir(mode=0o700)
    for name in ('deployment', 'cflags', 'ruby', 'openssl', 'yaml'):
        value = NATIVE_RECIPE[name]
        (output / name).write_text('\n'.join(value if isinstance(value, list) else [value]) + '\n')


def toolchain_facts():
    def command(*argv):
        value = subprocess.run(argv, capture_output=True, check=True, timeout=15).stdout.decode().strip()
        if not value or len(value) > 8192:
            raise ValueError('Unexpected native toolchain response')
        return value
    return {'sdk': command('/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-version'),
            'clang': command('/usr/bin/xcrun', '--sdk', 'macosx', 'clang', '--version')}


def checked_source(source):
    if not isinstance(source, str) or not re.fullmatch(r'[0-9a-f]{40}', source):
        raise ValueError('Expected exact base source commit')
    return source


def positive(value):
    if not isinstance(value, str) or not re.fullmatch(r'[1-9][0-9]{0,19}', value):
        raise ValueError('Expected positive Actions identifier')
    return int(value)


def artifact_name(arch, source, attempt, *, assembled=False):
    if arch not in ('arm64', 'x86_64') or type(attempt) is not int or attempt <= 0:
        raise ValueError('Invalid base architecture/attempt')
    kind = 'runtime' if assembled else 'base'
    return f'mac-store-{kind}-{arch}-{checked_source(source)}-{attempt}'


def api(path):
    # Fixed repository/API routes only; GH_TOKEN is provided only to this step.
    result = subprocess.run(['gh', 'api', f'repos/{REPOSITORY}/{path}'],
                            capture_output=True, check=True, timeout=60)
    if len(result.stdout) > 2 * 1024 * 1024:
        raise ValueError('Unexpected API response size')
    return json.loads(result.stdout)


def validate_origin(run, workflow, artifact, jobs, *, run_id, source, arch, attempt, assembled=False):
    """Whole-run failure is allowed: the original selected producer must pass."""
    admitted_ref = (run.get('head_branch') == BRANCH and run.get('event') in ('push', 'workflow_dispatch'))
    if assembled and run.get('head_branch') == ASSEMBLY_BRANCH and run.get('event') == 'workflow_dispatch':
        admitted_ref = True
    if (run.get('id') != run_id or run.get('repository', {}).get('full_name') != REPOSITORY
            or run.get('head_repository', {}).get('full_name') != REPOSITORY
            or not admitted_ref
            or run.get('head_sha') != checked_source(source)
            or workflow.get('path') != WORKFLOW or run.get('workflow_id') != workflow.get('id')):
        raise ValueError('Base workflow origin differs')
    if (artifact.get('expired') is not False or artifact.get('name') != artifact_name(arch, source, attempt, assembled=assembled)
            or artifact.get('workflow_run', {}).get('id') != run_id
            or artifact.get('workflow_run', {}).get('head_sha') != source
            or type(artifact.get('size_in_bytes')) is not int
            or not 0 < artifact['size_in_bytes'] <= LIMIT + 1024 * 1024
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', artifact.get('digest', ''))):
        raise ValueError('Base artifact binding differs')
    job_name = 'Assemble Store runtime' if assembled else 'Native Ruby base'
    selected = [job for job in jobs if job.get('name') == f'{job_name} ({arch})']
    if (len(selected) != 1 or selected[0].get('run_id') != run_id
            or selected[0].get('run_attempt') != attempt
            or selected[0].get('head_sha') != source
            or selected[0].get('status') != 'completed' or selected[0].get('conclusion') != 'success'):
        raise ValueError('Original native base job did not pass')


def archive_base(base, output, source, arch, run_id, attempt):
    artifact_name(arch, source, attempt)
    output.mkdir(mode=0o700)
    total = count = 0
    archive = output / 'ruby-base.tar.gz'
    with tarfile.open(archive, 'w:gz', dereference=False) as target:
        for path in [base, *sorted(base.rglob('*'))]:
            info = path.lstat()
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                raise ValueError('Nonordinary base entry')
            count += 1
            total += info.st_size if path.is_file() else 0
            if count > 100_000 or total > LIMIT:
                raise ValueError('Base exceeds component bounds')
            target.add(path, arcname='ruby-base' if path == base else 'ruby-base/' + path.relative_to(base).as_posix(), recursive=False)
    if archive.stat().st_size > LIMIT:
        raise ValueError('Base archive exceeds component bounds')
    with archive.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    metadata = {'schema': 1, 'source': source, 'arch': arch, 'versions': VERSIONS,
                'runId': run_id, 'runAttempt': attempt, 'archiveSha256': digest,
                'nativeInputs': native_inputs(), 'toolchain': toolchain_facts()}
    (output / 'base.json').write_text(json.dumps(metadata, sort_keys=True) + '\n')


def _extract_component(archive, output, root_name):
    # Inspect each archive entry once. data_filter can be called AGAIN for
    # directory permission fixups; duplicate accounting must not live in it.
    count = total = 0
    names, inventory = set(), {}
    output.mkdir(mode=0o700)
    with tarfile.open(archive, 'r:gz') as source:
        members = []
        for member in source:
            count += 1
            total += member.size
            name = member.name[:-1] if member.isdir() and member.name.endswith('/') else member.name
            parts = name.split('/')
            if (count > 100_000 or total > LIMIT or member.size < 0 or name in names
                    or parts[0] != root_name or any(part in ('', '.', '..') for part in parts)
                    or not (member.isdir() or member.isfile())):
                raise ValueError('Nonordinary/oversize base archive')
            names.add(name)
            # Include implicit parents: TAR need not contain directory headers.
            # The full plan must have one spelling and type for every Mac name.
            for end in range(1, len(parts) + 1):
                path = '/'.join(parts[:end])
                node = (path, end < len(parts) or member.isdir())
                previous = inventory.setdefault(path.casefold(), node)
                if previous != node or len(inventory) > 100_000:
                    raise ValueError('Aliased/conflicting base archive path')
            members.append(member)
        source.extractall(output, members=members, filter=tarfile.data_filter)
    base = output / root_name
    if not base.is_dir() or not (base / 'bin/ruby').is_file():
        raise ValueError('Missing native Ruby base')
    return base


def extract_base(archive, output):
    return _extract_component(archive, output, 'ruby-base')


def restore_runtime(output, run_id, source, arch, artifact_id):
    """Restore one completed unsigned assembly; never execute or sign its code.

    This is the existing Actions supplier boundary, not another release or
    native-signature authority. There is deliberately no latest-artifact mode.
    """
    checked_source(source)
    if any(type(value) is not int or value <= 0 for value in (run_id, artifact_id)):
        raise ValueError('Expected exact original runtime run/artifact identifiers')
    run = api(f'actions/runs/{run_id}')
    workflow = api('actions/workflows/desktop-macos-store-runtime.yml')
    artifact = api(f'actions/artifacts/{artifact_id}')
    match = re.fullmatch(re.escape(f'mac-store-runtime-{arch}-{source}-') + r'([1-9][0-9]*)', artifact.get('name', ''))
    if artifact.get('id') != artifact_id or match is None:
        raise ValueError('Runtime artifact identity differs')
    attempt = int(match[1])
    jobs = api(f'actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100')
    if jobs.get('total_count', 101) > 100:
        raise ValueError('Unexpected original assembly job roster')
    validate_origin(run, workflow, artifact, jobs['jobs'], run_id=run_id, source=source,
                    arch=arch, attempt=attempt, assembled=True)
    output.mkdir(mode=0o700)
    transport = output / 'artifact.zip'
    with transport.open('xb') as stream:
        subprocess.run(['gh', 'api', f'repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip'],
                       stdout=stream, check=True, timeout=180)
    if transport.stat().st_size != artifact['size_in_bytes']:
        raise ValueError('Runtime artifact transport size differs')
    with transport.open('rb') as stream:
        if 'sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest() != artifact['digest']:
            raise ValueError('Runtime artifact service digest differs')
    with zipfile.ZipFile(transport) as zipped:
        entries = zipped.infolist()
        if len(entries) != 2 or {row.filename for row in entries} != {'base-origin.json', 'store-runtime.tar.gz'}:
            raise ValueError('Unexpected runtime artifact entries')
        for row in entries:
            maximum = 32 * 1024 if row.filename == 'base-origin.json' else LIMIT
            if row.file_size <= 0 or row.file_size > maximum or row.flag_bits & 1:
                raise ValueError('Oversize/encrypted runtime artifact')
            with zipped.open(row) as original, (output / row.filename).open('xb') as target:
                shutil.copyfileobj(original, target, 1024 * 1024)
    base = json.loads((output / 'base-origin.json').read_bytes())
    if (type(base) is not dict or type(base.get('schema')) is not int or base.get('schema') != 1 or base.get('arch') != arch
            or base.get('versions') != VERSIONS or base.get('nativeInputs') != native_inputs()):
        raise ValueError('Runtime original native inputs differ')
    archive = output / 'store-runtime.tar.gz'
    runtime = _extract_component(archive, output / 'extracted', 'runtime')
    with archive.open('rb') as stream:
        archive_digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    # Keep the original base provenance verbatim. The independent assembly
    # source and service binding are descriptive reuse facts, not signing proof.
    (output / 'runtime-origin.json').write_text(json.dumps({
        'schema': 1, 'source': source, 'arch': arch, 'runId': run_id,
        'runAttempt': attempt, 'artifactId': artifact_id,
        'artifactDigest': artifact['digest'], 'signed': False,
        'archiveSha256': archive_digest,
    }, sort_keys=True) + '\n')
    transport.unlink()
    # Retain the exact service-authenticated compressed PRE for the signing
    # owner's held input. The extracted copy is never used as signing authority.
    print(f'Restored unsigned {arch} runtime artifact {artifact_id}, source {source}, attempt {attempt}.')
    return runtime


def _signed_producer(run_id, source, arch, attempt):
    """Original signing authority, independent of the ZIP's current storage."""
    checked_source(source)
    if (arch not in ('arm64', 'x86_64')
            or any(type(v) is not int or v <= 0 for v in (run_id, attempt))):
        raise ValueError('Expected exact signed component source/run/attempt')
    run = api(f'actions/runs/{run_id}')
    workflow = api('actions/workflows/desktop-macos-python-runtime-signing.yml')
    if (run.get('id') != run_id or run.get('repository', {}).get('full_name') != REPOSITORY
            or run.get('head_repository', {}).get('full_name') != REPOSITORY
            or run.get('head_branch') != 'verify/desktop-macos-store-signing' or run.get('event') != 'push'
            or run.get('head_sha') != source or workflow.get('path') != '.github/workflows/desktop-macos-python-runtime-signing.yml'
            or run.get('workflow_id') != workflow.get('id')):
        raise ValueError('Signed Store service origin differs')
    jobs = api(f'actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100')
    if type(jobs.get('total_count')) is not int or not 0 < jobs['total_count'] <= 100:
        raise ValueError('Signed Store job roster differs')
    selected = [row for row in jobs['jobs'] if row.get('name') == f'Store signing ({arch})']
    if (len(selected) != 1 or selected[0].get('run_id') != run_id or selected[0].get('run_attempt') != attempt
            or selected[0].get('head_sha') != source or selected[0].get('status') != 'completed'
            or selected[0].get('conclusion') != 'success'):
        raise ValueError('Original signed Store producer did not pass')


def _signed_origin(run_id, source, arch, artifact_id, *, expected_attempt=None):
    checked_source(source)
    if (arch not in ('arm64', 'x86_64')
            or any(type(v) is not int or v <= 0 for v in (run_id, artifact_id))):
        raise ValueError('Expected exact signed component source/run/artifact')
    target = 'aarch64-apple-darwin' if arch == 'arm64' else 'x86_64-apple-darwin'
    artifact = api(f'actions/artifacts/{artifact_id}')
    matched = re.fullmatch(re.escape(f'store-signed-{target}-{run_id}-') + r'([1-9][0-9]*)', artifact.get('name', ''))
    if (matched is None
            or artifact.get('id') != artifact_id or artifact.get('expired') is not False
            or artifact.get('workflow_run', {}).get('id') != run_id
            or artifact.get('workflow_run', {}).get('head_sha') != source
            or type(artifact.get('size_in_bytes')) is not int or not 0 < artifact['size_in_bytes'] <= ZIP_LIMIT
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', artifact.get('digest', ''))):
        raise ValueError('Signed Store service origin differs')
    attempt = int(matched[1])
    if expected_attempt is not None and (type(expected_attempt) is not int or attempt != expected_attempt):
        raise ValueError('SOURCE-selected signed Store attempt differs')
    _signed_producer(run_id, source, arch, attempt)
    return {'source': source, 'runId': str(run_id), 'runAttempt': str(attempt),
            'artifactId': str(artifact_id), 'digest': artifact['digest'], 'bytes': artifact['size_in_bytes']}


def _check_signed_zip(path, binding):
    with path.open('rb') as stream:
        if (path.stat().st_size != binding['bytes']
                or 'sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest() != binding['digest']):
            raise ValueError('Signed Store transport differs')


def _download_signed_zip(path, binding):
    artifact_id = int(binding['artifactId'])
    with path.open('xb') as stream:
        subprocess.run(['gh', 'api', f'repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip'],
                       stdout=stream, check=True, timeout=180)
    _check_signed_zip(path, binding)


def restore_signed(output, run_id, source, arch, artifact_id, *, expected_attempt=None, archive_pin=None):
    """Project one exact successful signing job, without executing its payload."""
    origin = _signed_origin(run_id, source, arch, artifact_id, expected_attempt=expected_attempt)
    if archive_pin is not None and archive_pin != origin:
        raise ValueError('SOURCE-pinned original signed Store ZIP differs')
    output.mkdir(mode=0o700)
    _download_signed_zip(output / 'artifact.zip', origin)
    return _project_signed(output, origin, arch)


def _project_signed(output, origin, arch, *, retained_transport=None):
    # Retention changes only storage. This is the same original receipt,
    # signer, complete archive and native-member validation for both routes.
    run_id, attempt, artifact_id = (int(origin[key]) for key in ('runId', 'runAttempt', 'artifactId'))
    source = origin['source']
    target = 'aarch64-apple-darwin' if arch == 'arm64' else 'x86_64-apple-darwin'
    transport = output / 'artifact.zip'
    with zipfile.ZipFile(transport) as zipped:
        entries = zipped.infolist()
        if len(entries) != 2 or {r.filename for r in entries} != {'store-signed.tar.gz', 'store-signed-receipt.json'}:
            raise ValueError('Signed Store transport roster differs')
        for row in entries:
            maximum = 256 * 1024 if row.filename.endswith('.json') else LIMIT
            if row.flag_bits & 1 or not 0 < row.file_size <= maximum:
                raise ValueError('Signed Store transport bounds differ')
            with zipped.open(row) as original, (output / row.filename).open('xb') as destination:
                shutil.copyfileobj(original, destination, 1024 * 1024)
    # Only fixed first-party DATA parsers. None invokes main or payload code.
    modules = {}
    for filename in ('macos_store_signing.py', 'stage_macos_installed.py',
                     'macos_cpython_orchestrator.py', 'macos_android_helper_package.py'):
        label = '_mrk_store_restore_' + filename[:-3]
        spec = importlib.util.spec_from_file_location(label, ROOT / 'desktop/tools' / filename)
        module = importlib.util.module_from_spec(spec)
        sys.modules[label] = module
        spec.loader.exec_module(module)
        modules[filename] = module
    signing, stager, matcher, helper = (modules[name] for name in
        ('macos_store_signing.py', 'stage_macos_installed.py', 'macos_cpython_orchestrator.py', 'macos_android_helper_package.py'))
    archive = output / 'store-signed.tar.gz'
    archive_body = archive.read_bytes()
    receipt_body = (output / 'store-signed-receipt.json').read_bytes()
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError('Duplicate signed Store receipt key')
            result[key] = value
        return result
    receipt = json.loads(receipt_body, object_pairs_hook=pairs)
    producer = (ROOT / 'desktop/packaging/macos-install-producer-signing.profile').read_bytes()
    service = (ROOT / 'desktop/packaging/macos-android-service-signing.profile').read_bytes()
    selected_identity = stager.packaging_signing_data(producer, service)
    identity = stager.service_signing_data(service)
    expected_signer = {'teamIdentifier': identity[0], 'certificateSha1': identity[1],
                      'producerProfileSha256': selected_identity.producer_sha256,
                      'serviceProfileSha256': selected_identity.service_sha256}
    context = receipt.get('credentialContexts') if type(receipt) is dict else None
    if (type(receipt) is not dict or type(receipt.get('schemaVersion')) is not int or receipt['schemaVersion'] != 1
            or receipt.get('kind') != 'macos-store-signed-v1' or receipt.get('source') != source
            or receipt.get('runId') != str(run_id) or receipt.get('runAttempt') != str(attempt)
            or receipt.get('workflow') != REPOSITORY + '/.github/workflows/desktop-macos-python-runtime-signing.yml@refs/heads/verify/desktop-macos-store-signing'
            or receipt.get('target') != target or receipt.get('signer') != expected_signer
            or any(receipt.get(k) is not True for k in ('originalsClosed', 'sourcePost', 'inputPost', 'nonNativeUnchanged', 'outerExitRequired'))
            or receipt.get('nativeCallCount') != len(signing.ROLES) or receipt.get('credentialCallCount') != 19
            or type(context) is not list or len(context) != 1 or context[0].get('purpose') != signing.PHASE
            or any(context[0].get(k) is not True for k in ('closed', 'retired', 'searchRestored', 'defaultUnchanged'))
            or receipt.get('signedArchiveSha256') != signing.sha(archive_body)
            or type(receipt.get('signedArchiveBytes')) is not int or receipt['signedArchiveBytes'] != len(archive_body)):
        raise ValueError('Signed Store original completion/identity differs')
    current = SimpleNamespace(stager=stager, target=target, arch=arch)
    rows = signing.archive_scan(archive_body, lambda body, name: signing.native_policy(body, name, current, matcher))
    native_rows = receipt.get('nativeMembers')
    if (receipt.get('signedInventorySha256') != signing.sha(signing.canonical(rows))
            or type(native_rows) is not list or len(native_rows) != signing.NATIVE_COUNT
            or len({row.get('path') for row in native_rows if type(row) is dict}) != signing.NATIVE_COUNT):
        raise ValueError('Signed Store complete inventory differs')
    signing.validate_projection_receipt(receipt, rows)
    by_name = {row['path']: row for row in native_rows}
    with tarfile.open(fileobj=io.BytesIO(archive_body), mode='r:gz') as contents:
        for entry, row in zip(contents, rows, strict=True):
            if not row['native']: continue
            expected = by_name.get(row['path'], {})
            with contents.extractfile(entry) as stream: body = stream.read(signing.FILE_LIMIT + 1)
            flags = helper.python_code_flags(body, arch, 'python-shipping', matcher)
            if (expected.get('signedSha256') != row['sha256'] or expected.get('signedBytes') != row['bytes']
                    or expected.get('identifier') != signing.identifier(row['path']) or expected.get('codeDirectoryFlags') != flags):
                raise ValueError('Signed Store native member differs')
    runtime = _extract_component(archive, output / 'extracted', 'runtime')
    provenance = {'schema': 1, 'source': source, 'target': target,
        'runId': run_id, 'runAttempt': attempt, 'artifactId': artifact_id, 'artifactDigest': origin['digest'],
        'receiptSha256': hashlib.sha256(receipt_body).hexdigest(), 'archiveSha256': receipt['signedArchiveSha256']}
    if retained_transport is not None:
        provenance['retainedTransport'] = retained_transport
    (output / 'signed-origin.json').write_text(json.dumps(provenance, sort_keys=True) + '\n')
    transport.unlink()
    return runtime


def restore(output, run_id, source, arch, artifact_id=None):
    # Trust is resolved before archive bytes are accepted. No 'latest artifact'.
    checked_source(source)
    run = api(f'actions/runs/{run_id}')
    workflow = api('actions/workflows/desktop-macos-store-runtime.yml')
    if artifact_id is None:
        attempt = run['run_attempt']
        listing = api(f'actions/runs/{run_id}/artifacts?per_page=100')
        if listing.get('total_count', 101) > 100:
            raise ValueError('Unexpected artifact roster')
        found = [row for row in listing['artifacts'] if row['name'] == artifact_name(arch, source, attempt)]
        if not found:
            # Rerun-failed-jobs retains an earlier successful base. Accept only
            # one unambiguous earlier artifact, then verify its original job.
            prefix = f'mac-store-base-{arch}-{source}-'
            found = [row for row in listing['artifacts'] if re.fullmatch(re.escape(prefix) + r'[1-9][0-9]*', row['name'])]
        if len(found) != 1:
            raise ValueError('Expected one exact current-run base artifact')
        artifact_id = found[0]['id']
    artifact = api(f'actions/artifacts/{artifact_id}')
    # Name binds the original attempt, including when an assembly-only rerun
    # increments the current attempt without rebuilding this immutable base.
    match = re.fullmatch(re.escape(f'mac-store-base-{arch}-{source}-') + r'([1-9][0-9]*)', artifact.get('name', ''))
    if match is None:
        raise ValueError('Base artifact name differs')
    attempt = int(match[1])
    jobs = api(f'actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100')
    if jobs.get('total_count', 101) > 100:
        raise ValueError('Unexpected original job roster')
    validate_origin(run, workflow, artifact, jobs['jobs'], run_id=run_id, source=source, arch=arch, attempt=attempt)
    output.mkdir(mode=0o700)
    transport = output / 'artifact.zip'
    with transport.open('xb') as stream:
        subprocess.run(['gh', 'api', f'repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip'],
                       stdout=stream, check=True, timeout=180)
    if transport.stat().st_size != artifact['size_in_bytes']:
        raise ValueError('Artifact transport size differs')
    with transport.open('rb') as stream:
        if 'sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest() != artifact['digest']:
            raise ValueError('Artifact service digest differs')
    with zipfile.ZipFile(transport) as zipped:
        entries = zipped.infolist()
        if len(entries) != 2 or {row.filename for row in entries} != {'base.json', 'ruby-base.tar.gz'}:
            raise ValueError('Unexpected base artifact entries')
        for row in entries:
            maximum = 32 * 1024 if row.filename == 'base.json' else LIMIT
            if row.file_size <= 0 or row.file_size > maximum or row.flag_bits & 1:
                raise ValueError('Oversize/encrypted base artifact')
            with zipped.open(row) as original, (output / row.filename).open('xb') as target:
                shutil.copyfileobj(original, target, 1024 * 1024)
    metadata = json.loads((output / 'base.json').read_bytes())
    expected = {'schema': 1, 'source': source, 'arch': arch, 'versions': VERSIONS,
                'runId': run_id, 'runAttempt': attempt, 'archiveSha256': metadata.get('archiveSha256'),
                'nativeInputs': native_inputs(), 'toolchain': metadata.get('toolchain')}
    toolchain = metadata.get('toolchain')
    if (not isinstance(toolchain, dict) or set(toolchain) != {'sdk', 'clang'}
            or any(not isinstance(value, str) or not 0 < len(value) <= 8192 for value in toolchain.values())):
        raise ValueError('Missing original native toolchain facts')
    if metadata != expected or type(metadata.get('schema')) is not int or not re.fullmatch(r'[0-9a-f]{64}', metadata.get('archiveSha256', '')):
        raise ValueError('Base component metadata differs')
    archive = output / 'ruby-base.tar.gz'
    with archive.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != metadata['archiveSha256']:
            raise ValueError('Base payload digest differs')
    base = extract_base(archive, output / 'extracted')
    transport.unlink(); archive.unlink()
    # Retain a small provenance link for final assembly evidence, not authority
    # to publish or imply that the assembly used the old first-party tooling.
    metadata['artifactId'] = artifact_id
    (output / 'base.json').write_text(json.dumps(metadata, sort_keys=True) + '\n')
    print(f'Restored {arch} base artifact {artifact_id}, source {source}, attempt {attempt}.')
    return base


def _source_selector():
    spec = importlib.util.spec_from_file_location('_mrk_store_source_selector', ROOT / 'desktop/tools/stage_macos_installed.py')
    stager = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = stager
    spec.loader.exec_module(stager)
    return stager


def retained_selection_data(body, selected, stager):
    """SOURCE pins historical service bytes; a carrier cannot nominate them."""
    if type(body) is not bytes or not 0 < len(body) <= RETAINED_SELECTION_LIMIT:
        raise ValueError('Signed Store retention nomination size differs')
    value = stager.decode(body, byte_limit=RETAINED_SELECTION_LIMIT, node_limit=256)
    if (type(value) is not dict or set(value) != {'schemaVersion', 'targets'}
            or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
            or type(value['targets']) is not dict or set(value['targets']) != set(stager.MAC_TARGETS)):
        raise ValueError('Signed Store retention nomination shape differs')

    fields = {'source', 'runId', 'runAttempt', 'artifactId', 'digest', 'bytes'}
    def archive_binding(row, limit):
        if (type(row) is not dict or set(row) != fields
                or type(row['source']) is not str or not re.fullmatch(r'[0-9a-f]{40}', row['source'])
                or any(type(row[key]) is not str or not re.fullmatch(r'[1-9][0-9]{0,15}', row[key])
                       or int(row[key]) > 9007199254740991 for key in ('runId', 'runAttempt', 'artifactId'))
                or type(row['digest']) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}', row['digest'])
                or type(row['bytes']) is not int or not 0 < row['bytes'] <= limit):
            raise ValueError('Signed Store retention archive binding differs')

    for target, row in value['targets'].items():
        if row is None:
            continue  # Explicit original route, not a failed-retention fallback.
        if (type(row) is not dict or set(row) != {'original', 'transport'}
                or type(row['transport']) is not dict):
            raise ValueError('Signed Store retention target shape differs')
        archive_binding(row['original'], ZIP_LIMIT)
        transport = row['transport']
        if transport == {'kind': 'original'}:
            continue
        if (target != stager.ARM_TARGET or set(transport) != fields | {'kind'}
                or transport['kind'] != 'retained-actions'):
            raise ValueError('Signed Store retention transport differs')
        archive_binding({key: transport[key] for key in fields}, RETAINED_ZIP_LIMIT)
    target = stager.mac_target(selected['target'])
    row = value['targets'][target]
    if row is not None and any(row['original'][key] != selected[key]
                               for key in ('source', 'runId', 'runAttempt', 'artifactId')):
        raise ValueError('Signed Store retention original selection differs')
    return row


def _retained_selection(stager, selected):
    with stager.parent(stager.DESKTOP / RETAINED_SELECTION) as (fd, leaf):
        body, info = stager.read_at(fd, leaf, RETAINED_SELECTION_LIMIT)
        return retained_selection_data(body, selected, stager), (body, stager.signature(info))


def _selection_post(stager, target, selection, retained):
    if stager.signed_store_selection(target) != selection:
        raise ValueError('SOURCE-selected signed Store changed during operation')
    if _retained_selection(stager, selection[0]) != retained:
        raise ValueError('SOURCE-selected signed Store retention changed during operation')


def _validate_retained_transport(record, target):
    # Expiry of the original ZIP does not replace its original signing job.
    # No original artifact GET/download or fabricated expired=false response:
    # the explicitly reviewed SOURCE pin authenticates those historical bytes.
    original, transport = record['original'], record['transport']
    _signed_producer(int(original['runId']), original['source'], 'arm64', int(original['runAttempt']))
    run_id, attempt, artifact_id = (int(transport[key]) for key in ('runId', 'runAttempt', 'artifactId'))
    source = transport['source']
    run = api(f'actions/runs/{run_id}')
    workflow = api('actions/workflows/desktop-macos-components.yml')
    artifact = api(f'actions/artifacts/{artifact_id}')
    if (run.get('id') != run_id or run.get('repository', {}).get('full_name') != REPOSITORY
            or run.get('head_repository', {}).get('full_name') != REPOSITORY
            or run.get('head_branch') != RETAINED_BRANCH or run.get('event') != 'workflow_dispatch'
            or run.get('head_sha') != source or workflow.get('path') != RETAINED_WORKFLOW
            or run.get('workflow_id') != workflow.get('id')
            or artifact.get('id') != artifact_id or artifact.get('expired') is not False
            or artifact.get('name') != f'store-signed-retained-{target}-{run_id}-{attempt}'
            or artifact.get('workflow_run', {}).get('id') != run_id
            or artifact.get('workflow_run', {}).get('head_sha') != source
            or type(artifact.get('size_in_bytes')) is not int or artifact['size_in_bytes'] != transport['bytes']
            or artifact.get('digest') != transport['digest']):
        raise ValueError('Retained signed Store service transport differs')
    jobs = api(f'actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100')
    if type(jobs.get('total_count')) is not int or not 0 < jobs['total_count'] <= 100:
        raise ValueError('Retained signed Store job roster differs')
    selected = [row for row in jobs['jobs'] if row.get('name') == RETAINED_JOB]
    if (len(selected) != 1 or selected[0].get('run_id') != run_id or selected[0].get('run_attempt') != attempt
            or selected[0].get('head_sha') != source or selected[0].get('status') != 'completed'
            or selected[0].get('conclusion') != 'success'):
        raise ValueError('Original signed Store retention job did not pass')


def _restore_retained(output, record, target):
    _validate_retained_transport(record, target)
    output.mkdir(mode=0o700)
    outer = output / 'retained-transport.zip'
    _download_signed_zip(outer, record['transport'])
    with zipfile.ZipFile(outer) as zipped:
        entries = zipped.infolist()
        if (len(entries) != 1 or entries[0].filename != ORIGINAL_ZIP
                or entries[0].file_size != record['original']['bytes'] or entries[0].flag_bits & 1
                or stat.S_IFMT(entries[0].external_attr >> 16) not in (0, stat.S_IFREG)):
            raise ValueError('Retained signed Store transport roster differs')
        with zipped.open(entries[0]) as original, (output / 'artifact.zip').open('xb') as destination:
            shutil.copyfileobj(original, destination, 1024 * 1024)
    _check_signed_zip(output / 'artifact.zip', record['original'])
    runtime = _project_signed(output, record['original'], 'arm64', retained_transport=record['transport'])
    outer.unlink()
    return runtime


def retain_selected(output, target):
    """Copy the live original ZIP once; no payload parsing or native work."""
    stager = _source_selector()
    selection = stager.signed_store_selection(target)
    selected = selection[0]
    retained = _retained_selection(stager, selected)
    record = retained[0]
    if target != stager.ARM_TARGET or record is None or record['transport'] != {'kind': 'original'}:
        raise ValueError('Retention requires the explicitly pinned original ARM signed Store ZIP')
    origin = _signed_origin(int(selected['runId']), selected['source'], 'arm64',
                            int(selected['artifactId']), expected_attempt=int(selected['runAttempt']))
    if origin != record['original']:
        raise ValueError('SOURCE-pinned original signed Store ZIP differs')
    output.mkdir(mode=0o700)
    path = output / ORIGINAL_ZIP
    _download_signed_zip(path, origin)
    _selection_post(stager, target, selection, retained)
    return path


def restore_selected(output, target):
    stager = _source_selector()
    selection = stager.signed_store_selection(target)
    selected = selection[0]
    retained = _retained_selection(stager, selected)
    record = retained[0]
    arch = 'arm64' if target == stager.ARM_TARGET else 'x86_64'
    if record is not None and record['transport']['kind'] == 'retained-actions':
        runtime = _restore_retained(output, record, target)
    else:
        runtime = restore_signed(output, int(selected['runId']), selected['source'], arch,
                                 int(selected['artifactId']), expected_attempt=int(selected['runAttempt']),
                                 archive_pin=record['original'] if record is not None else None)
    _selection_post(stager, target, selection, retained)
    return runtime


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    selected = sub.add_parser('restore-selected', help='Restore only the fixed SOURCE-selected signed Store component')
    selected.add_argument('output', type=Path)
    selected.add_argument('--target', required=True, choices=['aarch64-apple-darwin', 'x86_64-apple-darwin'])
    retain = sub.add_parser('retain-selected', help='Retain the exact live original signed ARM Store ZIP without extraction')
    retain.add_argument('output', type=Path)
    retain.add_argument('--target', required=True, choices=['aarch64-apple-darwin'])
    config = sub.add_parser('config')
    config.add_argument('output', type=Path)
    pack = sub.add_parser('archive')
    pack.add_argument('base', type=Path); pack.add_argument('output', type=Path)
    get = sub.add_parser('restore')
    get.add_argument('output', type=Path)
    get.add_argument('--artifact-id', default='')
    runtime = sub.add_parser('restore-runtime', help='Restore an exact successful unsigned assembly, without executing it')
    runtime.add_argument('output', type=Path)
    runtime.add_argument('--artifact-id', required=True)
    signed = sub.add_parser('restore-signed', help='Project one exact signed Store producer artifact, without execution')
    signed.add_argument('output', type=Path)
    signed.add_argument('--artifact-id', required=True)
    for item in (pack, get, runtime, signed):
        item.add_argument('--source', required=True)
        item.add_argument('--arch', choices=['arm64', 'x86_64'], required=True)
        item.add_argument('--run-id', required=True)
    pack.add_argument('--attempt', required=True)
    args = parser.parse_args()
    if args.command == 'restore-selected':
        restore_selected(args.output, args.target)
    elif args.command == 'retain-selected':
        retain_selected(args.output, args.target)
    elif args.command == 'config':
        write_build_config(args.output)
    elif args.command == 'archive':
        archive_base(args.base, args.output, checked_source(args.source), args.arch,
                     positive(args.run_id), positive(args.attempt))
    elif args.command == 'restore-signed':
        restore_signed(args.output, positive(args.run_id), checked_source(args.source), args.arch, positive(args.artifact_id))
    elif args.command == 'restore-runtime':
        restore_runtime(args.output, positive(args.run_id), checked_source(args.source), args.arch,
                        positive(args.artifact_id))
    else:
        restore(args.output, positive(args.run_id), checked_source(args.source), args.arch,
                positive(args.artifact_id) if args.artifact_id else None)


if __name__ == '__main__':
    main()
