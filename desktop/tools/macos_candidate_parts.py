"""Source-bound checkpoints for independently retried Mac candidate jobs.

These are intermediate build DATA, never installed/native/signing authority.
Every consumer must also admit the actual GitHub job, artifact and originals.
No application change is admitted as a compatible checkpoint continuation.
"""
import hashlib
import json
import re
from types import MappingProxyType

REPOSITORY = 'Apdelrahman1911/mobile-release-kit'
WORKFLOW = '.github/workflows/desktop-macos-installed.yml'
BRANCH = 'verify/desktop-macos-candidate'
TARGET = 'aarch64-apple-darwin'
SCOPE = 'macos-candidate-intermediate-data-v1'
MANIFEST_LIMIT = 8 * 1024 * 1024
MEMBER_LIMIT = 512 * 1024 * 1024
TOTAL_LIMIT = 2 * 1024 * 1024 * 1024
MAX_MEMBERS = 32768
PROFILES = MappingProxyType({'tool-setup': ('Tool26', 'macos-26'), 'git-native': ('Git27', 'xcode-27')})
EXTRA_STEPS = {
    'prepare': ('Bind the complete reviewed first-party checkout before compilation',
                'Prepare the current payload from the independently accepted fresh Python supplier',
                'Latch the same computed runtime binding before any application compilation',
                'Exercise projected signed Store native CRC32 and Fastlane without a Store lane',
                'Acquire and verify the two fixed Android support archives as DATA'),
    'sign-remover': ('Sign only the fixed compiled remover',),
    'sign-cli': ('Sign only the fixed compiled installed CLI',),
}

# A native owner invocation remains one indivisible part. A failed invocation
# exports no reusable result; its original clocks/finality are never renewed.
PARTS = MappingProxyType({
    'prepare': (),
    'resident': ('prepare',),
    'vault': ('prepare',),
    'frontend': ('prepare',),
    'observer': ('resident', 'vault', 'frontend'),
    'remover': ('resident',),
    'cli': ('resident',),
    'sign-remover': ('remover',),
    'sign-cli': ('cli',),
    'assemble': ('observer', 'vault', 'sign-remover', 'sign-cli'),
    'notarize-payload': ('assemble',),
    'installer': ('notarize-payload',),
    'scripts-package': ('installer',),
    'final-package': ('scripts-package',),
})
ORIGINAL_CUTS = MappingProxyType({
    'prepare': (),
    'resident': ('Build and sign the fixed resident image and C facades',),
    'vault': ('Build and sign the separate fixed vault helper before binding the app',),
    'frontend': ('Build the embedded frontend once before native compilation',),
    'observer': ('Build the current nonshipping observer',
                 'Check the compiled observer before building more helpers or notarizing',
                 'Record the effective pinned compiler and preflight configured observer DATA'),
    'remover': ('Build the fixed remover and selected removal-only observer',),
    'cli': ('Build the fixed installed CLI',),
    'sign-remover': (),
    'sign-cli': (),
    'assemble': ('Assemble the current observer and sign code inside-out (never --deep)',),
    'notarize-payload': ('Notarize and staple the signed payload, then bind Installer inputs',),
    'installer': ('Compile the fixed ordinary root Installer before credential admission',),
    'scripts-package': ('Build the fixed one-shot root Installer and scripts-only package',),
    # The final receipt, export and cleanup keep the same original job origin.
    'final-package': ('Sign and notarize the same completed observer package before final P',
               'Publish only the prepared signed input checkpoint; not installed',
               'Upload the immutable prepared input; first retention attempt',
               'Retain prepared signed input for failed-job-only installation retries',
               "Retire only the completed candidate's disposable compiler outputs"),
})


def need(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii') + b'\n'


def sha(body):
    return hashlib.sha256(body).hexdigest()


def hex_data(value, size=64):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(size) + '}', value) is not None and value != '0' * size


def decimal(value):
    return type(value) is str and re.fullmatch('[1-9][0-9]{0,15}', value) is not None and int(value) <= 9007199254740991


def decode(body):
    need(type(body) is bytes and 0 < len(body) <= MANIFEST_LIMIT, 'part-json-bound')
    def pairs(rows):
        need(len({key for key, _ in rows}) == len(rows), 'part-json-duplicate')
        return dict(rows)
    def constant(_):
        raise ValueError('part-json-constant')
    value = json.loads(body, object_pairs_hook=pairs, parse_constant=constant)
    need(canonical(value) == body, 'part-json-canonical')
    return value


def origin_data(value):
    need(type(value) is dict and set(value) == {'source', 'tree', 'target', 'runId', 'runAttempt',
        'jobId', 'nativeScope', 'hostProfile'} and all(hex_data(value[k], 40) for k in ('source', 'tree'))
        and all(decimal(value[k]) for k in ('runId', 'runAttempt', 'jobId'))
        and value['target'] == TARGET and type(value['nativeScope']) is str
        and value['nativeScope'] in PROFILES and value['hostProfile'] == PROFILES[value['nativeScope']][1],
        'part-origin')
    return dict(value)


def part_name(value):
    need(type(value) is str and value in PARTS, 'part-name')
    return value


def artifact_name(part, origin):
    part, origin = part_name(part), origin_data(origin)
    return '-'.join(('macos-candidate-part', part, origin['nativeScope'], origin['source'],
                     origin['runId'], origin['runAttempt']))


def job_name(part, origin):
    part, origin = part_name(part), origin_data(origin)
    if part == 'final-package':
        return 'Build signed candidate (' + PROFILES[origin['nativeScope']][0] + ')'
    return 'macOS part (' + PROFILES[origin['nativeScope']][0] + ' / ' + part + ')'


def ancestors(part):
    part_name(part)
    result = set()
    def visit(current):
        for prior in PARTS[current]:
            if prior not in result:
                result.add(prior)
                visit(prior)
    visit(part)
    return tuple(name for name in PARTS if name in result)


def same_candidate(left, right):
    return all(left[k] == right[k] for k in ('source', 'tree', 'target', 'runId', 'nativeScope', 'hostProfile'))


def path_data(value):
    need(type(value) is str and 0 < len(value.encode('utf-8')) <= 4096 and '\x00' not in value
         and not any(ord(c) < 32 or ord(c) == 127 for c in value)
         and '\\' not in value and value.split('/')[0] in ('work', 'dist', 'cargo-registry')
         and all(item not in ('', '.', '..') for item in value.split('/')),
         'part-member-path')
    # The actual exporter additionally selects the SOURCE-owned part roster.
    # This generic namespace never contains a signing store or credential file.
    need(not any(re.search(r'(?i)(\.keychain(?:-db)?$|\.p12$|\.pfx$|notary-key\.p8$)', item)
                 for item in value.split('/'))
         and not (value.startswith('work/') and value.split('/')[1].startswith(('credential-', 'notary-auth-'))),
         'part-credential-member')
    return value


def manifest_data(value):
    fields = {'schemaVersion', 'scope', 'part', 'origin', 'dependencies', 'members', 'workName', 'directories',
              'originalCallerZero', 'originalReadsClosed', 'nativeAuthority', 'installed', 'productReady'}
    need(type(value) is dict and set(value) == fields and type(value['schemaVersion']) is int
         and value['schemaVersion'] == 1 and value['scope'] == SCOPE
         and all(value[k] is True for k in ('originalCallerZero', 'originalReadsClosed'))
         and all(value[k] is False for k in ('nativeAuthority', 'installed', 'productReady')),
         'part-manifest')
    part, origin = part_name(value['part']), origin_data(value['origin'])
    need(type(value['workName']) is str and re.fullmatch(r'mrk-macos-installed\.[A-Za-z0-9]{8}', value['workName']),
         'part-work-name')
    deps = value['dependencies']
    need(type(deps) is list and len(deps) == len(ancestors(part))
         and [d.get('part') if type(d) is dict else None for d in deps] == list(ancestors(part)),
         'part-dependency-roster')
    for row in deps:
        need(set(row) == {'part', 'origin', 'artifactId', 'artifactSha256', 'manifestSha256'}
             and same_candidate(origin, origin_data(row['origin'])) and decimal(row['artifactId'])
             and all(hex_data(row[k]) for k in ('artifactSha256', 'manifestSha256')),
             'part-dependency-binding')
    members = value['members']
    need(type(members) is list and 0 < len(members) <= MAX_MEMBERS, 'part-member-count')
    names, total = [], 0
    for row in members:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'mode', 'sha256'}
             and type(row['bytes']) is int and 0 <= row['bytes'] <= MEMBER_LIMIT
             and type(row['mode']) is int and row['mode'] in (0o400, 0o444, 0o555, 0o600, 0o644, 0o700, 0o755)
             and hex_data(row['sha256']), 'part-member')
        names.append(path_data(row['path']))
        total += row['bytes']
    need(names == sorted(set(names)) and total <= TOTAL_LIMIT
         and not any(name.startswith(prior + '/') for prior, name in zip(names, names[1:])),
         'part-member-roster')
    dirs = value['directories']
    need(type(dirs) is list and len(dirs) <= MAX_MEMBERS, 'part-directory-count')
    directory_names = []
    for row in dirs:
        need(type(row) is dict and set(row) == {'path', 'mode'} and type(row['mode']) is int
             and row['mode'] in (0o500, 0o555, 0o700, 0o755), 'part-directory')
        directory_names.append(path_data(row['path']))
    need(directory_names == sorted(set(directory_names)) and not set(directory_names) & set(names),
         'part-directory-roster')
    return value


def service_metadata_data(run, job, artifact, part, origin):
    """Actual successful job and pinned transport; never trust a receipt alone."""
    origin, part = origin_data(origin), part_name(part)
    need(type(run) is dict and type(job) is dict and type(artifact) is dict
         and type(run.get('id')) is int and run['id'] == int(origin['runId'])
         and run.get('head_sha') == origin['source'] and run.get('head_branch') == BRANCH
         and run.get('event') == 'push' and run.get('path') == WORKFLOW
         and type(run.get('workflow_id')) is int and run['workflow_id'] == 363563168
         and type(run.get('run_attempt')) is int and run['run_attempt'] >= int(origin['runAttempt'])
         and run.get('head_commit', {}).get('id') == origin['source']
         and run['head_commit'].get('tree_id') == origin['tree']
         and run.get('repository', {}).get('full_name') == REPOSITORY, 'part-actual-run')
    title = job_name(part, origin)
    need(type(job.get('id')) is int and job['id'] == int(origin['jobId'])
         and type(job.get('run_id')) is int and job['run_id'] == run['id']
         and type(job.get('run_attempt')) is int and job['run_attempt'] == int(origin['runAttempt'])
         and job.get('head_sha') == origin['source'] and job.get('status') == 'completed'
         and job.get('conclusion') == 'success' and job.get('name') in (title, 'Candidate parts / ' + title)
         and job.get('labels') == [origin['hostProfile']], 'part-actual-job')
    steps = job.get('steps')
    need(type(steps) is list and 0 < len(steps) <= 128, 'part-actual-steps')
    required = (*ORIGINAL_CUTS[part], *EXTRA_STEPS.get(part, ()),
                'Verify and freeze completed part originals', 'Upload immutable completed part')
    for name in required:
        rows = [s for s in steps if type(s) is dict and s.get('name') == name]
        need(len(rows) == 1 and rows[0].get('status') == 'completed'
             and rows[0].get('conclusion') == 'success', 'part-original-step')
    need(type(artifact.get('id')) is int and artifact['id'] > 0 and artifact.get('expired') is False
         and artifact.get('name') == artifact_name(part, origin)
         and type(artifact.get('size_in_bytes')) is int and 22 <= artifact['size_in_bytes'] <= TOTAL_LIMIT
         and type(artifact.get('digest')) is str and re.fullmatch('sha256:[0-9a-f]{64}', artifact['digest'])
         and artifact.get('workflow_run', {}).get('id') == run['id']
         and artifact['workflow_run'].get('head_sha') == origin['source']
         and artifact['workflow_run'].get('head_branch') == BRANCH, 'part-actual-artifact')
    return {'part': part, 'origin': origin, 'artifactId': str(artifact['id']),
            'artifactSha256': artifact['digest'][7:]}


def metadata_data(run, job, artifact, manifest):
    manifest = manifest_data(manifest)
    return dict(service_metadata_data(run, job, artifact, manifest['part'], manifest['origin']),
                manifestSha256=sha(canonical(manifest)))


def ready_parts(statuses):
    """A failed part is retried; its successful ancestors stay completed."""
    need(type(statuses) is dict and set(statuses) == set(PARTS)
         and all(type(v) is str and v in ('pending', 'running', 'success', 'failure', 'skipped')
                 for v in statuses.values()), 'part-status-roster')
    return tuple(part for part in PARTS if statuses[part] in ('pending', 'failure', 'skipped')
                 and all(statuses[prior] == 'success' for prior in PARTS[part]))


if __name__ == '__main__':
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location('mrk_part_transport',
        Path(__file__).with_name('macos_candidate_part_transport.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.main()
