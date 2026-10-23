"""Candidate owner reusing original source, signature, install and cleanup checks."""
import os
from pathlib import Path
import platform
import re
import stat
import sys
import time
from types import MappingProxyType, ModuleType, FunctionType

_SYSTEM_TOOL_FAILURE = None  # One diagnostic slot; never grants original custody.
_PREDECESSOR_DETACH = None  # Finite SAME-call observations, never cleanup authority.
_RETAINED_DETACH = None
STARTED_NS = time.monotonic_ns()
ROOT = Path(__file__).absolute().parents[2]
sys.path.insert(0, str(ROOT))
from desktop.tools import macos_candidate_carrier as candidate
from desktop.tools import macos_fixed_carrier_resume as resume


CANDIDATE_ROOT = Path('/Users/runner/work/mobile-release-kit/mobile-release-kit')
HELPER_ROOT = CANDIDATE_ROOT / '.candidate-consumer-helper'
WORKFLOW = '.github/workflows/desktop-macos-candidate-consume.yml'
BRANCH = 'verify/desktop-macos-candidate-consume'
REMOVAL_BRANCH = 'task/ci-simplification-20261015'
PREDECESSOR_BRANCH = 'verify/desktop-macos-predecessor-install'
RETAINED_OBSERVER_BRANCH = 'verify/desktop-macos-observer-reuse'
SELECTION_PATH = 'desktop/macos-installed-inputs/candidate-carrier-selection.json'
REMOVAL_SELECTION_PATH = 'desktop/macos-installed-inputs/candidate-removal-selection.json'
PREDECESSOR_SELECTION_PATH = 'desktop/macos-installed-inputs/predecessor-install-selection.json'
RETAINED_OBSERVER_SELECTION_PATH = 'desktop/macos-installed-inputs/retained-observer-selection.json'
CHILD_SOURCE_LIMIT = 256 << 10
PARSER_SOURCE_LIMIT = 64 << 10
LEGACY_PATH = 'desktop/tools/macos_fixed_carrier_resume.py'
PARSER_PATH = 'desktop/tools/macos_candidate_carrier.py'
STAGER_PATH = 'desktop/tools/stage_macos_installed.py'
CONSUMER_PATH = 'desktop/tools/macos_candidate_consumer.py'
FIXTURE_PATH = 'desktop/tools/macos_app_absence_fixture.py'
BASELINE_RECEIPT = 'candidate-baseline.json'
BASELINE_STATUS = 'candidate-baseline.status'
PURPOSES = ('install', 'acquire', 'acquire-restore', 'restore-install', 'acquire-removal')
REMOVAL_PHASES = ('finalize-remove-package', 'package-remove', 'finalize-remove-image', 'remove-preview')
REMOVAL_DONORS = ('Install.pkg', 'producer.json', 'producer.sig', 'install-inventory.json', 'mrk-macos-remove')
CANDIDATE_SOURCE_INPUTS = (
    ('desktop/macos-installed-inputs/build-release.json', 4096),
    ('desktop/macos-installed-inputs/build-release-intel.json', 4096),
    ('desktop/packaging/macos-install-producer-signing.profile', 1024),
    ('desktop/packaging/macos-android-service-signing.profile', 512),
)
HELPER_SOURCE_INPUTS = tuple(path for path in resume.SOURCE_FILES if path not in
                           (STAGER_PATH, 'desktop/tools/macos_public_verification_evidence.py'))


PREDECESSOR_METADATA_LIMIT = 16 << 10
DETACH_LOG_LIMIT = 16 << 10
DA_SUBSYSTEM = 'com.apple.DiskArbitration.diskarbitrationd'


def retained_detach_clock():
    try:
        pair = (time.time_ns(), time.monotonic_ns())
        return pair if all(type(v) is int and 0 < v < 1 << 63 for v in pair) else None
    except BaseException:
        return None


def retained_detach_log_argv(device, before, after):
    resume.need(type(device) is str and re.fullmatch(r'/dev/disk[0-9]{1,5}(?:s[0-9]{1,3})?', device)
        and all(type(p) is tuple and len(p) == 2 and all(type(v) is int and 0 < v < 1 << 63 for v in p)
                for p in (before, after)), 'retained-log')
    wall, mono = after[0] - before[0], after[1] - before[1]
    resume.need(0 <= wall and 0 <= mono <= 30_000_000_000 and abs(wall - mono) <= 2_000_000_000,
                'retained-log')
    start, end = before[0] // 1_000_000_000, (after[0] + 999_999_999) // 1_000_000_000
    resume.need(0 < start < end, 'retained-log')
    dates = [time.strftime('%Y-%m-%d %H:%M:%S+0000', time.gmtime(v)) for v in (start, end)]
    # Apple DARequest.c:1522 / DAQueue.c:304; error-level public messages.
    predicate = ('process == "diskarbitrationd" AND subsystem == "' + DA_SUBSYSTEM + '" AND category == "default" AND ('
        'eventMessage BEGINSWITH "unable to unmount ' + device + ' (status code " OR '
        'eventMessage CONTAINS "kind = disk unmount approval, disk = ' + device + ', dissented, status = ")')
    return ['/usr/bin/log', 'show', '--style', 'json', '--start', dates[0], '--end', dates[1],
            '--timezone', 'UTC', '--no-pager', '--predicate', predicate]


def retained_detach_log_codes(stdout, stderr, code, device):
    resume.need(type(stdout) is bytes and type(stderr) is bytes and len(stdout) + len(stderr) <= DETACH_LOG_LIMIT
                and type(code) is int and type(device) is str
                and re.fullmatch(r'/dev/disk[0-9]{1,5}(?:s[0-9]{1,3})?', device), 'retained-log')
    if code != 0 or stderr: return None
    rows = resume.decode(stdout, allow_finite_floats=True)
    resume.need(type(rows) is list and len(rows) <= 64, 'retained-log')
    disk, codes = re.escape(device), set()
    patterns = (('unmount-failure-log', r'unable to unmount ' + disk + r' \(status code 0x([0-9A-F]{8})\)\.'),
        ('api-dissent-log', r'  dispatched response, id = [0-9A-F]{16}:[0-9A-F]{16}, kind = disk unmount approval, disk = '
         + disk + r', dissented, status = 0x([0-9A-F]{8})\.'))
    for row in rows:
        resume.need(type(row) is dict and row.get('subsystem') == DA_SUBSYSTEM and row.get('category') == 'default'
            and type(row.get('eventMessage')) is str and len(row['eventMessage']) <= 512, 'retained-log')
        for kind, pattern in patterns:
            found = re.fullmatch(pattern, row['eventMessage'])
            if found: codes.add((kind, int(found[1], 16)))
    resume.need(len(codes) <= 8, 'retained-log')
    return {'codes': [dict(kind=kind, code=code) for kind, code in sorted(codes)]}


def retained_detach_diagnostic_data(value):
    """Observations only, never request/holder authentication."""
    if type(value) is not dict or type(value.get('originalReturncode')) is not int or value['originalReturncode'] != 16:
        return None
    flags = {k: value.get(k) if type(value.get(k)) is bool else None for k in
             ('entered', 'returned', 'settled', 'resourceUnknown', 'warnings')}
    codes = value.get('codes')
    valid = (type(codes) is list and len(codes) <= 8 and all(type(r) is dict and set(r) == {'kind', 'code'}
        and type(r['kind']) is str and r['kind'] in ('unmount-failure-log', 'api-dissent-log')
        and type(r['code']) is int and 0 <= r['code'] < 1 << 32 for r in codes))
    codes = [dict(r) for r in codes] if valid else []
    observed = (value.get('state') == 'observed' and codes and flags['resourceUnknown'] is False
                and all(flags[k] is True for k in ('entered', 'returned', 'settled')))
    return {'state': 'observed' if observed else 'unavailable', 'originalReturncode': 16, **flags,
        'codes': codes if observed else [],
        'rawOutputExported': False, 'absenceEstablished': False, 'requestAttributionEstablished': False,
        'holderAuthentication': False, 'systemServiceExitClaimed': False}


def predecessor_metadata_data(value, nomination):
    """Closed public DATA only; actual owner finality, not this parser, permits export."""
    selected = candidate.candidate_selection_data(nomination)
    keys = {'schemaVersion', 'scope', 'nomination', 'members', 'package', 'descriptor', 'signature',
            'inventory', 'release', 'inventoryFiles', 'inventoryPayloadBytes',
            'nativeQualificationInferred', 'updateActivated'}
    resume.need(type(value) is dict and set(value) == keys
        and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
        and value['scope'] == 'candidate-public-predecessor-metadata-v1'
        and candidate.candidate_selection_data(value['nomination']) == selected
        and value['nativeQualificationInferred'] is False and value['updateActivated'] is False,
        'candidate-predecessor-metadata-shape')
    def member(row, name, cap):
        resume.need(type(row) is dict and set(row) == {'name', 'bytes', 'sha256'}
            and row['name'] == name and type(row['bytes']) is int and 0 < row['bytes'] <= cap
            and digest(row['sha256'], 64), 'candidate-predecessor-member')
    def digest(value, length):
        return type(value) is str and len(value) == length and re.fullmatch(r'[0-9a-f]+', value) is not None and value != '0'*length
    members = value['members']
    resume.need(type(members) is list and len(members) == len(resume.CANDIDATE_MEMBERS), 'candidate-predecessor-members')
    for row, name in zip(members, sorted(resume.CANDIDATE_MEMBERS)):
        member(row, name, resume.CANDIDATE_MEMBERS[name])
    resume.need(sum(row['bytes'] for row in members) <= resume.LIMIT, 'candidate-predecessor-members')
    for key, name, cap in (('package', 'Install.pkg', resume.LIMIT), ('descriptor', 'producer.json', 16384),
            ('signature', 'producer.sig', 512), ('inventory', 'install-inventory.json', 12 << 20)):
        member(value[key], name, cap)
    release = value['release']
    resume.need(type(release) is dict and set(release) == {'profile', 'packageIdentifier', 'bundleIdentifier',
        'packageVersion', 'release', 'sourceCommit', 'protocolSha256', 'runtimeManifestSha256',
        'inventorySha256', 'signingPolicySha256', 'packageSha256'}, 'candidate-predecessor-release')
    architecture = 'arm64' if selected['target'] == 'aarch64-apple-darwin' else 'x86_64'
    version, label = release['packageVersion'], release['release']
    resume.need(type(version) is str and len(version) <= 32
        and re.fullmatch(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)', version) is not None
        and all(int(part) <= 0xffffffff for part in version.split('.'))
        and type(label) is str and len(label) <= 128 and label.startswith('macos26-'+architecture+'-')
        and len(label) > len('macos26-'+architecture+'-') and re.fullmatch(r'[a-z0-9_.-]*[a-z0-9]', label) is not None
        and release['profile'] == 'fixed-macos26-'+architecture+'-maintenance-v2'
        and release['packageIdentifier'] == 'dev.mobile-release-kit.desktop.installed'
        and release['bundleIdentifier'] == 'dev.mobile-release-kit.desktop'
        and release['sourceCommit'] == selected['source']
        and all(digest(release[key], 64) for key in ('protocolSha256', 'runtimeManifestSha256',
            'inventorySha256', 'signingPolicySha256', 'packageSha256'))
        and release['packageSha256'] == value['package']['sha256']
        and release['inventorySha256'] == value['inventory']['sha256'], 'candidate-predecessor-release')
    resume.need(type(value['inventoryFiles']) is int and 0 < value['inventoryFiles'] <= 16384
        and type(value['inventoryPayloadBytes']) is int and 0 <= value['inventoryPayloadBytes'] <= resume.LIMIT,
        'candidate-predecessor-inventory-counts')
    resume.need(len(resume.canonical(value)) <= PREDECESSOR_METADATA_LIMIT, 'candidate-predecessor-metadata-bound')
    return value


def predecessor_metadata_projection(result, nomination):
    # Called only after the existing native producer-signature and mounted POST.
    # Do not retain inventoryDocument, raw signed bodies or signing-policy data.
    value = {key: result[key] for key in ('members', 'package', 'descriptor', 'signature', 'inventory',
                                         'release', 'inventoryFiles', 'inventoryPayloadBytes')}
    value.update(schemaVersion=1, scope='candidate-public-predecessor-metadata-v1',
        nomination=dict(nomination), nativeQualificationInferred=False, updateActivated=False)
    return resume.canonical(predecessor_metadata_data(value, nomination))


def selection_data(body, target):
    value = resume.decode(body)
    resume.need(type(value) is dict and set(value) == {'schemaVersion', 'targets'}
                and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
                and type(value['targets']) is dict and 0 < len(value['targets']) <= 2 and set(value['targets']) <=
                    {'aarch64-apple-darwin', 'x86_64-apple-darwin'}, 'candidate-source-selection')
    rows = {key: candidate.candidate_selection_data(row) for key, row in value['targets'].items()}
    resume.need(all(key == row['target'] for key, row in rows.items()) and target in rows,
                'candidate-source-selection-target')
    return rows[target]


def context_data(environment, root, machine):
    target = environment.get('MRK_MACOS_TARGET')
    target_names(target)
    arm = target == 'aarch64-apple-darwin'
    source = environment.get('GITHUB_SHA', '')
    removal = environment.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and environment.get('MRK_CANDIDATE_MODE') == 'remove-delivery'
    predecessor = environment.get('MRK_CANDIDATE_MODE') == 'install-predecessor'
    retained = environment.get('MRK_CANDIDATE_MODE') == 'install-retained-observer'
    branch = RETAINED_OBSERVER_BRANCH if retained else PREDECESSOR_BRANCH if predecessor else REMOVAL_BRANCH if removal else BRANCH
    resume.need(root == HELPER_ROOT and environment.get('GITHUB_WORKSPACE') == str(CANDIDATE_ROOT)
                and environment.get('RUNNER_TEMP') == '/Users/runner/work/_temp'
                and environment.get('GITHUB_REPOSITORY') == resume.REPOSITORY
                and (environment.get('GITHUB_EVENT_NAME') == 'push' and not (predecessor or retained) or
                     environment.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
                     and (removal or predecessor or retained))
                and (not (predecessor or retained) or arm)
                and environment.get('GITHUB_REF') == 'refs/heads/' + branch
                and environment.get('GITHUB_WORKFLOW_REF') == resume.REPOSITORY + '/' + WORKFLOW + '@refs/heads/' + branch
                and re.fullmatch(r'[0-9a-f]{40}', source) and source != '0' * 40
                and environment.get('GITHUB_WORKFLOW_SHA') == source
                and environment.get('RUNNER_OS') == 'macOS'
                and environment.get('RUNNER_ARCH') == ('ARM64' if arm else 'X64')
                and environment.get('RUNNER_ENVIRONMENT') == 'github-hosted'
                and machine == ('arm64' if arm else 'x86_64')
                and all(type(environment.get(k)) is str and re.fullmatch(r'[1-9][0-9]{0,19}', environment[k])
                        for k in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')), 'candidate-hosted-context')
    work = environment.get('MRK_MACOS_WORK', '')
    resume.need(type(work) is str and re.fullmatch(r'/Users/runner/work/_temp/mrk-macos-installed\.[A-Za-z0-9]{8}', work),
                'candidate-private-work-context')
    return {'target': target, 'helperSource': source, 'runId': environment['GITHUB_RUN_ID'],
            'runAttempt': environment['GITHUB_RUN_ATTEMPT'], 'work': Path(work) / 'resume-carrier'}


def source_rows_data(body, expected):
    """Same tracked Git blob correspondence used by the existing normal UI.

    No index/status/filter/diff execution, no manual implementation hash pins.
    Only the exact held SOURCE files of the two selected commits are compared.
    """
    import hashlib
    resume.need(type(body) is bytes and 0 < len(body) <= 8192 and body.endswith(b'\0'), 'candidate-source-roster')
    seen = set()
    for row in body[:-1].split(b'\0'):
        header, name = row.split(b'\t', 1)
        mode, kind, blob = header.split(b' ')
        name = name.decode('utf-8', 'strict')
        resume.need(name in expected and name not in seen and kind == b'blob' and mode in (b'100644', b'100755'),
                    'candidate-source-roster')
        source = expected[name]
        resume.need(hashlib.sha1(b'blob ' + str(len(source)).encode('ascii') + b'\0' + source).hexdigest().encode('ascii') == blob,
                    'candidate-source-blob')
        seen.add(name)
    resume.need(seen == set(expected), 'candidate-source-roster-complete')


def target_names(target):
    resume.need(target in ('aarch64-apple-darwin', 'x86_64-apple-darwin'), 'candidate-target')
    return ('arm64' if target == 'aarch64-apple-darwin' else 'intel')


def candidate_transport_path(run, attempt, nomination):
    selected = candidate.candidate_selection_data(nomination)
    resume.need(all(type(v) is str and re.fullmatch(r'[1-9][0-9]{0,19}', v)
                    for v in (run, attempt)), 'candidate-transport-context')
    context = '\n'.join((run, attempt, selected['target'], selected['artifactSha256'], 'candidate-consumer'))
    return Path('/Volumes') / ('MRK-Install-' + resume.sha(context.encode('ascii'))[:32])


def predecessor_detach_data(stdout, stderr):
    """Same bounded lexical policy as the production detach DATA helpers.

    Kept local to avoid a 97th lifetime SOURCE original just for diagnostics.
    Literal text hints are not cause, stage, PID or service-finality evidence.
    """
    label = 'unclassified'
    if type(stderr) is bytes and len(stderr) <= 65536:
        known = {b'Resource busy': 'resource-busy', b'Permission denied': 'permission-denied',
                 b'Operation not permitted': 'operation-not-permitted', b'No such device': 'no-such-device'}
        lines = stderr.split(b'\n')
        found = {label for token, label in known.items() if b'hdiutil: detach failed - ' + token in lines}
        label = 'empty' if not stderr else next(iter(found)) if len(found) == 1 else 'unclassified'
    if type(stdout) is not bytes or type(stderr) is not bytes or len(stdout) + len(stderr) > 65536:
        return {'stderr': label, 'textHints': None}
    data = stdout.lower() + b'\n' + stderr.lower()
    hints = [hint for token, hint in ((b'resource busy', 'resource-busy-text'),
        (b'unmount', 'unmount-text'), (b'eject', 'eject-text'), (b'dissent', 'dissent-text')) if token in data]
    return {'stderr': label, 'textHints': hints}


def candidate_resource_requirements(nomination, retained, host_bytes, *, image_bytes=None):
    """Fund ZIP first, then its checked image before decode; retain disk cap."""
    row = candidate.candidate_selection_data(nomination)
    resume.need(type(retained) is int and 0 <= retained <= 1 << 30
                and type(host_bytes) is int and 0 <= host_bytes <= 1 << 30,
                'candidate-resource-bound')
    resume.need(image_bytes is None or type(image_bytes) is int and 0 < image_bytes <= resume.LIMIT,
                'candidate-image-bound')
    image = 0 if image_bytes is None else image_bytes
    memory = 6 * (row['artifactBytes'] + image) + (16 << 20) + retained + (512 << 20) + (1 << 30)
    # Fund both disk copies and the original installation/codec reserve.
    disk = (3 << 30) + 2 * row['artifactBytes'] + 2 * (resume.LIMIT if image_bytes is None else image) + host_bytes
    return {'acquisitionMemory': memory, 'postAcquisitionMemory': memory - 6 * row['artifactBytes'],
            'requiredDisk': disk}


def acquisition_bootstrap(helper_root, bodies):
    """Only two held SOURCE bodies, no ambient desktop imports in the child."""
    resume.need(helper_root == HELPER_ROOT and type(bodies) is dict
                and set(bodies) == {LEGACY_PATH, PARSER_PATH}, 'candidate-child-sources')
    for name, limit in ((LEGACY_PATH, resume.SOURCE_LIMIT), (PARSER_PATH, PARSER_SOURCE_LIMIT)):
        resume.need(type(bodies[name]) is bytes and 0 < len(bodies[name]) <= limit,
                    'candidate-child-source-bound')
    # Quote escaping is bounded before building any source literal/copy. Four
    # bytes funds every escaped input byte; printable unquoted ASCII needs one.
    quoted_bound = sum(2 + sum(1 if 32 <= byte < 127 and byte not in (34, 39, 92) else 4
                               for byte in body) for body in bodies.values())
    resume.need(sum(map(len, bodies.values())) <= CHILD_SOURCE_LIMIT
                and quoted_bound + 8192 <= CHILD_SOURCE_LIMIT, 'candidate-child-source-bound')
    text = 'import sys,types\n'
    for name in ('desktop', 'desktop.tools'):
        text += 'm=types.ModuleType(' + repr(name) + ');m.__path__=[];sys.modules[' + repr(name) + ']=m\n'
    for name, relative in (('desktop.tools.macos_fixed_carrier_resume', LEGACY_PATH),
                           ('desktop.tools.macos_candidate_carrier', PARSER_PATH)):
        path = str(helper_root / relative)
        text += ('m=types.ModuleType(' + repr(name) + ');m.__file__=' + repr(path)
                 + ';m.__package__="desktop.tools";sys.modules[' + repr(name) + ']=m\n'
                 + 'exec(compile(' + repr(bodies[relative]) + ',' + repr(path) + ',"exec"),m.__dict__)\n')
    text += ('r=sys.modules["desktop.tools.macos_fixed_carrier_resume"]\n'
             'c=sys.modules["desktop.tools.macos_candidate_carrier"]\n'
             'sys.stdout.buffer.write(r.canonical(r.acquisition_main(candidate=c))+b"\\n")\n')
    resume.need(len(text.encode('utf-8')) <= CHILD_SOURCE_LIMIT, 'candidate-child-source-bound')
    return text


class CandidateResume(resume.Resume):
    """Candidate adapter with separate held helper/application sources."""
    command_roles = (*resume.Resume.command_roles, 'helper-source', 'candidate-source')

    def __init__(self, helper_root, candidate_root, work, clock, factory, *, nomination=None, quota=None, purpose="install",
                 predecessor_install=False, retained_observer=False):
        resume.need(helper_root == HELPER_ROOT and candidate_root == CANDIDATE_ROOT,
                    'candidate-separate-source-roots')
        resume.need(type(purpose) is str and purpose in PURPOSES, "candidate-purpose")
        resume.need(type(predecessor_install) is bool
                    and (not predecessor_install or purpose == 'install' and nomination is None),
                    'candidate-predecessor-install-purpose')
        resume.need(type(retained_observer) is bool and (not retained_observer
                    or purpose == 'install' and nomination is None and not predecessor_install),
                    'retained-observer-install-purpose')
        self.__purpose = purpose
        self.__predecessor_install = predecessor_install
        self.__retained_observer = retained_observer
        self.__retained_selection = self.__observer_product = self.__image_document = None
        self.__detach_observation = None
        self.__installed_signature_state = None
        self.__mounted_reread_inputs = self.__mounted_reread_state = None
        self.baseline = self.baseline_entry = self.baseline_receipt = self.fixture_api = None
        self.acquisition_result = None
        self.__predecessor_metadata = None
        self.__nomination = None if nomination is None else MappingProxyType(candidate.candidate_selection_data(nomination))
        self.__binding = None
        self.__restore_inputs = None
        self.__removal_program = None
        self.candidate_root = candidate_root
        self.__source_loaded = False
        self.__artifact_admitted = False
        self.__acquisition_entered = False
        self.__installation_entered = False
        super().__init__(helper_root, work, clock, factory, quota=quota)

    @property
    def purpose(self):
        return self.__purpose

    def command(self, role, argv, maximum, *, env=None):
        if self.__retained_observer and role == 'detach':
            resume.need(self.__detach_observation is None and type(argv) is list and len(argv) == 3
                and argv[:2] == ['/usr/bin/hdiutil', 'detach'] and type(argv[2]) is str
                and maximum == 30 and env is None and self.clock.finality is True, 'retained-detach-once')
            self.__detach_observation = {}
            count, before = len(self.calls), retained_detach_clock()
            result = super().command(role, argv, maximum)
            after = retained_detach_clock()
            if result.returncode == 16:
                try:
                    self.observe_retained_detach(result, count, before, after)
                except BaseException:
                    pass
            return result
        if not self.__predecessor_install or role != 'detach':
            return super().command(role, argv, maximum, env=env)
        # Resume.install_image alone supplies its original reported device,
        # after its existing consuming mounted-book finish. No retry/new owner.
        resume.need(self.__detach_observation is None and type(argv) is list and len(argv) == 3
                    and argv[:2] == ['/usr/bin/hdiutil', 'detach'] and type(argv[2]) is str
                    and maximum == 30 and env is None and self.clock.finality is True,
                    'candidate-predecessor-detach-once')
        observation = {'entered': True, 'returned': False, 'outcome': 'unknown',
            'installerReturnedZero': self.installer_zero is True, 'readbackKnown': self.readback_known is True,
            'finalMountedRereadKnown': self.__mounted_reread_state == 'verified',
            'stderr': 'unclassified', 'textHints': None, 'systemServiceExitClaimed': False}
        self.__detach_observation = observation
        global _PREDECESSOR_DETACH
        _PREDECESSOR_DETACH = observation
        result = super().command(role, argv + ['-verbose'], maximum)
        observation.update(returned=True, outcome='detach0' if result.returncode == 0 else
                           'detach16' if result.returncode == 16 else 'other-return')
        try:
            observation.update(predecessor_detach_data(result.stdout, result.stderr))
        except BaseException:
            pass  # A diagnostic failure never replaces this identical result.
        return result

    def observe_retained_detach(self, original, count, before, after):
        if self.__detach_observation != {}: return
        record = {'originalReturncode': 16, 'state': 'unavailable',
            'entered': False, 'returned': False, 'settled': False, 'resourceUnknown': False,
            'warnings': False, 'codes': []}
        self.__detach_observation = record
        global _RETAINED_DETACH
        _RETAINED_DETACH = record
        tool_pending = False
        try:
            resume.need(self.__retained_observer and self.__installation_entered and self.installer_entered
                and self.installer_zero and self.readback_known and type(getattr(self, 'installation', None)) is dict
                and self.clock.finality is True and len(self.calls) == count + 1
                and self.calls[-1]['role'] == 'detach' and self.calls[-1].get('returncode') == original.returncode == 16
                and sum(row['role'] == 'detach' for row in self.calls) == 1
                and all(row['returned'] and row['capturesSettled'] and row.get('returncode') == (16 if i == count else 0)
                        for i, row in enumerate(self.calls)), 'retained-log')
            argv = retained_detach_log_argv(original.args[2], before, after)
            self.point()
            endpoint = min(self.clock.deadline - 15_000_000_000, self.clock.check() + 10_000_000_000)
            resume.need(os.getuid() == os.geteuid() != 0 and Path('/usr/bin') in self.outer.directories
                and self.quota.reserved + 1 <= resume.MAX_ORIGINALS, 'retained-log')
            # Original16 cannot spend the success-only third iterator cell.
            tool_pending = True
            _entry, body = self.quota.call(self.outer, 'file', Path('/usr/bin/log'), 64 << 20,
                                           uid=0, modes=(0o555, 0o755))
            resume.need(body, 'retained-log')
            tool_pending = False
            del body
            self.point()
            try: os.stat('.logrc', dir_fd=self.parent['fd'], follow_symlinks=False)
            except FileNotFoundError: pass
            else: raise resume.Refused('retained-log')
            timeout = min(self.clock.seconds(10), (endpoint - self.clock.check()) // 1_000_000_000)
            resume.need(timeout > 0, 'retained-log')
            record['entered'] = True
            result = self.owner.run_owned(argv, environ=dict(self.environment, HOME=str(self.work)), cwd=self.work,
                timeout=timeout, capture=True, text=False, output_limit=DETACH_LOG_LIMIT, cleanup=True)
            resume.need(result.args == argv and type(result.returncode) is int and type(result.stdout) is bytes
                and type(result.stderr) is bytes and len(result.stdout) + len(result.stderr) <= DETACH_LOG_LIMIT,
                'retained-log')
            record.update(returned=True, settled=True, warnings=bool(result.stderr))
            self.point()
            parsed = retained_detach_log_codes(result.stdout, result.stderr, result.returncode, original.args[2])
            if parsed is not None:
                record.update(parsed, state='observed' if parsed['codes'] else 'unavailable')
        except BaseException:
            record['resourceUnknown'] |= tool_pending or record['entered'] and not record['settled']
            # Never replace original16 or retry.

    @property
    def nomination(self):
        resume.need(self.__nomination is not None, 'candidate-source-selection-not-loaded')
        return dict(self.__nomination)

    @property
    def target(self):
        resume.need(self.__nomination is not None, 'candidate-source-selection-not-loaded')
        return self.__nomination['target']

    @property
    def origin(self):
        resume.need(self.__binding is not None, 'candidate-image-not-bound')
        return resume.decode(self.__binding)

    def mount_path(self):
        return candidate_transport_path(self.run_id, self.run_attempt, self.nomination)

    def load_nomination(self, target):
        resume.need(self.__nomination is None, 'candidate-source-selection-once')
        resume.need(not self.__predecessor_install or target == 'aarch64-apple-darwin', 'candidate-predecessor-target')
        if self.__retained_observer:
            resume.need(target == 'aarch64-apple-darwin', 'retained-observer-target')
            selected = candidate.retained_observer_selection_data(resume.decode(self.source(RETAINED_OBSERVER_SELECTION_PATH, 8192)))
            self.__retained_selection = resume.canonical(selected)
            self.__nomination = MappingProxyType(selected['origin'])
            return
        path = (PREDECESSOR_SELECTION_PATH if self.__predecessor_install else
                REMOVAL_SELECTION_PATH if self.purpose == 'acquire-removal' else SELECTION_PATH)
        body = self.source(path, 8192)
        self.__nomination = MappingProxyType(selection_data(body, target))

    def retained_selection(self):
        resume.need(self.__retained_observer and self.__retained_selection is not None, 'retained-observer-source-not-loaded')
        return candidate.retained_observer_selection_data(resume.decode(self.__retained_selection))

    def verify_sources(self):
        """Original owned Git queries; source bytes stay held across every call."""
        env = dict(self.environment, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                   GIT_NO_REPLACE_OBJECTS='1', GIT_OPTIONAL_LOCKS='0', GIT_TERMINAL_PROMPT='0')
        for role, root, selected in (('helper-source', self.root, self.helper_source),
                                     ('candidate-source', self.candidate_root, self.nomination['source'])):
            files = {str(entry['path'].relative_to(root)): body for entry, body in self.sources
                     if entry['path'].is_relative_to(root)
                     and not (root == self.candidate_root and entry['path'].is_relative_to(self.root))}
            resume.need(files, 'candidate-source-empty')
            prefix = ['/usr/bin/git', '-C', str(root), '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
                      '--no-optional-locks', '--literal-pathspecs']
            call = self.command(role, prefix + ['rev-parse', 'HEAD', 'HEAD^{tree}'], 15, env=env)
            rows = call.stdout.splitlines()
            resume.need(call.returncode == 0 and call.stderr == b'' and len(rows) == 2
                        and rows[0] == selected.encode('ascii') and re.fullmatch(rb'[0-9a-f]{40}', rows[1]),
                        'candidate-checkout-identity')
            if role == 'candidate-source':
                resume.need(rows[1] == self.nomination['tree'].encode('ascii'), 'candidate-checkout-tree')
            else:
                previous = getattr(self, 'helper_tree', None)
                resume.need(previous is None or previous == rows[1].decode('ascii'), 'candidate-helper-tree-post')
                self.helper_tree = rows[1].decode('ascii')
            listed = self.command(role, prefix + ['ls-tree', '-z', '--full-tree', selected, '--', *sorted(files)], 15, env=env)
            resume.need(listed.returncode == 0 and listed.stderr == b'', 'candidate-source-command')
            source_rows_data(listed.stdout, files)
        self.point()

    def load_sources(self):
        """Actual source paths stay distinct; retain originals across native use."""
        resume.need(not self.__source_loaded, 'candidate-source-once')
        self.source(CONSUMER_PATH, 96 << 10)
        self.child_sources = {LEGACY_PATH: self.source(LEGACY_PATH, resume.SOURCE_LIMIT),
                              PARSER_PATH: self.source(PARSER_PATH, PARSER_SOURCE_LIMIT)}
        self.child_bootstrap = (acquisition_bootstrap(self.root, self.child_sources)
                                if self.purpose != "restore-install" else "")
        fixture_body = self.source(FIXTURE_PATH, 128 << 10) if self.purpose in ("restore-install", "acquire-restore") else None
        package_body = self.source("desktop/tools/macos_android_helper_package.py", resume.SOURCE_MODULE_LIMIT) if self.purpose == "acquire-restore" else None
        bodies = {}
        for relative, cap in ((STAGER_PATH, resume.SOURCE_MODULE_LIMIT), *CANDIDATE_SOURCE_INPUTS):
            entry, body = self.quota.call(self.outer, 'file', self.candidate_root / relative, cap, uid=os.getuid())
            self.sources.append((entry, body)); bodies[relative] = body
        # The candidate's code is not executed until its real Git tree and every
        # source byte here match the exact service-nominated checkout.
        self.verify_sources()
        if fixture_body is not None:
            self.fixture_api = resume.load_module("_mrk_candidate_fixture", self.root / FIXTURE_PATH, fixture_body)
        if package_body is not None:
            self.package_api = resume.load_module("_mrk_candidate_package", self.root / "desktop/tools/macos_android_helper_package.py", package_body)
        self.stager = resume.load_module('_mrk_candidate_stager', self.candidate_root / STAGER_PATH, bodies[STAGER_PATH])
        resume.need(self.stager.DESKTOP == self.candidate_root / 'desktop', 'candidate-stager-source-root')
        self.selection = self.stager.source_build_selection(self.target)
        # Producer/source policy is subordinate to the independently pinned G2
        # certificate retained by the helper, never PREVIEW's claimed identity.
        relative, size, digest = resume.SIGNING_CERTIFICATE
        leaf = self.source(relative, size, digest)
        import hashlib
        identity = {'teamIdentifier': '7CGZ2343AA', 'leafCertificateSha1': hashlib.sha1(leaf).hexdigest(),
                    'leafCertificateSha256': resume.sha(leaf)}
        resume.need(identity['leafCertificateSha1'] == '5effa7d19bbe005b19c1617833cbe22186c2af96',
                    'candidate-trusted-signing-leaf')
        policy = self.stager.packaging_signing_data(bodies[CANDIDATE_SOURCE_INPUTS[2][0]], bodies[CANDIDATE_SOURCE_INPUTS[3][0]])
        resume.need((policy.team, policy.leaf_sha1, policy.leaf_sha256) == tuple(identity.values()),
                    'candidate-source-signing-policy')
        self.signing_identity = MappingProxyType(identity)
        self.point()
        self.__source_loaded = True

    def initialize_host(self, host_module):
        # The caller must load this module from its original held helper source,
        # just as Resume.main does. Never default the Intel owner to ARM ABI.
        self.host_module = host_module
        self.host = host_module.DarwinAPI(self.clock, target=self.target)
        self.host.waitable_sigchld()

    def admit_resources(self, retained, host_bytes, *, image_bytes=None, acquiring=False, package_bytes=None, reading=False):
        resume.need(type(retained) is int and retained >= sum(len(body) for _, body in self.sources)
                    + len(self.child_bootstrap.encode('utf-8')), 'candidate-retained-source-budget')
        quote = candidate_resource_requirements(self.nomination, retained, host_bytes, image_bytes=image_bytes)
        required = quote['acquisitionMemory' if image_bytes is None or acquiring else 'postAcquisitionMemory']
        if self.__retained_observer and (image_bytes is None or acquiring):
            required = candidate.retained_observer_memory_requirement(self.retained_selection(), retained, image_bytes=image_bytes)
        resume.need(type(reading) is bool and (package_bytes is not None or not reading), 'candidate-package-stage')
        if package_bytes is not None:
            resume.need(not acquiring and image_bytes is not None and type(package_bytes) is int
                        and 0 < package_bytes <= resume.LIMIT, 'candidate-package-bound')
            # Initial image copies have returned. Fund the package read peak,
            # then its retained bytes separately from every codec allocation.
            required += -5 * image_bytes + (6 if reading else 1) * package_bytes + 2 * 65536
        call = self.command('memory', ['/usr/bin/vm_stat'], 10)
        page_size, physical = resume.host_memory_data(self.host, self.clock)
        memory = resume.memory_data(call.stdout, call.stderr, call.returncode, page_size=page_size, physical_bytes=physical)
        disk = os.fstatvfs(self.parent['fd'])
        facts = resume.resource_admission_data(memory['availableEstimateBytes'], required,
                                              disk.f_bavail * disk.f_frsize, quote['requiredDisk'])
        resume.STATE['resourceAdmission'] = facts
        resume.need(facts['memorySufficient'] and facts['diskSufficient'], 'candidate-resource-admission')
        self.memory_base, self.required_disk = required, quote['requiredDisk']
        self.allocation_samples, self.cpio_window = 0, None

    def acquire_fixed(self):
        return self.acquire_candidate()

    def acquire_candidate(self):
        resume.need(self.__source_loaded and not self.__acquisition_entered and self.__binding is None,
                    'candidate-acquire-order')
        self.__acquisition_entered = True
        self.point(); self.quota.reserve(3)
        selected = self.nomination
        role = 'retained-observer' if self.__retained_observer else 'candidate'
        request = {'row': self.retained_selection() if self.__retained_observer else selected,
                   'role': role, 'target': self.target, 'work': str(self.work),
                   'workIdentity': list(self.parent['identity']), 'caPath': self.ca_path, 'caSha256': self.ca_sha,
                   'endpoint': min(self.clock.work, self.clock.check() + 120_000_000_000)}
        env = dict(self.environment, MRK_P0_REQUEST=resume.canonical(request).decode('ascii'), MRK_P0_READ_TOKEN=self.token)
        bootstrap = self.child_bootstrap
        call = self.command('acquire-carrier', [self.python, '-I', '-S', '-B', '-c', bootstrap], 120, env=env)
        resume.need(call.returncode == 0 and call.stderr == b'' and resume.decode(call.stdout) == {
            'schemaVersion': 1, 'role': role, 'target': self.target, 'bytes': selected['artifactBytes'],
            'sha256': selected['artifactSha256'], 'closedMetadataMatched': True, 'originalClosesKnown': True},
            'candidate-original-acquisition')
        return self.read_candidate_zip()

    def read_candidate_zip(self):
        selected = self.nomination
        name = target_names(self.target) + ('-retained-observer.zip' if self.__retained_observer else '-candidate.zip')
        entry, body = self.quota.call(self.outer, 'file', self.work / name, selected['artifactBytes'], modes=(0o600,))
        self.private[name] = entry['identity']
        def before_image(size):
            self.admit_resources(*self._resource_inputs, image_bytes=size, acquiring=True)
        if self.__retained_observer:
            values = candidate.retained_observer_members(body, self.retained_selection(), self.clock,
                before_image=before_image)
            resume.retained_image_post(self.outer, entry, body, self.clock)
            self.__members_document = resume.canonical(values['members'])
            self.__image_document = resume.canonical(next(v for v in values['members']
                if v['name'] == candidate.RETAINED_OBSERVER_IMAGE))
            self.__artifact_admitted = True
            return {candidate.RETAINED_OBSERVER_IMAGE: values['image']}
        values = candidate.candidate_members(body, selected, self.clock, before_image=before_image)
        resume.need(self.outer.read(entry) == body, 'candidate-acquisition-original-post')
        self.__members_document = resume.canonical([{'name': name, 'bytes': len(body), 'sha256': resume.sha(body)}
                                                   for name, body in sorted(values.items())])
        self.preview_bytes, self.preview_sha = len(values['PREVIEW.json']), resume.sha(values['PREVIEW.json'])
        self.__preview_document = resume.canonical(candidate.candidate_preview_data(values['PREVIEW.json'], selected))
        self.__artifact_admitted = True
        return values

    def reuse_candidate(self):
        resume.need(self.purpose == "restore-install" and self.baseline_receipt is not None
                    and not self.__acquisition_entered and not self.__artifact_admitted,
                    "candidate-reuse-order")
        self.__acquisition_entered = True
        return self.read_candidate_zip()

    def admit_baseline(self):
        """Actual held root-owned baseline; no pathname-only or old producer receipt."""
        resume.need(self.purpose == "restore-install" and self.fixture_api is not None
                    and self.baseline_receipt is None and self.__source_loaded,
                    "candidate-baseline-order")
        # Two receipt originals plus Library/Application Support/baseline,
        # with the complete remaining native seventeen originals still funded.
        resume.need(self.quota.reserved + 5 + 17 <= resume.MAX_ORIGINALS,
                    'candidate-baseline-original-budget')
        api = self.fixture_api
        status, body = self.quota.call(self.outer, 'file', self.work / BASELINE_STATUS, 4, modes=(0o600,))
        resume.need(body == b'0\n', 'candidate-baseline-caller-zero')
        record, body = self.quota.call(self.outer, 'file', self.work / BASELINE_RECEIPT, 65536, modes=(0o600,))
        value = api.candidate_baseline_receipt_data(self.stager.maintenance_json(body, 65536),
            self.nomination, self.helper_source, self.helper_tree, self.run_id, self.run_attempt)
        path = Path('/Library/Application Support') / api.baseline_name_data(
            {key: value['binding'][key] for key in ('fixtureSource','productSource','runId','runAttempt','target')})
        entry, baseline_body = self.quota.call(self.outer, 'file', path, api.RECORD_LIMIT, uid=0, modes=(0o444,))
        library = self.outer.directories[Path('/Library')]
        resume.need(library['identity'][3] == 0 and not library['identity'][2] & 0o022,
                    'candidate-baseline-protected-ancestor')
        parent = self.outer.directories[path.parent]
        parent_id = dict(zip(('device','inode','mode','uid','gid'), parent['identity']))
        resume.need(parent_id['uid'] == 0 and not parent_id['mode'] & 0o022
                    and entry['identity'][4] == 0 and entry['identity'][5] == 1,
                    'candidate-baseline-protected-original')
        api.baseline_value_data(self.stager.maintenance_json(baseline_body, api.RECORD_LIMIT),
                                value['binding'], parent_id)
        q = entry['identity']
        observed = {'bytes':len(baseline_body), 'sha256':resume.sha(baseline_body),
                    'identity':list(q[:3] + (q[5],q[3],q[4]) + q[6:])}  # Existing fixture stat order.
        resume.need(observed == value['baselineOriginal'] and observed['sha256'] == value['baselineSha256'],
                    'candidate-baseline-original-binding')
        self.baseline, self.baseline_entry = value, entry
        self.baseline_receipt = (record, body, status)
        self.point()

    def baseline_post(self):
        resume.need(self.purpose == 'restore-install' and self.baseline_entry is not None,
                    'candidate-baseline-not-admitted')
        record, receipt, status = self.baseline_receipt
        self.point()
        resume.need(self.outer.read(record) == receipt and self.outer.read(status) == b'0\n'
                    and resume.sha(self.outer.read(self.baseline_entry)) == self.baseline['baselineSha256'],
                    'candidate-baseline-original-post')

    def read_mounted(self, mounted, directory, mount, image, preview):
        resume.need(self.__binding is None and self.__artifact_admitted, 'candidate-mounted-once')
        resume.need(self.stager.source_build_selection(self.target) == self.selection, 'candidate-source-selection-post')
        self.point()
        if self.__retained_observer:
            resume.need(preview is None, 'retained-observer-no-preview')
            info = os.stat('Install.pkg', dir_fd=directory['fd'], follow_symlinks=False)
            resume.need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= resume.LIMIT, 'retained-observer-package-bound')
            package_size = info.st_size
        else:
            package_size = preview['packageSize']
        self.admit_resources(*self._resource_inputs, image_bytes=len(image),
                             package_bytes=package_size, reading=True)
        originals, selected = {}, {}
        held = [] if self.__predecessor_install else None
        for key, name, cap in (('package', 'Install.pkg', package_size),
                              ('descriptor', 'producer.json', self.stager.PRODUCER_DESCRIPTOR_BYTES),
                              ('signature', 'producer.sig', self.stager.PRODUCER_SIGNATURE_BYTES)):
            info = os.stat(name, dir_fd=directory['fd'], follow_symlinks=False)
            resume.need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= cap
                        and info.st_uid in (0, os.getuid()) and info.st_gid in (0, os.getgid()), 'candidate-mounted-shape')
            entry, body = self.quota.call(mounted, 'file', mount / name, info.st_size, uid=info.st_uid, modes=(0o444,))
            resume.need(len(body) == info.st_size and (self.__retained_observer or resume.sha(body) == preview[key + 'Sha256'])
                        and (key != 'package' or len(body) == package_size), 'candidate-mounted-content-pin')
            originals[name] = (body, 0o444)
            selected[key] = {'name': name, 'bytes': len(body), 'sha256': resume.sha(body)}
            if held is not None: held.append((name, entry, body))
        release = (self.stager.maintenance_producer_data(originals['producer.json'][0], target=self.target)['releaseSet']['current']
                   if self.__retained_observer else None)
        row = dict(self.nomination, **selected, packageVersion=self.selection.package_version, release=self.selection.release,
            members=resume.decode(self.__members_document),
            inventorySha256=release['inventorySha256'] if self.__retained_observer else preview['installerInventorySha256'],
            runtimeManifestSha256=release['runtimeManifestSha256'] if self.__retained_observer else preview['runtimeManifestSha256'],
            signingIdentity=dict(self.signing_identity))
        self.admit_resources(*self._resource_inputs, image_bytes=len(image),
                             package_bytes=len(originals['Install.pkg'][0]))
        options = ({'capture_scripts': self.__capture_restore_scripts} if self.purpose == 'acquire-restore' else
                   {'capture_scripts': self.__capture_removal_program} if self.purpose == 'acquire-removal' else {})
        result, inventory = resume.mounted_data(originals, row, self.target, self.stager,
                                               allocation_budget=self.allocation_budget, candidate=True, retained_observer=self.__retained_observer, **options)
        self.point()
        self.__binding = resume.canonical(row)
        self.__binding_image_bytes = len(image)
        if held is not None: self.__mounted_reread_inputs = (mounted, tuple(held))  # Aliases only; no byte copy/new original.
        if self.purpose in ("acquire-restore", "acquire-removal"): self._restore_originals = originals
        return originals, row, result, inventory

    def pre_detach_originals(self, post, facts):
        super().pre_detach_originals(post, facts)
        if not self.__predecessor_install: return
        # Production's final mounted-read workload, after full readback and
        # immediately before the unchanged consuming mounted.finish/detach.
        # Bounded streaming is NOT production's whole-file syscall schedule.
        # Stay in the SAME work region; never spend the cleanup reserve here.
        resume.need(self.__installed_signature_state == 'deferred' and self.__mounted_reread_state is None
                    and self.__mounted_reread_inputs is not None and self.__detach_observation is None
                    and self.installer_zero is True and self.readback_known is True and self.clock.finality is False,
                    'candidate-predecessor-reread-order')
        self.__mounted_reread_state = 'entered'
        mounted, held = self.__mounted_reread_inputs
        self.__mounted_reread_inputs = None  # Drop extra aliases before any fallible reread; never retry.
        resume.STATE['phase'] = 'mounted-reread'
        names = ('Install.pkg', 'producer.json', 'producer.sig')
        mount = self.mount_path()
        resume.need(tuple(name for name, entry, body in held) == names
                    and sum(entry['kind'] == 'file' for entry in mounted.entries) == 3,
                    'candidate-predecessor-reread-originals')
        for name, entry, body in held:
            resume.need(any(entry is original for original in mounted.entries)
                        and entry['kind'] == 'file' and entry['path'] == mount / name
                        and type(entry['fd']) is int and entry['fd'] >= 0 and entry['closed'] is False
                        and type(body) is bytes and 0 < len(body) <= resume.LIMIT
                        and entry['identity'][6] == len(body) and stat.S_IMODE(entry['identity'][2]) == 0o444,
                        'candidate-predecessor-reread-originals')
            self.point()
            # The existing reader compares exact retained bytes plus EOF and
            # original identity, with 64KiB reads and no full-size extra copy.
            resume.retained_image_post(mounted, entry, body, self.clock)
            self.point()
        self.__mounted_reread_state = 'verified'

    def install_image(self, image, preview):
        resume.need(self.__artifact_admitted and self.__binding is None and self.__source_loaded
                    and not self.__installation_entered,
                    'candidate-install-order')
        self.__installation_entered = True
        if self.__retained_observer:
            resume.need(preview is None and self.__image_document == resume.canonical({
                'name': candidate.RETAINED_OBSERVER_IMAGE, 'bytes': len(image), 'sha256': resume.sha(image)}),
                'retained-observer-install-image-binding')
        else:
            resume.need(resume.canonical(preview) == self.__preview_document
                        and (len(image), resume.sha(image)) == (preview['distributionBytes'], preview['distributionSha256']),
                        'candidate-install-image-binding')
        # Artifact pins never replace native signature verification.
        installed = super().install_image(image, preview)
        if self.__predecessor_install:
            # The unchanged owner has consumed mounted originals and completed
            # its sole detach0/namespace POST. A failed/unknown detach never gets
            # here. These remain actual calls under the SAME owner and deadline.
            resume.need(self.__installed_signature_state == 'deferred' and self.__mounted_reread_state == 'verified'
                        and self.mount_detached is True
                        and self.__detach_observation is not None and self.__detach_observation['outcome'] == 'detach0'
                        and self.installer_zero is True and self.readback_known is True,
                        'candidate-predecessor-signature-order')
            self.__installed_signature_state = 'entered'
            resume.STATE['phase'] = 'installed-signature'
            super().verify_installed_signatures()
            self.__installed_signature_state = 'verified'
        return installed

    def verify_installed_signatures(self):
        if not self.__predecessor_install:
            return super().verify_installed_signatures()
        # Only this isolated comparison defers the pair; this is NOT a verified
        # result. install_image above must perform both after first detach0.
        resume.need(self.__installed_signature_state is None and self.__detach_observation is None
                    and self.installer_zero is True and self.readback_known is True,
                    'candidate-predecessor-signature-order')
        self.__installed_signature_state = 'deferred'

    def __capture_restore_scripts(self, inventory, rows, scripts):
        # Retain only immutable app slices from the already budgeted parse.
        # No file is written before the mounted producer signature POST.
        resume.need(self.purpose == 'acquire-restore' and self.__binding is None
                    and self.__restore_inputs is None and self.fixture_api is not None,
                    'candidate-restore-capture-order')
        apps = self.fixture_api.app_rows(rows)
        selected = {"input/" + name: scripts["input/" + name] for name in apps}
        resume.need(all(type(value) is tuple and len(value) == 2 and type(value[0]) is bytes
                        and type(value[1]) is int for value in selected.values()),
                    'candidate-restore-capture-data')
        self.__restore_inputs = (inventory, MappingProxyType(selected))

    def __capture_removal_program(self, inventory, rows, scripts):
        # Same single full-package parse; retain one signed leaf, never rebuild it.
        resume.need(self.purpose == 'acquire-removal' and self.__binding is None
                    and self.__removal_program is None, 'candidate-removal-capture-order')
        name = 'app/' + self.stager.REMOVER
        row = rows[name]
        body, mode = scripts['input/' + name]
        resume.need(type(body) is bytes and mode == 0o555 and row['executable'] is True
                    and (len(body), resume.sha(body)) == (row['size'], row['sha256']),
                    'candidate-removal-program-inventory')
        self.__removal_program = body

    def publish_removal_inputs(self, inventory):
        # Called after native producer verification. Each fresh original closes
        # before returning; later phases independently rebind the exact donor.
        resume.need(self.purpose == 'acquire-removal' and self.__removal_program is not None
                    and not self.installer_entered, 'candidate-removal-publication-order')
        values = {name: self._restore_originals[name][0] for name in REMOVAL_DONORS[:3]}
        values.update({'install-inventory.json': inventory, 'mrk-macos-remove': self.__removal_program})
        # Existing publisher cap, not a new large-file transport or quota.
        resume.need(all(0 < len(body) <= 128 << 20 for body in values.values()), 'candidate-removal-output-bound')
        self.admit_resources(*self._resource_inputs, image_bytes=self.__binding_image_bytes,
                             package_bytes=len(values['Install.pkg']), reading=True)
        resume.need(self.quota.reserved + len(values) <= resume.MAX_ORIGINALS, 'candidate-removal-original-quote')
        for name in REMOVAL_DONORS:
            self.publish_owned(self.work / name, values[name], mode=0o555 if name == 'mrk-macos-remove' else 0o444)
        self.acquisition_result['remover'] = {'name': 'mrk-macos-remove', 'bytes': len(values['mrk-macos-remove']),
                                            'sha256': resume.sha(values['mrk-macos-remove'])}
        self.acquisition_result['removalDonor'] = {'sourcePackageVersion': self.selection.package_version,
            'release': self.selection.release, 'removerSha256': resume.sha(values['mrk-macos-remove'])}
        self.__removal_program = None
        del self._restore_originals
        self.point()

    def prepare_readback(self, result, inventory):
        # This hook runs only AFTER actual mounted producer signature POST.
        if self.__retained_observer:
            resume.need(self.__observer_product is None and self.__binding is not None, 'retained-observer-signed-product-once')
            self.__observer_product = resume.canonical({key: result[key] for key in
                ('package', 'descriptor', 'signature', 'inventory', 'release')})
            return None
        if self.purpose in ('acquire', 'acquire-restore', 'acquire-removal'):
            self.acquisition_result = {key: result[key] for key in ('package','descriptor','signature','inventory')}
            self.acquisition_result.update(runtimeManifestSha256=result['release']['runtimeManifestSha256'])
            if self.purpose == 'acquire-restore':
                resume.need(self.__restore_inputs is not None and self.__restore_inputs[0] is inventory,
                            'candidate-restore-captured-inventory')
                try:
                    self.package_api.candidate_materialize(self, self._restore_originals, inventory,
                                                          self.__restore_inputs[1])
                finally:
                    self.__restore_inputs = None
                    del self._restore_originals
            if self.purpose == 'acquire-removal': self.publish_removal_inputs(inventory)
            return False  # Existing owner detaches without ever entering Installer.
        if self.purpose == 'restore-install':
            self.baseline_post()
            expected = self.baseline['acquisition']
            resume.need(all(result[key] == expected[key] for key in ('package','descriptor','signature','inventory'))
                        and result['release']['runtimeManifestSha256'] == expected['runtimeManifestSha256'],
                        'candidate-baseline-product')
        if self.purpose == 'install':
            resume.need(self.__predecessor_metadata is None, 'candidate-predecessor-metadata-once')
            self.__predecessor_metadata = predecessor_metadata_projection(result, self.nomination)
        # Do not manufacture legacy P0/ce644 release evidence.
        return None

    def observe_installation(self, args, readback):
        resume.need(readback is None, 'candidate-no-legacy-readback')
        resume.need(self.stager.source_build_selection(self.target) == self.selection,
                    'candidate-source-selection-post')
        observed = self.stager.observation_command(args)
        resume.need(observed['originalInstallerResult']['action'] == 'fresh-install'
                    and len(observed['installationMetadata']) == 1, 'candidate-readback-not-fresh')
        if self.purpose == 'restore-install':
            self.baseline_post()
            self._initial = self.fixture_api.candidate_initial_data(observed, self.baseline,
                                                                    self.stager.same_package_result_census())
        return observed

    def retire(self):
        if self.purpose == 'install':
            return super().retire()
        self.point()
        keep = (set(REMOVAL_DONORS) if self.purpose == 'acquire-removal'
                else {target_names(self.target) + '-candidate.zip'})
        if self.purpose == 'restore-install':
            keep.update((BASELINE_RECEIPT, BASELINE_STATUS, 'installer-output.status'))
        for book in self.quota.books:
            if isinstance(book, resume.FixedSudoOriginals): continue
            for entry in book.entries:
                if entry['kind'] != 'directory': book.close(entry)
        resume.need(all(not book.errors for book in self.quota.books), 'candidate-retirement-close')
        for spelling, before in self.private.items():
            if spelling in keep: continue
            path = self.work / spelling
            parent = self.outer.directories[path.parent]
            resume.need(resume.identity(os.stat(path.name, dir_fd=parent['fd'], follow_symlinks=False)) == before,
                        'candidate-retirement-original')
            os.unlink(path.name, dir_fd=parent['fd'])
        input_parent = self.outer.directories.get(self.work / 'input')
        if input_parent is not None:
            resume.need(os.listdir(input_parent['fd']) == [], 'candidate-input-retirement-roster')
            self.outer.close(input_parent)
            resume.need(input_parent['closed'], 'candidate-input-retirement-close')
            os.rmdir('input', dir_fd=self.parent['fd'])
        self.outer.check()
        resume.need(set(os.listdir(self.parent['fd'])) == keep, 'candidate-retained-handoff-roster')

    def consume(self, retained, host_bytes):
        """One attempt under the original endpoint and final-close rules."""
        primary = None
        try:
            resume.need(self.__source_loaded, 'candidate-source-not-loaded')
            # Lifetime original cells, never live-FD credits.
            pending = 22 if self.purpose == 'acquire-removal' else 17 if self.purpose in ('restore-install','acquire','acquire-restore') else 20
            resume.need(self.quota.reserved + pending <= resume.MAX_ORIGINALS, 'candidate-original-ledger-capacity')
            self._resource_inputs = (retained, host_bytes)
            self.admit_resources(retained, host_bytes)
            artifact = self.reuse_candidate() if self.purpose == 'restore-install' else self.acquire_candidate()
            preview = None if self.__retained_observer else candidate.candidate_preview_data(artifact['PREVIEW.json'], self.nomination)
            image = artifact[candidate.RETAINED_OBSERVER_IMAGE if self.__retained_observer else 'MobileReleaseKit.dmg']
            self.admit_resources(retained, host_bytes, image_bytes=len(image))
            self.verify_sources()
            self.install_image(image, preview)
            self.verify_sources()
            if self.purpose == 'restore-install': self.baseline_post()
            self.point(); self.clock.finality = True
            self.retire()
            resume.need(self.quota.finish(), 'candidate-original-final-closes')
            self.clock.check()
            resume.need(all(row['returned'] and row['capturesSettled'] for row in self.calls)
                        and self.mount_detached and ((not self.installer_entered and self.acquisition_result is not None)
                        if self.purpose in ('acquire','acquire-restore','acquire-removal') else (self.installer_zero and self.readback_known)),
                        'candidate-original-terminal-finality')
            if self.__retained_observer:
                return self.retained_observer_receipt()
            if self.purpose in ('acquire','acquire-restore','acquire-removal'):
                return {'schemaVersion':1, 'scope':'candidate-closed-acquisition', 'nomination':self.nomination,
                    'helperSource':self.helper_source, 'helperTree':self.helper_tree,
                    'consumerRunId':self.run_id, 'consumerRunAttempt':self.run_attempt,
                    **self.acquisition_result, 'nativeProducerSignatureVerified':True,
                    'originalMountDetached':True, 'originalClosesKnown':True, 'installerEntered':False,
                    'productReady':False}
            result = {'scope': 'candidate-fresh-installer-observation', 'target': self.target,
                    'producerSource': self.nomination['source'], 'producerTree': self.nomination['tree'],
                    'artifactId': self.nomination['artifactId'], 'artifactSha256': self.nomination['artifactSha256'],
                    'producerRunId': self.nomination['runId'], 'producerRunAttempt': self.nomination['runAttempt'],
                    'producerJobId': self.nomination['jobId'], 'helperSource': self.helper_source,
                    'helperTree': self.helper_tree, 'consumerRunId': self.run_id, 'consumerRunAttempt': self.run_attempt,
                    'originalInstallerReturnedZero': True, 'sameRequestReadback': True,
                    'originalMountDetached': True, 'originalClosesKnown': True,
                    'workloadsKnownSettled': True, 'privateOutputsRetired': True,
                    'productReady': False, 'uiQualified': False, 'p0Qualified': False}
            if self.purpose == 'install':
                resume.need(type(self.__predecessor_metadata) is bytes, 'candidate-predecessor-metadata-missing')
                result['predecessorMetadata'] = predecessor_metadata_data(resume.decode(self.__predecessor_metadata), self.nomination)
                if self.__predecessor_install:
                    resume.need(self.__installed_signature_state == 'verified', 'candidate-predecessor-installed-signatures')
                    resume.need(self.__mounted_reread_state == 'verified', 'candidate-predecessor-reread-known')
                    result.update(experiment='public-predecessor-install-detach',
                        detachObservation=dict(self.__detach_observation), packageInstallScheduleEqual=False,
                        installedSignatureCheckOrder='after-first-detach0', installedSignaturesVerified=True,
                        finalMountedRereadOrder='after-readback-before-mounted-closes', finalMountedRereadVerified=True)
                resume.need(len(resume.canonical(result)) <= PREDECESSOR_METADATA_LIMIT, 'candidate-predecessor-receipt-bound')
                self.clock.check()
            if self.purpose == 'restore-install':
                result['scope'] = 'candidate-baseline-fresh-installer-observation'
                result['privateOutputsRetired'] = False  # Prior original handoffs remain for the chain.
                result['baselineSha256'] = self.baseline['baselineSha256']
                result['initial'] = resume.decode(resume.canonical(self._initial))
                # This is the ORIGINAL status published after native Installer0,
                # not a status synthesized from this wrapper's future return.
                status = self.private.get('installer-output.status')
                resume.need(status is not None and status[6] == 2, 'candidate-installer-status-original')
                result['installerStatusOriginal'] = {'bytes': 2, 'sha256': resume.sha(b'0\n'),
                                                     'identity': list(status)}
            return result
        except BaseException as error:
            primary = error
            raise
        finally:
            settled = False
            try:
                settled = self.quota.finish()
            except BaseException:
                if primary is None: raise
                BaseException.add_note(primary, 'candidate-original-final-closes')
            if not settled:
                if primary is None: raise resume.Refused('candidate-original-final-closes')
                BaseException.add_note(primary, 'candidate-original-final-closes')

    def retained_observer_receipt(self):
        # Only consume's successful actual finality reaches this projection.
        # The shell must still write a separate status after THIS caller exits.
        resume.need(self.__retained_observer and self.__observer_product is not None,
                    'retained-observer-signed-product-missing')
        observed = self.installation
        q = self.outer.directories[self.work.parent]['identity']
        work_identity = (q[0], q[1], q[3])
        value = {'schemaVersion': 1, 'scope': 'retained-observer-fresh-install',
            'packageRole': 'installed-shell-observation', 'nativeScope': 'tool-setup', 'target': self.target,
            'nomination': self.nomination, 'members': resume.decode(self.__members_document),
            'image': resume.decode(self.__image_document), **resume.decode(self.__observer_product),
            'helperSource': self.helper_source, 'helperTree': self.helper_tree,
            'consumerRunId': self.run_id, 'consumerRunAttempt': self.run_attempt, 'consumerWorkDirectory': list(work_identity),
            'freshInstall': {'requestId': observed['requestId'], 'invocation': observed['invocation'],
                'instance': observed['installationMetadata'][0]['instance'],
                'stateSha256': observed['originalInstallerResult']['stateSha256'],
                'resultSha256': observed['installerResultExport']['sha256']},
            'nativeProducerSignatureVerified': True, 'installedSignaturesVerified': True,
            'originalInstallerReturnedZero': True, 'sameRequestReadback': True,
            'originalMountDetached': True, 'originalClosesKnown': True, 'workloadsKnownSettled': True,
            'privateOutputsRetired': True, 'productReady': False, 'uiQualified': False, 'p0Qualified': False}
        return candidate.retained_observer_install_receipt_data(value, self.retained_selection(), self.helper_source,
            self.helper_tree, self.run_id, self.run_attempt, work_identity)


def resume_identity(entry):
    """Explicit adapter between the existing owners' different stat field order."""
    q = entry["identity"]
    resume.need(type(q) is tuple and len(q) == 9, "candidate-helper-original-shape")
    return q[:3] + (q[4],q[5],q[3]) + q[6:]


def candidate_install_receipt_data(api, value, nomination, helper_source, helper_tree, run, attempt, baseline):
    """The genuine closed candidate Installer handoff, not old package status."""
    need, nonzero_hex_data = resume.need, api.nonzero_hex_data
    expected = {'scope':'candidate-baseline-fresh-installer-observation', 'target':nomination['target'],
        'producerSource':nomination['source'], 'producerTree':nomination['tree'],
        'artifactId':nomination['artifactId'], 'artifactSha256':nomination['artifactSha256'],
        'producerRunId':nomination['runId'], 'producerRunAttempt':nomination['runAttempt'],
        'producerJobId':nomination['jobId'], 'helperSource':helper_source, 'helperTree':helper_tree,
        'consumerRunId':run, 'consumerRunAttempt':attempt, 'originalInstallerReturnedZero':True,
        'sameRequestReadback':True, 'originalMountDetached':True, 'originalClosesKnown':True,
        'workloadsKnownSettled':True, 'privateOutputsRetired':False, 'productReady':False,
        'uiQualified':False, 'p0Qualified':False, 'baselineSha256':baseline['baselineSha256']}
    need(type(value) is dict and set(value) == set(expected) | {'initial','installerStatusOriginal'}
         and all(type(value[k]) is type(v) and value[k] == v for k,v in expected.items()),
         'candidate-restore-installer-handoff')
    initial = value['initial']
    need(type(initial) is dict and set(initial) == {'requestId','invocation','stateSha256','resultSha256','instance'}
         and all(nonzero_hex_data(initial[k],32 if k in ('requestId','invocation','instance') else 64)
                 for k in initial), 'candidate-restore-initial-data')
    status = value['installerStatusOriginal']
    need(type(status) is dict and set(status) == {'bytes','sha256','identity'} and type(status['bytes']) is int
         and status['bytes'] == 2 and status['sha256'] == resume.sha(b'0\n')
         and type(status['identity']) is list and len(status['identity']) == 9
         and all(type(v) is int for v in status['identity']), 'candidate-restore-native-status')
    return value


def candidate_restore(op, baseline_entry, baseline_status, installed_entry, installed_status, native_status):
    """Only the closed candidate bootstrap calls this existing-chain adapter."""
    context = getattr(op, 'candidate_restore_context', None)
    api = op.app_absence_module
    need = resume.need
    need(op.phase == api.RESTORE and type(context) is dict and op.app_absence is not None
         and not op.calls and not op.errors and not op.credential_calls and not op.credential_contexts,
         'candidate-restore-owner')
    for entry in (baseline_entry,baseline_status,installed_entry,installed_status,native_status):
        need(op.entry_registry.get(id(entry)) is entry, 'candidate-restore-original')
    need(op.read(baseline_status) == op.read(installed_status) == b'0\n', 'candidate-restore-caller-zero')
    baseline_body, installed_body = op.read(baseline_entry), op.read(installed_entry)
    value = api.candidate_baseline_receipt_data(op.app_absence_api.tool_json(baseline_body), context['nomination'],
        context['helperSource'], context['helperTree'], context['runId'], context['runAttempt'])
    installed = candidate_install_receipt_data(api, op.app_absence_api.tool_json(installed_body), context['nomination'],
        context['helperSource'], context['helperTree'], context['runId'], context['runAttempt'], value)
    native_body = op.read(native_status)
    need(native_body == b'0\n' and installed['installerStatusOriginal'] == {
        'bytes':len(native_body), 'sha256':resume.sha(native_body), 'identity':list(resume_identity(native_status))},
        'candidate-restore-native-status-original')
    api.preparation_input(op)
    need(value['preparationReceiptSha256'] == op.app_absence['preparationSha256'],
         'candidate-restore-preparation-original')
    op.package_sources.extend(((baseline_entry,baseline_body),(baseline_status,b'0\n'),
        (installed_entry,installed_body),(installed_status,b'0\n'),(native_status,native_body)))
    previous = {key:value[key] for key in ('binding','layout','image','baselineSha256','baselineOriginal')}
    previous['initial'] = installed['initial']
    # Only an internal common-body input is assembled; no legacy owner receipt,
    # role list, source/run relabel or future native result is manufactured.
    need(native_status['name'] == 'installer-output.status'
         and native_status['parent_entry'] is op.directory(op.work_entry, 'resume-carrier', 'candidate-transport'),
         'candidate-restore-native-status-route')
    status_path = op.work / 'resume-carrier' / 'installer-output.status'
    api.restore_from_initial(op, previous, baseline_body, initial_status=status_path)
    need(op.read(baseline_entry) == baseline_body and op.read(installed_entry) == installed_body
         and op.read(native_status) == native_body, 'candidate-restore-handoff-post')


def fixture_main(purpose):
    context = entry_context((purpose,))
    resume.need(os.environ.get("GITHUB_EVENT_NAME") == "push", "candidate-fixture-push-only")
    context["started"] = STARTED_NS
    os.environ.pop("GITHUB_TOKEN", None)
    path = HELPER_ROOT / "desktop/tools/macos_android_helper_package.py"
    original, body = resume.host_read(path, resume.SOURCE_MODULE_LIMIT)
    module = resume.load_module("_mrk_candidate_fixture_phase", path, body)
    return module.candidate_fixture_phase(sys.modules[__name__], context, purpose, STARTED_NS, (original,path,body))


def removal_acquisition_data(value, nomination, helper_source, helper_tree, run, attempt, selection):
    """Same-run original acquisition, not an authority supplied by environment."""
    fixed = dict(schemaVersion=1, scope='candidate-closed-acquisition', nomination=nomination,
        helperSource=helper_source, helperTree=helper_tree, consumerRunId=run, consumerRunAttempt=attempt,
        nativeProducerSignatureVerified=True, originalMountDetached=True, originalClosesKnown=True,
        installerEntered=False, productReady=False)
    names = dict(package='Install.pkg', descriptor='producer.json', signature='producer.sig',
                 inventory='install-inventory.json', remover='mrk-macos-remove')
    resume.need(type(value) is dict and set(value) == set(fixed) | set(names) | {'runtimeManifestSha256','removalDonor'}
        and all(type(value[k]) is type(v) and value[k] == v for k,v in fixed.items()), 'candidate-removal-acquisition')
    for key,name in names.items():
        row=value[key]
        resume.need(type(row) is dict and set(row)=={'name','bytes','sha256'} and row['name']==name
            and type(row['bytes']) is int and 0 < row['bytes'] <= 128 << 20
            and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256'])
            and row['sha256'] != '0'*64, 'candidate-removal-donor')
    resume.need(type(value['runtimeManifestSha256']) is str and re.fullmatch('[0-9a-f]{64}',value['runtimeManifestSha256'])
        and value['runtimeManifestSha256'] != '0'*64 and value['removalDonor'] == {
            'sourcePackageVersion':selection.package_version,'release':selection.release,
            'removerSha256':value['remover']['sha256']}, 'candidate-removal-source-selection')
    return value


def removal_main(phase):
    context = entry_context((phase,))
    resume.need(phase in REMOVAL_PHASES and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
                and os.environ.get('MRK_CANDIDATE_MODE') == 'remove-delivery', 'candidate-removal-entry')
    path = HELPER_ROOT / 'desktop/tools/macos_android_helper_package.py'
    original, body = resume.host_read(path, resume.SOURCE_MODULE_LIMIT)
    module = resume.load_module('_mrk_candidate_removal_phase', path, body)
    return module.candidate_removal_phase(sys.modules[__name__], context, phase, (original, path, body))


def entry_context(arguments):
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    context = context_data(os.environ, ROOT, platform.machine())
    resume.need(tuple(sys.argv[1:]) == arguments and sys.version_info[:3] == (3, 14, 7)
                and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
                and sys.platform == 'darwin' and os.getuid() == os.geteuid() != 0
                and os.getgid() == os.getegid(), 'candidate-host-interpreter')
    return context


def host_base():
    """Private shell capture before the ordinary documented without-pip venv."""
    entry_context(('host-base',))
    copy_path = Path(sys._base_executable).absolute()
    copy_executable = copy_path.resolve()
    original, body = resume.host_read(copy_executable, 64 << 20, base=True)
    return {'launcherPath': sys.executable, 'executable': str(Path(sys.executable).resolve()),
            'copyPath': str(copy_path), 'copyExecutable': str(copy_executable), 'prefix': sys.base_prefix,
            'identity': list(original), 'sha256': resume.sha(body)}


def bind_host():
    """Use the existing copy/config/roster rules, never a new interpreter owner.

    The preceding ordinary shell step must have joined `python -m venv --copies
    --without-pip --without-scm-ignore-files` under umask077 in fresh host-python.
    This entry executes only in that copy, and publishes its original sidecar
    exclusively. Partial/foreign/uncertain outputs are preserved, never adopted.
    """
    context = entry_context(('bind-host',))
    raw = os.environ.pop('MRK_HOST_BASE_CONTEXT', '')
    resume.need(type(raw) is str and 0 < len(raw) <= 16384, 'candidate-host-base-context')
    base = resume.decode(raw.encode('ascii'))
    host = context['work'].parent / 'host-python'
    # Select the actual interpreter's base, not an environment-provided path.
    copy = Path(sys._base_executable).resolve()
    original, body = resume.host_read(copy, 64 << 20, base=True)
    resume.need(type(base) is dict and base.get('copyExecutable') == str(copy)
                and base.get('identity') == list(original) and base.get('sha256') == resume.sha(body),
                'candidate-host-base-post')
    snapshot, cfg = resume.host_snapshot(host, resume.host_directory, resume.host_read)
    native = {'executable': str(Path(sys.executable).resolve()), 'prefix': sys.prefix,
              'basePrefix': sys.base_prefix, 'baseExecutable': str(copy)}
    binding = {'schemaVersion': 1, 'source': context['helperSource'], 'runId': context['runId'],
               'runAttempt': context['runAttempt'], 'base': base, 'prefix': native['prefix'],
               'basePrefix': native['basePrefix'], 'baseExecutable': native['baseExecutable'],
               **snapshot, 'retainedUntilHostedTeardown': True}
    resume.host_selection_data(binding, snapshot, cfg, host, native, context['helperSource'], context['runId'], context['runAttempt'])
    data = resume.canonical(binding) + b'\n'
    resume.need(len(data) <= 32768, 'candidate-host-binding-bound')
    parent = fd = None
    primary = None
    try:
        parent = os.open(host, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        before_parent = resume.identity(os.fstat(parent))[:5]
        resume.need(before_parent == resume.identity(os.stat(host, follow_symlinks=False))[:5]
                    and before_parent[2] == stat.S_IFDIR | 0o700
                    and before_parent[3:] == (os.getuid(), os.getgid()), 'candidate-host-directory')
        fd = os.open('host-binding.json', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        opened = resume.identity(os.fstat(fd))
        resume.need(opened[2] == stat.S_IFREG | 0o600 and opened[3:7] == (os.getuid(), os.getgid(), 1, 0),
                    'candidate-host-binding-original')
        at = 0
        while at < len(data):
            written = os.write(fd, data[at:]); resume.need(written > 0, 'candidate-host-binding-write'); at += written
        os.fsync(fd)
        final = resume.identity(os.fstat(fd))
        resume.need(final[:6] == opened[:6] and final[6] == len(data) and os.pread(fd, len(data) + 1, 0) == data
                    and not os.pread(fd, 1, len(data))
                    and resume.identity(os.stat('host-binding.json', dir_fd=parent, follow_symlinks=False)) == final,
                    'candidate-host-binding-post')
        after, after_cfg = resume.host_snapshot(host, resume.host_directory, resume.host_read, sidecar=True)
        resume.need(after == snapshot and after_cfg == cfg
                    and resume.identity(os.fstat(parent))[:5] == before_parent
                    == resume.identity(os.stat(host, follow_symlinks=False))[:5], 'candidate-host-copy-post')
    except BaseException as error:
        primary = error
        raise
    finally:
        errors = []
        for opened in (fd, parent):
            if opened is not None:
                try: os.close(opened)
                except BaseException as error: errors.append(error)
        if errors:
            if primary is None: raise resume.Refused('candidate-host-binding-close-unknown')
            BaseException.add_note(primary, 'candidate-host-binding-close-unknown')
    return {'hostPrepared': True, 'source': context['helperSource'], 'target': context['target'],
            'runId': context['runId'], 'runAttempt': context['runAttempt']}



def _admit_system_tool(session, role, tool):
    try:
        uid = os.stat(tool, follow_symlinks=False).st_uid
        resume.need(uid == 0, 'candidate-tool-owner')
        _entry, body = session.quota.call(session.outer, 'file', Path(tool), 64 << 20, uid=0,
            modes=(0o555, 0o755, 0o4555, 0o4755), system_tool=True)
        resume.need(body, 'candidate-tool-original')
    except BaseException as error:
        try:
            global _SYSTEM_TOOL_FAILURE
            _SYSTEM_TOOL_FAILURE = (error, role, type(session.outer))
        except BaseException:
            pass  # Diagnostics must not replace this identical original failure.
        raise


def main(purpose="install"):
    """Hosted fixed acquisition/install and explicit reuse only."""
    global _SYSTEM_TOOL_FAILURE, _PREDECESSOR_DETACH, _RETAINED_DETACH
    _SYSTEM_TOOL_FAILURE = None
    _PREDECESSOR_DETACH = None
    _RETAINED_DETACH = None
    resume.need(type(purpose) is str and purpose in PURPOSES, 'candidate-purpose')
    predecessor = os.environ.get('MRK_CANDIDATE_MODE') == 'install-predecessor'
    retained = os.environ.get('MRK_CANDIDATE_MODE') == 'install-retained-observer'
    resume.need(not predecessor or purpose == 'install', 'candidate-predecessor-install-purpose')
    resume.need(not retained or purpose == 'install', 'retained-observer-install-purpose')
    resume.need((purpose == 'acquire-removal' or predecessor or retained) == (os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'),
                'candidate-removal-purpose')
    context = entry_context(() if purpose == "install" else (purpose,))
    clock = resume.Deadline(started=STARTED_NS)
    quota = resume.OriginalQuota()
    session, primary = None, None
    try:
        clock.check()
        if purpose != 'restore-install':
            quota.reserve(1)
            os.mkdir(context['work'], 0o700)
        quota.reserve(1)  # Consuming bootstrap source FD, retained re-read below.
        session = CandidateResume(HELPER_ROOT, CANDIDATE_ROOT, context['work'], clock,
                                  resume.bootstrap_originals(HELPER_ROOT), quota=quota, purpose=purpose,
                                  predecessor_install=predecessor, retained_observer=retained)
        session.helper_source = context['helperSource']
        session.run_id, session.run_attempt = context['runId'], context['runAttempt']
        session.load_nomination(context['target'])
        if purpose == 'restore-install':
            resume.need(session.parent['identity'][3:5] == (os.getuid(), os.getgid())
                        and stat.S_IMODE(session.parent['identity'][2]) == 0o700
                        and set(os.listdir(session.parent['fd'])) == {target_names(context['target'])+'-candidate.zip', BASELINE_RECEIPT, BASELINE_STATUS},
                        'candidate-reuse-work-roster')
        modules = {}
        for path in HELPER_SOURCE_INPUTS:
            body = session.source(path, resume.SOURCE_MODULE_LIMIT)
            if path.startswith('desktop/tools/') and Path(path).name != 'macos_e2_native_fixture.py':
                modules[Path(path).name] = resume.load_module('_mrk_candidate_' + Path(path).stem, HELPER_ROOT / path, body)
        session.owner = modules['macos_aqua_qualification.py'].load_owner(HELPER_ROOT)
        session.initialize_host(modules['macos_xcode_host_preparation.py'])
        session.python = os.path.realpath(sys.executable)
        session.environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC',
                               'HOME': '/Users/runner', 'TMPDIR': str(session.work) + '/',
                               'DEVELOPER_DIR': '/Applications/Xcode.app/Contents/Developer'}
        host_root = session.work.parent / 'host-python'
        host_entry, host_body = quota.call(session.outer, 'file', host_root / 'host-binding.json', 32768, modes=(0o600,))
        host_binding = resume.decode(host_body)
        def directory(path):
            held = quota.call(session.outer, 'directory', path)
            return held['identity'], os.listdir(held['fd'])
        def read_file(path, limit):
            held, body = quota.call(session.outer, 'file', path, limit)
            return held['identity'], body
        snapshot, cfg = resume.host_snapshot(host_root, directory, read_file, sidecar=True)
        host_context = {'executable': session.python, 'prefix': sys.prefix, 'basePrefix': sys.base_prefix,
                        'baseExecutable': str(Path(sys._base_executable).resolve())}
        host_bytes = resume.host_selection_data(host_binding, snapshot, cfg, host_root, host_context,
                                                session.helper_source, session.run_id, session.run_attempt) + len(host_body)
        # host_snapshot already holds this exact interpreter original. Reuse it
        # rather than spending a duplicate lifetime cell merely to reopen it.
        python_entries = [entry for entry in session.outer.entries if entry['kind'] == 'file'
                          and entry['path'] == Path(session.python) and not entry['closed']]
        resume.need(len(python_entries) == 1 and python_entries[0]['identity'][6] > 0, 'candidate-host-python-original')
        for role, tool in (('git', '/usr/bin/git'), ('hdiutil', '/usr/bin/hdiutil'),
                           ('vm_stat', '/usr/bin/vm_stat'), ('openssl', '/usr/bin/openssl'),
                           ('codesign', '/usr/bin/codesign'), ('installer', '/usr/sbin/installer')):
            if purpose != 'acquire-removal' or role != 'installer':
                _admit_system_tool(session, role, tool)
        if purpose != 'acquire-removal':
            sudo = quota.book(lambda: resume.FixedSudoOriginals(session.host_module, session.host, clock, os.getuid()))
            sudo.acquire(quota)
        session.load_sources()
        if purpose == 'restore-install':
            ca = b''  # No network/acquisition child, no unused CA originals.
            session.admit_baseline()
        else:
            ca = resume.admit_pinned_tls_roots(session)
            session.token = os.environ.pop('GITHUB_TOKEN', None)
            resume.request_headers(authenticated=True, token=session.token)
        session.verify_sources()
        retained = sum(len(body) for _, body in session.sources) + len(session.child_bootstrap.encode('utf-8'))
        retained += len(ca) + len(host_body) + len(cfg) + (2 << 20)
        return session.consume(retained, host_bytes)
    except BaseException as error:
        primary = error
        raise
    finally:
        settled = False
        try: settled = quota.finish()
        except BaseException:
            if primary is None: raise
            BaseException.add_note(primary, 'candidate-original-final-closes')
        if not settled:
            if primary is None: raise resume.Refused('candidate-original-final-closes')
            BaseException.add_note(primary, 'candidate-original-final-closes')


def failure_data(error):
    """Useful public failure locations, never exception text or frame locals."""
    allowed = {'candidate-hosted-context', 'candidate-source-identity', 'candidate-source-tree',
        'candidate-predecessor-install-purpose', 'candidate-predecessor-target',
        'candidate-predecessor-detach-once', 'resume-original-detach',
        'candidate-predecessor-signature-order', 'candidate-predecessor-installed-signatures', 'resume-installed-signature',
        'candidate-predecessor-reread-order', 'candidate-predecessor-reread-originals',
        'candidate-predecessor-reread-known', 'resume-image-retained-post', 'resume-image-retained-eof',
        'candidate-original-ledger-capacity', 'candidate-materialize-whole-original-quote',
        'candidate-materialize-lifetime-quote', 'candidate-materialize-live-quote',
        'candidate-materialize-os-fd-limit', 'candidate-materialize-originals-known',
        'candidate-materialize-originals-bound',
        'candidate-bootstrap-original-post', 'candidate-fixture-entry', 'candidate-fixture-terminal',
        'candidate-native-original-quote', 'candidate-source-query-quote', 'candidate-carrier-close-unknown',
        'candidate-baseline-original-binding', 'restore-chain-complete-original-quote',
        'restore-chain-bootstrap-original-quote', 'restore-chain-lifetime-original-quote',
        'restore-chain-live-original-quote', 'restore-chain-os-fd-limit',
        'app-absence-original-deadline', 'candidate-restore-native-status-original'}
    parts = BaseException.args.__get__(error)
    reason = parts[0] if len(parts) == 1 and type(parts[0]) is str and parts[0] in allowed else 'unavailable'
    classes = {resume.Refused: 'Refused', OSError: 'OSError', FileNotFoundError: 'FileNotFoundError',
        PermissionError: 'PermissionError', ValueError: 'ValueError', TypeError: 'TypeError',
        RuntimeError: 'RuntimeError', KeyError: 'KeyError', AttributeError: 'AttributeError',
        ImportError: 'ImportError', KeyboardInterrupt: 'KeyboardInterrupt', SystemExit: 'SystemExit'}
    # Exact loaded globals and compile paths only.
    origins = ((globals(), __file__), (vars(resume), resume.__file__), (vars(candidate), candidate.__file__))
    captured, donor, boundary_seen, donor_seen = _SYSTEM_TOOL_FAILURE, None, False, False
    if (type(captured) is tuple and len(captured) == 3 and captured[0] is error
            and type(captured[1]) is str and captured[1] in ('git', 'hdiutil', 'vm_stat', 'openssl', 'codesign', 'installer')):
        module = sys.modules.get('_mrk_p0_originals')
        path = str(HELPER_ROOT / 'desktop/tools/macos_e2_native_fixture.py')
        if (type(module) is ModuleType and vars(module).get('__file__') == path
                and type(captured[2]) is type and captured[2] is vars(module).get('Originals')):
            function = vars(captured[2]).get('file')
            if type(function) is FunctionType and function.__globals__ is vars(module) and function.__code__.co_filename == path:
                donor = (vars(module), path)
                origins += (donor,)
    frames, resource_seen = [], False
    tb = BaseException.__traceback__.__get__(error)
    for _ in range(32):
        if tb is None:
            break
        code = tb.tb_frame.f_code
        resource_seen |= any(code is fn.__code__ and tb.tb_frame.f_globals is fn.__globals__
            for fn in (CandidateResume.admit_resources, resume.Resume.allocation_budget))
        boundary_seen |= code is _admit_system_tool.__code__ and tb.tb_frame.f_globals is globals()
        for namespace, path in origins:
            if (tb.tb_frame.f_globals is namespace and code.co_filename == path
                and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', code.co_name)
                and type(tb.tb_lineno) is int and 0 < tb.tb_lineno < 1000000):
                donor_seen |= donor is not None and namespace is donor[0]
                frames.append({'file': Path(path).name, 'function': code.co_name, 'line': tb.tb_lineno})
                frames = frames[-8:]
                break
        tb = tb.tb_next
    system_tool, error_class = None, classes.get(type(error), 'other')
    if donor is not None and boundary_seen:
        original = donor_seen and type(error) is donor[0].get('Refused')
        native = type(error) in (OSError, FileNotFoundError, PermissionError)
        local = type(error) is resume.Refused
        if original or native or local:
            system_tool = {'role': captured[1], 'errno': None}
            if native:
                number = OSError.errno.__get__(error)
                if type(number) is int and 0 <= number <= 65535: system_tool['errno'] = number
            if original:
                error_class = 'Refused'
                labels = {'system-tool-selection', 'directory-spelling', 'directory-owner-mode', 'original-handle-bound',
                    'original-unbound', 'original-changed', 'file-original-policy', 'original-short-read', 'original-grew'}
                reason = parts[0] if len(parts) == 1 and type(parts[0]) is str and parts[0] in labels else 'unavailable'
            elif local and len(parts) == 1 and type(parts[0]) is str and parts[0] in ('candidate-tool-owner', 'candidate-tool-original'):
                reason = parts[0]
    resource = None
    if type(error) is resume.Refused and resource_seen and len(parts) == 1 and type(parts[0]) is str and parts in (
            ('candidate-resource-admission',), ('resume-resource-memory-admission',), ('resume-resource-disk-admission',)):
        reason = parts[0]
        try: resource = resume.resource_projection_data(resume.STATE.get('resourceAdmission'))
        except Exception: pass
    value = {'scope': 'candidate-consumer-failure-only', 'reason': reason, 'resourceAdmission': resource,
        'exceptionClass': error_class, 'sourceFrames': frames, 'systemTool': system_tool,
        'rawOutputExported': False, 'cleanupAuthorized': False}
    if _PREDECESSOR_DETACH is not None:
        value.update(detachObservation=dict(_PREDECESSOR_DETACH), packageInstallScheduleEqual=False,
                     installedSignatureCheckOrder='after-first-detach0')
    if _RETAINED_DETACH is not None:
        value['retainedDetachObservation'] = retained_detach_diagnostic_data(_RETAINED_DETACH)
    return candidate.stager_failure_data(error, value, origins, CANDIDATE_ROOT / STAGER_PATH)


if __name__ == '__main__':
    try:
        arguments = sys.argv[1:]
        result = (host_base() if arguments == ['host-base'] else bind_host() if arguments == ['bind-host'] else
                  removal_main(arguments[0]) if len(arguments) == 1 and arguments[0] in REMOVAL_PHASES else
                  fixture_main(arguments[0]) if len(arguments) == 1 and arguments[0] in ('prepare-restore','restore-baseline','restore-chain') else
                  main(arguments[0]) if len(arguments) == 1 and arguments[0] in PURPOSES[1:] else main())
    except BaseException as error:
        # Exact public labels only; never arbitrary exception text/captures.
        try:
            sys.stderr.buffer.write(resume.canonical(failure_data(error)) + b'\n')
        except BaseException:
            sys.stderr.write('candidate-consumer-refused reason=unavailable\n')
        raise SystemExit(1) from None
    sys.stdout.buffer.write(resume.canonical(result) + b'\n')
