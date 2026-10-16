"""Detached candidate acquisition/install owner; no workflow activation.

Both real checkout roots and the original hosted Python/native process owner
are admitted before acquiring a carrier. A claimed commit alone is not enough.
It reuses Resume's actual native install, request census, readback, held inputs,
producer verification, detach and retirement rather than interpreting old status.
"""
import os
from pathlib import Path
import platform
import re
import stat
import sys
import time
from types import MappingProxyType

STARTED_NS = time.monotonic_ns()
ROOT = Path(__file__).absolute().parents[2]
sys.path.insert(0, str(ROOT))
from desktop.tools import macos_candidate_carrier as candidate
from desktop.tools import macos_fixed_carrier_resume as resume


CANDIDATE_ROOT = Path('/Users/runner/work/mobile-release-kit/mobile-release-kit')
HELPER_ROOT = CANDIDATE_ROOT / '.candidate-consumer-helper'
WORKFLOW = '.github/workflows/desktop-macos-candidate-consume.yml'
BRANCH = 'verify/desktop-macos-candidate-consume'
SELECTION_PATH = 'desktop/macos-installed-inputs/candidate-carrier-selection.json'
CHILD_SOURCE_LIMIT = 256 << 10
PARSER_SOURCE_LIMIT = 64 << 10
LEGACY_PATH = 'desktop/tools/macos_fixed_carrier_resume.py'
PARSER_PATH = 'desktop/tools/macos_candidate_carrier.py'
STAGER_PATH = 'desktop/tools/stage_macos_installed.py'
CONSUMER_PATH = 'desktop/tools/macos_candidate_consumer.py'
FIXTURE_PATH = 'desktop/tools/macos_app_absence_fixture.py'
BASELINE_RECEIPT = 'candidate-baseline.json'
BASELINE_STATUS = 'candidate-baseline.status'
PURPOSES = ('install', 'acquire', 'restore-install')
CANDIDATE_SOURCE_INPUTS = (
    ('desktop/macos-installed-inputs/build-release.json', 4096),
    ('desktop/macos-installed-inputs/build-release-intel.json', 4096),
    ('desktop/packaging/macos-install-producer-signing.profile', 1024),
    ('desktop/packaging/macos-android-service-signing.profile', 512),
)
HELPER_SOURCE_INPUTS = tuple(path for path in resume.SOURCE_FILES if path not in
                           (STAGER_PATH, 'desktop/tools/macos_public_verification_evidence.py'))


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
    resume.need(root == HELPER_ROOT and environment.get('GITHUB_WORKSPACE') == str(CANDIDATE_ROOT)
                and environment.get('RUNNER_TEMP') == '/Users/runner/work/_temp'
                and environment.get('GITHUB_REPOSITORY') == resume.REPOSITORY
                and environment.get('GITHUB_EVENT_NAME') == 'push'
                and environment.get('GITHUB_REF') == 'refs/heads/' + BRANCH
                and environment.get('GITHUB_WORKFLOW_REF') == resume.REPOSITORY + '/' + WORKFLOW + '@refs/heads/' + BRANCH
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


def candidate_resource_requirements(nomination, retained, host_bytes, *, image_bytes=None):
    """Before parsing PREVIEW reserve its full image cap, not the old ARM image.

    The post-acquisition quote credits ZIP copies only after parse+held POST has
    returned. Codec envelopes remain subject to Resume's actual vm_stat checks.
    """
    row = candidate.candidate_selection_data(nomination)
    resume.need(type(retained) is int and 0 <= retained <= 1 << 30
                and type(host_bytes) is int and 0 <= host_bytes <= 1 << 30,
                'candidate-resource-bound')
    resume.need(image_bytes is None or type(image_bytes) is int and 0 < image_bytes <= resume.LIMIT,
                'candidate-image-bound')
    image = resume.LIMIT if image_bytes is None else image_bytes
    memory = 6 * (row['artifactBytes'] + image) + (16 << 20) + retained + (512 << 20) + (1 << 30)
    # Include both the retained transport and its actual published image. Keep
    # the original installation/codec/disk reserve without crediting old bytes.
    disk = (3 << 30) + 2 * row['artifactBytes'] + 2 * image + host_bytes
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
    """Internal owner; no nomination is read from carrier bytes or ambient env.

    Host/process admission and the two checkout service bindings are deliberately
    not replaced by this constructor. main supplies their original bootstrap;
    no workflow currently activates this entry.
    """
    command_roles = (*resume.Resume.command_roles, 'helper-source', 'candidate-source')

    def __init__(self, helper_root, candidate_root, work, clock, factory, *, nomination=None, quota=None, purpose="install"):
        resume.need(helper_root == HELPER_ROOT and candidate_root == CANDIDATE_ROOT,
                    'candidate-separate-source-roots')
        resume.need(type(purpose) is str and purpose in PURPOSES, "candidate-purpose")
        self.__purpose = purpose
        self.baseline = self.baseline_entry = self.baseline_receipt = self.fixture_api = None
        self.acquisition_result = None
        self.__nomination = None if nomination is None else MappingProxyType(candidate.candidate_selection_data(nomination))
        self.__binding = None
        self.candidate_root = candidate_root
        self.__source_loaded = False
        self.__artifact_admitted = False
        self.__acquisition_entered = False
        self.__installation_entered = False
        super().__init__(helper_root, work, clock, factory, quota=quota)

    @property
    def purpose(self):
        return self.__purpose

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
        body = self.source(SELECTION_PATH, 8192)
        self.__nomination = MappingProxyType(selection_data(body, target))

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
        self.source(CONSUMER_PATH, 64 << 10)
        self.child_sources = {LEGACY_PATH: self.source(LEGACY_PATH, resume.SOURCE_LIMIT),
                              PARSER_PATH: self.source(PARSER_PATH, PARSER_SOURCE_LIMIT)}
        self.child_bootstrap = (acquisition_bootstrap(self.root, self.child_sources)
                                if self.purpose != "restore-install" else "")
        fixture_body = self.source(FIXTURE_PATH, 128 << 10) if self.purpose == "restore-install" else None
        bodies = {}
        for relative, cap in ((STAGER_PATH, resume.SOURCE_MODULE_LIMIT), *CANDIDATE_SOURCE_INPUTS):
            entry, body = self.quota.call(self.outer, 'file', self.candidate_root / relative, cap, uid=os.getuid())
            self.sources.append((entry, body)); bodies[relative] = body
        # The candidate's code is not executed until its real Git tree and every
        # source byte here match the exact service-nominated checkout.
        self.verify_sources()
        if fixture_body is not None:
            self.fixture_api = resume.load_module("_mrk_candidate_fixture", self.root / FIXTURE_PATH, fixture_body)
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

    def admit_resources(self, retained, host_bytes, *, image_bytes=None):
        resume.need(type(retained) is int and retained >= sum(len(body) for _, body in self.sources)
                    + len(self.child_bootstrap.encode('utf-8')), 'candidate-retained-source-budget')
        quote = candidate_resource_requirements(self.nomination, retained, host_bytes, image_bytes=image_bytes)
        call = self.command('memory', ['/usr/bin/vm_stat'], 10)
        page_size, physical = resume.host_memory_data(self.host, self.clock)
        memory = resume.memory_data(call.stdout, call.stderr, call.returncode, page_size=page_size, physical_bytes=physical)
        disk = os.fstatvfs(self.parent['fd'])
        required = quote['acquisitionMemory' if image_bytes is None else 'postAcquisitionMemory']
        facts = resume.resource_admission_data(memory['availableEstimateBytes'], required,
                                              disk.f_bavail * disk.f_frsize, quote['requiredDisk'])
        resume.STATE['resourceAdmission'] = facts
        resume.need(facts['memorySufficient'] and facts['diskSufficient'], 'candidate-resource-admission')
        self.memory_base, self.required_disk = required, quote['requiredDisk']
        self.allocation_samples, self.cpio_window = 0, None

    def acquire_fixed(self):
        # No accidental fallback to the historical carrier from a base caller.
        return self.acquire_candidate()

    def acquire_candidate(self):
        resume.need(self.__source_loaded and not self.__acquisition_entered and self.__binding is None,
                    'candidate-acquire-order')
        self.__acquisition_entered = True
        self.point(); self.quota.reserve(3)
        selected = self.nomination
        request = {'row': selected, 'role': 'candidate', 'target': self.target, 'work': str(self.work),
                   'workIdentity': list(self.parent['identity']), 'caPath': self.ca_path, 'caSha256': self.ca_sha,
                   'endpoint': min(self.clock.work, self.clock.check() + 120_000_000_000)}
        env = dict(self.environment, MRK_P0_REQUEST=resume.canonical(request).decode('ascii'), MRK_P0_READ_TOKEN=self.token)
        bootstrap = self.child_bootstrap
        call = self.command('acquire-carrier', [self.python, '-I', '-S', '-B', '-c', bootstrap], 120, env=env)
        resume.need(call.returncode == 0 and call.stderr == b'' and resume.decode(call.stdout) == {
            'schemaVersion': 1, 'role': 'candidate', 'target': self.target, 'bytes': selected['artifactBytes'],
            'sha256': selected['artifactSha256'], 'closedMetadataMatched': True, 'originalClosesKnown': True},
            'candidate-original-acquisition')
        return self.read_candidate_zip()

    def read_candidate_zip(self):
        selected = self.nomination
        name = target_names(self.target) + '-candidate.zip'
        entry, body = self.quota.call(self.outer, 'file', self.work / name, selected['artifactBytes'], modes=(0o600,))
        self.private[name] = entry['identity']
        values = candidate.candidate_members(body, selected, self.clock)
        resume.need(self.outer.read(entry) == body, 'candidate-acquisition-original-post')
        self.preview_bytes, self.preview_sha = len(values['PREVIEW.json']), resume.sha(values['PREVIEW.json'])
        self.__preview_document = resume.canonical(candidate.candidate_preview_data(values['PREVIEW.json'], selected))
        self.__members_document = resume.canonical([{'name': name, 'bytes': len(body), 'sha256': resume.sha(body)}
                                                   for name, body in sorted(values.items())])
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
        observed = {'bytes':len(baseline_body), 'sha256':resume.sha(baseline_body), 'identity':list(entry['identity'])}
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
        originals, selected = {}, {}
        for key, name, cap in (('package', 'Install.pkg', preview['packageSize']),
                              ('descriptor', 'producer.json', self.stager.PRODUCER_DESCRIPTOR_BYTES),
                              ('signature', 'producer.sig', self.stager.PRODUCER_SIGNATURE_BYTES)):
            info = os.stat(name, dir_fd=directory['fd'], follow_symlinks=False)
            resume.need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= cap
                        and info.st_uid in (0, os.getuid()) and info.st_gid in (0, os.getgid()), 'candidate-mounted-shape')
            entry, body = self.quota.call(mounted, 'file', mount / name, info.st_size, uid=info.st_uid, modes=(0o444,))
            resume.need(len(body) == info.st_size and resume.sha(body) == preview[key + 'Sha256']
                        and (key != 'package' or len(body) == preview['packageSize']), 'candidate-mounted-content-pin')
            originals[name] = (body, 0o444)
            selected[key] = {'name': name, 'bytes': len(body), 'sha256': resume.sha(body)}
        row = dict(self.nomination, **selected, packageVersion=self.selection.package_version, release=self.selection.release,
            members=resume.decode(self.__members_document),
            inventorySha256=preview['installerInventorySha256'], runtimeManifestSha256=preview['runtimeManifestSha256'],
            signingIdentity=dict(self.signing_identity))
        result, inventory = resume.mounted_data(originals, row, self.target, self.stager,
                                               allocation_budget=self.allocation_budget, candidate=True)
        self.point()
        self.__binding = resume.canonical(row)
        return originals, row, result, inventory

    def install_image(self, image, preview):
        resume.need(self.__artifact_admitted and self.__binding is None and self.__source_loaded
                    and not self.__installation_entered,
                    'candidate-install-order')
        self.__installation_entered = True
        resume.need(resume.canonical(preview) == self.__preview_document
                    and (len(image), resume.sha(image)) == (preview['distributionBytes'], preview['distributionSha256']),
                    'candidate-install-image-binding')
        # load_sources pinned SOURCE and independent G2 identity; parser-bound
        # artifact pins do not replace the native signature checks in this body.
        return super().install_image(image, preview)

    def prepare_readback(self, result, inventory):
        # This hook runs only AFTER actual mounted producer signature POST.
        if self.purpose == 'acquire':
            self.acquisition_result = {key: result[key] for key in ('package','descriptor','signature','inventory')}
            self.acquisition_result.update(runtimeManifestSha256=result['release']['runtimeManifestSha256'])
            return False  # Existing owner detaches without ever entering Installer.
        if self.purpose == 'restore-install':
            self.baseline_post()
            expected = self.baseline['acquisition']
            resume.need(all(result[key] == expected[key] for key in ('package','descriptor','signature','inventory'))
                        and result['release']['runtimeManifestSha256'] == expected['runtimeManifestSha256'],
                        'candidate-baseline-product')
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
        keep = {target_names(self.target) + '-candidate.zip'}
        if self.purpose == 'restore-install': keep.update((BASELINE_RECEIPT, BASELINE_STATUS))
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
        """One attempt after the external original source/host bootstrap.

        Caller retains the original endpoint; this does not renew a clock or
        provide UI authority. Failure keeps the existing Resume unknown-state
        preservation rules and always attempts each original final close.
        """
        primary = None
        try:
            resume.need(self.__source_loaded, 'candidate-source-not-loaded')
            # Exact remaining original acquisitions in the reused body: child3,
            # ZIP1, image publish/read2, Volumes1, mounted directory+files4,
            # producer key/message/read3, input directory/inventory/status3 and
            # the three transport iterators. These are lifetime cells, not live
            # FD credits; every later acquisition still uses OriginalQuota.
            pending = 17 if self.purpose == 'restore-install' else 20
            resume.need(self.quota.reserved + pending <= resume.MAX_ORIGINALS, 'candidate-original-ledger-capacity')
            self.admit_resources(retained, host_bytes)
            artifact = self.reuse_candidate() if self.purpose == 'restore-install' else self.acquire_candidate()
            preview = candidate.candidate_preview_data(artifact['PREVIEW.json'], self.nomination)
            self.admit_resources(retained, host_bytes, image_bytes=len(artifact['MobileReleaseKit.dmg']))
            self.verify_sources()
            self.install_image(artifact['MobileReleaseKit.dmg'], preview)
            self.verify_sources()
            if self.purpose == 'restore-install': self.baseline_post()
            self.point(); self.clock.finality = True
            self.retire()
            resume.need(self.quota.finish(), 'candidate-original-final-closes')
            self.clock.check()
            resume.need(all(row['returned'] and row['capturesSettled'] for row in self.calls)
                        and self.mount_detached and ((not self.installer_entered and self.acquisition_result is not None)
                        if self.purpose == 'acquire' else (self.installer_zero and self.readback_known)),
                        'candidate-original-terminal-finality')
            if self.purpose == 'acquire':
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
            if self.purpose == 'restore-install':
                result['scope'] = 'candidate-baseline-fresh-installer-observation'
                result['privateOutputsRetired'] = False  # Prior original handoffs remain for the chain.
                result['baselineSha256'] = self.baseline['baselineSha256']
                result['initial'] = resume.decode(resume.canonical(self._initial))
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


def main(purpose="install"):
    """Hosted acquire/install only. No workflow currently activates this entry."""
    resume.need(type(purpose) is str and purpose in PURPOSES, 'candidate-purpose')
    context = entry_context(())
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
                                  resume.bootstrap_originals(HELPER_ROOT), quota=quota, purpose=purpose)
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
        for tool in ('/usr/bin/git', '/usr/bin/hdiutil', '/usr/bin/vm_stat', '/usr/bin/openssl',
                     '/usr/bin/codesign', '/usr/sbin/installer'):
            uid = os.stat(tool, follow_symlinks=False).st_uid
            resume.need(uid in (0, os.getuid()), 'candidate-tool-owner')
            _entry, body = quota.call(session.outer, 'file', Path(tool), 64 << 20, uid=uid,
                                      modes=(0o555, 0o755, 0o4555, 0o4755))
            resume.need(body, 'candidate-tool-original')
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


if __name__ == '__main__':
    try:
        result = host_base() if sys.argv[1:] == ['host-base'] else bind_host() if sys.argv[1:] == ['bind-host'] else main()
    except BaseException:
        # No environment, exception text, URLs, token, carrier or native capture.
        sys.stderr.write('candidate-consumer-refused\n')
        raise SystemExit(1) from None
    sys.stdout.buffer.write(resume.canonical(result) + b'\n')
