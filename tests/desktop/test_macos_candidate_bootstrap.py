"""Actual candidate main/bootstrap with inert OS/tool/acquisition boundaries.

No native execution, downloads or native custody claims. OriginalQuota,
source-binding/selection, host admission, consume and retirement control flow
are real. The filesystem/native endpoints below are explicitly synthetic.
"""
from collections import namedtuple
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from types import MappingProxyType, SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from desktop.tools import macos_candidate_consumer as C
from desktop.tools import macos_fixed_carrier_resume as R
from desktop.tools import macos_app_absence_fixture as F
from desktop.tools import macos_android_helper_package as H
from test_macos_candidate_carrier import fixture, archive


class CandidateBootstrapTests(unittest.TestCase):
    def test_retained_workflow_adds_only_closed_git_operation_and_preserves_original_handoff_and_clocks(self):
        workflow = (ROOT / C.WORKFLOW).read_text()
        self.assertIn('install-retained-observer, install-retained-git-observer]', workflow)
        self.assertNotIn('\n  install-retained-git-observer:', workflow)
        job = workflow.split('\n  install-retained-observer:\n', 1)[1].split('\n  install-predecessor:\n', 1)[0]
        self.assertIn("inputs.operation == 'install-retained-observer' || inputs.operation == 'install-retained-git-observer'", job)
        self.assertIn("inputs.architecture == 'arm64' && github.ref == 'refs/heads/verify/desktop-macos-observer-reuse'", job)
        self.assertIn('timeout-minutes: 260\n', job)
        self.assertIn('MRK_CANDIDATE_MODE: ${{ inputs.operation }}', job)
        expression = "${{ inputs.operation == 'install-retained-git-observer' && '%s' || '%s' }}"
        for key, git, tool in (('runs-on', 'xcode-27', 'macos-26'), ('MRK_MACOS_RUNNER', 'xcode-27', 'macos-26'),
                ('MRK_MACOS_HOSTED_JOB', 'github-hosted-xcode27-arm64', 'github-hosted-macos26-arm64'),
                ('MRK_MACOS_NATIVE_SCOPE', 'git-native', 'tool-setup'),
                ('DEVELOPER_DIR', '/Library/Developer/CommandLineTools', '/Applications/Xcode.app/Contents/Developer')):
            self.assertIn(key + ': ' + expression % (git, tool), job)
        for key in ('MRK_CANDIDATE_SOURCE', 'MRK_MACOS_INSTALL_SOURCE_COMMIT'):
            self.assertIn(key + ': ' + expression % (C.candidate.RETAINED_GIT_TUPLE[0], 'a498dd67ffba352e8aaa4a9e3f53c892a76e834f'), job)
        sections = re.split(r'^      - name: ', job, flags=re.M)[1:]
        steps = {section.splitlines()[0]: section for section in sections}
        tool_names = ('Verify four supported project identity edits', 'Start the fixed native service and verify readiness',
            'Verify the installed CLI with the native service', 'Prepare only the required isolated Android tool inputs',
            'Verify tool acquisition, cancellation and missing-only reuse',
            'Verify signing-key reuse, cancellation, restart and encrypted backup')
        for name, clock in zip(tool_names, (15, 13, 3, 22, 122, 60)):
            self.assertIn("if: env.MRK_CANDIDATE_MODE == 'install-retained-observer'", steps[name])
            self.assertIn('timeout-minutes: ' + str(clock) + '\n', steps[name])
        install = steps['Reuse the retained signed image for a fresh install and file verification']
        for required in ('timeout-minutes: 12\n', 'phase_status=$?', 'saved_status=$?',
                'retained-observer-install.json', 'retained-observer-install.status', 'unset GITHUB_TOKEN',
                'if [[ "$phase_status" != 0 ]]; then exit "$phase_status"; fi', '[[ "$saved_status" == 0 ]] || exit "$saved_status"'):
            self.assertIn(required, install)
        git = steps['Verify fifteen existing Git cases on the freshly installed signed Git observer']
        self.assertIn("if: env.MRK_CANDIDATE_MODE == 'install-retained-git-observer'", git)
        self.assertIn('timeout-minutes: 25\n', git)
        self.assertIn('set -euo pipefail', git)
        calls = re.findall(r'^          (exec )?"\$MRK_PYTHON" -I -S -B "\$driver" --retained-observer --target "\$MRK_MACOS_TARGET" --scope ([a-z-]+)$', git, re.M)
        self.assertEqual(calls, [('', 'git-index-cli-native'), ('', 'git-branch-cli-native'),
            ('', 'git-fetch-native'), ('', 'git-push-native'), ('', 'git-push-create-native'), ('exec ', 'git-upstream-native')])
        self.assertNotIn('GITHUB_TOKEN', git)
        self.assertNotIn('continue-on-error', job)
        self.assertNotIn('secrets.', job)
        self.assertEqual(R.MAX_ORIGINALS, 96)
        for path, cap in ((C.CONSUMER_PATH, 96 << 10), (C.LEGACY_PATH, R.SOURCE_LIMIT), (C.PARSER_PATH, C.PARSER_SOURCE_LIMIT)):
            self.assertLessEqual((ROOT / path).stat().st_size, cap)

    def exercise(self, target, fault=None, purpose="install", transport=None):
        work = Path('/Users/runner/work/_temp/mrk-macos-installed.ABCDEFGH/resume-carrier')
        host = work.parent / 'host-python'
        context = dict(target=target, helperSource='d' * 40, runId='51', runAttempt='2', work=work)
        row, preview, *_ = fixture(target)
        preview['packageSize'] = 32  # Valid XAR minimum at the inert native boundary.
        zip_body, selected = archive(row, [('MobileReleaseKit.dmg', b'DATA'),
            ('PREVIEW.json', R.canonical(preview) + b'\n'), ('README.md', b'Inert guide\n')])
        if transport is not None: zip_body, selected = transport
        files, modes, dirs, calls, effects, books = {}, {}, set(), [], [], []
        uid, gid = os.getuid(), os.getgid()
        for relative in (*C.HELPER_SOURCE_INPUTS, C.CONSUMER_PATH, C.LEGACY_PATH, C.PARSER_PATH):
            path = C.HELPER_ROOT / relative
            files[path] = (ROOT / relative).read_bytes() if (ROOT / relative).is_file() else b'inert source\n'
        if purpose in ("restore-install", "acquire-restore"):
            files[C.HELPER_ROOT / C.FIXTURE_PATH] = (ROOT / C.FIXTURE_PATH).read_bytes()
        if purpose == "acquire-restore":
            files[C.HELPER_ROOT / "desktop/tools/macos_android_helper_package.py"] = (ROOT / "desktop/tools/macos_android_helper_package.py").read_bytes()
        files[C.HELPER_ROOT / C.SELECTION_PATH] = R.canonical({'schemaVersion': 1, 'targets': {target: selected}})
        for relative in (C.STAGER_PATH, *(path for path, _ in C.CANDIDATE_SOURCE_INPUTS)):
            files[C.CANDIDATE_ROOT / relative] = b'inert candidate source\n'
        files[C.HELPER_ROOT / R.SIGNING_CERTIFICATE[0]] = (ROOT / R.SIGNING_CERTIFICATE[0]).read_bytes()
        files[C.HELPER_ROOT / R.TLS_CA_PATH] = b'inert CA'
        base = Path('/inert-base/bin/python3')
        binary = b'inert-interpreter-never-executed'
        files[base] = binary; modes[base] = 0o755
        base_value = {'launcherPath': str(base), 'executable': str(base), 'copyPath': str(base),
                      'copyExecutable': str(base), 'prefix': '/inert-base'}
        cfg = ('home = /inert-base/bin\ninclude-system-site-packages = false\nversion = 3.14.7\n'
               'executable = /inert-base/bin/python3\ncommand = /inert-base/bin/python3 -m venv --copies '
               '--without-pip --without-scm-ignore-files ' + str(host) + '\n').encode()
        for relative in (*R.HOST_FILES, R.HOST_OPTIONAL):
            executable = relative in ('bin/python', 'bin/python3', 'bin/python3.14', R.HOST_OPTIONAL)
            files[host / relative] = binary if executable else cfg if relative == 'pyvenv.cfg' else b'inert activation\n'
            modes[host / relative] = 0o755 if executable else 0o644
        for relative in R.HOST_DIRS: dirs.add(host / relative)
        tools = ('/usr/bin/git', '/usr/bin/hdiutil', '/usr/bin/vm_stat', '/usr/bin/openssl', '/usr/bin/codesign', '/usr/sbin/installer')
        for path in tools: files[Path(path)] = b'inert native tool'; modes[Path(path)] = 0o755

        def info(path):
            path = Path(path)
            mode = (stat.S_IFREG | modes.get(path, 0o644)) if path in files else stat.S_IFDIR | (0o755 if str(path).startswith('/Library') else 0o700)
            return SimpleNamespace(st_dev=1, st_ino=int.from_bytes(hashlib.sha256(str(path).encode()).digest()[:6], 'big'),
                st_mode=mode, st_uid=0 if str(path).startswith(('/usr', '/Library')) else uid,
                st_gid=0 if str(path).startswith(('/usr', '/Library')) else gid, st_nlink=1,
                st_size=len(files[path]) if path in files else 0, st_mtime_ns=1, st_ctime_ns=1)

        def children(path):
            return sorted({p.relative_to(path).parts[0] for p in (*files, *dirs)
                           if p != path and p.is_relative_to(path)})

        mounted_result = {key:dict(name=name,bytes=size,sha256=preview[key+'Sha256']) for key,name,size in
            (('package','Install.pkg',preview['packageSize']),('descriptor','producer.json',100),('signature','producer.sig',70))}
        mounted_result.update(inventory=dict(name='install-inventory.json',bytes=100,sha256=preview['installerInventorySha256']),
                              release=dict(runtimeManifestSha256=preview['runtimeManifestSha256']))
        if purpose == 'restore-install':
            acquisition, problem, *_ = self.exercise(target, purpose='acquire', transport=(zip_body,selected))
            self.assertIsNone(problem, repr(problem))
            binding = dict(fixtureSource=context['helperSource'],productSource=selected['source'],runId='51',runAttempt='2',target=target,
                packageSha256=preview['packageSha256'], producerDescriptorSha256=preview['descriptorSha256'],
                producerSignatureSha256=preview['signatureSha256'], fixtureExecutableSha256='1'*64,
                inventorySha256=preview['installerInventorySha256'], runtimeManifestSha256=preview['runtimeManifestSha256'], protocolSha256='2'*64)
            root_baseline = Path('/Library/Application Support') / F.baseline_name_data({key:binding[key]
                for key in ('fixtureSource','productSource','runId','runAttempt','target')})
            parent = dict(zip(('device','inode','mode','uid','gid'),R.identity(info(root_baseline.parent))[:5]))
            body = R.canonical(dict(schemaVersion=1,kind='app-absence-baseline',binding=binding,rootNonce='3'*32,
                parentIdentity=parent,privateIdentity=dict(parent,mode=stat.S_IFDIR|0o700,inode=123),
                siblingCensusSha256='4'*64,siblingCount=0,rootAbsent=True,transportState='pending-original-exit'))
            files[root_baseline]=body; modes[root_baseline]=0o444
            original = dict(bytes=len(body),sha256=R.sha(body),identity=list(H.signature(info(root_baseline))))
            if fault=='prior-manifest-malformed': acquisition['runtimeManifestSha256'] = '0'*64
            if fault=='prior-manifest-missing': del acquisition['runtimeManifestSha256']
            baseline_fault = 'close' if fault=='baseline-close' else fault if fault in ('prior-status','prior-manifest-malformed','prior-manifest-missing') else None
            baseline = self.baseline_phase(acquisition,binding,original, fault=baseline_fault)
            if baseline_fault is not None: return None, baseline, [], [], [], files
            files[work / C.BASELINE_RECEIPT] = R.canonical(baseline)
            files[work / C.BASELINE_STATUS] = b'0\n'
            files[work / (C.target_names(target)+'-candidate.zip')] = zip_body
            for name in (C.BASELINE_RECEIPT,C.BASELINE_STATUS,C.target_names(target)+'-candidate.zip'): modes[work/name]=0o600
            if fault=='baseline-drift': files[root_baseline] += b'changed'
            if fault=='baseline-status': files[work / C.BASELINE_STATUS] = b'1\n'
            dirs.add(work)

        base_value.update(identity=list(R.identity(info(base))), sha256=R.sha(binary))
        snapshot, _ = R.host_snapshot(host, lambda p: (R.identity(info(p)), children(p)),
                                     lambda p, limit: (R.identity(info(p)), files[p]))
        files[host / 'host-binding.json'] = R.canonical(dict(schemaVersion=1, source=context['helperSource'],
            runId='51', runAttempt='2', base=base_value, prefix=str(host), basePrefix='/inert-base',
            baseExecutable=str(base), **snapshot, retainedUntilHostedTeardown=True))
        modes[host / 'host-binding.json'] = 0o600

        class Book:
            def __init__(self, *args):
                self.entries, self.directories, self.errors, self.close_attempts = [], {}, [], []
                books.append(self)
            def register(self, path, kind):
                path = Path(path)
                entry = {'path': path, 'kind': kind, 'identity': R.identity(info(path))[:5 if kind == 'directory' else 9],
                         'fd': len(self.entries) + 1000, 'closed': False}
                self.entries.append(entry)
                return entry
            def directory(self, path):
                path = Path(path)
                if path not in self.directories:
                    if path != Path('/'): self.directory(path.parent)
                    dirs.add(path); self.directories[path] = self.register(path, 'directory')
                return self.directories[path]
            def file(self, path, limit, **kwargs):
                self.directory(path.parent)
                data = files[path]
                if len(data) > limit: raise ValueError('inert file exceeds real caller bound')
                entry = self.register(path, 'file')
                return entry, data
            def read(self, entry): return files[entry['path']]
            def check(self): pass
            def check_one(self, entry): pass
            def close(self, entry):
                if entry['fd'] is None: return
                entry['fd'] = None; self.close_attempts.append(entry)
                if fault in ('close','reuse-close') and entry['path'] == C.HELPER_ROOT / C.CONSUMER_PATH:
                    self.errors.append('inert consuming close unknown')
                else: entry['closed'] = True
            def finish(self):
                for entry in reversed(self.entries): self.close(entry)
                return not self.errors and all(entry['closed'] for entry in self.entries)
            def publish(self, path, data, mode=0o600):
                self.directory(path.parent); files[path] = data; modes[path] = mode
                entry = self.register(path, 'output'); self.close(entry)
        class Sudo(Book):
            def acquire(self, quota):
                quota.reserve(4)
                for path in ('/', '/usr', '/usr/bin', '/usr/bin/sudo'):
                    self.register(Path(path), 'file' if path.endswith('sudo') else 'directory')

        def command(argv, **kw):
            calls.append(tuple(argv))
            self.assertNotIn('GITHUB_TOKEN', kw['environ'])
            if argv[0] == '/usr/bin/git':
                root = Path(argv[argv.index('-C') + 1]); helper = root == C.HELPER_ROOT
                self.assertEqual(kw['environ']['GIT_NO_REPLACE_OBJECTS'], '1')
                if 'rev-parse' in argv:
                    source, tree = (context['helperSource'], 'e' * 40) if helper else (selected['source'], selected['tree'])
                    out = (source + '\n' + tree + '\n').encode()
                else:
                    out = b''
                    for name in argv[argv.index('--') + 1:]:
                        data = files[root / name]
                        if fault == 'source' and not helper and name == C.STAGER_PATH: data += b'changed'
                        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest().encode()
                        out += b'100644 blob ' + blob + b'\t' + name.encode() + b'\0'
            elif argv == ['/usr/bin/vm_stat']:
                out = b'inert vm statistics'
            else:
                self.assertEqual(argv[:5], [str(host / 'bin/python3'), '-I', '-S', '-B', '-c'])
                if fault == 'acquire': raise RuntimeError('inert acquisition original unknown')
                request = R.decode(kw['environ']['MRK_P0_REQUEST'].encode())
                self.assertEqual(request['row'], selected)
                files[work / (C.target_names(target) + '-candidate.zip')] = zip_body
                modes[work / (C.target_names(target) + '-candidate.zip')] = 0o600
                out = R.canonical(dict(schemaVersion=1, role='candidate', target=target,
                    bytes=selected['artifactBytes'], sha256=selected['artifactSha256'], closedMetadataMatched=True, originalClosesKnown=True))
            return SimpleNamespace(args=argv, returncode=0, stdout=out, stderr=b'')

        selection_type = namedtuple('BuildSelection', 'target package_version release')
        leaf = files[C.HELPER_ROOT / R.SIGNING_CERTIFICATE[0]]
        stage = SimpleNamespace(maintenance_json=lambda body,limit: R.decode(body), DESKTOP=C.CANDIDATE_ROOT / 'desktop',
            source_build_selection=lambda target: selection_type(target, '0.1.9', 'inert-current-release'),
            packaging_signing_data=lambda *args: SimpleNamespace(team='7CGZ2343AA', leaf_sha1=hashlib.sha1(leaf).hexdigest(), leaf_sha256=R.sha(leaf)))
        def module(name, path, body):
            if path.name == 'macos_aqua_qualification.py': return SimpleNamespace(load_owner=lambda root: SimpleNamespace(run_owned=command))
            if path.name == 'macos_xcode_host_preparation.py':
                return SimpleNamespace(DarwinAPI=lambda clock, target: SimpleNamespace(waitable_sigchld=lambda: effects.append(('host', target))))
            if path.name == 'macos_app_absence_fixture.py': return F
            if path.name == 'macos_android_helper_package.py': return H
            effects.append(('candidate-stager-loaded',))
            return stage

        def native_install(owner, image, observed_preview):
            # This is the explicit native boundary, not simulated Installer
            # success evidence. Allocate its complete original plan for real.
            effects.append(('native-install-boundary',))
            owner.installer_entered = owner.installer_zero = owner.readback_known = False
            q, outer = owner.quota, owner.outer
            q.reserve(1)  # actual image publisher's original
            image_path = work / owner.image_name; files[image_path] = image; modes[image_path] = 0o444
            entry, _ = q.call(outer, 'file', image_path, len(image)); owner.private[image_path.name] = entry['identity']
            q.call(outer, 'directory', Path('/Volumes'))
            for _ in range(3): q.reserve(1)
            mounted = owner.fresh_book(transport=True)
            mount = owner.mount_path(); q.call(mounted, 'directory', mount)
            for name in ('Install.pkg', 'producer.json', 'producer.sig'):
                files[mount / name] = b'inert native input'; q.call(mounted, 'file', mount / name, 100)
            owner.publish_owned(work / 'producer-key.pem', b'inert key')
            owner.publish_owned(work / 'producer-message.bin', b'inert domain')
            q.call(outer, 'file', work / 'producer-message.bin', 100)
            inventory = b'inert inventory'
            if purpose == 'acquire-restore':
                owner._restore_originals = {}
                owner._CandidateResume__restore_inputs = (inventory, MappingProxyType({}))
            readback = owner.prepare_readback(mounted_result, inventory)
            if readback is False:
                mounted.finish(); owner.mount_detached = True
                effects.append(('acquisition-no-installer',))
                return
            owner.fresh_directory(owner.parent, 'input')
            owner.publish_owned(work / 'input/install-inventory.json', b'inert inventory')
            owner.publish_owned(work / 'installer-output.status', b'0\n', 0o600)
            mounted.finish()
            owner.installer_entered = owner.installer_zero = owner.readback_known = owner.mount_detached = True
            if purpose == 'restore-install':
                exported = dict(bytes=321,sha256='5'*64,identity=[1]*9)
                observed = dict(schemaVersion=2, originalInstallerReturnedZero=True, originalWriterJoined=True,
                    originalInstallerResult=dict(action='fresh-install',writerState='installed',stateSha256='6'*64),
                    sourceCommit=selected['source'],completedPackageSha256=preview['packageSha256'],
                    inventorySha256=preview['installerInventorySha256'],runtimeManifestSha256=preview['runtimeManifestSha256'],
                    requestId='7'*32, invocation='8'*32, installerResultExport=exported, installationMetadata=[dict(instance='9'*32)])
                stage.observation_command=lambda args: observed
                stage.same_package_result_census=lambda: {'7'*32:exported}
                owner.installation=owner.observe_installation(SimpleNamespace(),readback)
            else: owner.installation = {'inert': True}
            effects.append(('full-native-quote', q.reserved))

        def listdir(path):
            if isinstance(path, int):
                # Synthetic fd numbers are local to each book. Only the main
                # outer directory fd is queried by actual bootstrap/retirement.
                path = next(entry['path'] for entry in books[0].entries if entry['fd'] == path)
            return children(Path(path))
        def unlink(name, *, dir_fd):
            parent = next(entry['path'] for entry in books[0].entries if entry['fd'] == dir_fd)
            effects.append(('unlink', name)); del files[parent / name]
        def rmdir(name, *, dir_fd):
            parent = next(entry['path'] for entry in books[0].entries if entry['fd'] == dir_fd)
            dirs.discard(parent / name)
        def mkdir(path, *args, **kw):
            path = Path(path) if 'dir_fd' not in kw else next(e['path'] for e in books[0].entries if e['fd'] == kw['dir_fd']) / path
            effects.append(('mkdir',str(path))); dirs.add(path)
        def materialize(owner, originals, inventory, app_scripts):
            effects.append(('materialize-boundary',owner.quota.reserved,sum(e['fd'] is not None for b in owner.quota.books for e in b.entries)))
            self.assertFalse(owner.installer_entered)
            self.assertTrue(all(q['returned'] and q['capturesSettled'] for q in owner.calls))
            if fault=='materialize': raise ValueError('inert materializer uncertain close')
        result = failure = None
        with ExitStack() as patches:
            for obj, name, value in ((C, 'entry_context', lambda args: context), (R, 'bootstrap_originals', lambda root: Book),
                    (R, 'load_module', module), (R, 'FixedSudoOriginals', Sudo),
                    (R.Resume, 'install_image', native_install), (H,'candidate_materialize',materialize), (R, 'host_memory_data', lambda host, clock: (4096, 64 << 30)),
                    (R, 'memory_data', lambda *a, **kw: {'availableEstimateBytes': 64 << 30}),
                    (C.os, 'stat', lambda path, **kw: info(Path(path) if 'dir_fd' not in kw else
                        next(e['path'] for e in books[0].entries if e['fd'] == kw['dir_fd']) / path)),
                    (C.os, 'listdir', listdir), (C.os, 'mkdir', mkdir),
                    (C.os, 'unlink', unlink), (C.os, 'rmdir', rmdir),
                    (C.os, 'fstatvfs', lambda fd: SimpleNamespace(f_bavail=1 << 30, f_frsize=4096))):
                patches.enter_context(mock.patch.object(obj, name, value))
            patches.enter_context(mock.patch.object(C.sys, 'executable', str(host / 'bin/python3')))
            patches.enter_context(mock.patch.object(C.sys, 'prefix', str(host)))
            patches.enter_context(mock.patch.object(C.sys, 'base_prefix', '/inert-base'))
            patches.enter_context(mock.patch.object(C.sys, '_base_executable', str(base)))
            patches.enter_context(mock.patch.dict(C.os.environ, {'GITHUB_TOKEN': 'inert-token-not-a-credential'}, clear=True))
            patches.enter_context(mock.patch.object(R, 'TLS_CA_BYTES', len(b'inert CA')))
            patches.enter_context(mock.patch.object(R, 'TLS_CA_SHA256', R.sha(b'inert CA')))
            try: result = C.main(purpose)
            except BaseException as error: failure = error
        return result, failure, calls, effects, books, files

    def test_acquire_restore_bootstrap_quotes_helper_source_and_stops_before_installer(self):
        for target in F.TARGETS:
            result,error,calls,effects,books,files=self.exercise(target,purpose='acquire-restore')
            self.assertIsNone(error,repr(error));self.assertEqual(result['scope'],'candidate-closed-acquisition')
            boundaries=[q for q in effects if q[0]=='materialize-boundary']
            self.assertEqual(len(boundaries),1);self.assertLessEqual(boundaries[0][1],96)
            self.assertEqual(boundaries[0][1],95)
            self.assertFalse(result['installerEntered'])
            self.assertTrue(all(e['closed'] for b in books for e in b.entries))
            print('INERT acquire-restore reservation/live',boundaries[0][1:])
            result,error,_,effects,_,_=self.exercise(target,'materialize',purpose='acquire-restore')
            self.assertIsNone(result);self.assertIsNotNone(error)
            self.assertNotIn(('full-native-quote',96),effects)

    def baseline_phase(self, acquisition, binding, original, fault=None):
        """Real phase/finish; only unavailable mount/native/root endpoints inert."""
        environment=dict(GITHUB_SHA='d'*40,GITHUB_WORKFLOW_SHA='d'*40,GITHUB_RUN_ID='51',GITHUB_RUN_ATTEMPT='2',
            GITHUB_EVENT_NAME='push',GITHUB_REF='refs/heads/'+C.BRANCH,GITHUB_WORKFLOW_REF=R.REPOSITORY+'/'+C.WORKFLOW+'@refs/heads/'+C.BRANCH,
            MRK_MACOS_PACKAGE_ROLE='ordinary-image')
        observed=dict(binding,schemaVersion=1,kind='app-absence-phase-observation',phase='baseline',
            baselineSha256=original['sha256'],recordSha256=original['sha256'],proof={k:True for k in F.PROOFS['baseline']},
            originalOuterExitRequired=True,systemServiceExitClaimed=False,productReady=False)
        with tempfile.TemporaryDirectory() as tmp:
            work=Path(tmp); work.chmod(0o700)
            op=H.Operation(None,C.CANDIDATE_ROOT,work,'candidate-baseline',environment,
                           SimpleNamespace(DESKTOP=C.CANDIDATE_ROOT/'desktop'),target=binding['target'])
            op.open(); op.image_source=binding['productSource'];op.app_absence_module=F;op.app_absence_api=H
            (work/'acquired.json').write_bytes(R.canonical(acquisition));(work/'acquired.json').chmod(0o600)
            entry=op.original(op.work_entry,'acquired.json','acquisition',65536,(0o600,))
            (work/'acquired.status').write_bytes(b'1\n' if fault=='prior-status' else b'0\n');(work/'acquired.status').chmod(0o600)
            status=op.original(op.work_entry,'acquired.status','acquisition-status',4,(0o600,))
            def native(role, argv, **kwargs):
                F.dispatch(op,role)
                op.calls.append(dict(role=role,entered=True,returned=True,capturesSettled=True,returncode=0))
                F.returned(op,role)
                body=b'MRK_MACOS_APP_ABSENCE_RESULT='+json.dumps(observed,separators=(',',':')).encode()+b'\n' if role=='app-absence-baseline' else b''
                return SimpleNamespace(args=argv,returncode=0,stdout=body,stderr=b'')
            op.package_call=native
            def image(owner,producer):
                owner.app_absence['nativeBinding']=binding
                owner.app_absence['preparationSha256']='a'*64
                owner.app_absence['image']=dict(bytes=64,sha256='b'*64)
                owner.app_absence['layout']={name:dict(name=name,bytes=(acquisition[key]['bytes'] if key else 100),
                    sha256=(acquisition[key]['sha256'] if key else 'c'*64),mode=0o444,links=1)
                    for name,key in [('Install.pkg','package'),('producer.json','descriptor'),('producer.sig','signature'),
                        *[(name,None) for name in (*F.PHASE_NAMES,*F.CUT_PACKAGES)]]}
                owner.app_absence['mount']=dict(entered=False,known=True,detached=False)
                for role in F.roles(owner)[:3]: native(role,[])
            def detach(owner,role):
                native(role,[]);owner.app_absence['mount']['detached']=True
            close=op.close
            def closing(item):
                close(item)
                if fault=='close' and item is entry:
                    item['closed']=False;op.errors.append(dict(stage='close',role='acquisition',type='OSError'))
            with mock.patch.object(F,'baseline_log',side_effect=lambda owner,**kwargs: native('app-absence-log-cursor',[])), \
                 mock.patch.object(F,'image_prepare',side_effect=image), mock.patch.object(F,'detach',side_effect=detach), \
                 mock.patch.object(F,'mounted_post'),mock.patch.object(F,'baseline_read',return_value=original), \
                 mock.patch.object(op,'close',side_effect=closing):
                try: result=op.candidate_baseline(entry,status,None,acquisition['nomination'],'e'*40)
                except Exception as error:
                    if fault in ('prior-status','prior-manifest-malformed','prior-manifest-missing'):
                        self.assertEqual(op.calls,[])
                        self.assertTrue(all(item['closed'] for item in op.entries));return error
                    if fault=='close':
                        self.assertFalse(op.receipt['originalClosesKnown']);self.assertFalse(op.receipt['targetRetired'])
                        self.assertTrue(all(item['fd'] is None for item in op.entries));return error
                    raise
            self.assertTrue(all(item['closed'] and item['fd'] is None for item in op.entries))
            self.assertEqual(result['acquisition'],acquisition)
            return result

    def test_restore_reuse_actual_main_exact96_and_prior_baseline_owner_both_targets(self):
        for target in ('aarch64-apple-darwin','x86_64-apple-darwin'):
            result,failure,calls,effects,books,files=self.exercise(target,purpose='restore-install')
            self.assertIsNone(failure,repr(failure))
            self.assertEqual(result['scope'],'candidate-baseline-fresh-installer-observation')
            self.assertEqual(result['initial']['requestId'],'7'*32)
            self.assertIn(('full-native-quote',96),effects)
            self.assertFalse(any(call[0].endswith('python3') for call in calls))
            self.assertFalse(any(effect==('mkdir','/Users/runner/work/_temp/mrk-macos-installed.ABCDEFGH/resume-carrier') for effect in effects))
            entries=[entry for book in books for entry in book.entries]
            self.assertFalse(any(str(entry['path']).endswith(R.TLS_CA_PATH) or entry['path'].name=='fixed-consumer-tls' for entry in entries))
            for path in ('/Library','/Library/Application Support'):
                self.assertEqual(sum(str(entry['path'])==path for entry in entries),1)
            self.assertTrue(all(entry['closed'] for entry in entries))
            self.assertEqual(sum('/resume-carrier/' in str(path) for path in files),4)
            self.assertEqual(result['installerStatusOriginal']['sha256'],R.sha(b'0\n'))
            self.assertEqual(result['installerStatusOriginal']['bytes'],2)

    def test_restore_reuse_baseline_refuses_before_installer_and_unknown_close_preserves(self):
        for fault in ('baseline-drift','baseline-status','baseline-close','prior-status','prior-manifest-malformed','prior-manifest-missing','reuse-close'):
            result,failure,calls,effects,books,files=self.exercise('aarch64-apple-darwin',fault,purpose='restore-install')
            self.assertIsNone(result);self.assertIsNotNone(failure)
            if fault != 'reuse-close': self.assertNotIn(('native-install-boundary',),effects)
            self.assertFalse(any(effect[0]=='unlink' for effect in effects))
            self.assertTrue(all(entry['fd'] is None for book in books for entry in book.entries))

    def test_actual_main_bootstrap_and_lifetime_owner_success_both_targets(self):
        for target in ('aarch64-apple-darwin', 'x86_64-apple-darwin'):
            result, failure, calls, effects, books, files = self.exercise(target)
            self.assertIsNone(failure, repr(failure))
            self.assertEqual(result['target'], target)
            self.assertEqual(result['helperSource'], 'd' * 40)
            self.assertTrue(result['originalClosesKnown'])
            self.assertIn(('host', target), effects)
            self.assertIn(('native-install-boundary',), effects)
            self.assertIn(('full-native-quote', 96), effects)
            self.assertTrue(all(entry['closed'] for book in books for entry in book.entries))
            self.assertTrue(all(len(book.close_attempts) == len(book.entries) for book in books))
            self.assertFalse(any('/resume-carrier/' in str(path) for path in files))

    def test_actual_main_source_refusal_before_candidate_code_or_acquisition(self):
        result, failure, calls, effects, books, files = self.exercise('aarch64-apple-darwin', 'source')
        self.assertIsNone(result); self.assertIsInstance(failure, ValueError)
        self.assertNotIn(('candidate-stager-loaded',), effects)
        self.assertNotIn(('native-install-boundary',), effects)
        self.assertTrue(all(call[0] == '/usr/bin/git' for call in calls))
        self.assertTrue(all(entry['closed'] for book in books for entry in book.entries))

    def test_actual_main_unknown_acquisition_and_consuming_close_never_mint_success(self):
        for fault in ('acquire', 'close'):
            result, failure, calls, effects, books, files = self.exercise('aarch64-apple-darwin', fault)
            self.assertIsNone(result); self.assertIsNotNone(failure)
            self.assertFalse(any(effect[0] == 'unlink' for effect in effects))
            self.assertTrue(all(entry['fd'] is None for book in books for entry in book.entries))
            self.assertTrue(all(len(book.close_attempts) == len(book.entries) for book in books))
            if fault == 'acquire': self.assertNotIn(('native-install-boundary',), effects)
            else: self.assertTrue(any(book.errors for book in books))

    def test_legacy_default_command_roles_and_candidate_acquisition_refusal(self):
        self.assertEqual(R.Resume.command_roles, ('memory', 'acquire-carrier', 'attach', 'detach', 'producer-key',
            'producer-signature', 'installer', 'entry-signature', 'payload-signature'))
        owner = object.__new__(R.Resume)
        owner.point = mock.Mock()
        owner.clock = SimpleNamespace(seconds=lambda value: value, finality=False)
        owner.owner = SimpleNamespace(run_owned=mock.Mock(side_effect=lambda argv, **kw:
            SimpleNamespace(args=argv, returncode=0, stdout=b'', stderr=b'')))
        owner.calls, owner.environment, owner.work = [], {}, Path('/inert')
        for role in ('helper-source', 'candidate-source'):
            with self.assertRaises(ValueError): owner.command(role, ['/usr/bin/git'], 15)
        owner.point.assert_not_called(); owner.owner.run_owned.assert_not_called()
        owner.command('memory', ['/usr/bin/vm_stat'], 10)
        self.assertEqual(len(owner.calls), 1)
        self.assertTrue(owner.calls[0]['returned'] and owner.calls[0]['capturesSettled'])
        request = dict(row={}, role='candidate', target='aarch64-apple-darwin',
            work='/Users/runner/work/_temp/mrk-macos-installed.ABCDEFGH/resume-carrier',
            workIdentity=[], caPath='/inert', caSha256='0' * 64, endpoint=C.time.monotonic_ns() + 1000000000)
        with mock.patch.dict(os.environ, {'MRK_P0_REQUEST': R.canonical(request).decode()}, clear=True):
            with self.assertRaisesRegex(ValueError, 'p0-child-admission'): R.acquisition_main()

    def host_fixture(self, root):
        host, base = root / 'host-python', root / 'base/bin/python3'
        base.parent.mkdir(parents=True)
        binary = b'inert-not-an-executable'
        base.write_bytes(binary); base.chmod(0o755)
        context = dict(work=root / 'resume-carrier', helperSource='d' * 40, runId='51', runAttempt='2',
                       target='aarch64-apple-darwin')
        for relative in R.HOST_DIRS: (host / relative).mkdir(parents=True, exist_ok=True, mode=0o700)
        cfg = ('home = ' + str(base.parent) + '\ninclude-system-site-packages = false\nversion = 3.14.7\n'
               'executable = ' + str(base) + '\ncommand = ' + str(base) + ' -m venv --copies --without-pip '
               '--without-scm-ignore-files ' + str(host) + '\n').encode()
        for relative in (*R.HOST_FILES, R.HOST_OPTIONAL):
            executable = relative in ('bin/python', 'bin/python3', 'bin/python3.14', R.HOST_OPTIONAL)
            path = host / relative
            path.write_bytes(binary if executable else cfg if relative == 'pyvenv.cfg' else b'inert activation\n')
            path.chmod(0o755 if executable else 0o644)
        with mock.patch.object(C, 'entry_context', return_value=context), \
             mock.patch.object(sys, 'executable', str(base)), mock.patch.object(sys, '_base_executable', str(base)), \
             mock.patch.object(sys, 'base_prefix', str(root / 'base')):
            base_value = C.host_base()
        return host, base, context, base_value

    def test_host_binding_real_inert_files_and_original_closes(self):
        self.assertNotEqual(os.getuid(), 0)
        with tempfile.TemporaryDirectory() as temporary:
            host, base, context, base_value = self.host_fixture(Path(temporary))
            before = len(os.listdir('/proc/self/fd'))
            with mock.patch.object(C, 'entry_context', return_value=context), \
                 mock.patch.object(sys, 'executable', str(host / 'bin/python3')), \
                 mock.patch.object(sys, '_base_executable', str(base)), mock.patch.object(sys, 'prefix', str(host)), \
                 mock.patch.object(sys, 'base_prefix', str(base.parent.parent)), \
                 mock.patch.dict(os.environ, {'MRK_HOST_BASE_CONTEXT': R.canonical(base_value).decode()}, clear=True):
                result = C.bind_host()
            self.assertTrue(result['hostPrepared'])
            self.assertEqual(len(os.listdir('/proc/self/fd')), before)
            original = (host / 'host-binding.json').read_bytes()
            self.assertEqual(R.decode(original)['source'], context['helperSource'])
            self.assertEqual((host / 'host-binding.json').stat().st_mode & 0o777, 0o600)

    def test_host_binding_unknown_consuming_close_and_foreign_collision_preserve_files(self):
        for fault in ('close', 'collision'):
            with tempfile.TemporaryDirectory() as temporary:
                host, base, context, base_value = self.host_fixture(Path(temporary))
                if fault == 'collision': (host / 'host-binding.json').write_bytes(b'foreign')
                before = len(os.listdir('/proc/self/fd')); close = os.close
                def consume(fd):
                    name = os.readlink('/proc/self/fd/' + str(fd))
                    close(fd)
                    if fault == 'close' and name.endswith('/host-binding.json'): raise OSError('inert consuming close unknown')
                with mock.patch.object(C, 'entry_context', return_value=context), \
                     mock.patch.object(sys, 'executable', str(host / 'bin/python3')), \
                     mock.patch.object(sys, '_base_executable', str(base)), mock.patch.object(sys, 'prefix', str(host)), \
                     mock.patch.object(sys, 'base_prefix', str(base.parent.parent)), mock.patch.object(os, 'close', side_effect=consume), \
                     mock.patch.dict(os.environ, {'MRK_HOST_BASE_CONTEXT': R.canonical(base_value).decode()}, clear=True):
                    with self.assertRaises(ValueError): C.bind_host()
                self.assertEqual(len(os.listdir('/proc/self/fd')), before)
                self.assertTrue((host / 'host-binding.json').exists())
                if fault == 'collision': self.assertEqual((host / 'host-binding.json').read_bytes(), b'foreign')
