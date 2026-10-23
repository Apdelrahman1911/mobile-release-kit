"""Memory-only current candidate admission; no native calls or downloads."""
import copy
import importlib.util
import io
import json
import stat
import struct
import sys
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile
import zlib


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location('candidate_carrier_data',
    ROOT / 'desktop/tools/macos_candidate_carrier.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
R = sys.modules['desktop.tools.macos_fixed_carrier_resume']
CLOCK = SimpleNamespace(check=lambda: None)


def fixture(target='aarch64-apple-darwin'):
    row = dict(source='1' * 40, tree='2' * 40, target=target, runId='42', runAttempt='2',
               jobId='43', artifactId='44', artifactBytes=100, artifactSha256='3' * 64)
    preview = dict(schemaVersion=2, sourceCommit=row['source'], sourceTree=row['tree'], runId='42', runAttempt='2',
        platform='macOS26-arm64' if target.startswith('aarch64') else 'macOS26-x86_64',
        workflow='.github/workflows/desktop-macos-installed.yml',
        workflowRef='Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-installed.yml@refs/heads/verify/desktop-macos-candidate',
        scope='current-macos-candidate', packageRole='ordinary-image', instrumented=False,
        normalBuild='passed', packageAudit='passed', installationReadback='passed',
        originalInstallerReturnedZero=True, originalPackageGroupReturnedZero=True,
        originalObservationMountDetached=True, originalImageFinalizationReturnedZero=True,
        originalFinalImageMountDetached=True, finalImageScopedNotarizationObserved=True,
        fullM2Qualified=False, maintenanceQualified=False, fullUIQualified=False,
        distributionQualified=False, productReady=False, automaticWindowOpen='unexecuted',
        normalQuit='unexecuted', ordinaryEntryRoute='unexecuted', directPayloadPreMain='unqualified',
        manualUIAcceptance='pending', unexecutedReason='candidate-export-before-independent-ui-verification',
        distributionBytes=4, distributionSha256=M.sha(b'DATA'), packageSize=3,
        packageSha256='4' * 64, descriptorSha256='5' * 64, signatureSha256='6' * 64,
        runtimeManifestSha256='7' * 64, installerInventorySha256='8' * 64)
    run = dict(id=42, run_attempt=2, head_sha=row['source'], head_branch='verify/desktop-macos-candidate', event='push',
        path='.github/workflows/desktop-macos-installed.yml', workflow_id=363563168,
        repository={'full_name': 'Apdelrahman1911/mobile-release-kit'}, status='completed', conclusion='failure')
    names = ('Standard Installer only is privileged; never execute the app or Python as root',
             'Notarize, staple and verify only the final user image',
             'Stage the current signed candidate only after actual installation and final-image verification',
             'Retain the complete candidate for independent installed-app testing')
    job = dict(id=43, run_id=42, run_attempt=2, head_sha=row['source'], name='normal-installed-' + target,
        status='completed', conclusion='failure', steps=[dict(number=n + 20, name=name, status='completed', conclusion='success')
                                                      for n, name in enumerate(names)])
    job['steps'].append(dict(number=24, name='later UI', status='completed', conclusion='failure'))
    artifact = dict(id=44, expired=False, size_in_bytes=row['artifactBytes'], digest='sha256:' + row['artifactSha256'],
        name=f"mobile-release-kit-macos26-{target}-candidate-{row['source']}-42-2",
        workflow_run=dict(id=42, head_sha=row['source'], head_branch='verify/desktop-macos-candidate'))
    return row, preview, run, job, artifact


def archive(row, entries, compression=zipfile.ZIP_DEFLATED, *, streaming=False):
    class Unseekable(io.BytesIO):
        def seekable(self): return False
        def seek(self, *args): raise io.UnsupportedOperation('inert descriptor fixture')
    stream = Unseekable() if streaming else io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=compression) as output:
        for name, body in entries:
            output.writestr(name, body)
    body = stream.getvalue()
    return body, dict(row, artifactBytes=len(body), artifactSha256=M.sha(body))


class CandidateCarrierData(unittest.TestCase):
    def test_metadata_reuses_closed_stages_without_fabricating_whole_run_success(self):
        for target in ('aarch64-apple-darwin', 'x86_64-apple-darwin'):
            row, _, run, job, artifact = fixture(target)
            for outcome in ('success', 'failure', 'cancelled', None):
                run['conclusion'] = job['conclusion'] = outcome
                self.assertEqual(M.candidate_metadata_data(run, job, artifact, row), row)
            self.assertIsNone(job['conclusion'])
            prepared = dict(job, name='prepared-installed-' + target, conclusion='success')
            self.assertEqual(M.candidate_metadata_data(run, prepared, artifact, row), row)
            # The prepared carrier job still needs ALL four original stages.
            for changed, selection in ((prepared, dict(row, jobId='45')),
                                       (dict(prepared, steps=prepared['steps'][1:]), row)):
                with self.assertRaises(ValueError):
                    M.candidate_metadata_data(run, changed, artifact, selection)
            for index, key, value in ((0, 'head_sha', 'a' * 40), (0, 'run_attempt', 1),
                    (0, 'head_branch', 'main'), (0, 'event', None), (0, 'event', 'workflow_dispatch'),
                    (0, 'event', 'pull_request'), (0, 'workflow_id', 1), (1, 'name', 'normal-installed-other'),
                    (1, 'id', True), (1, 'run_attempt', 1), (2, 'expired', True),
                    (2, 'digest', 'sha256:' + 'a' * 64), (2, 'id', 45), (2, 'size_in_bytes', True)):
                values = copy.deepcopy([run, job, artifact]); values[index][key] = value
                with self.subTest(target=target, index=index, key=key), self.assertRaises(ValueError):
                    M.candidate_metadata_data(*values, row)

    def test_missing_failed_duplicate_or_reordered_package_stage_refuses(self):
        row, _, run, job, artifact = fixture()
        for index in range(4):
            for change in ('skipped', 'failure', 'in_progress', 'missing', 'duplicate', 'reordered'):
                changed = copy.deepcopy(job)
                if change == 'missing': del changed['steps'][index]
                elif change == 'duplicate': changed['steps'].append(dict(changed['steps'][index], number=25))
                elif change == 'reordered': changed['steps'][index]['number'] = 30 if index < 3 else 1
                elif change == 'in_progress': changed['steps'][index]['status'] = change
                else: changed['steps'][index]['conclusion'] = change
                with self.subTest(index=index, change=change), self.assertRaises(ValueError):
                    M.candidate_metadata_data(run, changed, artifact, row)

    def test_preview_cannot_relabel_source_target_or_qualification(self):
        row, preview, *_ = fixture()
        body = json.dumps(preview).encode()
        self.assertEqual(M.candidate_preview_data(body, row), preview)
        for key, value in (('sourceCommit', 'a' * 40), ('sourceTree', 'b' * 40), ('platform', 'macOS26-x86_64'),
                ('runAttempt', '1'), ('workflowRef', 'another workflow'), ('productReady', True),
                ('normalQuit', 'passed'), ('instrumented', True), ('distributionBytes', True),
                ('distributionBytes', M.LIMIT + 1), ('packageSha256', '0' * 64), ('scope', 'normal-macos-early-preview')):
            changed = dict(preview); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                M.candidate_preview_data(json.dumps(changed).encode(), row)
        with self.assertRaises(ValueError):
            M.candidate_preview_data(body[:-1] + b',"productReady":false}', row)
        for key, value in (('artifactBytes', True), ('runId', '0'), ('target', 'other'), ('extra', 'untrusted')):
            with self.subTest(nomination=key), self.assertRaises(ValueError):
                M.candidate_selection_data(dict(row, **{key: value}))

    def test_exact_three_member_archive_and_actual_image_binding(self):
        for target in ('aarch64-apple-darwin', 'x86_64-apple-darwin'):
            row, preview, *_ = fixture(target)
            entries = [('MobileReleaseKit.dmg', b'DATA'), ('PREVIEW.json', json.dumps(preview).encode()), ('README.md', b'Guide\n')]
            for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                body, selected = archive(row, entries, compression)
                self.assertEqual(M.candidate_members(body, selected, CLOCK), dict(entries))
            invalid = (entries[:2], entries + [('extra', b'x')], entries[:2] + [('PREVIEW.json', b'{}')],
                entries[:2] + [('../README.md', b'x')], [('MobileReleaseKit.dmg', b'EDIT')] + entries[1:],
                entries[:2] + [('README.md', b'x' * 32769)])
            for case, changed in enumerate(invalid):
                # Duplicate name is intentional adversarial DATA, not a writer mistake.
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore', UserWarning)
                    body, selected = archive(row, changed)
                with self.subTest(target=target, case=case), self.assertRaises(ValueError):
                    M.candidate_members(body, selected, CLOCK)
            body, selected = archive(row, entries)
            tailed = body + b'x'
            with self.assertRaises(ValueError):
                M.candidate_members(tailed, dict(selected, artifactBytes=len(tailed), artifactSha256=M.sha(tailed)), CLOCK)
            wanted = [dict(name=n, bytes=len(b), sha256=M.sha(b)) for n, b in entries]
            with self.assertRaises(ValueError):
                M.zip_data(body, dict(kind='carrier', bytes=len(body), sha256=M.sha(body), members=wanted), CLOCK)
            legacy, _ = archive(row, entries[:2])
            self.assertEqual(M.zip_data(legacy, dict(kind='carrier', bytes=len(legacy), sha256=M.sha(legacy),
                members=wanted[:2]), CLOCK), dict(entries[:2]))

    def test_image_admission_precedes_decompression_and_declared_sizes_agree(self):
        row, preview, *_ = fixture()
        for mode in ('pass', 'refuse', 'late', 'wrong-size'):
            events, late = [], [False]
            def point():
                if late[0]: raise ValueError('deadline')
            def admit(size):
                self.assertEqual(size, 4)
                events.append('admit')
                if mode == 'refuse': raise ValueError('capacity')
                if mode == 'late': late[0] = True
            value = dict(preview, distributionBytes=5) if mode == 'wrong-size' else preview
            entries = [('MobileReleaseKit.dmg', b'DATA'), ('PREVIEW.json', json.dumps(value).encode()), ('README.md', b'Guide\n')]
            body, selected = archive(row, entries)
            actual = M.zip_data
            def decode(*args):
                events.append('decode')
                return actual(*args)
            with self.subTest(mode=mode), mock.patch.object(M, 'zip_data', side_effect=decode):
                if mode == 'pass':
                    self.assertEqual(M.candidate_members(body, selected, SimpleNamespace(check=point), before_image=admit), dict(entries))
                    self.assertEqual(events, ['admit', 'decode'])
                else:
                    with self.assertRaises(ValueError):
                        M.candidate_members(body, selected, SimpleNamespace(check=point), before_image=admit)
                    self.assertEqual(events, [] if mode == 'wrong-size' else ['admit'])

    def test_central_allocation_is_bounded_before_zipfile_construction(self):
        row, preview, *_ = fixture()
        entries = [('MobileReleaseKit.dmg', b'DATA'), ('PREVIEW.json', json.dumps(preview).encode()), ('README.md', b'Guide\n')]
        body, row = archive(row, entries)
        footer = list(struct.unpack('<4s4H2LH', body[-22:]))
        for field, invalid in ((3, 65535), (4, 65535), (5, 16385), (7, 1)):
            changed = list(footer); changed[field] = invalid
            malformed = body[:-22] + struct.pack('<4s4H2LH', *changed)
            nomination = dict(row, artifactBytes=len(malformed), artifactSha256=M.sha(malformed))
            with self.subTest(field=field), mock.patch.object(M.zipfile, 'ZipFile') as parser:
                with self.assertRaises(ValueError):
                    M.candidate_members(malformed, nomination, CLOCK)
                parser.assert_not_called()
        # A valid-looking classic footer must not let ZipFile replace the
        # admitted limits with ZIP64 fields during its constructor.
        record = struct.pack('<4sQ2H2L4Q', b'PK\x06\x06', 44, 45, 45, 0, 0, 100000, 100000, 1 << 20, 0)
        locator = struct.pack('<4sLQL', b'PK\x06\x07', 0, len(body) - 22, 1)
        footer[5] += len(record) + len(locator)
        malformed = body[:-22] + record + locator + struct.pack('<4s4H2LH', *footer)
        nomination = dict(row, artifactBytes=len(malformed), artifactSha256=M.sha(malformed))
        with mock.patch.object(M.zipfile, 'ZipFile') as parser, self.assertRaises(ValueError):
            M.candidate_members(malformed, nomination, CLOCK)
        parser.assert_not_called()


def retained_fixture(*, git=False):
    row, _, run, job, artifact = fixture()
    entries = [('android-helper-distribution-detach.status', b'16\n'),
               ('android-helper-distribution-detach.stderr', b'Resource busy\n'),
               ('android-helper-distribution-detach.stdout', b''),
               ('distribution/MobileReleaseKit-Observation.dmg', b'old-request-image'),
               ('distribution/MobileReleaseKit.dmg', b'plain-package-image')]
    if git:
        entries = entries[3:]
        row.update(zip(('source', 'runId', 'runAttempt'), M.RETAINED_GIT_TUPLE))
        run.update(id=int(row['runId']), run_attempt=int(row['runAttempt']), head_sha=row['source'])
        job.update(run_id=run['id'], run_attempt=run['run_attempt'], head_sha=row['source'])
        artifact['workflow_run'].update(id=run['id'], head_sha=row['source'])
    body, row = archive(row, entries)
    selection = dict(schemaVersion=1, kind='retained-observer-source-selection-v1',
        packageRole='installed-shell-observation', nativeScope='git-native' if git else 'tool-setup', origin=row,
        members=[dict(name=name, bytes=len(content)) for name, content in entries])
    suffix = '-git-native' if git else ''
    job.update(name='normal-installed-' + row['target'] + suffix,
        labels=['xcode-27' if git else 'macos-26'], steps=[dict(number=i + 10, name=name, status='completed',
        conclusion='failure' if name == M.RETAINED_OBSERVER_STEPS[-2] else 'success')
        for i, name in enumerate(M.RETAINED_OBSERVER_STEPS)])
    artifact.update(size_in_bytes=len(body), digest='sha256:' + M.sha(body),
        name='candidate-detach-nonshipping-unqualified-diagnostics-' + row['target'] + suffix
             + '-' + row['source'] + '-' + row['runId'] + '-' + row['runAttempt'])
    return selection, entries, body, run, job, artifact


def retained_receipt_fixture(selection, entries):
    controls = {key: dict(name=name, bytes=len(body), sha256=M.sha(body)) for key, name, body in (
        ('package', 'Install.pkg', b'package'), ('descriptor', 'producer.json', b'descriptor'),
        ('signature', 'producer.sig', b'signature'), ('inventory', 'install-inventory.json', b'inventory'))}
    release = dict(profile='fixed-macos26-arm64-maintenance-v2',
        packageIdentifier='dev.mobile-release-kit.desktop.installed', bundleIdentifier='dev.mobile-release-kit.desktop',
        packageVersion='0.1.3', release='macos26-arm64-desktop-03', sourceCommit=selection['origin']['source'],
        protocolSha256='4'*64, runtimeManifestSha256='5'*64, signingPolicySha256='6'*64,
        packageSha256=controls['package']['sha256'], inventorySha256=controls['inventory']['sha256'])
    members = [dict(name=name, bytes=len(body), sha256=M.sha(body)) for name, body in entries]
    return dict(schemaVersion=1, scope='retained-observer-fresh-install', packageRole='installed-shell-observation',
        nativeScope=selection['nativeScope'], target=selection['origin']['target'], nomination=selection['origin'],
        members=members, image=members[-1], **controls, release=release,
        helperSource='a'*40, helperTree='b'*40, consumerRunId='51', consumerRunAttempt='1', consumerWorkDirectory=[2,3,501],
        freshInstall=dict(requestId='1'*32, invocation='2'*32, instance='3'*32, stateSha256='7'*64, resultSha256='8'*64),
        nativeProducerSignatureVerified=True, installedSignaturesVerified=True,
        originalInstallerReturnedZero=True, sameRequestReadback=True, originalMountDetached=True,
        originalClosesKnown=True, workloadsKnownSettled=True, privateOutputsRetired=True,
        productReady=False, uiQualified=False, p0Qualified=False)


class RetainedObserverCarrierData(unittest.TestCase):
    def test_git_selection_is_original_tuple_and_closed_two_member_roster_not_optional_tool_files(self):
        selected, _, _, *_ = retained_fixture(git=True)
        tool, *_ = retained_fixture()
        self.assertEqual(M.retained_observer_selection_data(selected), selected)
        self.assertEqual(len(selected['members']), 2)
        changes = (dict(selected, members=tool['members']), dict(tool, members=selected['members']),
            dict(selected, nativeScope='tool-setup'), dict(selected, nativeScope='git-fetch-native'),
            dict(selected, members=selected['members'][1:]))
        changes += tuple(dict(selected, origin=dict(selected['origin'], **{key: value}))
            for key, value in (('source', tool['origin']['source']), ('runId', '42'), ('runAttempt', '2'),
                               ('target', 'x86_64-apple-darwin')))
        for changed in changes:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                M.retained_observer_selection_data(changed)

    def test_git_metadata_requires_original_combined_build_git_job_runner_artifact_and_closed_notary_stages(self):
        selected, _, _, run, job, artifact = retained_fixture(git=True)
        self.assertEqual(M.retained_observer_metadata_data(run, job, artifact, selected), selected)
        mutations = ((0, 'id', 42), (0, 'run_attempt', 2), (0, 'head_sha', 'f'*40),
            (1, 'id', 44), (1, 'name', 'normal-installed-aarch64-apple-darwin'),
            (1, 'labels', ['macos-26']), (1, 'labels', ['xcode-27', 'macos-26']),
            (2, 'id', 45), (2, 'expired', True), (2, 'digest', 'sha256:'+'f'*64),
            (2, 'name', artifact['name'].replace('-git-native-', '-')))
        for index, key, value in mutations:
            rows = copy.deepcopy([run, job, artifact]); rows[index][key] = value
            with self.subTest(index=index, key=key), self.assertRaises(ValueError):
                M.retained_observer_metadata_data(*rows, selected)
        for index in range(len(M.RETAINED_OBSERVER_STEPS)):
            for fault in ('missing', 'skipped', 'reordered', 'duplicate'):
                changed = copy.deepcopy(job)
                if fault == 'missing': del changed['steps'][index]
                elif fault == 'duplicate': changed['steps'].append(dict(changed['steps'][index], number=50))
                elif fault == 'reordered': changed['steps'][index]['number'] = 60 if index < 8 else 1
                else: changed['steps'][index]['conclusion'] = 'skipped'
                with self.subTest(index=index, fault=fault), self.assertRaises(ValueError):
                    M.retained_observer_metadata_data(run, changed, artifact, selected)
        changed = copy.deepcopy(job)
        changed['steps'][0]['name'] = 'Build only the current nonshipping observer'
        with self.assertRaises(ValueError): M.retained_observer_metadata_data(run, changed, artifact, selected)

    def test_git_two_member_codec_keeps_same_chunk_crc_eof_roster_and_main_only_memory_rules(self):
        selection, entries, *_ = retained_fixture(git=True)
        entries = [(name, data * 10000) for name, data in entries]
        selection['members'] = [dict(name=name, bytes=len(data)) for name, data in entries]
        expected = {'image': entries[-1][1], 'members': [dict(name=name, bytes=len(data), sha256=M.sha(data))
                                                       for name, data in entries]}
        complete = R.member_stream_complete
        for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            for streaming in (False, True):
                # Main first: discarded peer must still be checked after it.
                body, origin = archive(selection['origin'], list(reversed(entries)), compression, streaming=streaming)
                selected, events = dict(selection, origin=origin), []
                def bounded(stream, info, *args, **kwargs):
                    sink = kwargs['on_chunk']
                    def receive(chunk):
                        self.assertLessEqual(len(chunk), 65536)
                        sink(chunk)
                    events.append(info.filename)
                    return complete(stream, info, *args, **dict(kwargs, on_chunk=receive))
                with mock.patch.object(R, 'member_stream_complete', side_effect=bounded), \
                     mock.patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError('no second decode')):
                    self.assertEqual(M.retained_observer_members(body, selected, CLOCK,
                        before_image=lambda size: events.append(size)), expected)
                self.assertEqual(events, [len(entries[-1][1]), entries[-1][0], entries[0][0]])
                with zipfile.ZipFile(io.BytesIO(body)) as archive_data:
                    ignored = archive_data.getinfo(entries[0][0])
                local = struct.unpack('<4s5H3L2H', body[ignored.header_offset:ignored.header_offset + 30])
                start = ignored.header_offset + 30 + local[9] + local[10]
                changed = bytearray(body); changed[start] ^= 1; changed = bytes(changed)
                invalid = dict(selection, origin=dict(origin, artifactSha256=M.sha(changed)))
                with self.assertRaises((ValueError, zlib.error)):
                    M.retained_observer_members(changed, invalid, CLOCK)
        tool, *_ = retained_fixture()
        body, origin = archive(selection['origin'], entries + [('android-helper-distribution-detach.stdout', b'')])
        with self.assertRaises(ValueError): M.retained_observer_members(body, dict(selection, origin=origin), CLOCK)
        self.assertEqual(M.retained_observer_memory_requirement(selection, 17),
            3 * selection['origin']['artifactBytes'] + (16 << 20) + 17 + (512 << 20) + (1 << 30))
        with self.assertRaises(ValueError):
            M.retained_observer_memory_requirement(selection, 17, image_bytes=1)
        self.assertEqual(len(tool['members']), 5)

    def test_git_fresh_receipt_is_scoped_and_cannot_certify_a_tool_install_or_original_future_return(self):
        selected, entries, *_ = retained_fixture(git=True)
        receipt = retained_receipt_fixture(selected, entries)
        args = (selected, 'a'*40, 'b'*40, '51', '1', [2, 3, 501])
        self.assertEqual(M.retained_observer_install_receipt_data(receipt, *args), receipt)
        for key, value in (('nativeScope', 'tool-setup'), ('consumerRunId', selected['origin']['runId']),
                ('originalMountDetached', False), ('sameRequestReadback', False), ('originalInstallerReturnedZero', False),
                ('members', retained_receipt_fixture(*retained_fixture()[:2])['members'])):
            with self.subTest(key=key), self.assertRaises(ValueError):
                M.retained_observer_install_receipt_data(dict(receipt, **{key: value}), *args)

    def test_exact_nonshipping_selection_and_no_ordinary_substitution(self):
        selected, _, _, *_ = retained_fixture()
        self.assertEqual(M.retained_observer_selection_data(selected), selected)
        for change in (lambda v:v.update(nativeScope='git-native'), lambda v:v.update(packageRole='ordinary-image'),
                lambda v:v['origin'].update(target='x86_64-apple-darwin'), lambda v:v.update(schemaVersion=True),
                lambda v:v['members'][2].update(bytes=1), lambda v:v['members'][0].update(bytes=True),
                lambda v:v['members'].reverse(), lambda v:v['members'].append(v['members'][0]),
                lambda v:v['members'][0].update(sha256='a'*64), lambda v:v.update(PREVIEW={})):
            value=copy.deepcopy(selected); change(value)
            with self.assertRaises(ValueError): M.retained_observer_selection_data(value)
        with self.assertRaises(ValueError): M.candidate_selection_data(selected)

    def test_actual_stage_results_not_global_job_success_admit_bytes(self):
        selected, _, _, run, job, artifact = retained_fixture()
        for outcome in ('success','failure','cancelled',None):
            run['conclusion']=job['conclusion']=outcome
            self.assertEqual(M.retained_observer_metadata_data(run,job,artifact,selected),selected)
        for index in range(len(M.RETAINED_OBSERVER_STEPS)):
            for fault in ('missing','duplicate','skipped','in_progress','reordered'):
                changed=copy.deepcopy(job)
                if fault=='missing': del changed['steps'][index]
                elif fault=='duplicate': changed['steps'].append(dict(changed['steps'][index],number=40))
                elif fault=='reordered': changed['steps'][index]['number']=50 if index < len(M.RETAINED_OBSERVER_STEPS)-1 else 1
                elif fault=='in_progress': changed['steps'][index]['status']=fault
                else: changed['steps'][index]['conclusion']=fault
                with self.subTest(index=index,fault=fault), self.assertRaises(ValueError):
                    M.retained_observer_metadata_data(run,changed,artifact,selected)
        for index in range(len(M.RETAINED_OBSERVER_STEPS)-2):
            changed=copy.deepcopy(job); changed['steps'][index]['conclusion']='failure'
            with self.assertRaises(ValueError): M.retained_observer_metadata_data(run,changed,artifact,selected)
        for index,key,value in ((0,'head_sha','f'*40),(0,'run_attempt',1),(0,'path','other'),
                (0,'status','in_progress'),(1,'labels',['xcode-27']),(1,'id',True),
                (1,'name','prepared-installed-aarch64-apple-darwin'),(2,'expired',True),
                (2,'digest','sha256:'+'f'*64),(2,'name','ordinary-candidate')):
            values=copy.deepcopy([run,job,artifact]); values[index][key]=value
            with self.subTest(index=index,key=key),self.assertRaises(ValueError):
                M.retained_observer_metadata_data(*values,selected)

    def test_five_original_members_empty_stdout_and_no_preview(self):
        selection, entries, _, *_ = retained_fixture()
        expected = {'image': entries[-1][1], 'members': [dict(name=name, bytes=len(body), sha256=M.sha(body))
                                                       for name, body in entries]}
        for compression in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED):
            body,origin=archive(selection['origin'],entries,compression)
            selected=dict(selection,origin=origin); admitted=[]
            self.assertEqual(M.retained_observer_members(body,selected,CLOCK,before_image=admitted.append),expected)
            self.assertEqual(admitted,[len(entries[-1][1])])
            with self.assertRaises(ValueError): M.candidate_members(body,origin,CLOCK)
            with self.assertRaises(ValueError): M.retained_observer_members(body+b'x',selected,CLOCK)
        for entries2 in (entries[:-1],entries+[('PREVIEW.json',b'{}')],entries[:2]+[(entries[2][0],b'x')]+entries[3:],
                         entries[:-1]+[('../MobileReleaseKit.dmg',entries[-1][1])]):
            body,origin=archive(selection['origin'],entries2)
            with self.assertRaises(ValueError): M.retained_observer_members(body,dict(selection,origin=origin),CLOCK)
        body,origin=archive(selection['origin'],entries)
        with mock.patch.object(M,'zip_data') as decoder, self.assertRaisesRegex(ValueError,'capacity'):
            M.retained_observer_members(body,dict(selection,origin=origin),CLOCK,
                before_image=lambda size:(_ for _ in ()).throw(ValueError('capacity')))
        decoder.assert_not_called()

    def test_main_only_collection_hashes_all_members_once_in_bounded_chunks(self):
        selection, entries, *_ = retained_fixture()
        entries[-2] = (entries[-2][0], b'OBSOLETE' * 40000)
        entries[-1] = (entries[-1][0], b'MAIN' * 40000)
        selection['members'] = [dict(name=name, bytes=len(body)) for name, body in entries]
        expected = {'image': entries[-1][1], 'members': [dict(name=name, bytes=len(body), sha256=M.sha(body))
                                                       for name, body in entries]}
        actual = R.member_stream_complete
        for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            for streaming in (False, True):
                for order in (entries, [entries[-1], *entries[:-1]]):
                    with self.subTest(compression=compression, streaming=streaming, main_first=order is not entries):
                        body, origin = archive(selection['origin'], order, compression, streaming=streaming)
                        counts = dict(created=0, appended=0, largest=0, live=0)
                        emitted, events = {}, []
                        class MainBuffer(bytearray):
                            def __init__(self):
                                super().__init__()
                                counts['created'] += 1; counts['live'] += 1
                                events.append('main-buffer')
                            def extend(self, chunk):
                                counts['appended'] += len(chunk)
                                counts['largest'] = max(counts['largest'], len(chunk))
                                super().extend(chunk)
                            def __del__(self): counts['live'] -= 1
                        def bounded(stream, info, *args, **kwargs):
                            self.assertNotIn(info.filename, emitted)
                            emitted[info.filename] = 0
                            sink = kwargs['on_chunk']
                            def receive(chunk):
                                self.assertIs(type(chunk), bytes)
                                self.assertLessEqual(len(chunk), 65536)
                                emitted[info.filename] += len(chunk)
                                sink(chunk)
                            return actual(stream, info, *args, **dict(kwargs, on_chunk=receive))
                        def admit(size):
                            self.assertEqual(size, len(expected['image']))
                            events.append('admit')
                        with mock.patch.object(R, 'bytearray', MainBuffer, create=True), \
                             mock.patch.object(R, 'member_stream_complete', side_effect=bounded), \
                             mock.patch.object(zipfile.ZipFile, 'open', side_effect=AssertionError('second decode forbidden')):
                            result = M.retained_observer_members(body, dict(selection, origin=origin), CLOCK, before_image=admit)
                        self.assertEqual(result, expected)
                        self.assertEqual(emitted, {name: len(value) for name, value in entries})
                        self.assertEqual(counts['created'], 1)
                        self.assertEqual(counts['appended'], len(expected['image']))
                        self.assertLessEqual(counts['largest'], 65536)
                        self.assertEqual(counts['live'], 0)
                        self.assertEqual(events, ['admit', 'main-buffer'])

    def test_discarded_member_still_requires_every_original_zip_check(self):
        selection, entries, *_ = retained_fixture()
        # Main first proves a completed image never authorizes skipping a later
        # discarded member's corruption. Outer digest is deliberately repinned.
        body, origin = archive(selection['origin'], [entries[-1], *entries[:-1]],
                               zipfile.ZIP_STORED, streaming=True)
        ignored = entries[-2][0]
        with zipfile.ZipFile(io.BytesIO(body)) as parsed:
            info = parsed.getinfo(ignored)
        central = struct.unpack('<4s4H2LH', body[-22:])[6]
        while True:
            row = struct.unpack('<4s6H3L5H2L', body[central:central + 46])
            self.assertEqual(row[0], b'PK\x01\x02')
            name = body[central + 46:central + 46 + row[10]].decode()
            if name == ignored: break
            central += 46 + row[10] + row[11] + row[12]
        local = info.header_offset
        fields = struct.unpack('<4s5H3L2H', body[local:local + 30])
        start = local + 30 + fields[9] + fields[10]
        descriptor = start + info.compress_size
        self.assertEqual(body[descriptor:descriptor + 4], b'PK\x07\x08')
        for fault in ('crc', 'local-size', 'local-name', 'local-flags', 'encryption',
                      'compression', 'external-type', 'central-size', 'span', 'descriptor'):
            changed = bytearray(body)
            if fault == 'crc': changed[start] ^= 1
            elif fault == 'local-size': struct.pack_into('<L', changed, local + 22, info.file_size + 1)
            elif fault == 'local-name': changed[local + 30] ^= 1
            elif fault == 'local-flags': struct.pack_into('<H', changed, local + 6, 0)
            elif fault == 'encryption':
                struct.pack_into('<H', changed, local + 6, info.flag_bits | 1)
                struct.pack_into('<H', changed, central + 8, info.flag_bits | 1)
            elif fault == 'compression':
                struct.pack_into('<H', changed, local + 8, 99)
                struct.pack_into('<H', changed, central + 10, 99)
            elif fault == 'external-type': struct.pack_into('<L', changed, central + 38, stat.S_IFLNK << 16)
            elif fault == 'central-size': struct.pack_into('<L', changed, central + 24, info.file_size + 1)
            elif fault == 'span': struct.pack_into('<L', changed, central + 42, info.header_offset + 1)
            else: changed[descriptor + 4] ^= 1
            changed = bytes(changed)
            selected = dict(selection, origin=dict(origin, artifactBytes=len(changed), artifactSha256=M.sha(changed)))
            with self.subTest(fault=fault), self.assertRaises((ValueError, zipfile.BadZipFile, struct.error)):
                M.retained_observer_members(changed, selected, CLOCK)

    def test_retained_central_name_keeps_former_zipfile_original_spelling_check(self):
        selection, entries, body, *_ = retained_fixture()
        name = entries[-2][0]
        footer = list(struct.unpack('<4s4H2LH', body[-22:]))
        at = body.index(name.encode(), footer[6])
        central = at - 46
        self.assertEqual(body[central:central + 4], b'PK\x01\x02')
        suffix = b'\0not-a-selected-member'
        end = at + len(name)
        changed = bytearray(body[:end] + suffix + body[end:])
        struct.pack_into('<H', changed, central + 28, len(name) + len(suffix))
        footer[5] += len(suffix)
        changed[-22:] = struct.pack('<4s4H2LH', *footer)
        changed = bytes(changed)
        with zipfile.ZipFile(io.BytesIO(changed)) as parsed:
            info = parsed.getinfo(name)
            self.assertEqual(info.filename, name)
            self.assertEqual(info.orig_filename, name + suffix.decode())
            with self.assertRaises(zipfile.BadZipFile): parsed.open(info)
        selected = dict(selection, origin=dict(selection['origin'],
            artifactBytes=len(changed), artifactSha256=M.sha(changed)))
        with self.assertRaisesRegex(ValueError, 'p0-zip-member'):
            M.retained_observer_members(changed, selected, CLOCK)

    def test_discarded_deflate_codec_eof_crc_bound_and_deadline_remain_authoritative(self):
        data = b'IGNORED' * 40000
        compressor = zlib.compressobj(wbits=-15)
        packed = compressor.compress(data) + compressor.flush()
        name = 'distribution/MobileReleaseKit-Observation.dmg'
        for fault in ('none', 'tail', 'unfinished', 'crc', 'size', 'deadline'):
            raw = packed + b'X' if fault == 'tail' else packed[:-1] if fault == 'unfinished' else packed
            info = SimpleNamespace(filename=name, compress_size=len(raw), file_size=len(data) - (fault == 'size'),
                compress_type=zipfile.ZIP_DEFLATED, CRC=zlib.crc32(data) ^ (fault == 'crc'))
            emitted, calls = [], [0]
            def point():
                calls[0] += 1
                if fault == 'deadline' and calls[0] == 3: raise ValueError('deadline')
            with self.subTest(fault=fault):
                args = (io.BytesIO(raw), info, 0, len(raw), SimpleNamespace(check=point))
                options = dict(limits=R.RETAINED_OBSERVER_MEMBERS, on_chunk=lambda chunk: emitted.append(len(chunk)))
                if fault == 'none':
                    R.member_stream_complete(*args, **options)
                    self.assertEqual(sum(emitted), len(data))
                else:
                    with self.assertRaises(ValueError): R.member_stream_complete(*args, **options)
                self.assertTrue(all(size <= 65536 for size in emitted))
        # Chunk sinks do not change any ordinary carrier/P0 API or profile.
        with self.assertRaisesRegex(ValueError, 'collector-public-chunk-profile'):
            R.member_stream_complete(io.BytesIO(packed), info, 0, len(packed), CLOCK, on_chunk=lambda chunk: None)

    def test_retained_memory_quotes_bind_exact_phase_and_main_size(self):
        selection, entries, body, *_ = retained_fixture()
        image = len(entries[-1][1])
        for retained in (0, 12345, 1 << 30):
            reserve = (16 << 20) + retained + (512 << 20) + (1 << 30)
            self.assertEqual(M.retained_observer_memory_requirement(selection, retained), 3 * len(body) + reserve)
            self.assertEqual(M.retained_observer_memory_requirement(selection, retained, image_bytes=image),
                             2 * len(body) + 3 * image + reserve)
        for invalid in (True, -1, (1 << 30) + 1, 1.0):
            with self.assertRaisesRegex(ValueError, 'retained-observer-memory-bound'):
                M.retained_observer_memory_requirement(selection, invalid)
        for invalid in (True, 0, image - 1, image + 1, sum(len(value) for _, value in entries), 1.0):
            with self.assertRaisesRegex(ValueError, 'retained-observer-memory-bound'):
                M.retained_observer_memory_requirement(selection, 0, image_bytes=invalid)
        late = [False]
        def point():
            if late[0]: raise ValueError('deadline')
        def admit(size):
            self.assertEqual(size, image)
            late[0] = True
        with mock.patch.object(M, 'zip_data') as decoder, self.assertRaisesRegex(ValueError, 'deadline'):
            M.retained_observer_members(body, selection, SimpleNamespace(check=point), before_image=admit)
        decoder.assert_not_called()

    def test_receipt_separates_original_product_fresh_instance_and_current_consumer(self):
        selection,entries,*_=retained_fixture()
        value=retained_receipt_fixture(selection,entries)
        args=(selection,'a'*40,'b'*40,'51','1',(2,3,501))
        self.assertIs(M.retained_observer_install_receipt_data(value,*args),value)
        self.assertNotEqual(value['nomination']['runId'],value['consumerRunId'])
        for key in ('nativeProducerSignatureVerified','installedSignaturesVerified','originalInstallerReturnedZero',
                    'sameRequestReadback','originalMountDetached','originalClosesKnown','workloadsKnownSettled','privateOutputsRetired'):
            wrong=copy.deepcopy(value); wrong[key]=False
            with self.subTest(key=key),self.assertRaises(ValueError): M.retained_observer_install_receipt_data(wrong,*args)
        for change in (lambda v:v.update(productReady=True),lambda v:v.update(status=0),
                lambda v:v.update(consumerRunId='42'),lambda v:v.update(consumerWorkDirectory=[2,4,501]),
                lambda v:v['release'].update(sourceCommit='f'*40),lambda v:v['release'].update(packageSha256='f'*64),
                lambda v:v['release'].update(inventorySha256='f'*64),lambda v:v['release'].update(packageVersion='1.02.3'),
                lambda v:v['freshInstall'].update(instance='0'*32),lambda v:v['freshInstall'].update(requestId=True),
                lambda v:v['members'][2].update(sha256='f'*64),lambda v:v.update(runtimeBindingSha256='f'*64)):
            wrong=copy.deepcopy(value); change(wrong)
            with self.assertRaises(ValueError): M.retained_observer_install_receipt_data(wrong,*args)


if __name__ == '__main__':
    unittest.main()
