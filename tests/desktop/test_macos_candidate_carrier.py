"""Memory-only current candidate admission; no native calls or downloads."""
import copy
import importlib.util
import io
import json
import struct
import sys
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location('candidate_carrier_data',
    ROOT / 'desktop/tools/macos_candidate_carrier.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
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


def archive(row, entries, compression=zipfile.ZIP_DEFLATED):
    stream = io.BytesIO()
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


if __name__ == '__main__':
    unittest.main()
