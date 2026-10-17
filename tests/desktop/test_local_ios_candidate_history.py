"""Real iOS file/journal/lease readback. Native replies inert; no tools/Stores."""
import hashlib
import os
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import UUID
import test_local_candidate_inputs as android
from mobile_release import local_ios_candidate_review as review
from mobile_release import _desktop_local_history_protocol as wire
from mobile_release.local_ios_candidate_bundle import archive_digest
from mobile_release.local_release_journal import canonical
from mobile_release.ios_artifacts import _File


class IOSCandidateHistoryTests(unittest.TestCase):
    setUp=android.CandidateHistoryTests.setUp
    tearDown=android.CandidateHistoryTests.tearDown
    run_original=android.CandidateHistoryTests.run_original
    pending=android.CandidateHistoryTests.pending
    journal=android.CandidateHistoryTests.journal
    ready=android.CandidateHistoryTests.ready
    def request(self, fd, action):
        value = android.CandidateHistoryTests.request(self, fd, action)
        if action in {'review-inputs', 'abandon-inputs'}: value['context']['platform'] = 'ios'
        return value

    def ready_ios(self):
        self.pending(); directory = self.root / '.mobile-release/desktop-ios-archive' / UUID(android.CANDIDATE).hex
        parent = self.root
        for part in directory.relative_to(self.root).parts:
            parent /= part; parent.mkdir(mode=0o700, exist_ok=True); parent.chmod(0o700)
        archive = directory / 'archive.xcarchive'; archive.mkdir(mode=0o755)
        app = archive / 'App.app'; app.mkdir(mode=0o755)
        body = b'not executable: inert retained archive bytes'
        (app / 'Info.plist').write_bytes(body); (app / 'Info.plist').chmod(0o644)
        inventory = {'App.app': None, 'App.app/Info.plist': _File(len(body), hashlib.sha256(body).hexdigest(), body[:4])}
        (directory / 'export').mkdir(mode=0o700)
        rows = []
        for name in ('export/App.ipa', 'store-metadata.zip', 'validation-report.json'):
            body = ('inert exact retained ' + name).encode(); p = directory / name; p.write_bytes(body); p.chmod(0o600)
            rows.append(dict(fileName=name, bytes=len(body), sha256=hashlib.sha256(body).hexdigest()))
        manifest = dict(schemaVersion=1, scope='local-ios-candidate-inputs', operationId=android.CANDIDATE,
            enrollment=android.history.ENROLLMENT, sourceCommit=android.PENDING['sourceCommit'], sourceTree=android.PENDING['sourceTree'],
            savedConfig=dict(bytes=1, sha256=android.PENDING['configurationSha256']),
            savedVersion=dict(source='release/version.json', bytes=1, sha256=android.PENDING['versionSha256'], name='1.0.0', build=1),
            bundleId='com.example.candidate', signing=dict(platform='ios', kind='apple-distribution', teamId='ABCDEFGHIJ', certificateSha256='a'*64,
                profileUuid='12345678-1234-1234-1234-123456789ABC', profileExpiresAt='2027-01-01T00:00:00Z'), files=rows,
            archive=dict(directory='archive.xcarchive', entries=2, bytes=sum(v.size for v in inventory.values() if v), sha256=archive_digest(inventory)))
        raw = canonical(manifest) + b'\n'; p = directory / review.MANIFEST; p.write_bytes(raw); p.chmod(0o600)
        digest = hashlib.sha256(raw).hexdigest(); j = self.journal()
        try: j._append(expected_head=j.head(), operation_id=android.CANDIDATE, phase='inputs-ready', payload={'candidateSha256':digest})
        finally: j.close()
        return directory, manifest, digest

    def snapshot(self, directory):
        return {p.relative_to(directory).as_posix():(p.stat().st_ino, p.read_bytes()) for p in directory.rglob('*') if p.is_file()}

    def test_ios_ready_real_engine_reads_both_artifacts_and_preserves_every_file(self):
        directory, manifest, digest = self.ready_ios(); before = self.snapshot(directory)
        terminal, events, engine = self.run_original('review-inputs')
        self.assertEqual(terminal['outcome'], 'complete', engine.primary)
        inputs = terminal['result']['candidateInputs']
        self.assertEqual(inputs['archive'], manifest['archive']); self.assertEqual(inputs['files'], manifest['files'])
        self.assertEqual(inputs['candidateSha256'], digest); self.assertNotIn('applicationId', inputs)
        self.assertEqual(inputs['priorCreateFinality'], 'not-established')
        self.assertEqual(terminal['lifetime']['commands'], 0); self.assertEqual([e[0] for e in events], ['lease-ready','history-head'])
        self.assertEqual(engine.service.bundle.tree_reads, 2); self.assertTrue(engine.service.bundle.tree_closed())
        self.assertEqual(self.snapshot(directory), before)

    def test_ios_platform_context_is_exact_and_android_namespace_is_not_adopted(self):
        for action in ['verify','enroll','review-execution','review-reconcile','review-recovery']:
            with self.assertRaises(wire.ProtocolError): wire.context(dict(projectId='p', executionMode='local', action=action, platform='ios', candidateOperationId=android.CANDIDATE))
        for platform in [None,'android','macos']:
            with self.assertRaises(wire.ProtocolError): wire.context(dict(projectId='p',executionMode='local',action='review-inputs',platform=platform,candidateOperationId=android.CANDIDATE))
        # Seed authentic Android candidate; iOS must not reinterpret its flat bundle.
        self.ready(); terminal,_,_=self.run_original('review-inputs')
        self.assertNotEqual(terminal['outcome'],'complete'); self.assertIsNone(terminal['result'])

    def test_ios_pending_and_ready_abandon_preserve_outputs(self):
        self.pending();terminal,_,_=self.run_original('review-inputs')
        self.assertEqual(terminal['outcome'],'complete');self.assertIsNone(terminal['result']['candidateInputs'])
        terminal,_,_=self.run_original('abandon-inputs');self.assertEqual(terminal['outcome'],'complete')
        self.assertFalse((self.root/'.mobile-release').exists())
        self.tearDown();self.setUp()
        directory,_,_=self.ready_ios();before=self.snapshot(directory)
        terminal,events,_=self.run_original('abandon-inputs')
        self.assertEqual(terminal['outcome'],'complete');self.assertIsNone(terminal['result']['candidateInputs'])
        self.assertEqual([e[0] for e in events],['lease-ready','history-head','abandoned-head'])
        self.assertEqual(self.snapshot(directory),before)
        terminal,_,_=self.run_original('review-inputs');self.assertEqual(terminal['outcome'],'complete');self.assertIsNone(terminal['result']['candidateInputs'])
        terminal,_,_=self.run_original('abandon-inputs');self.assertEqual(terminal['outcome'],'refused')

    def test_ios_archive_and_ipa_drift_and_same_bytes_inode_replacement_refuse(self):
        for kind in ('archive','ipa','same-bytes'):
            with self.subTest(kind=kind):
                if kind!='archive': self.tearDown();self.setUp()
                directory,_,_=self.ready_ios(); original=review.IOSCandidateBundleReview.finish
                def changed(owner):
                    p=directory/('export/App.ipa' if kind=='ipa' else 'archive.xcarchive/App.app/Info.plist')
                    data=p.read_bytes()
                    if kind=='same-bytes':
                        temporary=p.with_name('replacement');temporary.write_bytes(data);temporary.chmod(0o644);os.replace(temporary,p)
                    else:p.write_bytes(data+b'changed')
                    return original(owner)
                with patch.object(review.IOSCandidateBundleReview,'finish',changed):terminal,_,_=self.run_original('review-inputs')
                self.assertNotEqual(terminal['outcome'],'complete');self.assertIsNone(terminal['result'])

    def test_ios_extra_export_or_top_file_and_symlink_are_not_adopted(self):
        for kind in ('export','top','symlink'):
            with self.subTest(kind=kind):
                if kind!='export':self.tearDown();self.setUp()
                directory,_,_=self.ready_ios()
                if kind=='symlink': (directory/'archive.xcarchive/App.app/link').symlink_to('Info.plist')
                else:
                    p=directory/('export/Other.ipa' if kind=='export' else 'extra');p.write_bytes(b'inert');p.chmod(0o600)
                terminal,_,_=self.run_original('review-inputs');self.assertNotEqual(terminal['outcome'],'complete')

    def test_ios_lost_tree_close_never_publishes_or_retries_numeric_close(self):
        self.ready_ios();original=review._FD.close;lost=[]
        def uncertain(slot):
            source=getattr(slot.guard,'_local_history_source',None);owner=source.operation if source else None
            bundle=getattr(owner,'bundle',None)
            selected=type(bundle) is review.IOSCandidateBundleReview and any(row[0] is slot and row[1].endswith('Info.plist') for row in bundle.tree_slots)
            if not selected or lost:return original(slot)
            fd=slot.number;builtin=os.close
            def close(number):
                if number==fd:lost.append(number);builtin(number);raise OSError('inert lost tree close')
                return builtin(number)
            with patch.object(os,'close',close):return original(slot)
        with patch.object(review._FD,'close',uncertain):terminal,_,engine=self.run_original('review-inputs',expect_unknown=True)
        self.assertEqual(len(lost),1);self.assertEqual(terminal['outcome'],'unknown');self.assertIsNone(terminal['result'])
        self.assertFalse(engine.service.bundle.tree_closed());self.assertTrue(engine.guard.lifetime_ledger.fatal)

    def test_ios_lost_iterator_close_never_becomes_empty_closed_state(self):
        directory,_,_=self.ready_ios();target=(directory/'archive.xcarchive/App.app').stat().st_ino;original=os.scandir;lost=[]
        class Iterator:
            def __init__(self, value):self.value=value
            def __iter__(self):return self
            def __next__(self):return next(self.value)
            def close(self):self.value.close();lost.append(True);raise OSError('inert lost iterator close')
        def scan(path):
            result=original(path)
            return Iterator(result) if type(path) is int and os.fstat(path).st_ino==target and not lost else result
        with patch.object(os,'scandir',scan):terminal,_,engine=self.run_original('review-inputs',expect_unknown=True)
        self.assertEqual(lost,[True]);self.assertEqual(terminal['outcome'],'unknown');self.assertFalse(engine.service.bundle.tree_closed())

    def test_ios_deadline_and_control_budget_are_enforced_before_summary(self):
        directory,_,_=self.ready_ios();original=review.IOSCandidateBundleReview.finish
        def expired(owner):owner.owner.source.work_end=time.monotonic()-0.001;return original(owner)
        with patch.object(review.IOSCandidateBundleReview,'finish',expired):terminal,_,_=self.run_original('review-inputs')
        self.assertNotEqual(terminal['outcome'],'complete');self.assertIsNone(terminal['result'])
        with patch.object(review,'CONTROL_BYTES',1):terminal,_,_=self.run_original('review-inputs')
        self.assertNotEqual(terminal['outcome'],'complete');self.assertIsNone(terminal['result'])
