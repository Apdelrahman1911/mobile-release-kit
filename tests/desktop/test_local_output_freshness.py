"""Original tiny output/copy custody with inert Gradle/signature boundaries.

No Android/native/Store tool executes. The composition fixture supplies actual
file owners and role consumption; only the native output and policy are inert.
"""
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import test_local_candidate_composition as composition
from mobile_release import local_release_candidate as C
from mobile_release._desktop_android_build_files import AndroidBuildFiles, AndroidSigningCandidate
from mobile_release.owned_process import ProcessCleanupError


class LocalOutputFreshnessTests(unittest.TestCase):
    setUp = composition.LocalCandidateCompositionTests.setUp
    patched = composition.LocalCandidateCompositionTests.patched
    forbidden = composition.LocalCandidateCompositionTests.forbidden
    close_sources = composition.LocalCandidateCompositionTests.close_sources
    subject = composition.LocalCandidateCompositionTests.subject

    def output(self, f):
        return f.operation.root / 'app/build/outputs/bundle/release'

    def test_missing_and_empty_scope_real_copy_chain_and_no_duplicate_prefix_opens(self):
        for initial in ('absent', 'empty'):
            with self.subTest(initial=initial):
                f, path, body = self.subject()
                f.signed_bytes = signed_body = body + b'INERT_SIGNER_ADDITION'
                if initial == 'empty': self.output(f).mkdir(parents=True, mode=0o700)
                directories, counts, prefixes = [], [], []
                original_open, limits = AndroidBuildFiles._directory_at, f.source.command_limits
                def opened(files, parent, name, record=None, **kwargs):
                    value = original_open(files, parent, name, record, **kwargs)
                    parts, item = [], value
                    while item is not None:
                        parts.append(item.name)
                        item = item.parent_record
                    if tuple(reversed(parts))[0] == 'app': directories.append(value)
                    return value
                def consume(*args):
                    role = f.operation._pending
                    answer = limits(*args)
                    counts.append((role, sum(s.close_state != 'CLOSED' for s in f.files.slots)))
                    if role == 'gradle': prefixes.extend(f.run._local_composition._output.prefix)
                    return answer
                with patch.object(AndroidBuildFiles, '_directory_at', new=opened), patch.object(f.source, 'command_limits', side_effect=consume):
                    with C.retain_local_android_candidate(f.run) as candidate:
                        f.run.run()
                        f.settle_outer()
                        terminal = f.run.terminal()
                        observed = candidate.observation()
                        witness = observed['outputFreshness']
                        self.assertEqual(witness, {'scope': 'new-output-in-original-invocation', 'initial': initial,
                            'gradleBeforeCommands': 7, 'unsignedOutput': {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()},
                            'signedArtifact': {'bytes': len(signed_body), 'sha256': hashlib.sha256(signed_body).hexdigest()}})
                        self.assertIs(candidate._output.source, f.artifact._source)
                        self.assertIs(candidate._output.signing, f.files.signing_candidate)
                        self.assertIs(candidate._output.artifact, f.artifact)
                        self.assertEqual(len(directories), 5)
                        self.assertEqual(len({id(r.slot) for r in directories}), 5)
                        self.assertEqual(candidate._output.prefix[:len(prefixes)], prefixes)
                        self.assertEqual(len(prefixes), 5 if initial == 'empty' else 1)
                        self.assertTrue(all(n <= candidate.quote['normalFiles'] for _, n in counts))
                        self.assertTrue(all(s.close_state == 'CLOSED' for s in f.files.slots))
                        self.assertEqual(f.selected_gradle, ('/inert/gradle', '--no-daemon', '--no-build-cache',
                            '--no-configuration-cache', '--rerun-tasks', f.bound.task))
                        self.assertEqual(terminal['freshness'], 'not-established')
                        self.assertEqual(f.artifact.freshness, 'not-established')
                        self.assertFalse(observed['candidatePrepared'] or observed['storeAuthorized'])
                        witness['signedArtifact']['sha256'] = 'foreign'
                        self.assertEqual(candidate.observation()['outputFreshness']['signedArtifact']['sha256'], hashlib.sha256(signed_body).hexdigest())
                self.assertEqual(path.read_bytes(), signed_body)
                self.assertEqual((self.output(f) / 'app-release.aab').read_bytes(), body)

    def test_any_preexisting_output_is_preserved_before_tools_or_material(self):
        for name, directory in (('old.aab', False), ('PRIVATE_user_notes.json', False), ('older', True)):
            with self.subTest(name=name):
                f, path, _ = self.subject()
                output = self.output(f)
                output.mkdir(parents=True, mode=0o700)
                old = output / name
                if directory: old.mkdir()
                else: old.write_bytes(b'USER_CONTENT_PRESERVE')
                with C.retain_local_android_candidate(f.run) as candidate:
                    with self.assertRaises(Exception): f.run.run()
                    f.run._signed_body.assert_not_called()
                    f.operation.prepare.assert_not_called()
                    f.settle_outer()
                    terminal = f.run.terminal()
                    self.assertEqual(terminal['outputFailure'], 'preexisting-output')
                    self.assertEqual(terminal['outputGuidance'], C.OUTPUT_REFUSALS['preexisting-output'])
                    self.assertIsNone(terminal['sourceFailure'])
                    self.assertIsNone(terminal['outputFreshness'])
                    self.assertNotIn('PRIVATE_', json.dumps(terminal))
                    with self.assertRaises(C.LocalCandidateError): candidate.observation()
                self.assertTrue(old.is_dir()) if directory else self.assertEqual(old.read_bytes(), b'USER_CONTENT_PRESERVE')
                self.assertFalse(path.exists())

    def test_missing_module_symlink_and_case_alias_never_create_output(self):
        for fault in ('missing', 'symlink', 'case-alias'):
            with self.subTest(fault=fault):
                f, path, _ = self.subject()
                module = f.operation.root / 'app'
                module.rmdir()
                if fault == 'symlink':
                    (f.operation.root / 'other').mkdir()
                    module.symlink_to('other', target_is_directory=True)
                elif fault == 'case-alias': (f.operation.root / 'App').mkdir()
                with C.retain_local_android_candidate(f.run) as candidate:
                    with self.assertRaises(Exception): f.run.run()
                    f.run._signed_body.assert_not_called()
                    f.operation.prepare.assert_not_called()
                    self.assertTrue(candidate.failed)
                    self.assertIsNone(candidate._output_data)
                    if fault == 'missing': self.assertEqual(candidate.output_failure, 'module-missing')
                    f.settle_outer()
                    self.assertIsNone(f.run.terminal()['outputFreshness'])
                self.assertFalse(path.exists())
                self.assertFalse(self.output(f).exists())

    def test_late_pre_gradle_entry_refuses_before_consuming_command(self):
        for initial in ('absent', 'empty'):
            with self.subTest(initial=initial):
                f, path, _ = self.subject()
                if initial == 'empty': self.output(f).mkdir(parents=True, mode=0o700)
                original = f.source.command_limits
                def consume(*args):
                    answer = original(*args)
                    if f.operation._pending == 'keytool-input':
                        self.output(f).mkdir(parents=True, exist_ok=True, mode=0o700)
                        (self.output(f) / 'old.aab').write_bytes(b'PREEXISTING')
                    return answer
                with patch.object(f.source, 'command_limits', side_effect=consume):
                    with C.retain_local_android_candidate(f.run) as candidate:
                        with self.assertRaises(Exception): f.run.run()
                        self.assertEqual(f.operation._roles['gradle'], 'armed')
                        self.assertNotIn('gradle', f.operation._returned)
                        self.assertFalse(candidate._output.armed)
                        self.assertEqual(candidate.output_failure, 'preexisting-output' if initial == 'empty' else 'output-changed')
                        self.assertIsNone(candidate._output_data)
                        f.settle_outer()
                        self.assertIsNone(f.run.terminal()['outputFreshness'])
                self.assertEqual((self.output(f) / 'old.aab').read_bytes(), b'PREEXISTING')
                self.assertFalse(path.exists())

    def test_original_prefix_rename_and_empty_scope_replacement_refuse_capture(self):
        for fault in ('module', 'empty-scope'):
            with self.subTest(fault=fault):
                f, path, _ = self.subject()
                if fault == 'empty-scope': self.output(f).mkdir(parents=True, mode=0o700)
                original = f.source.command_limits
                def consume(*args):
                    answer = original(*args)
                    if f.operation._pending == 'gradle':
                        old = f.operation.root / 'app' if fault == 'module' else self.output(f)
                        old.rename(old.with_name(old.name + '-preserved'))
                        old.mkdir(mode=0o700)
                    return answer
                with patch.object(f.source, 'command_limits', side_effect=consume):
                    with C.retain_local_android_candidate(f.run) as candidate:
                        with self.assertRaises(Exception): f.run.run()
                        self.assertEqual(f.operation._returned['gradle'], 0)
                        self.assertIsNone(candidate._output.source)
                        self.assertIsNone(candidate._output_data)
                preserved = f.operation.root / 'app-preserved' if fault == 'module' else self.output(f).with_name('release-preserved')
                self.assertTrue(preserved.is_dir())
                self.assertTrue((self.output(f) / 'app-release.aab').exists())
                self.assertFalse(path.exists())

    def test_zero_without_output_and_nonzero_cannot_mint_witness(self):
        for fault in ('no-output', 'nonzero'):
            with self.subTest(fault=fault):
                f, path, _ = self.subject()
                f.gradle_output = fault != 'no-output'
                f.gradle_code = 9 if fault == 'nonzero' else 0
                with C.retain_local_android_candidate(f.run) as candidate:
                    with self.assertRaises(Exception): f.run.run()
                    self.assertIsNone(candidate._output.source)
                    self.assertIsNone(candidate._output_data)
                    self.assertFalse(candidate.handoff.captured)
                    f.settle_outer()
                    self.assertIsNone(f.run.terminal()['outputFreshness'])
                    with self.assertRaises(C.LocalCandidateError): candidate.observation()
                self.assertFalse(path.exists())
                self.assertEqual((self.output(f) / 'app-release.aab').exists(), fault == 'nonzero')

    def test_unknown_gradle_keeps_output_and_prefix_debits_without_witness(self):
        f, path, _ = self.subject()
        original = f.source.command_limits
        error = ProcessCleanupError('PRIVATE_UNKNOWN', dispatched=None, contained=False)
        def consume(*args):
            answer = original(*args)
            if f.operation._pending == 'gradle':
                self.output(f).mkdir(parents=True, mode=0o700)
                (self.output(f) / 'partial.aab').write_bytes(b'PARTIAL_PRESERVED')
                f.ledger._command = object()
                f.ledger._command_published = True
                f.ledger._command_dispatched = None
                f.ledger._command_contained = False
                f.guard._abort(error)
                raise error
            return answer
        with patch.object(f.source, 'command_limits', side_effect=consume):
            with C.retain_local_android_candidate(f.run) as candidate:
                with self.assertRaises(ProcessCleanupError): f.run.run()
                self.assertEqual(f.operation._roles['gradle'], 'attempted')
                self.assertNotIn('gradle', f.operation._returned)
                self.assertTrue(candidate.failed and candidate._output.armed)
                self.assertIsNone(candidate._output_data)
                self.assertFalse(candidate.handoff.captured)
                self.assertTrue(all(r.slot.close_state != 'CLOSED' for r in candidate._output.prefix))
                live = sum(s.close_state != 'CLOSED' for s in f.files.slots)
                candidate.quote['normalFiles'] = live
                with self.assertRaises(C.LocalCandidateError): candidate._charge('file-slots', 1)
                with self.assertRaises(C.LocalCandidateError): candidate.observation()
        self.assertFalse(path.exists())
        self.assertEqual((self.output(f) / 'partial.aab').read_bytes(), b'PARTIAL_PRESERVED')

    def test_signing_copy_cannot_substitute_another_original(self):
        f, path, _ = self.subject()
        original = AndroidSigningCandidate.check
        def check(signing):
            result = original(signing)
            owner = f.run._local_composition._output
            if owner.source is not None and owner.signing is None:
                # Adversarial internal seam after real original copy: same
                # contents do not confer this original source's identity.
                from dataclasses import replace
                signing._source = replace(signing._source)
            return result
        with patch.object(AndroidSigningCandidate, 'check', new=check):
            with C.retain_local_android_candidate(f.run) as candidate:
                with self.assertRaises(Exception): f.run.run()
                self.assertIsNone(candidate._output.signing)
                self.assertIsNone(candidate._output_data)
                self.assertFalse(candidate.handoff.captured)
        self.assertFalse(path.exists())
        self.assertTrue((self.output(f) / 'app-release.aab').exists())

    def test_late_output_change_after_handoff_or_final_git_vetoes_join(self):
        for cut in ('handoff', 'final-git'):
            with self.subTest(cut=cut):
                f, path, _ = self.subject()
                original_capture, original_command = C.LocalAndroidBuildHandoff._capture, f.command.side_effect
                def change(): (self.output(f) / 'app-release.aab').write_bytes(b'CHANGED_OUTPUT')
                def captured(handoff, run, artifact):
                    original_capture(handoff, run, artifact)
                    if cut == 'handoff': change()
                def command(argv, **kwargs):
                    answer = original_command(argv, **kwargs)
                    if cut == 'final-git' and len(f.native_calls) == 8: change()
                    return answer
                with patch.object(C.LocalAndroidBuildHandoff, '_capture', new=captured):
                    f.command.side_effect = command
                    with C.retain_local_android_candidate(f.run) as candidate:
                        with self.assertRaises(Exception): f.run.run()
                        self.assertTrue(candidate.handoff.captured and candidate.failed)
                        self.assertFalse(candidate.source_closed or candidate.joined)
                        with self.assertRaises(C.LocalCandidateError): candidate.observation()
                self.assertTrue(path.exists())
                self.assertEqual((self.output(f) / 'app-release.aab').read_bytes(), b'CHANGED_OUTPUT')

    def test_original_output_prefix_unknown_close_vetoes_join_without_retry(self):
        f, path, _ = self.subject()
        original, target, attempts = os.close, [None], []
        signed = f.run._signed_body.side_effect
        def body(bound):
            signed(bound)
            target[0] = f.run._local_composition._output.prefix[0].slot.number
        def close(fd):
            original(fd)
            if fd == target[0]:
                attempts.append(fd)
                raise OSError('PRIVATE_CLOSE')
        f.run._signed_body.side_effect = body
        with patch.object(os, 'close', side_effect=close):
            with C.retain_local_android_candidate(f.run) as candidate:
                with self.assertRaises(ProcessCleanupError): f.run.run()
                self.assertTrue(candidate.source_closed and candidate.handoff.captured)
                self.assertTrue(candidate.failed)
                self.assertEqual(candidate._output.prefix[0].slot.close_state, 'UNKNOWN')
                self.assertFalse(candidate.joined)
                with self.assertRaises(C.LocalCandidateError): candidate.observation()
        self.assertEqual(attempts, [target[0]])
        self.assertTrue(path.exists())

    def test_default_gradle_argv_unchanged_and_wrong_candidate_task_refuses(self):
        f, _, _ = self.subject()
        f.operation._roles['keytool-input'] = 'returned'
        f.operation._returned['keytool-input'] = 0
        f.ledger._commands = 1
        f.operation.signing.input_checked = True
        self.assertEqual(f.operation.gradle_command(), ('/inert/gradle', '--no-daemon', f.bound.task))
        f, _, _ = self.subject()
        f.tools.gradle_command.side_effect = lambda task, work: ('/inert/gradle', ':other:bundleRelease')
        with C.retain_local_android_candidate(f.run) as candidate:
            with self.assertRaises(Exception): f.run.run()
            self.assertEqual(f.operation._roles['gradle'], 'new')
            self.assertFalse(candidate._output.arguments_selected)
            self.assertIsNone(candidate._output_data)


if __name__ == '__main__': unittest.main()
