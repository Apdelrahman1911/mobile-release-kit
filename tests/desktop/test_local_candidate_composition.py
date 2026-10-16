"""Actual source/service integration with real tiny held files, inert commands.

Only the existing native run_command, project admission and signed-build body
are fixtures. Source acquire/parser/dispatcher/POST/closes, core service/terminal
and retained artifact reader run normally. No Git/build/Store/native process is
executed here; command outcomes and outer producer finality are predicate DATA.
Separate existing local-Git tests exercise genuine Git output/custody.
"""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_local_release_candidate as handoff_data
import test_android_build_protocol as protocol
from mobile_release import local_release_candidate as C, local_release_source as S
from mobile_release import _command_process as process
from mobile_release import _desktop_android_build_protocol as wire
from mobile_release.checked_files import _Reader
from mobile_release.config import ReleaseConfig
from mobile_release.owned_process import ProcessCleanupError, run_owned


class LocalCandidateCompositionTests(unittest.TestCase):
    # Reuse the existing real artifact/inert producer fixture, not its tests.
    setUp = handoff_data.LocalAndroidHandoffTests.setUp
    patched = handoff_data.LocalAndroidHandoffTests.patched
    forbidden = handoff_data.LocalAndroidHandoffTests.forbidden
    close_sources = handoff_data.LocalAndroidHandoffTests.close_sources

    def subject(self, *, jarsigner=0):
        f, artifact, body = handoff_data.LocalAndroidHandoffTests.subject(self)
        op, source, root = f.operation, f.source, f.operation.root
        data = json.loads(f.bound.saved.configuration.raw)
        data['source']['localStoreEnabled'] = True
        raw = json.dumps(data, separators=(',', ':')).encode()
        saved = replace(f.bound.saved, configuration=replace(f.bound.saved.configuration, raw=raw))
        f.bound = op.inputs = replace(f.bound, saved=saved, config=ReleaseConfig(root / S.CONFIG_PATH, root, data))
        op.bind_inputs.return_value = f.bound
        request_data = json.loads(protocol.encoded(protocol.signed_request_data()))
        request_data['context'].update(f.request.context)
        request_data['context']['savedConfig'] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        request_data['native']['signingContext'] = dict(request_data['context']['savedConfig'])
        request_data['native'].update(projectRoot=str(root), cwd='/inert/cwd')
        f.request = f.run.request = op.request = wire.parse_request(protocol.encoded(request_data))
        source.work_end = time.monotonic() + 600
        op._roles = dict.fromkeys(C.BUILD_ROLES, 'new')
        f.files.slots, f.files.iterators = [], []
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        self.source_fds.append(root_fd)
        project = SimpleNamespace(fd=root_fd, directory=SimpleNamespace(slots=[None] * len(root.parts)))
        f.invocation.mode = 'build'
        f.invocation.root = root
        f.invocation.project_owner = f.invocation._original_project = project
        self.patched(f.invocation, 'require', return_value=None)
        for relative, value in ((S.CONFIG_PATH, raw), (saved.configuration.source, saved.version_raw),
                ('.git/config', b'[core]\nrepositoryformatversion=0\nbare=false\n'),
                ('.git/HEAD', b'ref: refs/heads/main\n'), ('.git/refs/heads/main', b'a' * 40 + b'\n'),
                ('.git/index', b'inert-index-not-executed')):
            p = root / relative
            p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            p.write_bytes(value)
            p.chmod(0o600)
        for relative in ('.git/objects/info', '.git/info'):
            (root / relative).mkdir(parents=True, mode=0o700)
        rows = [(name.encode(), hashlib.sha1(b'blob ' + str(len(value)).encode() + b'\0' + value).hexdigest().encode())
                for name, value in ((S.CONFIG_PATH, raw), (saved.configuration.source, saved.version_raw))]
        f.native_calls = []
        def command(argv, **kwargs):
            self.assertIs(kwargs['cancellation'], f.guard)
            self.assertIsNone(kwargs['execution_scope'])
            self.assertFalse(kwargs['text'])
            self.assertEqual(argv[0], '/usr/bin/git')
            self.assertLessEqual(kwargs['timeout'], 10)
            self.assertNotIn('operation-close', f.events)
            self.assertIs(f.invocation.project_owner, project)
            f.native_calls.append(tuple(argv))
            f.events.append('source-command')
            if 'config' in argv:
                output = b'core.repositoryformatversion\n0\0core.bare\nfalse\0'
            elif 'rev-parse' in argv:
                output = b'a' * 40 + b'\n' + b'b' * 40 + b'\n'
            elif '--stage' in argv:
                output = b''.join(b'100644 ' + sha + b' 0\t' + name + b'\0' for name, sha in rows)
            elif 'ls-files' in argv:
                output = b''.join(b'H ' + name + b'\0' for name, _ in rows)
            elif 'ls-tree' in argv:
                output = b''.join(b'100644 blob ' + sha + b'\t' + name + b'\0' for name, sha in rows)
            else:
                self.assertIn('status', argv)
                output = b''
            f.ledger._commands += 1
            f.ledger._command_dispatched = True
            return SimpleNamespace(args=argv, returncode=0, stdout=output, stderr=b'')
        f.command = self.patched(process, 'run_command', side_effect=command)
        def signed(bound):
            self.assertIs(bound, f.bound)
            self.assertEqual(f.ledger.verdict().commands, 6)
            self.assertEqual(len(f.run._local_composition.source.readers), 1)
            self.assertFalse(f.run._local_composition.source.closed)
            f.events.append('inert-signed-body')
            op._roles = dict.fromkeys(C.BUILD_ROLES, 'returned')
            op._returned = dict.fromkeys(C.BUILD_ROLES, 0)
            op._returned['jarsigner'] = jarsigner
            op._signature_passed = True
            f.ledger._commands += 6
            f.disposition.update(work='retained-work', artifacts='retained-incomplete')
        f.run._signed_body.side_effect = signed
        return f, artifact, body

    def test_real_service_source_reader_dispatch_full_terminal_and_retained_artifact(self):
        for jarsigner in (0, 4):
            with self.subTest(jarsigner=jarsigner):
                f, path, body = self.subject(jarsigner=jarsigner)
                with C.retain_local_android_candidate(f.run) as candidate:
                    endpoint = f.source.work_end
                    f.run.run()
                    self.assertEqual(len(f.native_calls), 8)
                    self.assertEqual(candidate.source.endpoint, endpoint)
                    self.assertGreater(endpoint - time.monotonic(), 120)
                    self.assertTrue(candidate.source_closed)
                    self.assertEqual(candidate.source.readers[0].assert_closed(), None)
                    self.assertLess(f.events.index('inert-signed-body'), f.events.index('operation-close'))
                    self.assertFalse(candidate.joined)
                    with self.assertRaises(C.LocalCandidateError): candidate.observation()
                    f.settle_outer()
                    terminal = f.run.terminal()
                    self.assertEqual(terminal['build']['outcome'], 'complete')
                    self.assertEqual(terminal['build']['lifetime']['commands'], 14)
                    self.assertEqual([r['before'] for r in terminal['sourceCalls']], [0, 1, 2, 3, 4, 5, 12, 13])
                    self.assertLessEqual(terminal['ownedPythonDescriptorQuote']['total'], 256)
                    self.assertEqual(candidate.source.held, len(candidate.source.readers[0].descriptors))
                    with self.assertRaises(wire.ProtocolError): wire.validate_terminal(terminal, f.request)
                    with self.assertRaises(wire.ProtocolError): wire.validate_terminal(terminal['build'], f.request)
                    observed = candidate.observation()
                    self.assertEqual(observed['sourceCorrespondence']['commit'], 'a' * 40)
                    self.assertFalse(observed['candidatePrepared'] or observed['storeAuthorized'])
                    self.assertEqual(observed['outerTransportFinality'], 'not-established')
                    with candidate.artifact_blocks() as blocks: self.assertEqual(b''.join(blocks), body)
                self.assertTrue(path.exists())
                with self.assertRaises(C.LocalCandidateError): candidate.observation()

    def test_source_nonzero_dispatch_is_not_gradle_and_cannot_resume(self):
        f, path, _ = self.subject()
        original = f.command.side_effect
        def failure(argv, **kwargs):
            result = original(argv, **kwargs)
            result.returncode = 7
            result.stderr = b'PRIVATE_SOURCE_SECRET /private/path'
            return result
        f.command.side_effect = failure
        with C.retain_local_android_candidate(f.run) as candidate:
            with self.assertRaises(S.LocalSourceError): f.run.run()
            f.run._signed_body.assert_not_called()
            f.settle_outer()
            terminal = f.run.terminal()
            self.assertEqual(terminal['build']['activity']['command']['outcome'], 'not-dispatched')
            self.assertTrue(terminal['build']['lifetime']['commandDispatched'])
            self.assertEqual(terminal['build']['lifetime']['commands'], 1)
            self.assertEqual(terminal['sourceFailure'], 'command')
            self.assertNotIn('PRIVATE_', json.dumps(terminal))
            self.assertTrue(candidate.failed)
            with self.assertRaises(C.LocalCandidateError): candidate.observation()
        self.assertTrue(path.exists())

    def test_default_saved_dispatch_refuses_unarmed_source_without_native_call(self):
        f, _, _ = self.subject()
        with self.assertRaises(ValueError):
            run_owned(['/usr/bin/git', 'status'], cancellation=f.guard, capture=True, text=False)
        f.command.assert_not_called()

    def test_real_build_role_arm_and_capture_keep_full_source_ledger(self):
        f, _, _ = self.subject()
        with C.retain_local_android_candidate(f.run) as candidate:
            with self.assertRaisesRegex(RuntimeError, '^inert-stop$'), candidate._source_scope(f.bound):
                op = f.operation
                self.assertEqual(f.ledger.verdict().commands, 6)
                for role in ('keytool-input', 'gradle'):
                    op._arm(role)
                    self.assertEqual(f.source.command_limits(5, role != 'gradle', 1024), (5, 1024))
                    f.ledger._commands += 1
                    op.returned(role, 0)
                    if role == 'keytool-input': op.signing.input_checked = True
                op.capture_ready(':app', 'release')
                f.ledger._commands += 1
                with self.assertRaises(ValueError): op.capture_ready(':app', 'release')
                # Fail scope deliberately: source POST must not run interleaved
                # with this intentionally unfinished build-role fixture.
                raise_marker = RuntimeError('inert-stop')
                raise raise_marker

    def test_unknown_source_close_vetoes_capture_join_and_is_not_retried(self):
        f, path, _ = self.subject()
        original_close = os.close
        target, attempts = [None], []
        original_signed = f.run._signed_body.side_effect
        def signed(bound):
            original_signed(bound)
            candidate = f.run._local_composition
            target[0] = candidate.source.readers[0]._number(candidate.source.files[0][1].slot)
        f.run._signed_body.side_effect = signed
        def close(fd):
            original_close(fd)
            if fd == target[0]:
                attempts.append(fd)
                raise OSError('PRIVATE_CLOSE')
        with patch.object(os, 'close', side_effect=close):
            with C.retain_local_android_candidate(f.run) as candidate:
                with self.assertRaises(ProcessCleanupError): f.run.run()
                self.assertTrue(candidate.handoff.captured)
                self.assertTrue(candidate.failed)
                self.assertFalse(candidate.source_closed or candidate.joined)
                with self.assertRaises(C.LocalCandidateError): candidate.observation()
        self.assertEqual(attempts, [target[0]])
        self.assertTrue(path.exists())

    def test_late_source_change_and_deadline_withhold_provisional_artifact(self):
        for fault in ('changed', 'deadline'):
            with self.subTest(fault=fault):
                f, path, _ = self.subject()
                original = C.LocalAndroidBuildHandoff._capture
                def capture(handoff, run, artifact):
                    original(handoff, run, artifact)
                    if fault == 'changed':
                        (f.operation.root / S.CONFIG_PATH).write_bytes(b'changed')
                    else:
                        run._local_composition.source.endpoint = time.monotonic() - 1
                with patch.object(C.LocalAndroidBuildHandoff, '_capture', new=capture):
                    with C.retain_local_android_candidate(f.run) as candidate:
                        with self.assertRaises(Exception): f.run.run()
                        self.assertTrue(candidate.handoff.captured and candidate.failed)
                        self.assertFalse(candidate.source_closed)
                        self.assertEqual(len(f.native_calls), 7)
                        with self.assertRaises(C.LocalCandidateError): candidate.observation()
                self.assertTrue(path.exists())

    def test_source_extra_ledger_and_wrong_pending_limits_fail_before_build(self):
        for fault in ('ledger', 'limits'):
            with self.subTest(fault=fault):
                f, _, _ = self.subject()
                original = f.command.side_effect
                def command(argv, **kwargs):
                    if fault == 'limits':
                        # Actual source callback is one-shot; second consumption
                        # cannot borrow the same armed original command.
                        f.source.command_limits(kwargs['timeout'], True, kwargs['output_limit'])
                    result = original(argv, **kwargs)
                    if fault == 'ledger': f.ledger._commands += 1
                    return result
                f.command.side_effect = command
                with C.retain_local_android_candidate(f.run) as candidate:
                    with self.assertRaises(Exception): f.run.run()
                    self.assertTrue(candidate.failed)
                    f.run._signed_body.assert_not_called()
                    with self.assertRaises(C.LocalCandidateError): candidate.observation()

    def test_reused_reader_rejects_later_leaf_before_read_or_command(self):
        for fault in ('oversize', 'replaced-during-open'):
            with self.subTest(fault=fault):
                f, _, _ = self.subject()
                path = f.operation.root / '.git/index'
                if fault == 'oversize':
                    with path.open('wb') as output: output.truncate(S.MAX_GIT_BYTES + 1)
                original_open, original_read = _Reader._open, _Reader.read
                read_names = []
                def opened(reader, name, **kwargs):
                    slot = original_open(reader, name, **kwargs)
                    if fault == 'replaced-during-open' and name == 'index':
                        path.unlink()
                        path.write_bytes(b'foreign replacement')
                        path.chmod(0o600)
                    return slot
                def read(reader, node):
                    read_names.append(node.canonical)
                    return original_read(reader, node)
                with patch.object(_Reader, '_open', new=opened), patch.object(_Reader, 'read', new=read):
                    with C.retain_local_android_candidate(f.run) as candidate:
                        with self.assertRaises(S.LocalSourceError): f.run.run()
                        self.assertTrue(candidate.failed)
                        self.assertEqual(len(candidate.source.readers), 1)
                        candidate.source.readers[0].assert_closed()
                        self.assertNotIn(path, read_names)
                        f.command.assert_not_called()

    def test_unknown_command_and_cancellation_preserve_original_failures(self):
        for fault in ('unknown', 'cancelled'):
            with self.subTest(fault=fault):
                f, path, _ = self.subject()
                error = ProcessCleanupError('PRIVATE_UNKNOWN', dispatched=None, contained=False) if fault == 'unknown' else KeyboardInterrupt()
                def command(argv, **kwargs):
                    if fault == 'unknown':
                        f.ledger._command = object()
                        f.ledger._command_published = True
                        f.ledger._command_dispatched = None
                        f.ledger._command_contained = False
                        f.guard._abort(error)
                    else:
                        f.ledger._commands += 1
                        f.ledger._command_dispatched = True
                        f.guard._cancelled = True
                    raise error
                f.command.side_effect = command
                with C.retain_local_android_candidate(f.run) as candidate:
                    with self.assertRaises(type(error)) as caught: f.run.run()
                    if fault == 'cancelled': self.assertIs(caught.exception, error)
                    f.run._signed_body.assert_not_called()
                    f.settle_outer()
                    terminal = f.run.terminal()
                    self.assertEqual(terminal['build']['outcome'], 'unknown' if fault == 'unknown' else 'cancelled')
                    self.assertEqual(terminal['build']['activity']['command']['outcome'], 'not-dispatched')
                    self.assertEqual(terminal['sourceCalls'][0]['settled'], fault == 'cancelled')
                    self.assertTrue(candidate.failed)
                    with self.assertRaises(C.LocalCandidateError): candidate.observation()
                self.assertTrue(path.exists())

    def test_early_unknown_candidate_terminal_is_absorbing(self):
        f, _, _ = self.subject()
        with C.retain_local_android_candidate(f.run) as candidate:
            f.run.run()
            self.assertEqual(f.run.terminal()['build']['outcome'], 'unknown')
            self.assertTrue(candidate.failed)
            f.settle_outer()
            with self.assertRaises(C.LocalCandidateError): f.run.terminal()
            with self.assertRaises(C.LocalCandidateError): candidate.observation()

    def test_fd_quote_preflight_and_live_unknown_closes_never_get_credit(self):
        quote = dict(project=5, source=25, bound_files=4, module_depth=1, root_depth=4, firebase=False)
        value = C.composition_fd_quote(**quote)
        self.assertEqual(value['total'], 236)
        quote['source'] += 256 - value['total']
        self.assertEqual(C.composition_fd_quote(**quote)['total'], 256)
        quote['source'] += 1
        with self.assertRaises(C.LocalCandidateError): C.composition_fd_quote(**quote)
        f, _, _ = self.subject()
        with C.retain_local_android_candidate(f.run) as candidate:
            with patch.object(S.LocalSourceObservation, 'descriptor_quote', return_value=96):
                with self.assertRaises(C.LocalCandidateError): f.run.run()
            f.command.assert_not_called()
            f.run._signed_body.assert_not_called()
        f, _, _ = self.subject()
        with C.retain_local_android_candidate(f.run) as candidate:
            candidate.quote = {'normalFiles': 1, 'normalIterators': 2}
            f.files.slots = [SimpleNamespace(close_state='UNKNOWN')]
            with self.assertRaises(C.LocalCandidateError): candidate._charge('file-slots', 1)
            f.files.slots[0].close_state = 'CLOSED'
            candidate._charge('file-slots', 1)


if __name__ == '__main__':
    unittest.main()
