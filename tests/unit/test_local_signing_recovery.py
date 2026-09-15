"""Crash replay uses actual on-disk layouts and the production recovery entry."""
from __future__ import annotations

import copy
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import mobile_release
from mobile_release import local_signing as signing
from mobile_release.errors import CredentialError
from mobile_release.credentials import _temporary_profile_installation
from .local_signing_helpers import NativeSigningModel, model_result
from .local_signing_workspace import NativeCaseWorkspaceMixin


class TTY(io.StringIO):
    def isatty(self): return True


class SigningRecoveryTests(NativeCaseWorkspaceMixin, unittest.TestCase):
    def setUp(self):
        self.root = self.native_case_directory(prefix='mrk-signing-recovery-')
        self.home = self.root / 'home'; self.home.mkdir(mode=0o700)
        self.model = NativeSigningModel(self.home)
        self.token = 'b'*32
        self.uuid = '12345678-1234-1234-1234-1234567890AB'
        self.session_path = self.home / signing.LEASE_DIRECTORY / ('session-'+self.token)

    def create(self):
        with signing.local_signing_lease(home=self.home) as lease:
            session = lease.session(token=self.token)
            session.bind_runner(self.model)
            session.open(create=True)
            session.prepare(b'fictional-profile', self.uuid)
        return self.session_path

    def recover(self, **kwargs):
        return signing.recover_signing(self.token, signing.CONFIRMATION, home=self.home, runner=self.model, **kwargs)

    def test_initial_stage_prefixes_are_not_misclassified_as_committed_authority(self):
        for content in (b'', b'{', b'{"untrusted":"not authority"}', b'x'*1024):
            self.create()
            stage = self.session_path / 'state.pending'
            stage.write_bytes(content); stage.chmod(0o600)
            (self.session_path / 'state.json').unlink()  # Initial committed state never dispatched work.
            result = self.recover()
            self.assertEqual(result['status'], 'recovered')
            self.assertEqual(signing.signing_status(home=self.home)['status'], 'idle')

    def test_old_committed_state_not_staged_bytes_controls_recovery(self):
        self.create()
        for name in ('state.pending', 'completed.pending', 'intent.pending'):
            stage = self.session_path / name
            stage.write_bytes(b'{"new-authority":true}'); stage.chmod(0o600)
        self.recover()
        self.assertEqual(self.model.preferences, self.model.original)
        self.assertFalse(self.session_path.exists())

    def test_duplicate_unknown_types_binding_and_version_in_committed_controls_refuse_without_native_work(self):
        self.create()
        control = self.session_path / 'state.json'
        original = control.read_bytes()
        value = json.loads(original)
        values = [original[:-2]+b',"version":1}\n']
        for field, invalid in (('version', 3), ('version', True), ('revision', True), ('token', 'c'*32),
                               ('conflict', 0), ('unknown', 'field'), ('native', {'other': {'device':1,'inode':1}}),
                               ('inflight', {'kind':'observe','worker':True})):
            updated = copy.deepcopy(value); updated[field] = invalid
            values.append(json.dumps(updated).encode())
        for malformed in values:
            with self.subTest(malformed=malformed):
                control.write_bytes(malformed)
                before = len(self.model.calls)
                with self.assertRaises(CredentialError): self.recover()
                self.assertEqual(len(self.model.calls), before)
        control.write_bytes(original)
        self.recover()

    def test_completed_marker_is_self_contained_and_never_restores_later_preferences(self):
        for cut in ('state.json', 'intent.json', 'completed.json'):
            self.create()
            real = signing.SigningSession._remove_control
            def remove(session, name):
                if name == cut: raise OSError('fictional teardown cut')
                return real(session, name)
            # The genuine public invocation mints its own confirmation-bound
            # attempt; a phase string or a loaded snapshot is not authority.
            with patch.object(signing.SigningSession, '_remove_control', new=remove), self.assertRaises(CredentialError):
                self.recover()
            self.assertTrue((self.session_path / 'completed.json').exists())
            foreign = {'default': str(self.home/'foreign.keychain-db'), 'search': []}
            self.model.preferences = copy.deepcopy(foreign)
            before = len(self.model.calls)
            self.recover()
            self.assertEqual(self.model.preferences, foreign)
            self.assertTrue(all('-s' not in argv for argv in self.model.calls[before:]))
            self.model.preferences = copy.deepcopy(self.model.original)

    def test_confirmation_and_manual_tty_guards_run_before_account_admission(self):
        with patch.object(signing, 'local_signing_lease', side_effect=AssertionError('no admission')):
            for token, confirm, manual in ((True, signing.CONFIRMATION, False), ('b'*31, signing.CONFIRMATION, False),
                                           (self.token, signing.CONFIRMATION+' ', False), (self.token, signing.CONFIRMATION, True)):
                with self.subTest(token=token, confirm=confirm, manual=manual), self.assertRaises(CredentialError):
                    signing.recover_signing(token, confirm, manual=manual, input_stream=io.StringIO(), output_stream=io.StringIO())

    def test_manual_recheck_holds_lease_and_removes_no_unknown_resource_itself(self):
        self.create()
        unknown = self.session_path / 'keychain/native-transaction-stage'
        unknown.write_bytes(b'fictional-unknown-native-stage'); unknown.chmod(0o600)
        session = self
        class OwnerInput(TTY):
            def readline(self, bound):
                session.assertEqual(signing.signing_status(home=session.home)['status'], 'busy')
                session.assertEqual(unknown.read_bytes(), b'fictional-unknown-native-stage')
                unknown.unlink()  # Only the owner's independently known fixture resource.
                return 'recheck '+session.token+'\n'
        output = TTY()
        self.assertEqual(self.recover(manual=True, input_stream=OwnerInput(), output_stream=output)['status'], 'recovered')
        self.assertNotIn(self.model.original['default'], output.getvalue())
        self.assertFalse(self.session_path.exists())

    def test_legacy_worker_fields_are_read_only_and_never_authorize_process_operations(self):
        self.create()
        control = self.session_path/'state.json'
        state = json.loads(control.read_bytes())
        state['version'] = 1
        state['inflight'] = {'kind':'observe', 'worker':987654}
        control.write_text(json.dumps(state))
        original = control.read_bytes()
        before = len(self.model.calls)
        with patch.object(os, 'kill', side_effect=AssertionError('recorded PID is not authority')), \
             patch.object(os, 'killpg', side_effect=AssertionError('recorded group is not authority')), \
             patch.object(os, 'waitpid', side_effect=AssertionError('recorded PID is not our child')):
            status = signing.signing_status(home=self.home)
            self.assertEqual(status['phase'], 'legacy-pending')
            self.assertEqual(status['recovery'], 'unsupported-legacy-controls')
            for manual in (False, True):
                with self.subTest(manual=manual), self.assertRaisesRegex(CredentialError, 'legacy controls'):
                    self.recover(manual=manual, input_stream=TTY(), output_stream=TTY())
        self.assertEqual(len(self.model.calls), before)
        self.assertEqual(control.read_bytes(), original)

    def test_snapshot_is_immutable_and_reload_never_renews_original_failure_or_recovery_authority(self):
        self.create()
        with signing.local_signing_lease(home=self.home, recovery=True) as lease:
            session = lease.session(token=self.token)
            session.open(create=False)
            snapshot = session.load()
            self.assertEqual(snapshot.phase, 'active')
            self.assertIsNone(session.intent)
            self.assertIsNone(session.state)
            with self.assertRaises(FrozenInstanceError):
                snapshot.phase = 'completed'
            for attribute in ('journal_failed', 'unresolved'):
                setattr(session, attribute, True)
                again = session.load()
                self.assertTrue(getattr(session, attribute))
                with self.assertRaises(CredentialError):
                    session._adopt_snapshot(again)
            with self.assertRaisesRegex(CredentialError, 'fresh original authorization'):
                session._recover_command_gate()
            with self.assertRaisesRegex(CredentialError, 'original fresh authorization'):
                session.recover(snapshot, authorization=None)
        self.assertEqual(self.recover()['status'], 'recovered')

    def test_prepared_without_any_command_dispatch_needs_a_fresh_attempt_before_cleanup(self):
        # Seed the PREPARED write through the real session path, then make the
        # explicitly selected runner fail before it invokes the command owner.
        # No public error flags or invented completion permit same-call cleanup.
        from mobile_release import owned_process

        injected = CredentialError('fixture pre-owner boundary')
        invoked, closed, handles = [], [], {}
        handlers = {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)}
        real_close = signing._close
        def close(descriptor):
            tracked, identity = descriptor in handles, None
            if tracked:
                try:
                    observed = os.fstat(descriptor)
                    identity = (observed.st_dev, observed.st_ino)
                except OSError:
                    pass  # An unavailable observation must not prevent the real close.
            result = real_close(descriptor)
            if tracked:
                closed.append((descriptor, identity))
            return result
        with patch.object(signing, '_close', new=close):
            with self.assertRaises(owned_process.ProcessError) as projected:
                with signing.local_signing_lease(home=self.home) as lease:
                    session = lease.session(token=self.token)
                    session.open(create=True)
                    session.bind_runner(self.model)
                    session.prepare(b'fictional-profile', self.uuid)
                    calls = len(self.model.calls)
                    intent = (self.session_path/'intent.json').read_bytes()
                    for descriptor in (lease.home_fd, lease.fd, session.fd, session.native_fd):
                        identity = os.fstat(descriptor)
                        handles[descriptor] = (identity.st_dev, identity.st_ino)
                    self.assertEqual(len(handles), 4)
                    def refuse(_argv, **kwargs):
                        invoked.append((kwargs['execution_scope'], kwargs['journal_binding']))
                        raise injected
                    session.bind_runner(refuse)
                    try:
                        session.run(['security', 'list-keychains', '-d', 'user'], kind='observe')
                    except CredentialError as error:
                        self.assertIs(error, injected)  # Before real lease-exit projection.
                        raise
                    else:
                        self.fail('original pre-owner failure did not propagate')
        self.assertIs(type(projected.exception), owned_process.ProcessError)
        self.assertIsNot(projected.exception, injected)
        self.assertTrue(projected.exception.fatal)
        self.assertFalse(projected.exception.cleanup_complete)
        guard, ledger = lease.cancellation, lease.cancellation.lifetime_ledger
        self.assertTrue(ledger.fatal)
        self.assertEqual(guard.handler_state, 'RESTORED')
        self.assertTrue(all(signal.getsignal(signum) is handler for signum, handler in handlers.items()))
        self.assertCountEqual(closed, list(handles.items()))
        self.assertEqual(lease._hold_slot.state, 'CLOSED')
        self.assertFalse(lease.locked)
        self.assertIsNone(lease.active)
        self.assertTrue(session.closed)
        self.assertEqual((lease.home_fd, lease.fd, session.fd, session.native_fd), (None,) * 4)
        self.assertEqual(invoked, [(session._command_scope, session._command_binding)])
        scope, binding = invoked[0]
        self.assertIs(scope._binding, binding)
        self.assertFalse(scope._used)
        self.assertIsNone(scope.outcome._engine)
        self.assertIsNone(scope.outcome.read())
        self.assertIsNone(ledger._command)
        self.assertIsNone(ledger._profile)
        state = json.loads((self.session_path/'state.json').read_bytes())
        self.assertEqual(state['inflight']['phase'], 'PREPARED')
        self.assertEqual(state['token'], self.token)
        self.assertEqual((self.session_path/'intent.json').read_bytes(), intent)
        self.assertEqual(state['native'], {})
        self.assertIsNone(self.model.keychain)
        self.assertEqual(state['profile']['phase'], 'not-started')
        self.assertEqual(list((self.session_path/'keychain').iterdir()), [])
        self.assertTrue(session.unresolved)
        self.assertEqual(len(self.model.calls), calls)
        self.assertFalse(any((self.session_path/name).exists() for name in signing.FENCE_CONTROLS))
        # This is a white-box no-owner/no-native-resource case, not generic
        # permission to recover an unhealthy process or a new-interpreter test.
        # The old failed guard remains failed; a distinct public call owns only
        # its newly admitted lease, handlers and real command targets.
        recovered = []
        real_recover = signing.SigningSession.recover
        def recover(fresh_session, *args, **kwargs):
            recovered.append((fresh_session.lease, fresh_session.cancellation))
            self.assertIsNot(fresh_session.lease, lease)
            self.assertIsNot(fresh_session.cancellation, guard)
            self.assertTrue(ledger.fatal)
            self.assertTrue(session.unresolved)
            return real_recover(fresh_session, *args, **kwargs)
        with patch.object(signing.SigningSession, 'recover', new=recover):
            self.assertEqual(self.recover()['status'], 'recovered')
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0][1].handler_state, 'RESTORED')
        self.assertIs(guard.lifetime_ledger, ledger)
        self.assertTrue(ledger.fatal)
        self.assertTrue(session.unresolved)
        self.assertEqual(signing.signing_status(home=self.home)['status'], 'idle')
        with signing.local_signing_lease(home=self.home):
            pass  # Genuine renewed normal admission, not a reset of the old guard.

    def test_failed_real_recovery_query_revokes_manual_recheck_without_journalling_a_new_operation(self):
        self.create()
        controls = {name: (self.session_path/name).read_bytes() for name in ('intent.json', 'state.json')}
        self.model.result_policy = lambda _argv: model_result(returncode=9, perform_effect=False)
        entered = []
        original = signing.SigningSession.recover
        testcase = self
        def recovering(session, *args, **kwargs):
            entered.append(session)
            return original(session, *args, **kwargs)
        class NoRecheck(TTY):
            def readline(self, _bound):
                testcase.fail('a failed recovery query was manually reauthorized')
        with patch.object(signing.SigningSession, 'recover', new=recovering), self.assertRaises(CredentialError):
            self.recover(manual=True, input_stream=NoRecheck(), output_stream=TTY())
        self.assertEqual(len(entered), 1)
        self.assertTrue(entered[0]._recovery_attempt.revoked)
        self.assertEqual({name: (self.session_path/name).read_bytes() for name in controls}, controls)
        self.assertFalse(any((self.session_path/name).exists() for name in signing.FENCE_CONTROLS))
        self.model.result_policy = None
        self.assertEqual(self.recover()['status'], 'recovered')

    def test_armed_recovery_requires_unchanged_original_c_fence_before_any_new_query(self):
        with self.assertRaises(CredentialError):
            with signing.local_signing_lease(home=self.home) as lease:
                session = lease.session(token=self.token)
                session.open(create=True)
                session.bind_runner(self.model)
                session.prepare(b'fictional-profile', self.uuid)
                def collision(_argv, _kwargs, _result):
                    stage = self.session_path/'state.pending'
                    stage.write_bytes(b'fictional interrupted O checkpoint')
                    stage.chmod(0o600)
                self.model.after = collision
                session.run(['security', 'list-keychains', '-d', 'user'], kind='observe')
        self.model.after = None
        state_path = self.session_path/'state.json'
        pending, final = (self.session_path/name for name in ('command-final.pending', 'command-final.json'))
        state_bytes, fence_bytes = state_path.read_bytes(), final.read_bytes()
        self.assertEqual(json.loads(state_bytes)['inflight']['phase'], 'ARMED')
        self.assertEqual(json.loads(fence_bytes)['outcome'], 'producer-settled')
        self.assertEqual(pending.stat().st_ino, final.stat().st_ino)
        self.assertEqual(final.stat().st_nlink, 2)
        before = len(self.model.calls)
        bad_nonce = {**json.loads(fence_bytes), 'nonce': '0'*32}
        for malformed in (fence_bytes+b'\n', signing._fence_json(bad_nonce)):
            final.write_bytes(malformed)  # Negative mutation of this original C-owned fixture, not a forged receipt.
            with self.assertRaises(CredentialError): self.recover()
            self.assertEqual(len(self.model.calls), before)
            self.assertEqual(state_path.read_bytes(), state_bytes)
            final.write_bytes(fence_bytes)
        final.unlink()
        with self.assertRaises(CredentialError): self.recover()
        self.assertEqual(len(self.model.calls), before)
        os.link(pending, final)  # Restore only the test's original actual C inode.
        contradicted = json.loads(state_bytes)
        contradicted['inflight']['phase'] = 'PREPARED'
        state_path.write_bytes(signing._json(contradicted))
        with self.assertRaises(CredentialError): self.recover()
        self.assertEqual(len(self.model.calls), before)
        state_path.write_bytes(state_bytes)
        self.assertEqual(self.recover()['status'], 'recovered')

    def test_settled_fence_retirement_resumes_only_its_original_final_inode(self):
        real_unlink = os.unlink
        proxy = SimpleNamespace(**vars(os))
        reached = []
        def unlink(name, *args, **kwargs):
            result = real_unlink(name, *args, **kwargs)
            if name == 'command-final.pending':
                reached.append(True)
                raise OSError('fictional return loss after original fence-stage unlink')
            return result
        proxy.unlink = unlink
        with self.assertRaises(CredentialError):
            with signing.local_signing_lease(home=self.home) as lease:
                session = lease.session(token=self.token)
                session.open(create=True)
                session.bind_runner(self.model)
                session.prepare(b'fictional-profile', self.uuid)
                with patch.object(signing, 'os', proxy):
                    session.run(['security', 'list-keychains', '-d', 'user'], kind='observe')
        self.assertEqual(reached, [True])
        operation = json.loads((self.session_path/'state.json').read_bytes())['inflight']
        self.assertEqual(operation['phase'], 'SETTLED')
        final = self.session_path/'command-final.json'
        self.assertEqual(final.stat().st_nlink, 1)
        self.assertEqual(signing._identity(final.stat()), operation['settlement']['fence']['identity'])
        self.assertFalse((self.session_path/'command-final.pending').exists())
        self.assertEqual(self.recover()['status'], 'recovered')

    def test_retry_stage_observation_failed_real_borrowed_checkpoint_closes_handles_and_recovers(self):
        real_open, real_close, real_fstat, real_write = os.open, os.close, os.fstat, os.write
        handles, active_handles, closed, stat_calls, failed_writes = [], {}, [], [], []
        stage_name = '.mobile-release-profile-' + self.token
        with signing.local_signing_lease(home=self.home) as lease:
            session = lease.session(token=self.token)
            session.open(create=True); session.bind_runner(self.model)
            session.prepare(b'fictional-profile', self.uuid)
            guard = lease.cancellation
            def opening(path, *args, **kwargs):
                descriptor = real_open(path, *args, **kwargs)
                active_handles[descriptor] = str(path)
                if str(path) in (stage_name, 'Provisioning Profiles'):
                    details = real_fstat(descriptor)
                    handles.append((descriptor, details.st_dev, details.st_ino, str(path)))
                return descriptor
            def stating(descriptor):
                if active_handles.get(descriptor) == stage_name:
                    stat_calls.append(descriptor)
                    if len(stat_calls) == 1: raise OSError('fictional first stage fstat failure')
                return real_fstat(descriptor)
            def writing(descriptor, content):
                if (active_handles.get(descriptor) == 'state.pending'
                        and session.state['profile']['phase'] == 'stage-created' and not failed_writes):
                    failed_writes.append(descriptor)
                    return 0  # Real protected writer rejects this incomplete write; no checkpoint stub.
                return real_write(descriptor, content)
            def closing(descriptor):
                name = active_handles.pop(descriptor, None)
                if name in (stage_name, 'Provisioning Profiles'): closed.append((descriptor, name))
                return real_close(descriptor)
            try:
                with patch.object(os, 'open', new=opening), patch.object(os, 'fstat', new=stating), \
                     patch.object(os, 'write', new=writing), patch.object(os, 'close', new=closing), \
                     self.assertRaises(CredentialError):
                    with _temporary_profile_installation(b'fictional-profile', self.uuid, self.home,
                            cancellation=guard, observer=session.profile_event, reserved_stage=stage_name):
                        self.fail('failed ownership checkpoint admitted installer body')
                self.assertEqual(len(stat_calls), 2)
                self.assertEqual(len(failed_writes), 1)
                self.assertTrue(session.journal_failed)
                self.assertIs(lease.cancellation, guard)
                self.assertEqual(len(handles), 2)
                self.assertCountEqual(closed, [(fd, name) for fd, _, _, name in handles])
                for descriptor, *_ in handles:
                    with self.assertRaises(OSError): real_fstat(descriptor)
                self.assertTrue((self.session_path/'intent.json').is_file())
                self.assertEqual((self.session_path/'state.pending').read_bytes(), b'')
                committed = json.loads((self.session_path/'state.json').read_bytes())
                self.assertEqual(committed['profile']['phase'], 'stage-intent')
                self.assertEqual(committed['profile']['stageIdentity'], None)
                directory = self.home/'Library/MobileDevice/Provisioning Profiles'
                self.assertEqual(list(directory.iterdir()), [])
                lease.assert_owner()
            finally:
                for descriptor, device, inode, _ in handles:
                    try:
                        details = real_fstat(descriptor)
                        if (details.st_dev, details.st_ino) == (device, inode): real_close(descriptor)
                    except OSError:
                        pass
        self.assertEqual(signing.signing_status(home=self.home)['status'], 'pending')
        with self.assertRaises(signing.SigningPending):
            with signing.local_signing_lease(home=self.home): self.fail('pending checkpoint was ignored')
        before = len(self.model.calls)
        self.assertEqual(self.recover()['status'], 'recovered')
        self.assertTrue(all(argv[1] in {'list-keychains', 'default-keychain'} and '-s' not in argv
                            for argv in self.model.calls[before:]))
        self.assertEqual(self.model.preferences, self.model.original)
        self.assertEqual(signing.signing_status(home=self.home)['status'], 'idle')

    def test_status_has_no_native_effect_and_unknown_links_remain_untouched(self):
        self.create()
        before = len(self.model.calls)
        status = signing.signing_status(home=self.home)
        self.assertEqual(status['phase'], 'active')
        self.assertEqual(len(self.model.calls), before)
        self.assertNotIn(str(self.home), json.dumps(status))
        control = self.session_path/'state.pending'
        target = self.root/'outside'; target.write_bytes(b'foreign')
        control.symlink_to(target)
        with self.assertRaises(CredentialError): self.recover()
        self.assertTrue(control.is_symlink()); self.assertEqual(target.read_bytes(), b'foreign')
        control.unlink()
        self.recover()

    def test_link_intent_retains_original_identity_through_installer_and_recovery_finalization(self):
        for retained in (False, True):
            with self.subTest(retained=retained):
                backup = self.root / 'fixture-original-link'
                destination = self.home / 'Library/MobileDevice/Provisioning Profiles' / (self.uuid + '.mobileprovision')
                with signing.local_signing_lease(home=self.home) as lease:
                    session = lease.session(token=self.token)
                    session.open(create=True)
                    session.bind_runner(self.model)
                    session.prepare(b'fictional-profile', self.uuid)
                    def observe(phase, **kwargs):
                        if phase == 'linked':
                            os.link(destination, backup)
                            raise CredentialError('injected after-link completion failure')
                        session.profile_event(phase, **kwargs)
                    with self.assertRaises(CredentialError):
                        with _temporary_profile_installation(
                            b'fictional-profile', self.uuid, self.home, cancellation=lease.cancellation,
                            observer=observe, reserved_stage=session.intent['profile']['stage'], retain=lambda: retained,
                        ): self.fail('after-link failure admitted')
                    expected = signing._identity(backup.stat())
                    # Exercise both ways to finish a link-intent: the installer's
                    # caught-exit observer and recovery's independent reconciler.
                    if not retained:
                        self.assertEqual(session.state['profile']['ownedIdentity'], expected)
                    else:
                        self.assertEqual(session.state['profile']['phase'], 'link-intent')
                        self.assertIsNone(session.state['profile']['ownedIdentity'])
                original_remove = signing.SigningSession._remove_control
                def interrupt_terminal(session, name):
                    if name == 'state.pending' and (session.path / 'completed.json').exists():
                        raise CredentialError('injected terminal teardown interruption')
                    return original_remove(session, name)
                with patch.object(signing.SigningSession, '_remove_control', new=interrupt_terminal), self.assertRaises(CredentialError):
                    self.recover()
                marker = json.loads((self.session_path / 'completed.json').read_text())
                self.assertEqual(marker['state']['profile']['ownedIdentity'], expected)
                self.assertFalse(destination.exists())
                os.link(backup, destination)
                # A terminal marker cannot forget the original inode and clear
                # while that exact resource has reappeared. Do not delete it.
                with self.assertRaisesRegex(CredentialError, 'reappeared'):
                    self.recover()
                self.assertEqual(signing._identity(destination.stat()), expected)
                destination.unlink()
                backup.unlink()
                self.recover()
                self.assertFalse(self.session_path.exists())

    def test_interrupted_recovery_and_refused_manual_recheck_preserve_authority(self):
        self.create()
        unknown = self.session_path / 'keychain/unrecognized-native-stage'
        unknown.write_bytes(b'fictional unknown')
        unknown.chmod(0o600)
        intent = (self.session_path / 'intent.json').read_bytes()
        for answer in ('', 'recheck ' + 'd' * 32 + '\n'):
            with self.subTest(answer=answer), self.assertRaises(CredentialError):
                self.recover(manual=True, input_stream=TTY(answer), output_stream=TTY())
            self.assertEqual((self.session_path / 'intent.json').read_bytes(), intent)
            self.assertEqual(unknown.read_bytes(), b'fictional unknown')
        class InterruptInput(TTY):
            def readline(self, maximum):
                os.kill(os.getpid(), signal.SIGINT)
                raise AssertionError('cancellation not delivered')
        with self.assertRaises(KeyboardInterrupt):
            self.recover(manual=True, input_stream=InterruptInput(), output_stream=TTY())
        self.assertEqual((self.session_path / 'intent.json').read_bytes(), intent)
        unknown.unlink()  # Only this test's independently identified resource.
        self.recover()
        self.assertEqual(signing.signing_status(home=self.home)['status'], 'idle')


class SigningCrashMatrixTests(unittest.TestCase):
    """Finite bare-home contrasts; full96 owns the duplicate all-IO replay."""

    def setUp(self):
        from workflow import local_signing_persistent_fixture as owner
        self.root = Path(tempfile.mkdtemp(prefix="mrk-bare-home-cuts-")).resolve()
        self.root_identity = owner._directory_identity(self.root)

    def tearDown(self):
        from workflow import local_signing_persistent_fixture as owner
        # Successful cases remove themselves after all assertions. A failure,
        # refusal or missing original receipt leaves its entire evidence intact.
        self.assertEqual(owner._directory_identity(self.root), self.root_identity,
                         "finite fixture root was replaced; preserve it")
        self.assertFalse(any(Path(key).is_relative_to(self.root)
                             for ledger in (owner._CASE_CUSTODY, owner._CASE_RECOVERY_DEBT) for key in ledger),
                         "original case/C recovery is unconfirmed; finite fixture retained")
        self.assertEqual(list(self.root.iterdir()), [], "unsuccessful finite fixture evidence retained")
        self.root.rmdir()

    def invoke(self, root, selected=None):
        from workflow import local_signing_crash_fixture as crash
        from workflow import local_signing_persistent_fixture as owner
        if selected is not None:
            # Register exact original root identity BEFORE launch. Positive A/W/G
            # alone cannot settle a possibly surviving original C/account tail.
            owner.require_fresh_recovery(root)
        from workflow.local_signing_workload import worker_timeout
        owner.run_worker(root, "protocol", lambda: crash.main(root, selected),
                         timeout=worker_timeout("bare-home-original"), expect=0 if selected is None else 73)
        if selected is None:
            return json.loads((root / "protocol.json").read_bytes())
        reached = [json.loads(line) for line in (root / "cuts.jsonl").read_text().splitlines()][-1]
        self.assertEqual({key: reached[key] for key in ("event", "edge")}, selected,
                         "actual reached semantic cut differs from selected successful inventory")
        if selected["edge"] == "before":
            self.assertIsNone(reached["succeeded"])
        else:
            self.assertIs(reached["succeeded"], True)
        if selected["edge"] == "partial":
            self.assertTrue(0 < reached["partialBytes"] < reached["requestedBytes"])

    def fresh_recovery(self, root):
        from workflow import local_signing_persistent_fixture as owner
        from workflow import local_signing_case_owner as case_owner
        from workflow.local_signing_crash_fixture import TOKEN
        key, identity = str(root), owner._directory_identity(root)
        self.assertEqual(owner._CASE_RECOVERY_DEBT.get(key), identity,
                         "pending C debt must name the unchanged original root")
        self.assertEqual(owner._CASE_CUSTODY.get(key), identity,
                         "UNKNOWN original case custody cannot start a recovery worker")
        home = root / "home"
        directory = home / "Library/MobileDevice/Provisioning Profiles"

        def recover():
            self.assertIs(type(case_owner.CASE_DEADLINE), float)
            while signing.signing_status(home=home)["status"] == "busy":
                case_owner.remaining(case_owner.CASE_DEADLINE)
                import time
                time.sleep(min(.002, case_owner.remaining(case_owner.CASE_DEADLINE)))
            case_owner.remaining(case_owner.CASE_DEADLINE)
            model = NativeSigningModel(home)
            status = signing.signing_status(home=home)
            self.assertEqual(status["status"], "pending")
            self.assertEqual(status["session"], TOKEN)
            # No owner callback or journal/file edit can turn refusal into a
            # pass. Only the fresh production automatic attempt settles this cut.
            result = signing.recover_signing(TOKEN, signing.CONFIRMATION, home=home, runner=model)
            self.assertEqual(result, {"status": "recovered", "session": TOKEN})
            self.assertEqual(signing.signing_status(home=home)["status"], "idle")
            self.assertEqual(model.preferences, model.original)
            self.assertFalse(directory.is_symlink())
            self.assertEqual(list(directory.iterdir()) if directory.exists() else [], [])
            with signing.local_signing_lease(home=home):
                pass  # Genuine renewed admission, never a recorded PID/status shortcut.
            return {"automatic": result["status"], "recoveryAndRenewedAdmission": True}

        from workflow.local_signing_workload import worker_timeout
        owner.run_worker(root, "fresh-recovery", recover, timeout=worker_timeout("bare-home-recovery"))
        result = json.loads((root / "fresh-recovery.json").read_bytes())
        self.assertEqual(set(result), {"automatic", "recoveryAndRenewedAdmission"})
        self.assertEqual(result["automatic"], "recovered")
        self.assertIs(result["recoveryAndRenewedAdmission"], True)
        self.assertEqual(owner._directory_identity(root), identity)
        self.assertEqual(owner._CASE_CUSTODY.get(key), identity)
        self.assertEqual(owner._CASE_RECOVERY_DEBT.get(key), identity)
        del owner._CASE_RECOVERY_DEBT[key]  # Genuine recovery + unchanged exact root only.

    def test_seven_bare_home_parent_and_empty_native_prefix_cuts_recover_automatically(self):
        from workflow import local_signing_crash_fixture as crash
        from workflow import local_signing_persistent_fixture as owner
        inventory_root = self.root / "inventory"
        inventory_root.mkdir(mode=0o700)
        observed = self.invoke(inventory_root)
        self.assertIs(observed["completed"], True)
        selected = crash.select_cuts(observed["events"])
        self.assertEqual(len(selected), 7)
        self.assertEqual(sum(item["event"]["operation"] == "mkdir" for item in selected), 6)
        self.assertEqual(sum(item["edge"] == "partial" for item in selected), 1)
        for number, cut in enumerate(selected):
            # This number names a private fixture only; it never selects an IO.
            root = self.root / f"case-{number}-{cut['edge']}"
            root.mkdir(mode=0o700)
            self.invoke(root, cut)
            self.fresh_recovery(root)
            owner.remove_case(root)
        owner.remove_case(inventory_root)

    def test_finite_selection_requires_successful_exact_origin_path_phase_and_first_write(self):
        from workflow import local_signing_crash_fixture as crash
        events = [{"operation": "mkdir", "origin": crash.DIRECTORY_ORIGIN, "slot": slot,
                   "phase": crash.DIRECTORY_PHASE, "occurrence": 0, "context": {}, "succeeded": True}
                  for slot in crash.DIRECTORY_SLOTS]
        events.append({"operation": "write", "origin": crash.STATE_ORIGIN, "slot": crash.STATE_SLOT,
                       "phase": crash.STATE_PHASE, "occurrence": 0, "succeeded": True,
                       "context": {"profilePhase": "resolved", "native": {}, "searchAttempted": False,
                                   "defaultAttempted": False, "cleanupStarted": True}})
        expected = crash.select_cuts(events)
        self.assertEqual(len(expected), 7)
        # Inventory order and unrelated later writes cannot become an absolute
        # index shortcut or silently select a replacement for the first write.
        later = copy.deepcopy(events[-1])
        later["occurrence"] = 1
        self.assertEqual(crash.select_cuts([later, *reversed(events)]), expected)
        changes = ((0, "origin", "other:mkdir"), (1, "slot", "home/other"),
                   (2, "phase", "other:phase"), (0, "succeeded", False),
                   (3, "occurrence", 1), (3, "succeeded", False),
                   (3, "context", {**events[3]["context"], "profilePhase": "linked"}),
                   (3, "context", {**events[3]["context"], "native": {"unexpected": {}}}),
                   (3, "context", {**events[3]["context"], "searchAttempted": True}),
                   (3, "context", {**events[3]["context"], "defaultAttempted": True}))
        for index, field, value in changes:
            changed = copy.deepcopy(events)
            changed[index][field] = value
            with self.subTest(index=index, field=field), self.assertRaises(AssertionError):
                crash.select_cuts(changed)
        with self.assertRaises(AssertionError):
            crash.select_cuts([*events, copy.deepcopy(events[0])])
        with self.assertRaises(AssertionError):
            crash.select_cuts([*events, copy.deepcopy(events[3])])


if __name__ == '__main__': unittest.main()
