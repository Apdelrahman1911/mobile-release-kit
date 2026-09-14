"""Actual fresh recovery revocation; requires the disposable native test owner.

These are not shared-host-safe unit selectors. Only fictional native effects are
modeled; command outcomes, account custody, controls and recovery are genuine.
"""
from __future__ import annotations

import errno
import io
import os
import stat
import sys
import unittest
from contextlib import contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release import local_signing as signing
from mobile_release.errors import CredentialError
from .local_signing_helpers import NativeSigningModel, completed_case_directory, model_result


TOKEN = "e" * 32
UUID = "12345678-1234-1234-1234-1234567890AB"
CONTENT = b"fictional-authenticated-recovery-attempt-profile"


class NoRecheck(io.StringIO):
    def __init__(self):
        super().__init__()
        self.reads = 0

    def isatty(self):
        return True

    def readline(self, _bound):
        self.reads += 1
        raise AssertionError("a revoked original attempt reached manual recheck")


class RecoveryAttemptTests(unittest.TestCase):
    @contextmanager
    def case(self):
        # completed_case_directory retains a failing case, including original
        # native evidence. No unconditional TemporaryDirectory cleanup on error.
        with completed_case_directory(prefix="mrk-recovery-attempt-") as root:
            home = root / "home"
            home.mkdir(mode=0o700)
            yield SimpleNamespace(root=root, home=home, model=NativeSigningModel(home),
                                  path=home / signing.LEASE_DIRECTORY / ("session-" + TOKEN))

    def controls(self, case):
        result = {}
        for name in sorted(signing.CONTROLS | signing.FENCE_CONTROLS):
            path = case.path / name
            try:
                info = path.lstat()
            except FileNotFoundError:
                result[name] = None
                continue
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertLessEqual(info.st_size, signing.CONTROL_LIMIT)
            result[name] = (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, path.read_bytes())
        return result

    def prepare(self, case):
        with signing.local_signing_lease(home=case.home) as lease:
            session = lease.session(token=TOKEN)
            session.open(create=True)
            session.bind_runner(case.model)
            session.prepare(CONTENT, UUID)

    @contextmanager
    def fail_state_write(self, case, *, recovery):
        actual = signing.SigningSession._write
        hits = []
        failure = OSError(errno.EIO, "fictional original state write failure")

        def writing(descriptor, data):
            frame = sys._getframe(1)
            if frame.f_code is actual.__code__ and frame.f_locals["name"] == "state.json":
                session = frame.f_locals["self"]
                if (session.path == case.path and not hits
                        and (session._recovery_attempt is not None) is recovery):
                    self.assertEqual(descriptor, frame.f_locals["descriptor"])
                    self.assertEqual(frame.f_locals["stage"], "state.pending")
                    opened = os.fstat(descriptor)
                    named = os.stat("state.pending", dir_fd=session.fd, follow_symlinks=False)
                    self.assertEqual((opened.st_dev, opened.st_ino), (named.st_dev, named.st_ino))
                    self.assertEqual(opened.st_size, 0)
                    hits.append(session)
                    raise failure
            return os.write(descriptor, data)

        # Keep the operation seam local to this production module; do not alter
        # the bridge/command owner's os module or any original result.
        local_os = SimpleNamespace(**vars(os))
        local_os.write = writing
        with patch.object(signing, "os", local_os):
            yield hits, failure

    def seed_initializing(self, case):
        with self.fail_state_write(case, recovery=False) as (hits, _), self.assertRaises(CredentialError):
            self.prepare(case)
        self.assertEqual(len(hits), 1)
        self.assertTrue(hits[0].journal_failed)
        self.assertEqual(len(case.model.calls), 2)
        self.assertTrue((case.path / "intent.json").is_file())
        self.assertFalse((case.path / "state.json").exists())
        self.assertEqual((case.path / "state.pending").read_bytes(), b"")
        self.assertEqual(signing.signing_status(home=case.home)["phase"], "initializing")

    @contextmanager
    def fail_after_committed_deferral(self, case, session, hits, failure):
        actual = session.cancellation.deferred
        writer = signing.SigningSession._write

        def deferred(*, check_on_exit=True):
            frame = sys._getframe(1)
            selected = (frame.f_code is writer.__code__ and frame.f_locals["self"] is session
                        and frame.f_locals["name"] == "state.json")

            @contextmanager
            def invocation():
                with actual(check_on_exit=check_on_exit):
                    yield
                if selected and not hits:
                    self.assertIsNotNone(session._recovery_attempt)
                    self.assertFalse(session._recovery_attempt.revoked)
                    self.assertFalse(session.journal_failed)
                    self.assertEqual((case.path / "state.json").read_bytes(),
                                     session._committed_controls["state.json"])
                    self.assertFalse((case.path / "state.pending").exists())
                    hits.append(session)
                    # The real write/close/replace/fsync and publication finished.
                    # This exception is still inside the original _write try.
                    raise failure
            return invocation()

        with patch.object(session.cancellation, "deferred", new=deferred):
            yield

    def assert_no_revival(self, case, session, authorization, original_recover, *, journal_failed):
        self.assertIs(session._recovery_attempt, authorization)
        self.assertTrue(authorization.revoked)
        self.assertEqual(session.journal_failed, journal_failed)
        self.assertFalse(session.closed)
        before, calls = self.controls(case), list(case.model.calls)
        snapshot = session.load_snapshot()  # Read-only load cannot renew authority.
        self.assertTrue(authorization.revoked)
        for label, action in (
            ("checkpoint", session.checkpoint),
            ("query", lambda: session.observe(journal=False)),
            ("command-gate", session._recover_command_gate),
            ("reloaded-recover", lambda: original_recover(session, snapshot, authorization=authorization)),
        ):
            # A failed assertion must escape the case context so its evidence is
            # retained. unittest.subTest would suppress it and enable deletion.
            with self.assertRaises(CredentialError, msg=label):
                action()
            self.assertIs(session._recovery_attempt, authorization)
            self.assertTrue(authorization.revoked)
            self.assertEqual(self.controls(case), before)
            self.assertEqual(case.model.calls, calls)

    def failed_recovery(self, case, *, phase, journal_failed, injection=None, expected_error=None,
                        absent_native=False):
        original = signing.SigningSession.recover
        observed = []
        no_recheck, output = NoRecheck(), NoRecheck()

        def recovering(session, snapshot, *, authorization):
            self.assertEqual(session.path, case.path)
            self.assertEqual(snapshot.phase, phase)
            self.assertEqual(session.native_fd is None, absent_native)
            self.assertFalse(authorization.revoked)
            with nullcontext() if injection is None else injection(session):
                try:
                    return original(session, snapshot, authorization=authorization)
                except BaseException as error:
                    if expected_error is not None:
                        self.assertIs(error, expected_error)
                    observed.append((session, authorization, error))
                    self.assert_no_revival(case, session, authorization, original,
                                           journal_failed=journal_failed)
                    raise  # Preserve the exact original failure in this wrapper.

        with patch.object(signing.SigningSession, "recover", new=recovering), self.assertRaises(CredentialError):
            signing.recover_signing(TOKEN, signing.CONFIRMATION, manual=True, home=case.home,
                                    runner=case.model, input_stream=no_recheck, output_stream=output)
        # Public manual handling may project a revoked-authorization error. That
        # does not erase the original error observed above or permit a prompt.
        self.assertEqual(len(observed), 1)
        self.assertEqual(no_recheck.reads, 0)
        self.assertEqual(output.getvalue(), "")
        self.assertTrue(observed[0][0].closed)
        self.assertTrue(observed[0][1].revoked)
        self.assertEqual(case.model.preferences, case.model.original)
        self.assertFalse(any((case.path / name).exists() for name in signing.FENCE_CONTROLS))

    def fresh_success(self, case):
        result = signing.recover_signing(TOKEN, signing.CONFIRMATION, home=case.home, runner=case.model)
        self.assertEqual(result, {"status": "recovered", "session": TOKEN})
        self.assertEqual(case.model.preferences, case.model.original)
        self.assertFalse(case.path.exists())
        self.assertFalse((case.home / "Library/MobileDevice/Provisioning Profiles" /
                          (UUID + ".mobileprovision")).exists())
        self.assertEqual(signing.signing_status(home=case.home), {"status": "idle", "sessions": 0})
        with signing.local_signing_lease(home=case.home) as lease:
            lease.assert_owner()

    def test_precommit_recovery_write_revokes_original_attempt_without_reload_revival(self):
        with self.case() as case:
            self.seed_initializing(case)
            intent = (case.path / "intent.json").read_bytes()
            with self.fail_state_write(case, recovery=True) as (hits, failure):
                self.failed_recovery(case, phase="initializing", journal_failed=True, expected_error=failure)
            self.assertEqual(len(hits), 1)
            self.assertFalse((case.path / "state.json").exists())
            self.assertEqual((case.path / "state.pending").read_bytes(), b"")
            self.assertEqual((case.path / "intent.json").read_bytes(), intent)
            self.fresh_success(case)

    def test_committed_recovery_write_late_failure_revokes_even_without_journal_failure(self):
        with self.case() as case:
            self.seed_initializing(case)
            intent = (case.path / "intent.json").read_bytes()
            hits, failure = [], CredentialError("fictional late committed-write failure")
            self.failed_recovery(
                case, phase="initializing", journal_failed=False, expected_error=failure,
                injection=lambda session: self.fail_after_committed_deferral(case, session, hits, failure),
            )
            self.assertEqual(len(hits), 1)
            self.assertEqual((case.path / "intent.json").read_bytes(), intent)
            self.assertEqual((case.path / "state.json").read_bytes(), hits[0]._committed_controls["state.json"])
            self.assertFalse((case.path / "state.pending").exists())
            self.fresh_success(case)

    def fail_query(self, case, *, position, phase, absent_native=False):
        before, calls = self.controls(case), len(case.model.calls)
        case.model.result_policy = lambda _argv: (
            model_result(returncode=9, perform_effect=False)
            if len(case.model.calls) - calls == position else None
        )
        self.failed_recovery(case, phase=phase, journal_failed=False, absent_native=absent_native)
        self.assertEqual(len(case.model.calls) - calls, position)
        self.assertEqual(case.model.calls[-1], ["/usr/bin/security", "list-keychains" if position == 2 else
                                              "default-keychain", "-d", "user"])
        self.assertEqual(self.controls(case), before)
        case.model.result_policy = None

    def test_second_initial_query_failure_revokes_manual_recovery_without_new_journal(self):
        with self.case() as case:
            self.prepare(case)
            self.fail_query(case, position=2, phase="active")
            self.fresh_success(case)

    def test_completed_hold_only_query_failure_preserves_original_terminal_authority(self):
        with self.case() as case:
            self.prepare(case)
            original, cuts = signing.SigningSession._remove_control, []

            def before_intent_removal(session, name):
                if name == "intent.json" and session.path == case.path and not cuts:
                    self.assertIsNone(session.native_fd)
                    self.assertFalse((case.path / "keychain").exists())
                    self.assertIsNotNone(session.completed)
                    self.assertTrue((case.path / "completed.json").is_file())
                    cuts.append(session)
                    raise CredentialError("fictional terminal intent-removal entry cut")
                return original(session, name)

            with patch.object(signing.SigningSession, "_remove_control", new=before_intent_removal), \
                    self.assertRaises(CredentialError):
                signing.recover_signing(TOKEN, signing.CONFIRMATION, home=case.home, runner=case.model)
            self.assertEqual(len(cuts), 1)
            self.assertEqual(signing.signing_status(home=case.home)["phase"], "completed")
            self.assertFalse((case.path / "keychain").exists())
            self.fail_query(case, position=1, phase="completed", absent_native=True)
            self.assertFalse((case.path / "state.json").exists())
            self.fresh_success(case)
