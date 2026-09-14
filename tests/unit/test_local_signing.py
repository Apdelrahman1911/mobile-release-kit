"""Account admission, complete-state cleanup, and real private recovery layouts."""
from __future__ import annotations

import copy
import io
import json
import os
import signal
import stat
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from mobile_release import local_signing as signing
from mobile_release.credentials import _temporary_apple_signing_environment
from mobile_release.errors import CredentialError
from mobile_release.owned_process import ProcessError, run_owned
from mobile_release.preflight import preflight
from mobile_release.config import load_config

from .helpers import ios_config, write_project
from .ios_entitlement_helpers import profile
from .local_signing_helpers import NativeSigningModel, fictional_signing_profile, model_result
from .local_signing_algorithm_helpers import profile_algorithm_session
from .local_signing_workspace import NativeCaseWorkspaceMixin
from workflow.local_signing_regression_catalog import NATIVE_FAILURE_COMMANDS, SPECIAL_PROFILE_NATIVE_VARIANTS


SPECIAL_PROFILE_DIRECT_VARIANTS = (
    ("owned-symlink", False, "symlink"),
    ("owned-fifo", False, "fifo"),
    ("owned-directory", False, "directory"),
    ("borrowed-symlink", True, "symlink"),
    ("borrowed-fifo", True, "fifo"),
    ("borrowed-directory", True, "directory"),
)


class LocalSigningTests(NativeCaseWorkspaceMixin, unittest.TestCase):
    def setUp(self):
        self.root = self.native_case_directory(prefix="mrk-signing-account-")
        self.home = self.root / "home"; self.home.mkdir(mode=0o700)
        self.project = self.root / "project"; self.project.mkdir()
        self.private = self.root / "private"; self.private.mkdir(mode=0o700)
        self.p12, self.input = self.private / "identity.p12", self.private / "input.mobileprovision"
        self.p12.write_bytes(b"fictional-p12"); self.input.write_bytes(b"fictional-authenticated-profile")
        self.model = NativeSigningModel(self.home)
        self.uuid = profile()["UUID"]
        self.destination = self.home / "Library/MobileDevice/Provisioning Profiles" / (self.uuid + ".mobileprovision")
        self.leasedir = self.home / signing.LEASE_DIRECTORY
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        # This suite exercises account/resource ownership, not authentication.
        self.stack.enter_context(patch("mobile_release.credentials._authenticated_signing_profile",
                                       side_effect=fictional_signing_profile))
        self.stack.enter_context(patch("mobile_release.credentials._run_private", side_effect=self.model))

    def context(self, **kwargs):
        return _temporary_apple_signing_environment(p12=self.p12, password="fictional-password", profile=self.input,
                                                    directory=self.private, home=self.home, **kwargs)

    def assert_clean(self):
        self.assertEqual(self.model.preferences, self.model.original)
        self.assertEqual(signing.signing_status(home=self.home), {"status": "idle", "sessions": 0})
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.leasedir.iterdir()), [])

    def pending_token(self):
        result = signing.signing_status(home=self.home)
        self.assertEqual(result["status"], "pending")
        return result["session"]

    def recover(self, **kwargs):
        return signing.recover_signing(self.pending_token(), signing.CONFIRMATION,
                                       home=self.home, runner=self.model, **kwargs)

    def test_normal_context_round_trips_entire_native_state_and_account_inode(self):
        with self.context():
            inode = self.leasedir.stat().st_ino
            self.assertEqual(self.destination.read_bytes(), self.input.read_bytes())
            self.assertEqual(self.model.preferences, {"default": str(self.model.keychain), "search": [str(self.model.keychain)]})
            self.assertGreater(self.model.revisions, 2)
            self.assertEqual(signing.signing_status(home=self.home)["status"], "busy")
        self.assertEqual(self.leasedir.stat().st_ino, inode)
        self.assert_clean()

    def test_overlapping_context_refuses_before_profile_authentication_or_native_work(self):
        with self.context():
            calls = len(self.model.calls)
            with patch("mobile_release.credentials._authenticated_signing_profile", side_effect=AssertionError("busy must precede authentication")):
                with self.assertRaises(signing.SigningBusy):
                    with self.context(): self.fail("overlap admitted")
            self.assertEqual(len(self.model.calls), calls)
            self.assertTrue(self.destination.is_file())
        self.assert_clean()
        with self.context(): pass
        self.assert_clean()

    def test_full_preflight_busy_before_doctor_credentials_application_checks(self):
        config = load_config(write_project(self.project, ios_config(), platform="ios"))
        with signing.local_signing_lease(home=self.home):
            with patch("mobile_release.preflight.local_signing_lease", side_effect=lambda: signing.local_signing_lease(home=self.home)), \
                 patch("mobile_release.preflight.doctor", side_effect=AssertionError("not admitted")):
                report = preflight(config, mode="signing", platforms=("ios",), run_builds=True)
        self.assertFalse(report.ok)
        self.assertEqual([item.code for item in report.findings], ["ios.local-signing-lease"])
        self.assertEqual(self.model.calls, [])

    def test_same_lease_cannot_nest_a_second_signing_owner(self):
        with signing.local_signing_lease(home=self.home) as lease:
            with self.context(lease=lease):
                with self.assertRaisesRegex(CredentialError, "already has"):
                    with self.context(lease=lease): self.fail("nested signing admitted")
            lease.assert_owner()
        self.assert_clean()

    def test_pre_native_invalid_request_settles_original_no_dispatch_without_fabricated_result(self):
        # Setup and later verification execute real fixture targets. Only the
        # rejected request bypasses their argv adapter so the production byte
        # admission sees the genuinely invalid input before any C is created.
        with signing.local_signing_lease(home=self.home) as lease:
            retained_source = lease.execution_source()
            with self.context(lease=lease):
                session = lease.active
                for argument in ("invalid\x00argument", "unencodable-\ud800"):
                    with self.subTest(argument=repr(argument)):
                        before = len(self.model.calls)
                        with patch.object(session, "runner", run_owned), self.assertRaises(ProcessError) as caught:
                            session.run([sys.executable, argument], kind="observe")
                        self.assertFalse(caught.exception.fatal)
                        self.assertFalse(caught.exception.dispatched)
                        outcome = session._command_scope.outcome.read()
                        self.assertEqual(outcome.no_target.kind, "NO_W_CREATION")
                        self.assertEqual(outcome.result_integrity, "complete")
                        self.assertIsNone(outcome.returncode)
                        self.assertFalse(outcome.create_w.attempted or outcome.run_tool.attempted)
                        self.assertIsNone(session.state["inflight"])
                        self.assertFalse(session.unresolved or session.cancellation.lifetime_ledger.fatal)
                        self.assertFalse(lease._normal_execution_revoked)
                        retained_source.new_scope()
                        self.assertFalse(signing._names(session.fd) & signing.FENCE_CONTROLS)
                        self.assertEqual(len(self.model.calls), before)
                        self.assertEqual(session.observe(), self.model.preferences)
            self.assertTrue(session._disposal_complete)
            self.assertIsNone(lease.active)
            retained_source.new_scope()
        self.assert_clean()

    def test_external_preference_edits_preserved_and_conflict_clears_for_fresh_admission(self):
        foreign = str(self.home / "fictional-external.keychain-db")
        with self.assertRaises(CredentialError):
            with self.context():
                self.model.preferences = {"default": foreign, "search": [foreign, str(self.model.keychain), self.model.original['search'][1]]}
        self.assertEqual(self.model.preferences, {"default": foreign, "search": [foreign, self.model.original['search'][1]]})
        self.assertFalse(self.destination.exists())
        self.assertEqual(signing.signing_status(home=self.home)["status"], "idle")
        with self.context(): pass
        self.assertEqual(self.model.preferences["default"], foreign)

    def test_empty_search_list_round_trip_preserves_literal_paths(self):
        self.model.original["search"] = []
        self.model.preferences = copy.deepcopy(self.model.original)
        with self.context(): pass
        self.assert_clean()
        self.assertIn(["/usr/bin/security", "list-keychains", "-d", "user", "-s"], self.model.calls)

    def test_rc_zero_partial_native_display_error_never_mutates(self):
        def error(argv):
            if argv[1] == "list-keychains" and "-s" not in argv:
                return model_result(stderr="fictional per-entry display failure")
        self.model.result_policy = error
        with self.assertRaises(CredentialError):
            with self.context(): self.fail("partial native result admitted")
        self.assertFalse(any(call[1] in {"create-keychain", "delete-keychain"} or "-s" in call for call in self.model.calls))
        # No global resource was created; removal needs a complete native read.
        self.model.result_policy = None
        self.recover()
        self.assert_clean()

    def test_native_nonzero_after_effect_reconciles_without_repeating_setup(self):
        def result_policy(argv):
            if argv[1] == "create-keychain":
                return model_result(returncode=1)
        self.model.result_policy = result_policy
        with signing.local_signing_lease(home=self.home) as lease:
            retained_source = lease.execution_source()
            with self.assertRaises(CredentialError):
                with self.context(lease=lease): self.fail("native nonzero admitted")
            self.assertIsNone(lease.active)
            self.assertFalse(lease._normal_execution_revoked)
            retained_source.new_scope()
        self.assertEqual(sum(call[1] == "create-keychain" for call in self.model.calls), 1)
        self.assert_clean()

    def test_real_checkpoint_collision_after_effect_retained_and_explicit_original_recovery(self):
        def after(argv, kwargs, result):
            if argv[1] == "default-keychain" and "-s" in argv and argv[-1] == str(self.model.keychain):
                stage = self.model.keychain.parent.parent / "state.pending"
                stage.write_bytes(b"fictional interrupted checkpoint")
                stage.chmod(0o600)
        self.model.after = after
        with self.assertRaises(CredentialError):
            with self.context(): self.fail("ambiguous native completion admitted")
        self.assertTrue(self.destination.exists())
        self.assertTrue(self.model.keychain.exists())
        token = self.pending_token()
        with self.assertRaises(signing.SigningPending):
            with self.context(): self.fail("pending admission")
        self.model.after = None
        result = self.recover()
        self.assertIn(result["status"], {"recovered", "recovered-with-conflict"})
        self.assertEqual(signing.recover_signing(token, signing.CONFIRMATION, home=self.home, runner=self.model)["status"], "absent")
        self.assert_clean()

    def test_reused_profile_conflicts_require_explicit_original_recovery(self):
        for replacement in (b"same", b"different", None):
            self.destination.parent.mkdir(parents=True, exist_ok=True)
            self.destination.write_bytes(self.input.read_bytes()); self.destination.chmod(0o640)
            with self.subTest(replacement=replacement), self.assertRaises(CredentialError):
                with self.context():
                    self.destination.unlink()
                    if replacement is not None:
                        source = self.private / "replacement"
                        source.write_bytes(self.input.read_bytes() if replacement == b"same" else replacement)
                        source.chmod(0o644); source.replace(self.destination)
            self.assertEqual(signing.signing_status(home=self.home)["status"], "pending")
            self.assertEqual(self.recover()["status"], "recovered-with-conflict")
            self.assertEqual(signing.signing_status(home=self.home)["status"], "idle")
            if replacement is not None:
                self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o644)
                self.assertEqual(self.destination.read_bytes(), self.input.read_bytes() if replacement == b"same" else replacement)
                self.destination.unlink()
        self.assert_clean()

    def test_owned_destination_replacement_preserved_but_same_inode_edit_requires_recovery(self):
        with self.assertRaises(CredentialError):
            with self.context():
                foreign = self.private / "foreign"
                foreign.write_bytes(b"fictional-foreign"); foreign.chmod(0o640)
                foreign.replace(self.destination)
        self.assertEqual(signing.signing_status(home=self.home)["status"], "pending")
        self.assertEqual(self.destination.read_bytes(), b"fictional-foreign")
        self.assertEqual(self.recover()["status"], "recovered-with-conflict")
        self.assertEqual(signing.signing_status(home=self.home)["status"], "idle")
        self.destination.unlink()
        with self.assertRaises(CredentialError):
            with self.context(): self.destination.write_bytes(b"fictional-in-place-change")
        with self.assertRaises(CredentialError): self.recover()
        self.destination.unlink()  # Exact fixture-owned manual resolution, not toolkit adoption.
        self.recover()
        self.assert_clean()

    def test_native_replacement_outside_operation_is_never_adopted_or_deleted(self):
        with self.assertRaises(CredentialError):
            with self.context():
                foreign = self.private / "foreign-db"
                foreign.write_bytes(b"fictional-foreign-db"); foreign.chmod(0o600)
                foreign.replace(self.model.keychain)
        with self.assertRaises(CredentialError): self.recover()
        self.assertEqual(self.model.keychain.read_bytes(), b"fictional-foreign-db")
        self.model.keychain.unlink()
        (self.model.keychain.parent / signing.LOCK_NAME).unlink()
        self.model.preferences = copy.deepcopy(self.model.original)
        self.recover()
        self.assert_clean()

    def test_every_completed_native_failure_after_effect_is_cleaned_without_repeating_setup(self):
        for command in NATIVE_FAILURE_COMMANDS:
            with self.subTest(command=command):
                self.run_native_failure_variant(command)

    def run_native_failure_variant(self, command):
        self.assertIn(command, NATIVE_FAILURE_COMMANDS)
        fired = []
        before = len(self.model.calls)
        def fail_after(argv):
            if argv[1] == command and (command not in {'list-keychains', 'default-keychain'} or '-s' in argv) and not fired:
                fired.append(True)
                return model_result(returncode=9)
        self.model.result_policy = fail_after
        with self.assertRaises(CredentialError):
            with self.context():
                self.assertEqual(command, 'delete-keychain')
        self.assertTrue(fired)
        self.assertLessEqual(sum(argv[1] == 'create-keychain' for argv in self.model.calls[before:]), 1)
        self.model.result_policy = None
        self.assert_clean()

    def test_failed_create_without_effect_does_not_invent_native_ownership(self):
        def policy(argv):
            if argv[1] == 'create-keychain':
                return model_result(returncode=1, perform_effect=False)
        self.model.result_policy = policy
        with self.assertRaises(CredentialError):
            with self.context(): self.fail('failed create admitted')
        self.assertFalse(any(argv[1] == 'delete-keychain' for argv in self.model.calls))
        self.assert_clean()

    def test_recovery_preserves_special_foreign_replacements_of_borrowed_and_owned_profiles(self):
        for variant in SPECIAL_PROFILE_NATIVE_VARIANTS:
            with self.subTest(variant=variant[0]):
                self.run_native_special_profile_variant(variant)
        self.assert_clean()

    def run_native_special_profile_variant(self, variant):
        self.assertIn(variant, SPECIAL_PROFILE_NATIVE_VARIANTS)
        _name, borrowed, replacement = variant
        if borrowed:
            self.destination.parent.mkdir(parents=True, exist_ok=True)
            self.destination.write_bytes(self.input.read_bytes())
        def ambiguous(argv, kwargs, result):
            if argv[1] == 'default-keychain' and '-s' in argv and argv[-1] == str(self.model.keychain):
                stage = self.model.keychain.parent.parent / 'state.pending'
                stage.write_bytes(b'fictional interrupted checkpoint')
                stage.chmod(0o600)
        self.model.after = ambiguous
        with self.assertRaises(CredentialError):
            with self.context(): self.fail('ambiguous activation admitted')
        self.model.after = None
        # Retain the original inode until the foreign replacement is allocated.
        old = self.private / 'retained-original-profile'
        self.destination.replace(old)
        if replacement == 'symlink': self.destination.symlink_to(self.input)
        elif replacement == 'fifo': os.mkfifo(self.destination, 0o600)
        else: self.destination.mkdir(mode=0o700)
        before = self.destination.lstat()
        result = self.recover()
        self.assertEqual(result['status'], 'recovered-with-conflict')
        self.assertEqual(self.destination.lstat(), before)
        self.assertEqual(self.input.read_bytes(), b'fictional-authenticated-profile')
        self.assertEqual(signing.signing_status(home=self.home)['status'], 'idle')
        with signing.local_signing_lease(home=self.home) as renewed:
            renewed.assert_owner()
        if replacement == 'directory': self.destination.rmdir()
        else: self.destination.unlink()
        old.unlink()
        self.assert_clean()

    def test_direct_profile_cleanup_preserves_every_special_foreign_type_without_opening_it(self):
        self.assertEqual(len(SPECIAL_PROFILE_DIRECT_VARIANTS), 6)
        for variant in SPECIAL_PROFILE_DIRECT_VARIANTS:
            with self.subTest(variant=variant[0]):
                self.run_direct_special_profile_variant(variant)

    def run_direct_special_profile_variant(self, variant):
        from types import SimpleNamespace

        self.assertIn(variant, SPECIAL_PROFILE_DIRECT_VARIANTS)
        name, borrowed, replacement = variant
        root = self.root / ("algorithm-" + name)
        root.mkdir(mode=0o700)
        home = root / "home"
        home.mkdir(mode=0o700)
        source = root / "untouched-source.profile"
        content = b"fictional direct profile algorithm bytes"
        source.write_bytes(content)
        source.chmod(0o600)
        destination = home / "Library/MobileDevice/Provisioning Profiles" / (self.uuid + ".mobileprovision")
        if borrowed:
            destination.parent.mkdir(mode=0o700, parents=True)
            destination.write_bytes(content)
            destination.chmod(0o600)
        with profile_algorithm_session(home, content, self.uuid) as algorithm:
            session = algorithm.session
            self.assertEqual(session.state["profile"]["reused"], borrowed)
            self.assertEqual(session.state["profile"]["ownedIdentity"] is None, borrowed)
            original = root / "retained-original.profile"
            destination.rename(original)
            if replacement == "symlink":
                destination.symlink_to(source)
            elif replacement == "fifo":
                os.mkfifo(destination, 0o600)
            else:
                destination.mkdir(mode=0o700)
            before = destination.lstat()
            source_before = source.stat()
            self.assertNotEqual((before.st_dev, before.st_ino),
                                (original.stat().st_dev, original.stat().st_ino))
            attempts = []
            proxy = SimpleNamespace(**vars(os))

            def opening(path, *args, **kwargs):
                if str(path) in {destination.name, str(destination)}:
                    attempts.append(str(path))
                    raise AssertionError("known foreign profile must not be opened")
                return os.open(path, *args, **kwargs)

            proxy.open = opening
            with patch.object(signing, "os", proxy):
                session.cleanup_profile()
            self.assertEqual(attempts, [])
            self.assertEqual(destination.lstat(), before)
            self.assertEqual(source.stat(), source_before)
            self.assertEqual(source.read_bytes(), content)
            self.assertEqual(original.read_bytes(), content)
            self.assertTrue(session.state["conflict"])
            self.assertEqual(session.state["profile"]["phase"], "resolved")
            stored = json.loads((session.path / "state.json").read_bytes())
            self.assertEqual(stored, session.state)
            self.assertIn("fixtureAlgorithmData", stored)
            self.assertNotIn("version", stored)
            self.assertFalse(algorithm.attempts)
        self.assertEqual(self.model.calls, [], "direct algorithm used the native model")


class NativePathTests(unittest.TestCase):
    def test_literal_paths_and_empty_lists(self):
        paths = ['/fictional/login keychain', '/fictional/with\\slash أرشيف']
        self.assertEqual(signing.parse_keychain_paths(''.join('    "'+path+'"\n' for path in paths)), paths)
        self.assertEqual(signing.parse_keychain_paths(''), [])

    def test_ambiguous_bounded_paths_rejected(self):
        for text in ('/unquoted\n', '"relative"\n', '"/a" "b"\n', '"/a"\v', '"/a"\r\n', '"/a"\n"/a"\n', '"/a\x85b"\n', '\n'):
            with self.subTest(text=text), self.assertRaises(CredentialError): signing.parse_keychain_paths(text)
        with self.assertRaises(CredentialError): signing.parse_keychain_paths('', default=True)


if __name__ == '__main__': unittest.main()
