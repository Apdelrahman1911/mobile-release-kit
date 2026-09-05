"""Authenticated exact-byte installation with real filesystem failure injection."""
from __future__ import annotations

import base64
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release.config import load_config
import mobile_release
from mobile_release.credentials import (
    _temporary_apple_signing_environment, _temporary_profile_installation, _validate_apple_signing_material,
)
from mobile_release.errors import CredentialError, ValidationError
from mobile_release.reporting import Status

from .helpers import ios_config, write_project
from .ios_entitlement_helpers import profile


class ProfileInstallationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="mrk-profile-install-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.home = self.root / "home"; self.home.mkdir()
        self.directory = self.home / "Library/MobileDevice/Provisioning Profiles"
        self.uuid = profile()["UUID"]
        self.destination = self.directory / (self.uuid + ".mobileprovision")
        self.content = b"authenticated-fictional-profile"

    def install(self, content=None):
        return _temporary_profile_installation(self.content if content is None else content, self.uuid, self.home)

    def assert_no_files(self):
        self.assertEqual(list(self.directory.iterdir()) if self.directory.exists() else [], [])

    def test_atomic_link_observes_complete_private_bytes_and_removes_only_owned_files(self):
        link = os.link
        observed = []
        def inspect(source, destination, **kwargs):
            self.assertFalse(self.destination.exists())
            staged = self.directory / source
            self.assertEqual(staged.read_bytes(), self.content)
            self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o600)
            observed.append(staged.stat().st_ino)
            return link(source, destination, **kwargs)
        with patch("mobile_release.credentials.os.link", side_effect=inspect):
            with self.install():
                self.assertEqual(self.destination.read_bytes(), self.content)
                self.assertEqual(self.destination.stat().st_ino, observed[0])
                self.assertEqual(list(self.directory.iterdir()), [self.destination])
        self.assert_no_files()

    def test_existing_identical_profile_is_not_rewritten_or_deleted(self):
        self.directory.mkdir(parents=True)
        self.destination.write_bytes(self.content)
        self.destination.chmod(0o640)
        before = self.destination.stat()
        with patch("mobile_release.credentials.os.link", side_effect=AssertionError("no new link")), self.install():
            self.assertEqual(self.destination.read_bytes(), self.content)
        after = self.destination.stat()
        self.assertEqual((before.st_ino, before.st_mtime_ns, before.st_mode), (after.st_ino, after.st_mtime_ns, after.st_mode))

    def test_collision_symlink_fifo_and_invalid_input_never_overwrite_existing_state(self):
        self.directory.mkdir(parents=True)
        for kind in ("different", "symlink", "fifo"):
            with self.subTest(kind=kind):
                if kind == "different":
                    self.destination.write_bytes(b"other-profile")
                elif kind == "symlink":
                    self.destination.symlink_to(self.root / "outside")
                else:
                    os.mkfifo(self.destination)
                with self.assertRaises(CredentialError):
                    with self.install():
                        self.fail("unsafe destination entered")
                self.assertTrue(self.destination.exists() or self.destination.is_symlink())
                self.destination.unlink()
        for identity, content in ((True, self.content), ("../bad", self.content), (self.uuid, "not-bytes"), (self.uuid, b"")):
            with self.subTest(identity=identity), self.assertRaises(CredentialError):
                with _temporary_profile_installation(content, identity, self.home):
                    self.fail("invalid input entered")
        self.assert_no_files()

    def test_concurrent_destination_creation_never_clobbers_or_claims_foreign_ownership(self):
        link = os.link
        for identical in (False, True):
            def race(source, destination, **kwargs):
                self.destination.write_bytes(self.content if identical else b"other-profile")
                return link(source, destination, **kwargs)
            with self.subTest(identical=identical), patch("mobile_release.credentials.os.link", side_effect=race):
                if identical:
                    with self.install():
                        self.assertEqual(self.destination.read_bytes(), self.content)
                else:
                    with self.assertRaises(CredentialError):
                        with self.install():
                            self.fail("collision entered")
            self.assertEqual(self.destination.read_bytes(), self.content if identical else b"other-profile")
            self.assertEqual(list(self.directory.iterdir()), [self.destination])
            self.destination.unlink()

    def test_failure_after_successful_link_or_yield_cleans_all_owned_bytes(self):
        link = os.link
        def interrupted_link(*args, **kwargs):
            link(*args, **kwargs)
            raise KeyboardInterrupt
        with patch("mobile_release.credentials.os.link", side_effect=interrupted_link), self.assertRaises(KeyboardInterrupt):
            with self.install():
                self.fail("interrupted link entered")
        self.assert_no_files()
        with self.assertRaisesRegex(RuntimeError, "caller failed"):
            with self.install():
                raise RuntimeError("caller failed")
        self.assert_no_files()

    def test_partial_write_flush_fsync_link_and_stage_unlink_failures_leave_no_owned_files(self):
        original_fdopen, original_unlink = os.fdopen, os.unlink
        for phase in ("write", "flush", "fsync", "link", "stage-unlink"):
            with self.subTest(phase=phase), ExitStack() as stack:
                if phase in {"write", "flush"}:
                    class FailingWrite:
                        def __init__(self, handle): self.handle = handle
                        def __enter__(self): return self
                        def __exit__(self, *args): return self.handle.__exit__(*args)
                        def write(self, data):
                            self.handle.write(data[:5] if phase == "write" else data)
                            if phase == "write": raise OSError("injected partial write")
                        def flush(self):
                            self.handle.flush()
                            raise OSError("injected flush failure")
                    def fdopen(descriptor, mode, **kwargs):
                        handle = original_fdopen(descriptor, mode, **kwargs)
                        return FailingWrite(handle) if mode == "wb" else handle
                    stack.enter_context(patch("mobile_release.credentials.os.fdopen", side_effect=fdopen))
                elif phase in {"fsync", "link"}:
                    stack.enter_context(patch("mobile_release.credentials.os." + phase, side_effect=OSError("injected failure")))
                else:
                    failed = []
                    def unlink(path, **kwargs):
                        if str(path).startswith(".mobile-release-profile-") and not failed:
                            failed.append(True)
                            raise OSError("injected unlink failure")
                        return original_unlink(path, **kwargs)
                    stack.enter_context(patch("mobile_release.credentials.os.unlink", side_effect=unlink))
                with self.assertRaises(CredentialError):
                    with self.install():
                        self.fail("failed installation entered")
            self.assert_no_files()

    def test_replacement_or_edit_is_preserved_and_failed_cleanup_cannot_report_success(self):
        for replace in (False, True):
            with self.subTest(replace=replace), self.assertRaisesRegex(CredentialError, "changed or could not"):
                with self.install():
                    if replace:
                        foreign = self.directory / "foreign"
                        foreign.write_bytes(b"foreign-profile")
                        foreign.replace(self.destination)
                    else:
                        self.destination.write_bytes(b"foreign-profile")
            self.assertEqual(self.destination.read_bytes(), b"foreign-profile")
            self.destination.unlink()
        context = self.install(); context.__enter__()
        with patch("mobile_release.credentials.os.unlink", side_effect=PermissionError("injected")), self.assertRaisesRegex(CredentialError, "could not"):
            context.__exit__(None, None, None)
        self.assertEqual(self.destination.read_bytes(), self.content)

    def test_initial_fstat_failure_recovers_only_from_owned_fd_or_reports_empty_private_residue(self):
        real_open, real_fstat = os.open, os.fstat
        for persistent in (False, True):
            descriptors, calls = [], []
            def opening(path, *args, **kwargs):
                descriptor = real_open(path, *args, **kwargs)
                if str(path).startswith(".mobile-release-profile-"):
                    descriptors.append(descriptor)
                return descriptor
            def stating(descriptor):
                if descriptor in descriptors and (persistent or not calls):
                    calls.append(True)
                    raise OSError("injected ownership failure")
                return real_fstat(descriptor)
            with self.subTest(persistent=persistent), patch("mobile_release.credentials.os.open", side_effect=opening), patch("mobile_release.credentials.os.fstat", side_effect=stating):
                with self.assertRaises(CredentialError) as raised:
                    with self.install(): self.fail("unregistered inode entered")
            self.assertTrue(descriptors)
            for descriptor in descriptors:
                with self.assertRaises(OSError): real_fstat(descriptor)
            if persistent:
                self.assertIn("could not be cleaned up safely", str(raised.exception))
                residues = list(self.directory.iterdir())
                self.assertEqual(len(residues), 1)
                self.assertEqual(residues[0].read_bytes(), b"")
                self.assertEqual(stat.S_IMODE(residues[0].stat().st_mode), 0o600)
                residues[0].unlink()  # Exact fixture-owned fallback AFTER observing reported residue.
            self.assert_no_files()

    def test_fdopen_failure_cleans_registered_stage_and_stage_collision_never_claims_foreign_file(self):
        real_fdopen = os.fdopen
        def file_object(descriptor, mode, **kwargs):
            if mode == "wb":
                raise OSError("injected fdopen failure")
            return real_fdopen(descriptor, mode, **kwargs)
        with patch("mobile_release.credentials.os.fdopen", side_effect=file_object), self.assertRaises(CredentialError):
            with self.install(): self.fail("failed fdopen entered")
        self.assert_no_files()
        foreign = self.directory / (".mobile-release-profile-" + "b" * 32)
        foreign.write_bytes(b"foreign-stage")
        before = foreign.stat()
        with patch("mobile_release.credentials.secrets.token_hex", return_value="b" * 32), self.assertRaises(CredentialError):
            with self.install(): self.fail("foreign stage entered")
        self.assertEqual(foreign.read_bytes(), b"foreign-stage")
        self.assertEqual(foreign.stat().st_ino, before.st_ino)
        self.assertEqual(list(self.directory.iterdir()), [foreign])

    def test_ambiguous_close_is_not_retried_against_reused_foreign_descriptor(self):
        real_open, real_close, real_fstat = os.open, os.close, os.fstat
        for completed in (False, True):
            stage_fd, close_calls, foreign_fd = [], [], []
            def opening(path, *args, **kwargs):
                descriptor = real_open(path, *args, **kwargs)
                if str(path).startswith(".mobile-release-profile-"):
                    stage_fd.append(descriptor)
                return descriptor
            def closing(descriptor):
                if stage_fd and descriptor == stage_fd[0]:
                    close_calls.append(descriptor)
                    self.assertEqual(len(close_calls), 1, "ambiguous close was retried")
                    if completed:
                        real_close(descriptor)
                        foreign = real_open(self.root / "foreign-fd", os.O_RDWR | os.O_CREAT, 0o600)
                        if foreign != descriptor:
                            os.dup2(foreign, descriptor); real_close(foreign)
                        foreign_fd.append(descriptor)
                    raise OSError("ambiguous close failure")
                return real_close(descriptor)
            try:
                with self.subTest(completed=completed), patch("mobile_release.credentials.os.open", side_effect=opening), patch("mobile_release.credentials.os.close", side_effect=closing), self.assertRaisesRegex(CredentialError, "could not be cleaned up safely"):
                    with self.install(): self.fail("unconfirmed descriptor cleanup entered")
                self.assertEqual(close_calls, stage_fd)
                self.assert_no_files()
                # A true close failure is reported honestly, not falsely labelled
                # closed. A completed close must not close its foreign replacement.
                self.assertTrue(stage_fd)
                real_fstat(stage_fd[0])
                if completed:
                    self.assertEqual(real_fstat(foreign_fd[0]).st_ino, (self.root / "foreign-fd").stat().st_ino)
            finally:
                for descriptor in stage_fd:
                    try: real_close(descriptor)
                    except OSError: pass

    def test_custom_handlers_worker_threads_and_partial_handler_registration_preserve_host_state(self):
        original = signal.getsignal(signal.SIGTERM)
        custom = lambda *args: None
        signal.signal(signal.SIGTERM, custom)
        try:
            with self.install(): self.assertIs(signal.getsignal(signal.SIGTERM), custom)
            self.assertIs(signal.getsignal(signal.SIGTERM), custom)
        finally:
            signal.signal(signal.SIGTERM, original)
        errors = []
        def worker():
            try:
                with self.install(): self.assertTrue(self.destination.is_file())
            except BaseException as error:
                errors.append(error)
        with patch("mobile_release.cancellation.signal.signal", side_effect=AssertionError("worker changed process handler")):
            thread = threading.Thread(target=worker)
            thread.start(); thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assert_no_files()
        real_signal, calls = signal.signal, []
        before = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        def register(signum, handler):
            calls.append(signum)
            if len(calls) == 2:
                raise OSError("injected second handler registration failure")
            return real_signal(signum, handler)
        with patch("mobile_release.cancellation.signal.signal", side_effect=register), self.assertRaises(CredentialError):
            with self.install(): self.fail("failed handler registration entered")
        self.assertEqual({sig: signal.getsignal(sig) for sig in before}, before)
        self.assert_no_files()


@unittest.skipUnless(os.name == "posix", "local Apple signing signal ownership needs POSIX")
class ProfileInstallationSignalTests(unittest.TestCase):
    def run_boundary(self, mode):
        command = [sys.executable, "-I", "-S", "-B", str(Path(__file__).parents[1] / "workflow/profile_installation_fixture.py"),
                   str(Path(mobile_release.__file__).resolve().parent.parent), mode]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            output, error = process.communicate(timeout=15)
            self.assertEqual(process.returncode, 0, error.decode(errors="replace"))
            self.assertFalse(error)
            result = json.loads(output)
            self.assertTrue(result["ownedFilesAndDescriptorsGoneBeforeFallback"])
            self.assertTrue(result["handlersRestored"])
            return result
        finally:
            # Only this fixture process was launched; native/keychain work is
            # patched and cannot start other workers.
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
            process.stdout.close(); process.stderr.close()

    def test_real_pending_signals_during_native_open_fstat_fdopen_and_close_are_owned(self):
        for mode in ("open-home", "open-child", "open-stage", "fstat", "fdopen", "close"):
            with self.subTest(mode=mode):
                self.assertEqual(self.run_boundary(mode)["signalCount"], 1)

    def test_original_unmocked_open_and_initial_fstat_interruptions_cannot_leak_files_or_descriptors(self):
        for mode in ("assigned-open", "before-fstat"):
            with self.subTest(mode=mode): self.run_boundary(mode)

    def test_actual_caller_handoff_and_repeated_cleanup_signals_do_not_rely_on_generator_gc(self):
        for mode in ("handoff", "body-repeat", "unexpected-cleanup"):
            with self.subTest(mode=mode): self.run_boundary(mode)

    def test_successful_native_mutation_is_registered_before_deferred_cancellation(self):
        for mode in ("mutation-create", "mutation-search", "mutation-default"):
            with self.subTest(mode=mode): self.run_boundary(mode)

    def test_first_signal_at_cleanup_entry_and_before_exit_dispatch_cannot_skip_ownership(self):
        for prefix in ("", "standalone-"):
            for phase in ("cleanup-entry", "cleanup-dispatch", "restore-entry", "restore-active"):
                for signum in ("INT", "TERM"):
                    mode = f"{prefix}{phase}:{signum}"
                    with self.subTest(mode=mode):
                        self.assertEqual(self.run_boundary(mode)["cleanupAttempts"], 1)

    def test_handler_restoration_and_partial_installation_cannot_swallow_or_abandon_cancellation(self):
        for prefix in ("", "standalone-"):
            for phase in ("restore-term", "restore-int", "partial-install"):
                with self.subTest(prefix=prefix, phase=phase):
                    self.run_boundary(prefix + phase)

    def test_late_setup_and_actual_materialized_body_cancellation_never_execute_following_build_code(self):
        for prefix in ("", "standalone-", "material-"):
            for phase in ("pre-yield", "body"):
                for signum in ("INT", "TERM"):
                    mode = f"{prefix}{phase}:{signum}"
                    with self.subTest(mode=mode): self.run_boundary(mode)

    def test_cleanup_failure_is_not_masked_by_deferred_cancellation_and_remaining_cleanup_runs(self):
        for signum in ("INT", "TERM"):
            with self.subTest(signum=signum): self.run_boundary("cleanup-error-signal:" + signum)


class ProfileCredentialFlowTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="mrk-profile-credentials-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.private = self.root / "private"; self.private.mkdir()
        self.p12, self.profile_path = self.private / "identity.p12", self.private / "profile"
        self.p12.write_bytes(b"fictional-p12")
        self.profile_path.write_bytes(b"original-profile-bytes")

    def signing(self):
        return _temporary_apple_signing_environment(p12=self.p12, password="synthetic-secret", profile=self.profile_path,
                                                  directory=self.private, home=self.root)

    def test_authentication_failure_or_invalid_identity_dates_precedes_every_keychain_call(self):
        for payload in ({**profile(), "UUID": "../unsafe"}, {**profile(), "UUID": None},
                        {**profile(), "ExpirationDate": datetime(2000, 1, 1)}, {**profile(), "CreationDate": datetime(2100, 1, 1)}):
            with self.subTest(uuid=payload.get("UUID")), patch("mobile_release.ios_profiles.decode_authenticated_profile", return_value=payload), patch("mobile_release.credentials._run_private") as native:
                with self.assertRaises(CredentialError):
                    with self.signing(): self.fail("invalid authentication entered")
                native.assert_not_called()
                self.assertFalse((self.root / "Library").exists())
        with patch("mobile_release.ios_profiles.decode_authenticated_profile", side_effect=ValidationError("fixed issuer rejection")), patch("mobile_release.credentials._run_private") as native:
            with self.assertRaisesRegex(CredentialError, "issuer rejection"):
                with self.signing(): self.fail("unsigned input entered")
        native.assert_not_called()

    def test_install_uses_authenticated_snapshot_even_when_original_path_is_replaced(self):
        destination = self.root / "Library/MobileDevice/Provisioning Profiles" / (profile()["UUID"] + ".mobileprovision")
        def authenticate(raw):
            self.assertEqual(raw, b"original-profile-bytes")
            self.profile_path.write_bytes(b"substituted-after-authentication")
            return profile()
        calls = []
        def native(argv, **kwargs):
            calls.append(argv)
            self.assertEqual(destination.read_bytes(), b"original-profile-bytes")
            if argv[0] == "openssl" and "-out" in argv:
                Path(argv[argv.index("-out") + 1]).write_bytes(b"fictional-extracted-material")
            output = '"/fictional/login.keychain-db"\n' if argv[1] in {"default-keychain", "list-keychains"} and "-s" not in argv else ""
            return SimpleNamespace(returncode=0, stdout=output, stderr="")
        with patch("mobile_release.ios_profiles.decode_authenticated_profile", side_effect=authenticate), patch("mobile_release.credentials._run_private", side_effect=native):
            with self.signing():
                self.assertEqual(destination.read_bytes(), b"original-profile-bytes")
        self.assertFalse(destination.exists())
        self.assertTrue(any(argv[1] == "delete-keychain" for argv in calls))
        self.assertFalse(any(argv[1] == "cms" for argv in calls))

    def test_credential_material_authenticates_profile_before_p12_extraction(self):
        config = load_config(write_project(self.root / "project", ios_config(), platform="ios"))
        values = {"MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64": base64.b64encode(b"fictional-p12").decode(),
                  "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD": "fictional-password",
                  "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64": base64.b64encode(b"unsigned-profile").decode()}
        with patch("mobile_release.ios_profiles.load_authenticated_profile", side_effect=ValidationError("private-profile-canary")) as authenticate, patch("mobile_release.credentials._run_private") as native:
            findings = _validate_apple_signing_material(config, values, self.private)
        authenticate.assert_called_once(); native.assert_not_called()
        self.assertEqual([item.status for item in findings], [Status.INVALID])
        self.assertNotIn("private-profile-canary", findings[0].message)
        self.assertFalse((self.private / "private-key.pem").exists())


if __name__ == "__main__":
    unittest.main()
