"""Coherent profile observations through real installers, journals and recovery.

Only native signing/CMS responses are fictional. Race hooks perform actual IO;
all assertions precede fixture cleanup and no real account or Store is queried.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import ExitStack, nullcontext, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import mobile_release
from mobile_release import cli, credentials, local_signing as signing
from mobile_release.errors import CredentialError
from mobile_release.owned_process import ProcessError, run_owned
from workflow.local_signing_workload import worker_timeout
from .ios_entitlement_helpers import profile
from .local_signing_helpers import NativeSigningModel, fictional_signing_profile
from .local_signing_algorithm_helpers import profile_algorithm_session, refuse_signing_execution
from .local_signing_workspace import NativeCaseWorkspaceMixin
from workflow.local_signing_regression_catalog import PROFILE_OWNER_NATIVE_VARIANTS, PROFILE_BORROWED_NATIVE_VARIANTS
from .test_local_signing_failures import DescriptorFault

TOKEN = "e" * 32
UUID = "44444444-5555-6666-7777-888888888888"
CONTENT = b"fictional authenticated profile shared by original and equal-byte foreign file"
OTHER = b"different fictional profile bytes, not authenticated by this session"

# Exact finite variants: direct algorithms do not claim native/recovery evidence.
PROFILE_OWNER_DIRECT_VARIANTS = (
    ("owned-before-open-same", False, "before-open", "same"),
    ("owned-before-open-different", False, "before-open", "different"),
    ("owned-before-open-metadata", False, "before-open", "metadata"),
    ("owned-during-read-same", False, "during-read", "same"),
    ("owned-during-read-different", False, "during-read", "different"),
    ("owned-during-read-metadata", False, "during-read", "metadata"),
    ("owned-after-close-same", False, "after-close", "same"),
    ("owned-after-close-different", False, "after-close", "different"),
    ("owned-after-close-metadata", False, "after-close", "metadata"),
    ("borrowed-before-open-same", True, "before-open", "same"),
    ("borrowed-before-open-different", True, "before-open", "different"),
    ("borrowed-before-open-metadata", True, "before-open", "metadata"),
    ("borrowed-during-read-same", True, "during-read", "same"),
    ("borrowed-during-read-different", True, "during-read", "different"),
    ("borrowed-during-read-metadata", True, "during-read", "metadata"),
    ("borrowed-after-close-same", True, "after-close", "same"),
    ("borrowed-after-close-different", True, "after-close", "different"),
    ("borrowed-after-close-metadata", True, "after-close", "metadata"),
)
PROFILE_BORROWED_DIRECT_VARIANTS = (
    ("active-before-open-same", False, "before-open", "same"),
    ("active-before-open-different", False, "before-open", "different"),
    ("active-before-open-remove", False, "before-open", "remove"),
    ("active-before-open-metadata", False, "before-open", "metadata"),
    ("active-during-read-same", False, "during-read", "same"),
    ("active-during-read-different", False, "during-read", "different"),
    ("active-during-read-remove", False, "during-read", "remove"),
    ("active-during-read-metadata", False, "during-read", "metadata"),
    ("active-after-close-same", False, "after-close", "same"),
    ("active-after-close-different", False, "after-close", "different"),
    ("active-after-close-remove", False, "after-close", "remove"),
    ("active-after-close-metadata", False, "after-close", "metadata"),
    ("terminal-before-open-same", True, "before-open", "same"),
    ("terminal-before-open-different", True, "before-open", "different"),
    ("terminal-before-open-remove", True, "before-open", "remove"),
    ("terminal-before-open-metadata", True, "before-open", "metadata"),
    ("terminal-during-read-same", True, "during-read", "same"),
    ("terminal-during-read-different", True, "during-read", "different"),
    ("terminal-during-read-remove", True, "during-read", "remove"),
    ("terminal-during-read-metadata", True, "during-read", "metadata"),
    ("terminal-after-close-same", True, "after-close", "same"),
    ("terminal-after-close-different", True, "after-close", "different"),
    ("terminal-after-close-remove", True, "after-close", "remove"),
    ("terminal-after-close-metadata", True, "after-close", "metadata"),
)



def identity(details):
    return details.st_dev, details.st_ino


class ProfileIO:
    """Change exactly one real fixture file at a selected production IO boundary."""
    def __init__(self, target, boundary, effect, *, armed=True):
        self.target, self.boundary, self.effect, self.armed = target, boundary, effect, armed
        self.active, self.opened, self.closed, self.stats, self.unlinks = {}, [], [], [], []
        self.changed = False
        self.before = self.after = self.moved = None
        self.os = SimpleNamespace(**vars(os))
        for name in ("open", "dup", "close", "stat", "read", "fdopen", "unlink"):
            setattr(self.os, name, getattr(self, name))

    def change(self):
        if self.changed or not self.armed:
            return
        self.before = self.target.stat()
        if self.effect in {"same", "different", "remove"}:
            self.moved = self.target.parents[3] / ("fixture-moved-" + self.target.name)
            assert not self.moved.exists()
            self.target.rename(self.moved)  # Prevent accidental original inode recycling.
            if self.effect != "remove":
                self.target.write_bytes(CONTENT if self.effect == "same" else OTHER)
                self.target.chmod(0o640)
                assert identity(self.target.stat()) != identity(self.before)
        elif self.effect == "metadata":
            self.target.chmod(0o640 if stat.S_IMODE(self.before.st_mode) != 0o640 else 0o600)
            os.utime(self.target, ns=(self.before.st_atime_ns, self.before.st_mtime_ns - 1000000000))
            assert identity(self.target.stat()) == identity(self.before)
        elif self.effect == "content":
            self.target.write_bytes(OTHER)
            assert identity(self.target.stat()) == identity(self.before)
        else:
            raise AssertionError(self.effect)
        self.after = self.target.stat() if self.target.exists() else None
        self.changed = True

    def record(self, fd, name, flags=None):
        entry = {"fd": fd, "name": str(name), "identity": identity(os.fstat(fd)), "flags": flags}
        self.active[fd] = entry
        self.opened.append(entry)
        return fd

    def open(self, name, flags, *args, **kwargs):
        if name == self.target.name and self.boundary == "before-open" and self.armed and not self.changed:
            assert self.stats, "fixture did not reach an actual preceding pathname observation"
            self.change()
        return self.record(os.open(name, flags, *args, **kwargs), name, flags)

    def dup(self, fd):
        return self.record(os.dup(fd), "duplicate")

    def close(self, fd):
        entry = self.active.pop(fd, None)
        self.closed.append((fd, identity(os.fstat(fd))))
        os.close(fd)
        if entry is not None and entry["name"] == self.target.name and self.boundary == "after-close":
            self.change()

    def stat(self, name, *args, **kwargs):
        details = os.stat(name, *args, **kwargs)
        if name == self.target.name:
            self.stats.append(details)
        return details

    def read(self, fd, maximum):
        content = os.read(fd, maximum)
        if self.active.get(fd, {}).get("name") == self.target.name and self.boundary == "during-read":
            self.change()
        return content

    def fdopen(self, fd, mode, **kwargs):
        handle = os.fdopen(fd, mode, **kwargs)
        if self.active.get(fd, {}).get("name") != self.target.name or mode != "rb":
            return handle
        owner = self

        class Reader:
            def __enter__(self):
                handle.__enter__()
                return self

            def __exit__(self, *args):
                return handle.__exit__(*args)

            def read(self, maximum):
                content = handle.read(maximum)
                if owner.boundary == "during-read":
                    owner.change()
                return content

        return Reader()

    def unlink(self, name, *args, **kwargs):
        if name == self.target.name:
            current = os.stat(name, dir_fd=kwargs["dir_fd"], follow_symlinks=False)
            self.unlinks.append({"identity": identity(current), "afterChange": self.changed})
        return os.unlink(name, *args, **kwargs)

    def assert_preserved(self, test):
        test.assertTrue(self.changed, "the requested real filesystem boundary was not reached")
        test.assertEqual(self.active, {}, "production left an independently owned raw handle open")
        if self.effect == "remove":
            test.assertFalse(self.target.exists())
        else:
            test.assertEqual(identity(self.target.stat()), identity(self.after))
            test.assertEqual(self.target.stat().st_mode, self.after.st_mode)
            test.assertEqual(self.target.read_bytes(), OTHER if self.effect in {"different", "content"} else CONTENT)
        test.assertFalse(self.unlinks, "a contradicted profile observation became deletion authority")


class SetupStageIO(ProfileIO):
    """Fail one actual setup-stage boundary while tracking both owners' handles."""
    def __init__(self, target, cut, *, absent=False):
        super().__init__(target, "setup", "remove" if absent else "metadata", armed=False)
        self.cut, self.absent = cut, absent
        self.attempts = []

    def observe(self, operation, name, args, kwargs):
        if not self.armed or name != self.target.name:
            return
        self.attempts.append({"operation": operation, "afterFailure": self.changed})
        number = sum(item["operation"] == "stat" for item in self.attempts)
        at_cut = (operation == "stat" and number == (1 if self.cut == "first-stat" else 2)
                  and self.cut in {"first-stat", "comparison-stat"}) or (operation == "unlink" and self.cut.startswith("unlink"))
        if at_cut and not self.changed:
            self.change()  # Real chmod/utime, or move so the subsequent real syscall observes absence.
            if self.absent:
                return
            if self.cut == "unlink-after":
                os.unlink(name, *args, **kwargs)
            raise OSError("fictional one-shot setup-stage IO error")

    def stat(self, name, *args, **kwargs):
        self.observe("stat", name, args, kwargs)
        return super().stat(name, *args, **kwargs)

    def unlink(self, name, *args, **kwargs):
        self.observe("unlink", name, args, kwargs)
        return os.unlink(name, *args, **kwargs)


class ProfileIdentityTests(NativeCaseWorkspaceMixin, unittest.TestCase):
    def setUp(self):
        self.root = self.native_case_directory(prefix="mrk-profile-observation-")
        self.serial = 0

    def case(self, *, borrowed=False, native=True):
        self.serial += 1
        root = self.root / str(self.serial)
        root.mkdir(mode=0o700)
        home = root / "home"
        home.mkdir(mode=0o700)
        destination = home / "Library/MobileDevice/Provisioning Profiles" / (UUID + ".mobileprovision")
        if borrowed:
            destination.parent.mkdir(mode=0o700, parents=True)
            destination.write_bytes(CONTENT)
            destination.chmod(0o600)
        return SimpleNamespace(root=root, home=home, destination=destination,
                               model=NativeSigningModel(home) if native else None)

    def seed(self, case, *, stage=False):
        with signing.local_signing_lease(home=case.home) as lease:
            session = lease.session(token=TOKEN)
            session.open(create=True)
            session.bind_runner(case.model)
            session.prepare(CONTENT, UUID)

            def observer(phase, **kwargs):
                session.profile_event(phase, **kwargs)
                if stage and phase == "linked":
                    raise CredentialError("fictional interruption after real link/checkpoint")

            try:
                with credentials._temporary_profile_installation(
                    CONTENT, UUID, case.home, cancellation=lease.cancellation,
                    observer=observer, reserved_stage=session.intent["profile"]["stage"], retain=lambda: True,
                ):
                    self.assertFalse(stage)
            except CredentialError as error:
                self.assertTrue(stage)
                self.assertIn("fictional interruption", str(error))
        case.session = case.home / signing.LEASE_DIRECTORY / ("session-" + TOKEN)
        case.stage = case.destination.parent / (".mobile-release-profile-" + TOKEN)
        case.intent = (case.session / "intent.json").read_bytes()

    def terminal(self, case):
        self.seed(case)
        remove = signing.SigningSession._remove_control

        def interrupt(session, name):
            if name == "state.pending" and (session.path / "completed.json").exists():
                raise CredentialError("fictional terminal teardown interruption")
            return remove(session, name)

        with patch.object(signing.SigningSession, "_remove_control", new=interrupt), \
             self.assertRaisesRegex(CredentialError, "fictional terminal"):
            signing.recover_signing(TOKEN, signing.CONFIRMATION, home=case.home, runner=case.model)
        self.assertEqual(signing.signing_status(home=case.home)["phase"], "completed")

    def invoke(self, case, *, manual=False, callback=None):
        lease = signing.local_signing_lease

        class TTY(io.StringIO):
            def isatty(self):
                return True

            def readline(self, maximum=-1):
                if callback is not None:
                    callback()
                return super().readline(maximum)

        stdout, stderr = TTY(), io.StringIO()
        stdin = TTY("recheck " + TOKEN + "\n")
        with patch.object(signing, "local_signing_lease", side_effect=lambda **kw: lease(**{**kw, "home": case.home})), \
             patch.object(signing, "run_owned", case.model), patch.object(sys, "stdin", stdin), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            code = cli.main(["local-signing", "recover", "--session", TOKEN, "--confirm", signing.CONFIRMATION,
                             *(["--manual"] if manual else [])])
        return code, stdout.getvalue(), stderr.getvalue()

    def assert_pending(self, case, *, token=TOKEN):
        status = signing.signing_status(home=case.home)
        self.assertEqual(status["status"], "pending")
        self.assertEqual(status["session"], token)
        session = case.home / signing.LEASE_DIRECTORY / ("session-" + token)
        self.assertFalse((session / "completed.json").exists())
        with self.assertRaises(signing.SigningPending):
            with signing.local_signing_lease(home=case.home):
                self.fail("pending signing account was admitted")
        return session

    def fresh_recovery(self, case, *, expected="recovered", token=TOKEN):
        code = """
import json,sys
from pathlib import Path
from unittest.mock import patch
sys.path[:0] = sys.argv[1:3]
from mobile_release import cli, local_signing as signing
from unit.local_signing_helpers import NativeSigningModel
home=Path(sys.argv[3]); data=json.loads(sys.argv[4]); token=sys.argv[5]
model=NativeSigningModel(home); model.preferences=data['preferences']
model.keychain=Path(data['keychain']) if data['keychain'] else None
lease=signing.local_signing_lease
with patch.object(signing,'local_signing_lease',side_effect=lambda **kw: lease(**{**kw,'home':home})), patch.object(signing,'run_owned',model):
    status=cli.main(['local-signing','recover','--session',token,'--confirm',signing.CONFIRMATION])
if status in (0, 1):
    with lease(home=home) as renewed:
        renewed.assert_owner()
raise SystemExit(status)
"""
        result = run_owned(
            [sys.executable, "-I", "-S", "-B", "-c", code, str(Path(mobile_release.__file__).resolve().parent.parent),
             str(Path(__file__).parents[1]), str(case.home),
             json.dumps({"preferences": case.model.preferences, "keychain": str(case.model.keychain) if case.model.keychain else None}), token],
            cwd=self.root, environ={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(case.home)},
            capture=True, output_limit=64 * 1024, timeout=worker_timeout("fresh-cli-recovery"),
        )
        self.assertEqual(result.returncode, 1 if expected == "recovered-with-conflict" else 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"status": expected, "session": token})
        self.assertFalse(result.stderr)
        self.assertEqual(signing.signing_status(home=case.home)["status"], "idle")

    def context(self, case):
        private = case.root / "private"
        private.mkdir(mode=0o700, exist_ok=True)
        project = case.root / "project"
        project.mkdir(mode=0o700, exist_ok=True)
        p12, supplied = case.root / "input.p12", case.root / "input.mobileprovision"
        p12.write_bytes(b"fictional signing identity")
        supplied.write_bytes(CONTENT)
        p12.chmod(0o600); supplied.chmod(0o600)
        payload = profile()
        payload["UUID"] = UUID
        stack = ExitStack()
        stack.enter_context(patch("mobile_release.credentials._authenticated_signing_profile",
                                  side_effect=lambda path, *, cancellation: fictional_signing_profile(
                                      path, cancellation=cancellation, payload=payload)))
        stack.enter_context(patch.object(credentials, "_run_private", case.model))
        return stack, credentials._temporary_apple_signing_environment(
            p12=p12, password="fictional", profile=supplied, directory=private, home=case.home, project_root=project,
        )

    def test_full_stat_comparison_ignores_only_access_time(self):
        case = self.case(borrowed=True)
        details = case.destination.stat()
        fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns")
        values = {name: getattr(details, name) for name in (*fields, "st_atime_ns")}
        self.assertTrue(signing._same_file_state(details, details))
        for field in fields:
            with self.subTest(field=field):
                self.assertFalse(signing._same_file_state(details, SimpleNamespace(**{**values, field: values[field] + 1})))
        self.assertTrue(signing._same_file_state(details, SimpleNamespace(**{**values, "st_atime_ns": 1})))
        self.assertFalse(signing._same_file_state(details, None))
        self.assertFalse(signing._same_file_state(None, None))

    def test_owned_recovery_preserves_same_byte_foreign_inode_at_both_boundaries(self):
        for stage in (False, True):
            for boundary in ("before-open", "after-close"):
                with self.subTest(stage=stage, boundary=boundary):
                    case = self.case()
                    self.seed(case, stage=stage)
                    target = case.stage if stage else case.destination
                    seam = ProfileIO(target, boundary, "same")
                    with patch.object(signing, "os", seam.os):
                        code, stdout, stderr = self.invoke(case)
                    seam.assert_preserved(self)
                    self.assertEqual(case.model.preferences, case.model.original)
                    if stage:
                        self.assertEqual((code, stdout), (2, ""))
                        self.assertIn("stage was replaced", stderr)
                        self.assertEqual((self.assert_pending(case) / "intent.json").read_bytes(), case.intent)
                        # Explicit fixture-owner reconciliation, not toolkit adoption/deletion.
                        target.rename(case.root / "foreign-stage-retained-by-fixture")
                        self.fresh_recovery(case)
                    else:
                        self.assertEqual(code, 1, stderr)
                        self.assertEqual(json.loads(stdout)["status"], "recovered-with-conflict")
                        self.assertFalse(stderr)
                        self.assertEqual(signing.signing_status(home=case.home)["status"], "idle")

    def test_owned_recovery_disappearance_is_safe_without_type_error(self):
        for stage in (False, True):
            for boundary in ("before-open", "after-close"):
                with self.subTest(stage=stage, boundary=boundary):
                    case = self.case()
                    self.seed(case, stage=stage)
                    seam = ProfileIO(case.stage if stage else case.destination, boundary, "remove")
                    with patch.object(signing, "os", seam.os):
                        code, stdout, stderr = self.invoke(case)
                    seam.assert_preserved(self)
                    self.assertEqual(code, 0, stderr)
                    self.assertEqual(json.loads(stdout)["status"], "recovered")
                    self.assertFalse(stderr)
                    self.assertEqual(case.model.preferences, case.model.original)

    def test_owned_metadata_changes_require_fresh_explicit_recovery(self):
        for stage in (False, True):
            for boundary in ("before-open", "during-read", "after-close"):
                with self.subTest(stage=stage, boundary=boundary):
                    case = self.case()
                    self.seed(case, stage=stage)
                    seam = ProfileIO(case.stage if stage else case.destination, boundary, "metadata")
                    with patch.object(signing, "os", seam.os):
                        code, stdout, stderr = self.invoke(case)
                    seam.assert_preserved(self)
                    self.assertEqual((code, stdout), (2, ""))
                    self.assertIn("changed", stderr)
                    self.assertEqual((self.assert_pending(case) / "intent.json").read_bytes(), case.intent)
                    self.fresh_recovery(case)
                    self.assertFalse(case.destination.exists() or case.stage.exists())

    def test_borrowed_active_and_terminal_observations_report_all_conflicts(self):
        # The complete boundary/effect table is exercised by the direct policy
        # method below; these four retain the genuine active/terminal caller.
        for variant in PROFILE_BORROWED_NATIVE_VARIANTS:
            with self.subTest(variant=variant[0]):
                self.run_native_borrowed_variant(variant)

    def run_native_borrowed_variant(self, variant):
        self.assertIn(variant, PROFILE_BORROWED_NATIVE_VARIANTS)
        _name, terminal, boundary, effect = variant
        case = self.case(borrowed=True)
        self.terminal(case) if terminal else self.seed(case)
        seam = ProfileIO(case.destination, boundary, effect)
        with patch.object(signing, "os", seam.os):
            code, stdout, stderr = self.invoke(case)
        seam.assert_preserved(self)
        self.assertEqual(code, 1, stderr)
        self.assertEqual(json.loads(stdout)["status"], "recovered-with-conflict")
        self.assertFalse(stderr)
        self.assertEqual(case.model.preferences, case.model.original)
        self.assertEqual(signing.signing_status(home=case.home)["status"], "idle")

        with signing.local_signing_lease(home=case.home) as renewed:
            renewed.assert_owner()

    def test_direct_borrowed_active_terminal_policy_preserves_all_real_file_conflicts(self):
        self.assertEqual(len(PROFILE_BORROWED_DIRECT_VARIANTS), 24)
        for variant in PROFILE_BORROWED_DIRECT_VARIANTS:
            with self.subTest(variant=variant[0]):
                self.run_direct_borrowed_variant(variant)

    def run_direct_borrowed_variant(self, variant):
        self.assertIn(variant, PROFILE_BORROWED_DIRECT_VARIANTS)
        _name, terminal, boundary, effect = variant
        case = self.case(borrowed=True, native=False)
        with profile_algorithm_session(case.home, CONTENT, UUID) as algorithm:
            session = algorithm.session
            self.assertEqual(algorithm.events, ["inspected", "reused"])
            self.assertTrue(session.state["profile"]["reused"])
            self.assertIsNone(session.state["profile"]["ownedIdentity"])
            if terminal:
                # Real prior algorithm cleanup derives the resolved state; no
                # completed marker, native result or recovery attempt is made.
                session.cleanup_profile()
                self.assertFalse(session.state["conflict"])
            checkpoint = (session.path / "state.json").read_bytes()
            revision = session.state["revision"]
            seam = ProfileIO(case.destination, boundary, effect)
            with patch.object(signing, "os", seam.os):
                session.cleanup_profile(terminal=terminal)
            seam.assert_preserved(self)
            self.assertTrue(session.state["conflict"])
            self.assertEqual(session.state["profile"]["phase"], "resolved")
            actual = (session.path / "state.json").read_bytes()
            if terminal:
                self.assertEqual(actual, checkpoint, "terminal algorithm wrote a new checkpoint")
                self.assertEqual(session.state["revision"], revision)
            else:
                stored = json.loads(actual)
                self.assertEqual(stored, session.state)
                self.assertEqual(stored["revision"], revision + 1)
                self.assertIn("fixtureAlgorithmData", stored)
                self.assertNotIn("version", stored)
            self.assertFalse(algorithm.attempts)
            self.assertIsNone(case.model)

    def test_full_owner_preserves_conflicted_profiles_without_implicit_outer_retry(self):
        for variant in PROFILE_OWNER_NATIVE_VARIANTS:
            with self.subTest(variant=variant[0]):
                self.run_native_owner_variant(variant)

    def run_native_owner_variant(self, variant):
        self.assertIn(variant, PROFILE_OWNER_NATIVE_VARIANTS)
        _name, borrowed, boundary, effect = variant
        case = self.case(borrowed=borrowed)
        seam = ProfileIO(case.destination, boundary, effect, armed=False)
        stack, context = self.context(case)
        with stack, patch.object(credentials, "os", seam.os), patch.object(signing, "os", seam.os):
            with self.assertRaises(CredentialError):
                with context:
                    seam.stats.clear()
                    seam.armed = True
                    session, = (case.home / signing.LEASE_DIRECTORY).iterdir()
                    original = (session / "intent.json").read_bytes()
                    token = session.name.removeprefix("session-")
        seam.assert_preserved(self)
        session = self.assert_pending(case, token=token)
        self.assertEqual((session / "intent.json").read_bytes(), original)
        self.assertEqual(case.model.preferences, case.model.original)
        self.assertEqual(list((session / "keychain").iterdir()), [])
        self.assertFalse(list(case.destination.parent.glob(".mobile-release-profile-*")))
        expected = "recovered-with-conflict" if effect in {"same", "different"} else "recovered"
        self.fresh_recovery(case, expected=expected, token=token)
        self.assertEqual(case.destination.exists(), borrowed or effect in {"same", "different"})

    def test_direct_installer_preserves_all_real_owned_and_borrowed_conflicts(self):
        self.assertEqual(len(PROFILE_OWNER_DIRECT_VARIANTS), 18)
        for variant in PROFILE_OWNER_DIRECT_VARIANTS:
            with self.subTest(variant=variant[0]):
                self.run_direct_owner_variant(variant)

    def run_direct_owner_variant(self, variant):
        self.assertIn(variant, PROFILE_OWNER_DIRECT_VARIANTS)
        _name, borrowed, boundary, effect = variant
        case = self.case(borrowed=borrowed, native=False)
        seam = ProfileIO(case.destination, boundary, effect, armed=False)
        events, conflicts = [], []
        with refuse_signing_execution() as attempts:
            with patch.object(credentials, "os", seam.os), patch.object(signing, "os", seam.os), \
                 self.assertRaises(ProcessError) as caught:
                with signing.local_signing_lease(home=case.home) as lease:
                    with self.assertRaises(CredentialError):
                        with credentials._temporary_profile_installation(
                            CONTENT, UUID, case.home, cancellation=lease.cancellation,
                            observer=lambda phase, **_values: events.append(phase),
                            on_conflict=lambda: conflicts.append(True),
                        ):
                            seam.stats.clear()
                            seam.armed = True
                    self.assertTrue(conflicts)
                    self.assertNotIn("resolved", events)
                    self.assertEqual(events, ["inspected", "reused"] if borrowed else
                                     ["inspected", "stage-intent", "stage-created", "link-intent", "linked", "stage-removed"])
            # The caught installer conflict does not repair its original
            # guard. Its outer owner must preserve the fatal cleanup latch.
            self.assertTrue(caught.exception.fatal)
            self.assertFalse(caught.exception.dispatched)
            self.assertTrue(caught.exception.contained)
            self.assertFalse(caught.exception.cleanup_complete)
            self.assertTrue(lease.cancellation.lifetime_ledger.fatal)
            self.assertEqual(lease.cancellation.handler_state, "RESTORED")
            self.assertEqual(lease._hold_slot.state, "CLOSED")
            self.assertIsNone(lease.home_fd)
            seam.assert_preserved(self)
            self.assertFalse(list(case.destination.parent.glob(".mobile-release-profile-*")))
            self.assertFalse(attempts)
            self.assertIsNone(case.model)

    def test_initial_and_real_eexist_admission_bind_the_actual_read_inode(self):
        for raced in (False, True):
            for effect in ("same", "different", "metadata"):
                with self.subTest(raced=raced, effect=effect):
                    case = self.case(borrowed=not raced)
                    seam = ProfileIO(case.destination, "after-close", effect)
                    # Only installer's read; prepare's independent original snapshot stays real.
                    if raced:
                        def link(source, target, **kwargs):
                            case.destination.write_bytes(CONTENT)
                            case.destination.chmod(0o600)
                            return os.link(source, target, **kwargs)  # Genuine EEXIST.
                        seam.os.link = link
                    stack, context = self.context(case)
                    with stack, patch.object(credentials, "os", seam.os), self.assertRaises(CredentialError):
                        with context:
                            self.fail("a substituted admission snapshot entered the signing body")
                    seam.assert_preserved(self)
                    self.assertFalse(any(call[1] == "create-keychain" or Path(call[0]).name == "openssl" for call in case.model.calls))
                    status = signing.signing_status(home=case.home)
                    session = self.assert_pending(case, token=status["session"])
                    recorded = json.loads((session / "state.json").read_bytes())["profile"]
                    self.assertFalse(recorded["reused"])
                    self.assertIsNone(recorded["borrowed"])
                    self.assertFalse(list(case.destination.parent.glob(".mobile-release-profile-*")))
                    expected = "recovered-with-conflict" if raced or effect in {"same", "different"} else "recovered"
                    self.fresh_recovery(case, expected=expected, token=status["session"])

    def test_final_admission_detects_changes_after_link_or_stage_removal(self):
        for phase in ("linked", "stage-removed"):
            for effect in ("same", "different", "content"):
                with self.subTest(phase=phase, effect=effect):
                    case = self.case()
                    seam = ProfileIO(case.destination, "event", effect, armed=False)
                    real_event = signing.SigningSession.profile_event

                    def observer(session, name, **kwargs):
                        real_event(session, name, **kwargs)
                        if name == phase:
                            seam.armed = True
                            seam.change()

                    stack, context = self.context(case)
                    with stack, patch.object(credentials, "os", seam.os), \
                         patch.object(signing.SigningSession, "profile_event", new=observer), self.assertRaises(CredentialError):
                        with context:
                            self.fail("changed setup profile admitted native signing")
                    seam.assert_preserved(self)
                    self.assertFalse(any(call[1] == "create-keychain" for call in case.model.calls))
                    status = signing.signing_status(home=case.home)
                    self.assert_pending(case, token=status["session"])
                    if effect == "content":
                        case.destination.rename(case.root / "changed-original-retained-by-fixture")
                    self.fresh_recovery(case, token=status["session"],
                                        expected="recovered" if effect == "content" else "recovered-with-conflict")

    def test_final_admission_close_failure_keeps_fatal_ownership_and_original_session(self):
        for after in (False, True):
            with self.subTest(after=after):
                case = self.case()
                real_event = signing.SigningSession.profile_event
                events = []
                with DescriptorFault(case.root, lambda entry: entry["name"] == case.destination.name,
                                     after=after, armed=False) as fault:
                    def observer(session, phase, **kwargs):
                        events.append(phase)
                        real_event(session, phase, **kwargs)
                        if phase == "stage-removed":
                            fault.armed = True
                    stack, context = self.context(case)
                    with stack, patch.object(credentials, "os", fault.os), \
                         patch.object(signing.SigningSession, "profile_event", new=observer), self.assertRaises(ProcessError) as caught:
                        with context:
                            self.fail("fatal final read close admitted signing")
                    self.assertTrue(caught.exception.fatal)
                    # Baseline queries genuinely dispatched before installation;
                    # fatal aggregate projection cannot erase their history.
                    self.assertTrue(caught.exception.dispatched)
                    self.assertFalse(caught.exception.cleanup_complete)
                    self.assertTrue(caught.exception.contained)
                    self.assertNotIn("resolved", events)
                    fault.assert_observed(self)
                    status = signing.signing_status(home=case.home)
                    self.assert_pending(case, token=status["session"])
                    self.assertEqual(case.destination.read_bytes(), CONTENT)
                    self.assertFalse(any(call[1] == "create-keychain" for call in case.model.calls))
                self.fresh_recovery(case, token=status["session"])

    def test_owned_final_admission_snapshot_is_rechecked_after_its_close(self):
        for effect in ("same", "different", "metadata"):
            with self.subTest(effect=effect):
                case = self.case()
                seam = ProfileIO(case.destination, "after-close", effect, armed=False)
                real_event = signing.SigningSession.profile_event
                events = []

                def observer(session, phase, **kwargs):
                    events.append(phase)
                    real_event(session, phase, **kwargs)
                    if phase == "stage-removed":
                        seam.armed = True

                stack, context = self.context(case)
                with stack, patch.object(credentials, "os", seam.os), \
                     patch.object(signing.SigningSession, "profile_event", new=observer), self.assertRaises(CredentialError):
                    with context:
                        self.fail("changed final read was admitted before ExitStack registration")
                seam.assert_preserved(self)
                self.assertNotIn("resolved", events)
                self.assertEqual(sum(entry["name"] == case.destination.name for entry in seam.opened), 1)
                self.assertFalse(any(call[1] == "create-keychain" for call in case.model.calls))
                status = signing.signing_status(home=case.home)
                self.assert_pending(case, token=status["session"])
                self.fresh_recovery(case, token=status["session"],
                                    expected="recovered" if effect == "metadata" else "recovered-with-conflict")

    def test_one_shot_cleanup_stat_and_unlink_errors_are_not_retried_by_outer_owner(self):
        for operation in ("stat", "unlink"):
            for after in ((False, True) if operation == "unlink" else (False,)):
                with self.subTest(operation=operation, after=after):
                    case = self.case()
                    proxy = SimpleNamespace(**vars(os))
                    real = getattr(os, operation)
                    armed, failed, calls = False, False, []

                    def failing(name, *args, **kwargs):
                        nonlocal failed
                        if armed and name == case.destination.name:
                            calls.append(True)
                            if not failed:
                                failed = True
                                if after:
                                    real(name, *args, **kwargs)
                                raise OSError("fictional one-shot cleanup failure")
                        return real(name, *args, **kwargs)

                    setattr(proxy, operation, failing)
                    stack, context = self.context(case)
                    with stack, patch.object(credentials, "os", proxy), patch.object(signing, "os", proxy), \
                         self.assertRaises(CredentialError):
                        with context:
                            armed = True
                    self.assertTrue(failed)
                    self.assertEqual(len(calls), 1, "an implicit additional owner retried the failed profile operation")
                    status = signing.signing_status(home=case.home)
                    self.assert_pending(case, token=status["session"])
                    self.assertEqual(case.destination.exists(), not after)
                    self.assertEqual(case.model.preferences, case.model.original)
                    self.fresh_recovery(case, token=status["session"])

    def setup_stage_case(self, role, cut, *, absent=False):
        case = self.case()
        seam = SetupStageIO(case.destination.parent / "not-the-stage", cut, absent=absent)
        real_event = signing.SigningSession.profile_event
        events, original, borrowed = [], {}, []

        def link(source, destination, **kwargs):
            if role == "borrowed":
                case.destination.write_bytes(CONTENT)
                case.destination.chmod(0o600)
                borrowed.append(case.destination.stat())
            elif role == "owned-eexist":
                os.link(source, destination, **kwargs)
            return os.link(source, destination, **kwargs)  # Both EEXIST outcomes are real syscalls.

        def observer(session, phase, **kwargs):
            real_event(session, phase, **kwargs)
            events.append(phase)
            if phase == "linked":
                original.update(path=session.path, token=session.token,
                                intent=(session.path / "intent.json").read_bytes(),
                                identity=identity((session.path / "intent.json").stat()))
                seam.target = case.destination.parent / session.intent["profile"]["stage"]
                seam.armed = True

        seam.os.link = link
        stack, context = self.context(case)
        with stack, patch.object(credentials, "os", seam.os), patch.object(signing, "os", seam.os), \
             patch.object(signing.SigningSession, "profile_event", new=observer), self.assertRaises(CredentialError):
            with context:
                self.fail("failed setup-stage operation admitted signing/native creation")
        self.assertTrue(seam.changed, "the real stage boundary was not reached")
        self.assertEqual(seam.active, {}, "an acquired production descriptor survived both owners")
        self.assertFalse(any(call[1] == "create-keychain" or Path(call[0]).name == "openssl" for call in case.model.calls))
        self.assertEqual(case.model.preferences, case.model.original)
        self.assertIsNone(case.model.keychain)
        self.assertEqual(case.destination.exists(), role == "borrowed")
        if borrowed:
            self.assertTrue(signing._same_file_state(borrowed[0], case.destination.stat()))
            self.assertEqual(case.destination.read_bytes(), CONTENT)

        conflict = not absent or cut == "comparison-stat"
        if conflict:
            self.assertFalse(any(item["afterFailure"] for item in seam.attempts), "a cleanup owner retried the failed stage name")
            self.assertNotIn("resolved", events)
            session = self.assert_pending(case, token=original["token"])
            self.assertEqual(session, original["path"])
            self.assertEqual((session / "intent.json").read_bytes(), original["intent"])
            self.assertEqual(identity((session / "intent.json").stat()), original["identity"])
            self.assertEqual(json.loads((session / "state.json").read_bytes())["profile"]["phase"], "linked")
            if not absent and cut != "unlink-after":
                self.assertEqual(identity(seam.target.stat()), identity(seam.after))
                self.assertEqual(seam.target.stat().st_mode, seam.after.st_mode)
                self.assertEqual(seam.target.read_bytes(), CONTENT)
            else:
                self.assertFalse(seam.target.exists())
            self.fresh_recovery(case, token=original["token"])
        else:
            self.assertIn("resolved", events)
            self.assertEqual(signing.signing_status(home=case.home)["status"], "idle")
            self.assertFalse(original["path"].exists())
        self.assertFalse(seam.target.exists())
        if absent:
            self.assertEqual(identity(seam.moved.stat()), identity(seam.before))
            self.assertEqual(seam.moved.read_bytes(), CONTENT)  # Fixture-owned moved inode, never adopted/deleted.
        if borrowed:
            self.assertTrue(signing._same_file_state(borrowed[0], case.destination.stat()))

    def test_setup_stage_errors_keep_original_authority_without_same_name_retry(self):
        for role in ("owned", "borrowed", "owned-eexist"):
            for cut in ("first-stat", "comparison-stat", "unlink-before", "unlink-after"):
                with self.subTest(role=role, cut=cut):
                    self.setup_stage_case(role, cut)

    def test_setup_stage_absence_preserves_its_boundary_specific_semantics(self):
        for role in ("owned", "borrowed", "owned-eexist"):
            for cut in ("first-stat", "comparison-stat", "unlink-before"):
                with self.subTest(role=role, cut=cut):
                    self.setup_stage_case(role, cut, absent=True)

    def test_real_eexist_borrower_has_one_validated_last_cleanup_observation(self):
        for effect in ("stable", "metadata", "same", "different", "remove"):
            with self.subTest(effect=effect):
                case = self.case()
                seam = ProfileIO(case.destination, "final-borrowed-stat", effect, armed=False)
                real_reader, real_event = credentials._read_regular_at, signing.SigningSession.profile_event
                reads, observations, events, original = [], [], [], {}

                def link(source, destination, **kwargs):
                    case.destination.write_bytes(CONTENT)
                    case.destination.chmod(0o600)
                    return os.link(source, destination, **kwargs)  # Genuine foreign-owned EEXIST.

                def reader(fd, name):
                    value = real_reader(fd, name)
                    if seam.armed and name == case.destination.name:
                        self.assertFalse(any(item["name"] == name for item in seam.active.values()), "raw read has not closed")
                        reads.append(value[1])
                    return value

                def observing(name, *args, **kwargs):
                    if seam.armed and name == case.destination.name:
                        if reads and effect != "stable":
                            seam.change()  # Before the actual final post-close stat, never an obsolete fourth stat.
                        observations.append({"afterReadClose": bool(reads), "afterChange": seam.changed})
                    return seam.stat(name, *args, **kwargs)

                def observer(session, phase, **kwargs):
                    real_event(session, phase, **kwargs)
                    events.append(phase)
                    if phase == "linked":
                        self.assertFalse(kwargs["owned"])
                        original.update(path=session.path, token=session.token, intent=(session.path / "intent.json").read_bytes())
                    elif phase == "resolved":
                        original["installerObservationCount"] = len(observations)

                seam.os.link, seam.os.stat = link, observing
                stack, context = self.context(case)
                with stack, patch.object(credentials, "os", seam.os), patch.object(signing, "os", seam.os), \
                     patch.object(credentials, "_read_regular_at", side_effect=reader), \
                     patch.object(signing.SigningSession, "profile_event", new=observer), \
                     (nullcontext() if effect == "stable" else self.assertRaises(CredentialError)):
                    with context:
                        original["profile"] = case.destination.stat()
                        seam.armed = True
                self.assertEqual(len(reads), 1)
                # Outer success reconciliation has its own validated observations;
                # failed installer observations must suppress that entire retry.
                installer_observations = observations[:3]
                self.assertEqual([item["afterReadClose"] for item in installer_observations], [False, False, True])
                self.assertEqual(seam.active, {})
                self.assertEqual(case.model.preferences, case.model.original)
                self.assertFalse(seam.unlinks)
                if effect == "stable":
                    self.assertFalse(seam.changed)
                    self.assertIn("resolved", events)
                    self.assertEqual(original["installerObservationCount"], 3, "borrowed cleanup ran an unused owned-role stat")
                    self.assertTrue(signing._same_file_state(original["profile"], case.destination.stat()))
                    self.assertEqual(signing.signing_status(home=case.home)["status"], "idle")
                else:
                    self.assertEqual(len(observations), 3, "unused owned-role stat or implicit outer retry")
                    seam.assert_preserved(self)
                    self.assertNotIn("resolved", events)
                    session = self.assert_pending(case, token=original["token"])
                    self.assertEqual((session / "intent.json").read_bytes(), original["intent"])
                    self.fresh_recovery(case, token=original["token"],
                                        expected="recovered" if effect == "metadata" else "recovered-with-conflict")

    def test_own_inode_eexist_and_interrupted_link_keep_owned_cleanup_authority(self):
        for outcome in ("own-eexist", "interrupt", "io-error"):
            with self.subTest(outcome=outcome):
                case = self.case()
                proxy = SimpleNamespace(**vars(os))
                linked, body = [], []

                def link(source, destination, **kwargs):
                    os.link(source, destination, **kwargs)
                    linked.append(identity(case.destination.stat()))
                    if outcome == "own-eexist":
                        return os.link(source, destination, **kwargs)
                    if outcome == "interrupt":
                        raise KeyboardInterrupt
                    raise OSError("fictional error after successful owned link")

                proxy.link = link
                expected = nullcontext() if outcome == "own-eexist" else self.assertRaises(KeyboardInterrupt if outcome == "interrupt" else CredentialError)
                stack, context = self.context(case)
                with stack, patch.object(credentials, "os", proxy), expected:
                    with context:
                        body.append(True)
                        self.assertEqual(identity(case.destination.stat()), linked[0])
                self.assertEqual(len(linked), 1)
                self.assertEqual(bool(body), outcome == "own-eexist")
                self.assertFalse(case.destination.exists())
                self.assertEqual(list(case.destination.parent.iterdir()), [])
                self.assertEqual(signing.signing_status(home=case.home)["status"], "idle")
                self.assertEqual(case.model.preferences, case.model.original)

    def test_stable_hardlinks_and_own_unlink_metadata_are_valid(self):
        for borrowed in (False, True):
            with self.subTest(borrowed=borrowed):
                case = self.case(borrowed=borrowed)
                if borrowed:
                    os.link(case.destination, case.root / "independently-owned-alias")
                    original = case.destination.stat()
                stack, context = self.context(case)
                with stack, context:
                    self.assertEqual(case.destination.read_bytes(), CONTENT)
                self.assertEqual(signing.signing_status(home=case.home)["status"], "idle")
                if borrowed:
                    self.assertTrue(signing._same_file_state(original, case.destination.stat()))
                    self.assertEqual(case.destination.stat().st_nlink, 2)
                else:
                    self.assertFalse(case.destination.exists())

    def test_stable_initial_rejection_and_owned_disappearance_do_not_invent_conflicts(self):
        case = self.case(borrowed=True)
        case.destination.write_bytes(OTHER)
        original = case.destination.stat()
        stack, context = self.context(case)
        with stack, self.assertRaisesRegex(CredentialError, "different provisioning profile"):
            with context:
                self.fail("different initial content entered signing")
        self.assertEqual(signing.signing_status(home=case.home)["status"], "idle")
        self.assertTrue(signing._same_file_state(original, case.destination.stat()))
        self.assertEqual(case.destination.read_bytes(), OTHER)
        self.assertIsNone(case.model.keychain)

        case = self.case()
        seam = ProfileIO(case.destination, "before-open", "remove", armed=False)
        stack, context = self.context(case)
        with stack, patch.object(credentials, "os", seam.os):
            with context:
                seam.armed = True
                seam.stats.clear()
        seam.assert_preserved(self)
        self.assertEqual(signing.signing_status(home=case.home)["status"], "idle")
        self.assertEqual(case.model.preferences, case.model.original)

    def test_original_preexisting_snapshot_and_later_owned_identity_both_survive(self):
        case = self.case(borrowed=True)
        with signing.local_signing_lease(home=case.home) as lease:
            session = lease.session(token=TOKEN)
            session.open(create=True)
            session.bind_runner(case.model)
            session.prepare(CONTENT, UUID)
            original = case.destination.stat()
            case.destination.rename(case.root / "original-removed-by-fixture")
            with credentials._temporary_profile_installation(
                CONTENT, UUID, case.home, cancellation=lease.cancellation,
                observer=session.profile_event, reserved_stage=session.intent["profile"]["stage"], retain=lambda: True,
            ):
                self.assertNotEqual(identity(case.destination.stat()), identity(original))
        self.fresh_recovery(case, expected="recovered-with-conflict")
        self.assertFalse(case.destination.exists())
        self.assertEqual(identity((case.root / "original-removed-by-fixture").stat()), identity(original))

    def test_manual_recheck_is_explicit_new_observation_not_implicit_retry(self):
        case = self.case()
        self.seed(case)
        seam = ProfileIO(case.destination, "after-close", "metadata")
        confirmed = []

        def owner_recheck():
            self.assertTrue(seam.changed)
            self.assertEqual(identity(case.destination.stat()), identity(seam.after))
            self.assertEqual(case.destination.stat().st_mode, seam.after.st_mode)
            self.assertEqual(case.destination.read_bytes(), CONTENT)
            self.assertFalse(seam.unlinks)
            # Interactive recovery MUST still hold the account/session; only
            # the completed profile read/directory lifetimes have ended here.
            self.assertEqual({entry["name"] for entry in seam.active.values()},
                             {str(case.home), signing.LEASE_DIRECTORY, "session-" + TOKEN, "keychain"})
            self.assertEqual((case.session / "intent.json").read_bytes(), case.intent)
            confirmed.append(True)  # Exact explicit TTY input authorizes another observation.

        with patch.object(signing, "os", seam.os):
            code, stdout, stderr = self.invoke(case, manual=True, callback=owner_recheck)
        self.assertEqual(confirmed, [True])
        self.assertEqual(code, 0, stderr)
        self.assertIn("Recovery remains locked", stdout)
        self.assertIn('"status": "recovered"', stdout)
        self.assertFalse(stderr)
        self.assertEqual(seam.active, {})
        self.assertEqual(len(seam.unlinks), 1)
        self.assertFalse(case.destination.exists())

    def test_private_control_reader_and_profile_evidence_keep_their_contracts(self):
        case = self.case(borrowed=True)
        self.seed(case)
        intent = json.loads(case.intent)
        self.assertEqual(set(intent["profile"]["before"]), {"identity", "sha256"})
        self.assertEqual(intent["profile"]["before"]["sha256"], hashlib.sha256(CONTENT).hexdigest())
        fd = os.open(case.session, os.O_RDONLY | os.O_DIRECTORY)
        try:
            value, details = signing._read_regular(fd, "intent.json", signing.CONTROL_LIMIT, private=True)
            self.assertEqual(value, case.intent)
            self.assertTrue(signing._same_file_state(details, (case.session / "intent.json").stat()))
            self.assertIsNone(signing._read_regular(fd, "absent.json", signing.CONTROL_LIMIT, private=True))
        finally:
            os.close(fd)
        self.fresh_recovery(case)


if __name__ == "__main__":
    unittest.main()
