"""Fatal recovery boundaries use actual handles/journals, never real keychains."""
from __future__ import annotations

import base64
import errno
import io
import json
import os
import plistlib
import signal
import stat
import sys
import tempfile
import unittest
from contextlib import ExitStack, contextmanager, nullcontext, redirect_stderr, redirect_stdout
from pathlib import Path
from types import FunctionType, SimpleNamespace
from unittest.mock import patch

import mobile_release
from mobile_release import build_inputs, cancellation, cli, credentials, local_signing as signing, owned_process as owned
from mobile_release.cancellation import DefaultCancellation, cancellation_owner
from mobile_release.errors import CredentialError
from workflow.local_signing_workload import worker_timeout
from .ios_entitlement_helpers import profile
from .local_signing_helpers import NativeSigningModel, completed_case_directory, fictional_signing_profile, model_result
from .local_signing_algorithm_helpers import refuse_signing_execution
from .local_signing_workspace import NativeCaseWorkspaceMixin
from workflow.local_signing_regression_catalog import HANDLER_RESTORATION_VARIANTS

TOKEN = "b" * 32
UUID = "12345678-1234-1234-1234-1234567890AB"
CONTENT = b"fictional-authenticated-profile"

FATAL_BODY_NATIVE_VARIANTS = (("public-00", False, False),)
FATAL_BODY_INERT_VARIANTS = (
    ("public-01", False, True),
    ("public-11", True, True),
    ("public-00", False, False),
    ("public-10", True, False),
)


class TTY(io.StringIO):
    def __init__(self, callback=None):
        super().__init__()
        self.reads, self.callback = 0, callback

    def isatty(self):
        return True

    def readline(self, maximum):
        self.reads += 1
        if self.callback is not None:
            self.callback()
        return "recheck " + TOKEN + "\n"


class DescriptorFault:
    """Module-local close seam; observe live identity BEFORE test-only fallback."""
    def __init__(self, root, predicate, *, after=False, armed=True, maximum=1, on_fault=None):
        self.root, self.predicate, self.after, self.armed = root, predicate, after, armed
        self.maximum, self.on_fault = maximum, on_fault
        self.opened, self.active, self.faults, self.closed = [], {}, [], []
        self.os = SimpleNamespace(**vars(os))
        self.os.open, self.os.dup, self.os.close = self.open, self.dup, self.close

    @staticmethod
    def identity(fd):
        try:
            value = os.fstat(fd)
        except OSError as error:
            if error.errno == errno.EBADF:
                return None
            raise
        return value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode)

    def record(self, fd, name, flags=None):
        entry = {"fd": fd, "name": str(name), "flags": flags, "identity": self.identity(fd)}
        self.opened.append(entry)
        self.active[fd] = entry
        return fd

    def open(self, name, flags, *args, **kwargs):
        return self.record(os.open(name, flags, *args, **kwargs), name, flags)

    def dup(self, fd):
        return self.record(os.dup(fd), "duplicate")

    def close(self, fd):
        entry = self.active.pop(fd, None)
        event = (fd, self.identity(fd))
        close_index = len(self.closed)
        self.closed.append(event)
        if entry is not None and self.armed and len(self.faults) < self.maximum and self.predicate(entry):
            fault = {**entry, "entry": entry, "retainedIdentity": entry["identity"], "closeIndex": close_index}
            self.faults.append(fault)
            if self.on_fault is not None:
                self.on_fault()
            if self.after:
                os.close(fd)
                path = self.root / ("foreign-reused-descriptor-" + str(len(self.faults)))
                replacement = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
                if replacement != fd:
                    os.dup2(replacement, fd)
                    os.close(replacement)
                os.write(fd, b"independent fictional descriptor")
                fault["retainedIdentity"] = self.identity(fd)
            raise OSError("fictional-private-close-canary")
        result = os.close(fd)
        if entry is not None and event == (entry["fd"], entry["identity"]):
            # An attempted close or another acquisition's equal tuple is not
            # evidence that this exact opened entry was successfully closed.
            entry["normalCloseIndex"] = close_index
        return result

    def assert_observed(self, testcase):
        testcase.assertEqual(len(self.faults), self.maximum)
        testcase.assertEqual(self.active, {}, "an independent descriptor was not closed")
        for fault in self.faults:
            testcase.assertEqual(self.identity(fault["fd"]), fault["retainedIdentity"])
            testcase.assertEqual(self.closed[fault["closeIndex"]:].count((fault["fd"], fault["identity"])), 1)
            if self.after:
                testcase.assertNotIn((fault["fd"], fault["retainedIdentity"]),
                                     self.closed[fault["closeIndex"] + 1:])
                testcase.assertEqual(os.pread(fault["fd"], 100, 0), b"independent fictional descriptor")
        for entry in self.opened:
            if any(entry is fault["entry"] for fault in self.faults):
                continue
            identity = self.identity(entry["fd"])
            close_index = entry.get("normalCloseIndex")
            # FD/inode/type can recur after a prior handle and file disappear.
            # Only this entry's returned close, before the later fault, can
            # explain a currently equal historical identity. A before-close
            # fault can retain a reopened original just as an after-close fault
            # can retain a replacement with that same descriptor and identity.
            recycled = close_index is not None and any(
                0 <= close_index < fault["closeIndex"]
                and self.closed[close_index] == (entry["fd"], entry["identity"])
                and entry["fd"] == fault["fd"] and identity == fault["retainedIdentity"]
                for fault in self.faults)
            if not recycled:
                testcase.assertNotEqual(identity, entry["identity"])

    def __enter__(self):
        return self

    def __exit__(self, *_):
        for fault in self.faults:
            # Never retry production's close or guess a recycled FD identity.
            if self.identity(fault["fd"]) == fault["retainedIdentity"]:
                os.close(fault["fd"])
        # Failure-only fallback for any additional proven test-owned handle.
        # assert_observed above must establish absence before this runs.
        for entry in self.active.values():
            if self.identity(entry["fd"]) == entry["identity"]:
                os.close(entry["fd"])


class DescriptorFaultHistoryTests(unittest.TestCase):
    """Inert observation chronology, not native descriptor/recovery evidence."""

    @staticmethod
    def fixture():
        state = SimpleNamespace(live={}, content=b"independent fictional descriptor")

        def close(fd):
            del state.live[fd]

        modeled = SimpleNamespace(close=close, pread=lambda *_args: state.content)
        seam = SimpleNamespace(opened=[], active={}, faults=[], closed=[], after=False,
                               armed=True, maximum=1, on_fault=None,
                               predicate=lambda entry: entry["name"] == "fault",
                               identity=state.live.get)
        # Bind the actual observation methods to an isolated, minimal namespace.
        # Neither this fixture nor its doubles can call a real descriptor API;
        # the native after-close replacement itself stays a separate G obligation.
        for name in ("record", "close", "assert_observed"):
            original = getattr(DescriptorFault, name)
            method = FunctionType(original.__code__, {"os": modeled}, name, original.__defaults__)
            setattr(seam, name, method.__get__(seam))
        return seam, state, modeled

    def test_recycled_identity_observation_is_acquisition_scoped(self):
        fd, retained, other = 211, (1, 10, stat.S_IFREG), (1, 20, stat.S_IFREG)
        mutations = (None, "retained-close", "original-close", "missing-success", "late-success",
                     "wrong-success-event", "different-acquisition", "unrelated-live", "identity", "content")
        for after, original_equals_retained in ((False, True), (True, False), (True, True)):
            for mutation in mutations:
                if not after and mutation == "content":
                    continue  # Only the after-close replacement has canary bytes.
                with self.subTest(after=after, original_equals_retained=original_equals_retained, mutation=mutation):
                    seam, state, _ = self.fixture()
                    state.live[fd] = retained
                    seam.record(fd, "historical")
                    historical = seam.opened[-1]
                    seam.close(fd)
                    self.assertEqual(historical["normalCloseIndex"], 0)
                    original = retained if original_equals_retained else other
                    state.live[fd] = original
                    seam.record(fd, "fault")
                    with self.assertRaisesRegex(OSError, "fictional-private-close-canary"):
                        seam.close(fd)
                    fault = seam.faults[0]
                    self.assertIs(fault["entry"], seam.opened[-1])
                    self.assertNotIn("normalCloseIndex", fault["entry"])
                    if after:
                        # Model the already-created retained replacement, with no
                        # native close/open call or claim about OS allocation.
                        state.live[fd] = fault["retainedIdentity"] = retained
                        seam.after = True
                    else:
                        # The injected before-close failure leaves this original
                        # acquisition live; no replacement is created or claimed.
                        self.assertEqual(state.live[fd], original)
                        self.assertEqual(fault["retainedIdentity"], original)
                    if mutation == "retained-close":
                        seam.closed.append((fd, retained))
                    elif mutation == "original-close":
                        seam.closed.append((fd, original))
                    elif mutation == "missing-success":
                        del historical["normalCloseIndex"]
                    elif mutation == "late-success":
                        historical["normalCloseIndex"] = fault["closeIndex"]
                    elif mutation == "wrong-success-event":
                        seam.closed[0] = (fd, other)
                    elif mutation == "different-acquisition":
                        seam.opened.append({"fd": fd, "identity": retained, "name": "unclosed"})
                    elif mutation == "unrelated-live":
                        state.live[fd + 1] = retained
                        seam.opened.append({"fd": fd + 1, "identity": retained, "name": "independent"})
                    elif mutation == "identity":
                        state.live[fd] = other
                    elif mutation == "content":
                        state.content = b"changed fictional descriptor"
                    if mutation is None:
                        seam.assert_observed(self)
                    else:
                        with self.assertRaises(AssertionError):
                            seam.assert_observed(self)

    def test_normal_close_success_is_exact_and_recorded_after_return(self):
        fd, identity, other = 211, (1, 10, stat.S_IFREG), (1, 20, stat.S_IFREG)
        for outcome in ("returned", "raised", "changed-identity"):
            with self.subTest(outcome=outcome):
                seam, state, modeled = self.fixture()
                seam.maximum = 0
                state.live[fd] = identity
                seam.record(fd, "ordinary")
                entry, delegate = seam.opened[-1], modeled.close
                if outcome == "changed-identity":
                    state.live[fd] = other

                def closing(descriptor):
                    self.assertNotIn("normalCloseIndex", entry)
                    # Another observed event during the call cannot replace the
                    # original call's captured index when that call returns.
                    seam.closed.append((fd + 1, other))
                    if outcome == "raised":
                        raise OSError("inert ordinary close failure")
                    return delegate(descriptor)

                modeled.close = closing
                if outcome == "raised":
                    with self.assertRaisesRegex(OSError, "inert ordinary close failure"):
                        seam.close(fd)
                else:
                    self.assertIsNone(seam.close(fd))
                self.assertEqual(len(seam.closed), 2)
                if outcome == "returned":
                    self.assertEqual(entry["normalCloseIndex"], 0)
                    seam.assert_observed(self)
                else:
                    self.assertNotIn("normalCloseIndex", entry)
                    state.live[fd] = identity
                    with self.assertRaises(AssertionError):
                        seam.assert_observed(self)


class SigningFailureTests(NativeCaseWorkspaceMixin, unittest.TestCase):
    def setUp(self):
        self.root = self.native_case_directory(prefix="mrk-signing-fatal-")
        self.serial = 0

    def case(self, *, borrowed=False, seed=True):
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
        model = NativeSigningModel(home)
        if seed:
            with signing.local_signing_lease(home=home) as lease:
                session = lease.session(token=TOKEN)
                session.bind_runner(model)
                session.open(create=True)
                session.prepare(CONTENT, UUID)
        return root, home, destination, model

    def fresh_recovery(self, home, model, *, expected="recovered", token=TOKEN):
        # New interpreter, actual CLI/parser/recovery, installed runtime path when
        # this test is run by the wheel gate. Only native preferences are modeled.
        code = """
import json,sys
from pathlib import Path
from unittest.mock import patch
sys.path[:0] = sys.argv[1:3]
from mobile_release import cli, local_signing as signing
from unit.local_signing_helpers import NativeSigningModel
home=Path(sys.argv[3]); supplied=json.loads(sys.argv[4]); token=sys.argv[5]
model=NativeSigningModel(home); model.preferences=supplied['preferences']
model.keychain=Path(supplied['keychain']) if supplied['keychain'] else None
lease=signing.local_signing_lease
with patch.object(signing,'local_signing_lease',side_effect=lambda **kw: lease(**{**kw,'home':home})), patch.object(signing,'run_owned',model):
    status=cli.main(['local-signing','recover','--session',token,'--confirm',signing.CONFIRMATION])
if status in (0, 1):
    with lease(home=home) as renewed:
        renewed.assert_owner()
raise SystemExit(status)
"""
        result = owned.run_owned(
            [sys.executable, "-I", "-S", "-B", "-c", code,
             str(Path(mobile_release.__file__).resolve().parent.parent), str(Path(__file__).parents[1]),
             str(home), json.dumps({"preferences": model.preferences, "keychain": str(model.keychain) if model.keychain else None}), token],
            cwd=self.root, environ={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(home)},
            capture=True, output_limit=64 * 1024, timeout=worker_timeout("fresh-cli-recovery"),
        )
        self.assertEqual(result.returncode, 1 if expected == "recovered-with-conflict" else 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"status": expected, "session": token})
        self.assertFalse(result.stderr)
        self.assertEqual(signing.signing_status(home=home)["status"], "idle")

    def signing_context(self, root, home, model, *, runner=None):
        private = root / "private"
        private.mkdir(mode=0o700, exist_ok=True)
        project = root / "project"
        project.mkdir(mode=0o700, exist_ok=True)
        p12, supplied = root / "input.p12", root / "input.mobileprovision"
        p12.write_bytes(b"fictional-p12")
        supplied.write_bytes(CONTENT)
        p12.chmod(0o600)
        supplied.chmod(0o600)
        payload = profile()
        payload["UUID"] = UUID
        stack = ExitStack()
        stack.enter_context(patch("mobile_release.credentials._authenticated_signing_profile",
                                  side_effect=lambda path, *, cancellation: fictional_signing_profile(
                                      path, cancellation=cancellation, payload=payload)))
        stack.enter_context(patch("mobile_release.credentials._run_private", side_effect=runner or model))
        context = credentials._temporary_apple_signing_environment(
            p12=p12, password="fictional-password", profile=supplied, directory=private, home=home,
            project_root=project,
        )
        return stack, context

    def assert_fatal(self, error, *, dispatched=False, contained=True):
        # Fatal wrapper projection includes actual earlier dispatch in the
        # same original guard, not just the operation whose close failed.
        self.assertIsInstance(error, owned.ProcessError)
        self.assertTrue(error.fatal)
        self.assertFalse(error.cleanup_complete)
        self.assertEqual((error.dispatched, error.contained), (dispatched, contained))
        self.assertNotIn("fictional-private-close-canary", str(error))

    def test_actual_query_resource_failure_never_authorizes_manual_or_automatic_recovery(self):
        # This is the recovery/resource composition contract. The command owner
        # separately covers actual transport faults; no retired selector or
        # process API is mocked into fabricated command finality here.
        for phase, manual in (("initial", False), ("initial", True), ("later", False),
                              ("later", True), ("manual-recheck", True)):
            with self.subTest(phase=phase, manual=manual):
                root, home, _, model = self.case()
                session_path = home / signing.LEASE_DIRECTORY / ("session-" + TOKEN)
                intent = (session_path / "intent.json").read_bytes()
                unknown = session_path / "keychain/fictional-unknown-stage"
                if phase == "manual-recheck":
                    unknown.write_bytes(b"independently known test fixture")
                input_stream = TTY(unknown.unlink if phase == "manual-recheck" else None)
                output, calls_after = TTY(), []
                observation = root / "query-observation.bin"
                observation.write_bytes(b"fictional local query observation")
                observation.chmod(0o600)
                root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                calls, failed = 0, False
                failure_at = 3 if phase == "later" else 1
                try:
                    with DescriptorFault(root, lambda entry: entry["name"] == observation.name) as fault:
                        def runner(argv, **kwargs):
                            nonlocal calls, failed
                            calls += 1
                            if failed:
                                calls_after.append(argv)
                            result = model(argv, **kwargs)  # Genuine target and original command outcome.
                            if calls == failure_at:
                                failed = True
                                with patch.object(signing, "os", fault.os):
                                    signing._read_regular(root_fd, observation.name, 1024, private=True)
                            return result
                        with self.assertRaises(owned.ProcessError) as caught:
                            signing.recover_signing(TOKEN, signing.CONFIRMATION, home=home, runner=runner,
                                                    manual=manual, input_stream=input_stream, output_stream=output)
                        self.assert_fatal(caught.exception, dispatched=True)
                        self.assertEqual(input_stream.reads, int(phase == "manual-recheck"))
                        self.assertEqual("Recovery remains locked" in output.getvalue(), phase == "manual-recheck")
                        self.assertEqual(calls_after, [])
                        fault.assert_observed(self)
                        self.assertEqual((session_path / "intent.json").read_bytes(), intent)
                        self.assertEqual(signing.signing_status(home=home)["status"], "pending")
                        with self.assertRaises(signing.SigningPending):
                            with signing.local_signing_lease(home=home):
                                self.fail("pending ownership admitted a new signing session")
                finally:
                    os.close(root_fd)
                self.fresh_recovery(home, model)
                self.fresh_recovery(home, model, expected="absent")

    def test_profile_read_and_directory_close_failures_cannot_be_successful_conflicts(self):
        for label in (UUID + ".mobileprovision", "Provisioning Profiles"):
            for after in (False, True):
                for manual in (False, True):
                    with self.subTest(label=label, after=after, manual=manual):
                        root, home, destination, model = self.case(borrowed=True)
                        session_path = home / signing.LEASE_DIRECTORY / ("session-" + TOKEN)
                        intent = (session_path / "intent.json").read_bytes()
                        input_stream, output, calls_at_failure = TTY(), TTY(), []
                        with DescriptorFault(root, lambda e: e["name"] == label, after=after,
                                             on_fault=lambda: calls_at_failure.append(len(model.calls))) as fault:
                            with patch.object(signing, "os", fault.os), self.assertRaises(owned.ProcessError) as caught:
                                signing.recover_signing(TOKEN, signing.CONFIRMATION, home=home, runner=model,
                                                       manual=manual, input_stream=input_stream, output_stream=output)
                            self.assert_fatal(caught.exception, dispatched=True)
                            fault.assert_observed(self)
                            self.assertEqual(input_stream.reads, 0)
                            self.assertFalse(output.getvalue())
                            self.assertEqual(calls_at_failure, [len(model.calls)])
                            self.assertEqual((session_path / "intent.json").read_bytes(), intent)
                            self.assertFalse((session_path / "completed.json").exists())
                            self.assertEqual(signing.signing_status(home=home)["status"], "pending")
                            self.assertEqual(destination.read_bytes(), CONTENT)
                            self.assertEqual(model.preferences, model.original)
                        self.fresh_recovery(home, model)
                        self.assertEqual(destination.read_bytes(), CONTENT)

    def test_installer_cleanup_fatal_preserves_pending_and_all_independent_handles(self):
        for borrowed in (False, True):
            for after in (False, True):
                with self.subTest(borrowed=borrowed, after=after):
                    root, home, destination, model = self.case(borrowed=borrowed, seed=False)
                    with DescriptorFault(root, lambda e: e["name"] == destination.name, after=after, armed=False) as fault:
                        stack, context = self.signing_context(root, home, model)
                        with stack, patch.object(credentials, "os", fault.os), self.assertRaises(owned.ProcessError) as caught:
                            with context:
                                fault.armed = True
                        self.assert_fatal(caught.exception, dispatched=True)
                        fault.assert_observed(self)
                        status = signing.signing_status(home=home)
                        self.assertEqual(status["status"], "pending")
                        session_path = home / signing.LEASE_DIRECTORY / ("session-" + status["session"])
                        self.assertFalse((session_path / "completed.json").exists())
                        self.assertEqual(destination.read_bytes(), CONTENT)
                        self.assertEqual(model.preferences, model.original)
                    self.fresh_recovery(home, model, token=status["session"])
                    self.assertEqual(destination.exists(), borrowed)

    def test_initial_and_link_race_fatal_snapshots_are_never_retried_or_marked_resolved(self):
        for raced in (False, True):
            for after in (False, True):
                with self.subTest(raced=raced, after=after):
                    root, home, destination, model = self.case(borrowed=not raced, seed=False)
                    events, original_intents, linked_stages, foreign_inodes = [], [], [], []
                    real_event = signing.SigningSession.profile_event

                    def event(session, phase, **kwargs):
                        events.append(phase)
                        return real_event(session, phase, **kwargs)

                    def observed_failure():
                        session_path, = (home / signing.LEASE_DIRECTORY).iterdir()
                        original_intents.append((session_path / "intent.json").read_bytes())

                    def raced_link(source, target, **kwargs):
                        self.assertEqual(target, destination.name)
                        # Simulate an independent, valid same-UUID installation
                        # winning no-clobber link creation. Never use toolkit FDs.
                        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
                                     dir_fd=kwargs["dst_dir_fd"])
                        try:
                            os.write(fd, CONTENT)
                            os.fsync(fd)
                            foreign_inodes.append(os.fstat(fd).st_ino)
                        finally:
                            os.close(fd)
                        linked_stages.append(destination.parent / source)
                        return os.link(source, target, **kwargs)  # Actual EEXIST.

                    with DescriptorFault(root, lambda e: e["name"] == destination.name, after=after,
                                         on_fault=observed_failure) as fault:
                        if raced:
                            fault.os.link = raced_link
                        stack, context = self.signing_context(root, home, model)
                        with stack, patch.object(credentials, "os", fault.os), \
                             patch.object(signing.SigningSession, "profile_event", new=event), \
                             self.assertRaises(owned.ProcessError) as caught:
                            with context:
                                self.fail("fatal installation read admitted a signing body")
                        self.assert_fatal(caught.exception, dispatched=True)
                        fault.assert_observed(self)
                        self.assertEqual(events, ["inspected", "stage-intent", "stage-created", "link-intent"] if raced else [])
                        self.assertEqual(sum(entry["name"] == destination.name for entry in fault.opened), 1)
                        self.assertEqual(destination.read_bytes(), CONTENT)
                        self.assertEqual(model.preferences, model.original)
                        status = signing.signing_status(home=home)
                        self.assertEqual(status["status"], "pending")
                        session_path = home / signing.LEASE_DIRECTORY / ("session-" + status["session"])
                        self.assertEqual(original_intents, [(session_path / "intent.json").read_bytes()])
                        self.assertFalse((session_path / "completed.json").exists())
                        if raced:
                            self.assertEqual(foreign_inodes, [destination.stat().st_ino])
                            self.assertEqual(len(linked_stages), 1)
                            self.assertEqual(linked_stages[0].read_bytes(), CONTENT)
                    self.fresh_recovery(home, model, token=status["session"],
                                        expected="recovered-with-conflict" if raced else "recovered")
                    self.assertEqual(destination.read_bytes(), CONTENT)
                    self.assertTrue(all(not path.exists() for path in linked_stages))

    def test_session_and_lease_close_errors_attempt_every_handle_without_fd_retry(self):
        for target in ("keychain", "session-" + TOKEN, signing.LEASE_DIRECTORY, "home"):
            for after in (False, True):
                with self.subTest(target=target, after=after):
                    root, home, _, model = self.case(seed=False)
                    with DescriptorFault(root, lambda e: Path(e["name"]).name == target, after=after) as fault:
                        with patch.object(signing, "os", fault.os), self.assertRaises(owned.ProcessError) as caught:
                            with signing.local_signing_lease(home=home) as lease:
                                session = lease.session(token=TOKEN)
                                session.open(create=True)
                        self.assert_fatal(caught.exception)
                        fault.assert_observed(self)
                        self.assertTrue(session.closed)
                        self.assertIsNone(lease.active)
                        expected = "busy" if target == signing.LEASE_DIRECTORY and not after else "pending"
                        self.assertEqual(signing.signing_status(home=home)["status"], expected)
                    self.fresh_recovery(home, model)

    def test_terminal_close_error_is_not_success_and_does_not_recreate_journals(self):
        for after in (False, True):
            with self.subTest(after=after):
                root, home, _, model = self.case()
                input_stream, output = TTY(), TTY()
                with DescriptorFault(root, lambda e: e["name"] == "session-" + TOKEN, after=after) as fault:
                    with patch.object(signing, "os", fault.os), self.assertRaises(owned.ProcessError) as caught:
                        signing.recover_signing(TOKEN, signing.CONFIRMATION, home=home, runner=model,
                                               manual=True, input_stream=input_stream, output_stream=output)
                    self.assert_fatal(caught.exception, dispatched=True)
                    fault.assert_observed(self)
                    self.assertEqual(input_stream.reads, 0)
                    self.assertFalse(output.getvalue())
                    self.assertFalse((home / signing.LEASE_DIRECTORY / ("session-" + TOKEN)).exists())
                self.fresh_recovery(home, model, expected="absent")

    def test_fatal_body_quarantines_all_further_commands_regardless_of_public_dispatch_flags(self):
        for variant in FATAL_BODY_NATIVE_VARIANTS:
            with self.subTest(variant=variant[0]):
                self.run_native_fatal_body_variant(variant)

    def run_native_fatal_body_variant(self, variant):
        self.assertIn(variant, FATAL_BODY_NATIVE_VARIANTS)
        _name, dispatched, contained = variant
        root, home, destination, model = self.case(seed=False)
        stack, context = self.signing_context(root, home, model)
        with stack, self.assertRaises(owned.ProcessError) as caught:
            with context:
                calls = len(model.calls)
                raise owned.ProcessCleanupError("fictional body cleanup", dispatched=dispatched, contained=contained)
        # Real setup already dispatched under this guard. A false public flag
        # cannot erase it. The complete flag table has a separate inert caller.
        self.assert_fatal(caught.exception, dispatched=True, contained=contained)
        status = signing.signing_status(home=home)
        self.assertEqual(status["status"], "pending")
        self.assertTrue(destination.exists())
        self.assertEqual(len(model.calls), calls)
        self.fresh_recovery(home, model, token=status["session"])

    def test_actual_fatal_local_resource_in_body_cannot_finalize_or_release_signing_resources(self):
        root, home, destination, model = self.case(seed=False)
        observation = root / "body-observation.bin"
        observation.write_bytes(b"fictional independent local observation")
        observation.chmod(0o600)
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        stack, context = self.signing_context(root, home, model)
        try:
            with DescriptorFault(root, lambda entry: entry["name"] == observation.name) as fault:
                with stack, self.assertRaises(owned.ProcessError) as caught:
                    with context:
                        calls = len(model.calls)
                        session_path = model.keychain.parent.parent
                        intent = (session_path / "intent.json").read_bytes()
                        with patch.object(signing, "os", fault.os):
                            signing._read_regular(root_fd, observation.name, 1024, private=True)
                self.assert_fatal(caught.exception, dispatched=True)
                self.assertEqual(len(model.calls), calls)
                self.assertEqual(destination.read_bytes(), CONTENT)
                self.assertEqual((session_path / "intent.json").read_bytes(), intent)
                self.assertFalse((session_path / "completed.json").exists())
                status = signing.signing_status(home=home)
                self.assertEqual(status["status"], "pending")
                fault.assert_observed(self)  # Live failing FD before test-owned fallback.
        finally:
            os.close(root_fd)
        self.fresh_recovery(home, model, token=status["session"])

    def test_detached_exitstack_callback_retains_nonfatal_body_dispatch_before_later_fatal(self):
        for interrupted in (False, True):
            root, home, destination, model = self.case(seed=False)
            primary = (owned.ProcessInterrupted(dispatched=True, contained=True) if interrupted else
                       owned.ProcessError("fictional completed cleanup", dispatched=True))
            callback_facts = []

            class ObservedExitStack(ExitStack):
                def close(self):
                    try:
                        return super().close()
                    except owned.ProcessError as error:
                        # Actual stdlib boundary, before signing cleanup catches
                        # and merges its separately retained body facts.
                        pending, seen = [error], set()
                        while pending:
                            item = pending.pop()
                            if item is not None and id(item) not in seen:
                                seen.add(id(item))
                                pending.extend((item.__context__, item.__cause__))
                        callback_facts.append((id(primary) in seen, error.dispatched, error.fatal))
                        raise

            with self.subTest(interrupted=interrupted):
                with DescriptorFault(root, lambda e: e["name"] == destination.name, armed=False) as fault:
                    stack, context = self.signing_context(root, home, model)
                    expected = owned.ProcessInterrupted if interrupted else owned.ProcessError
                    with stack, patch.object(credentials, "os", fault.os), \
                         patch.object(credentials, "ExitStack", ObservedExitStack), self.assertRaises(expected) as caught:
                        with context:
                            guard = cancellation_owner(None, CredentialError, "fixed fixture owner")[0]
                            fault.armed = True
                            raise primary
                    if interrupted:
                        self.assertIs(caught.exception, primary)
                        self.assertTrue(guard.lifetime_ledger.fatal)
                    else:
                        self.assert_fatal(caught.exception, dispatched=True)
                    # The closer itself preserved the flags before ExitStack
                    # severed the body from the callback's full exception graph.
                    self.assertEqual(callback_facts, [(False, True, True)])
                    fault.assert_observed(self)
                    status = signing.signing_status(home=home)
                    self.assertEqual(status["status"], "pending")
                    self.assertTrue(destination.exists())
                self.fresh_recovery(home, model, token=status["session"])

    def test_genuine_nonzero_command_result_cannot_hide_later_independent_fatal_close(self):
        root, home, destination, model = self.case(seed=False)
        armed, failures, absent_at_close = False, [], []
        def runner(argv, **kwargs):
            nonlocal armed
            result = model(argv, **kwargs)
            if armed:
                armed = False
                failures.append(result.returncode)
                # Project an actual finalized target exit as a caller error;
                # this error supplies no settlement or cleanup authority.
                raise owned.ProcessError("fictional completed command rejection", dispatched=True)
            return result
        with DescriptorFault(root, lambda e: e["name"] == "Provisioning Profiles", armed=False,
                             on_fault=lambda: absent_at_close.append(not os.path.lexists(destination))) as fault:
            stack, context = self.signing_context(root, home, model, runner=runner)
            with stack, patch.object(credentials, "os", fault.os), self.assertRaises(owned.ProcessError) as caught:
                with context:
                    session_path = model.keychain.parent.parent
                    original_token = session_path.name.removeprefix("session-")
                    intent = (session_path / "intent.json").read_bytes()
                    armed = fault.armed = True
                    model.result_policy = lambda _argv: model_result(returncode=7, perform_effect=False)
            self.assertEqual(failures, [7])
            self.assert_fatal(caught.exception, dispatched=True)
            fault.assert_observed(self)
            status = signing.signing_status(home=home)
            self.assertEqual(status["status"], "pending")
            self.assertEqual(status["session"], original_token)
            # This fault is after the independently safe profile unlink, not
            # the earlier reader-close fault which must retain that profile.
            self.assertEqual(absent_at_close, [True])
            self.assertFalse(os.path.lexists(destination))
            self.assertEqual((session_path / "intent.json").read_bytes(), intent)
            self.assertFalse(os.path.lexists(session_path / "completed.json"))
            self.assertTrue(model.keychain.exists())
        model.result_policy = None
        self.fresh_recovery(home, model, token=status["session"])

    def test_actual_handler_restoration_cannot_mask_retained_resource_failure(self):
        for variant in HANDLER_RESTORATION_VARIANTS:
            with self.subTest(variant=variant):
                self.run_handler_restoration_variant(variant)

    def run_handler_restoration_variant(self, variant):
        self.assertIn(variant, HANDLER_RESTORATION_VARIANTS)
        boundary, masking = variant
        masking_type = {"OSError": OSError, "FileNotFoundError": FileNotFoundError,
                        "CredentialError": CredentialError, "KeyboardInterrupt": KeyboardInterrupt}[masking]
        root, home, destination, model = self.case(borrowed=True, seed=False)
        name = str(home) if boundary == "lease" else destination.name
        original_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        real_restore = DefaultCancellation.restore
        masked = []
        with DescriptorFault(root, lambda e: e["name"] == name, armed=boundary != "signing") as fault:
            def restore(guard):
                real_restore(guard)
                if fault.faults and not masked:
                    masked.append(True)
                    raise masking_type("fictional restoration canary")

            stack = ExitStack()
            context = None
            if boundary == "signing":
                stack, context = self.signing_context(root, home, model)
            try:
                with stack, patch.object(signing, "os", fault.os), patch.object(credentials, "os", fault.os), \
                     patch.object(DefaultCancellation, "restore", new=restore), self.assertRaises(owned.ProcessError) as caught:
                    if boundary == "read":
                        directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
                        try:
                            signing._profile_snapshot(directory, destination.name)
                        finally:
                            os.close(directory)
                    elif boundary == "lease":
                        with signing.local_signing_lease(home=home):
                            pass
                    elif boundary == "installer":
                        with credentials._temporary_profile_installation(CONTENT, UUID, home):
                            self.fail("initial read close failure admitted installer")
                    else:
                        with context:
                            fault.armed = True
                self.assert_fatal(caught.exception, dispatched=boundary == "signing")
                self.assertEqual(masked, [True])
                fault.assert_observed(self)
                self.assertEqual({sig: signal.getsignal(sig) for sig in original_handlers}, original_handlers)
            finally:
                for sig, handler in original_handlers.items():
                    signal.signal(sig, handler)
        status = signing.signing_status(home=home)
        if status["status"] == "pending":
            self.fresh_recovery(home, model, token=status["session"])

    def test_optional_missing_read_does_not_invent_a_new_failure_from_active_body_context(self):
        _, home, destination, _ = self.case(borrowed=True, seed=False)
        descriptor = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for active in (owned.ProcessCleanupError("contained predispatch body"),
                           owned.ProcessError("completed dispatched body", dispatched=True)):
                with self.subTest(active=type(active).__name__):
                    try:
                        raise active
                    except owned.ProcessError:
                        self.assertIsNone(signing._profile_snapshot(descriptor, "missing.mobileprovision"))
        finally:
            os.close(descriptor)

    def test_ordinary_missing_installer_snapshot_keeps_safe_predispatch_cleanup(self):
        for phase in ("linked", "body"):
            with self.subTest(phase=phase):
                root, home, destination, _ = self.case(seed=False)
                events, disappeared, guards = [], [], []
                primary = owned.ProcessCleanupError("contained predispatch body")
                armed = False
                with DescriptorFault(root, lambda _: False, maximum=0) as descriptors:
                    def opening(name, flags, *args, **kwargs):
                        nonlocal armed
                        if armed and name == destination.name:
                            armed = False
                            disappeared.append(True)
                            # Actual unlink after ownership stat, before opening
                            # the snapshot: missing ownership is not a new leak.
                            os.unlink(name, dir_fd=kwargs["dir_fd"])
                        return descriptors.open(name, flags, *args, **kwargs)

                    def observer(event, **kwargs):
                        nonlocal armed
                        events.append(event)
                        if not guards:
                            guards.append(cancellation_owner(None, CredentialError, "fixed test owner")[0])
                        if phase == "linked" and event == "linked":
                            armed = True
                            raise primary  # Stage still exists at this boundary.

                    descriptors.os.open = opening
                    with patch.object(credentials, "os", descriptors.os), self.assertRaises(owned.ProcessError) as caught:
                        with credentials._temporary_profile_installation(CONTENT, UUID, home, observer=observer):
                            self.assertEqual(phase, "body")
                            armed = True
                            raise primary
                    self.assert_fatal(caught.exception)
                    self.assertEqual(len(guards), 1)
                    self.assertIs(guards[0].lifetime_ledger._primary, primary)
                    self.assertEqual(disappeared, [True])
                    self.assertEqual(events[-1], "resolved")
                    self.assertFalse(destination.exists())
                    self.assertEqual(list(destination.parent.iterdir()), [])
                    descriptors.assert_observed(self)

    def test_ordinary_content_conflict_keeps_safe_predispatch_cleanup(self):
        for phase in ("linked", "body"):
            with self.subTest(phase=phase):
                root, home, destination, _ = self.case(seed=False)
                events, original_identity = [], []
                changed = b"ordinary same-inode independently modified content"
                # Explicit synthetic setup/body lifetime failure; the installer,
                # snapshot, content conflict, hardlinks and cleanup are real.
                primary = owned.ProcessCleanupError("synthetic contained predispatch setup/body failure")

                def change_content():
                    before = destination.stat()
                    original_identity.append((before.st_dev, before.st_ino))
                    destination.write_bytes(changed)
                    after = destination.stat()
                    self.assertEqual((after.st_dev, after.st_ino), original_identity[-1])

                def observer(event, **kwargs):
                    events.append(event)
                    if phase == "linked" and event == "linked":
                        self.assertTrue(list(destination.parent.glob(".mobile-release-profile-*")))
                        change_content()
                        raise primary  # The owned stage must still be cleaned.

                with DescriptorFault(root, lambda _: False, maximum=0) as descriptors:
                    with patch.object(credentials, "os", descriptors.os), self.assertRaises(owned.ProcessError) as caught:
                        with credentials._temporary_profile_installation(CONTENT, UUID, home, observer=observer):
                            self.assertEqual(phase, "body")
                            change_content()
                            raise primary
                    self.assert_fatal(caught.exception)
                    self.assertEqual(len(original_identity), 1)
                    self.assertEqual(destination.read_bytes(), changed)
                    after = destination.stat()
                    self.assertEqual((after.st_dev, after.st_ino), original_identity[0])
                    self.assertEqual(list(destination.parent.iterdir()), [destination])
                    self.assertNotIn("resolved", events)
                    descriptors.assert_observed(self)  # No new failed read lifetime.

    def test_actual_cli_pure_cancellation_stays_130_and_preserves_original_session(self):
        _, home, _, model = self.case()
        session_path = home / signing.LEASE_DIRECTORY / ("session-" + TOKEN)
        original = (session_path / "intent.json").read_bytes()
        output, errors, issued = io.StringIO(), io.StringIO(), []
        handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        lease = signing.local_signing_lease

        def interrupt(*args, **kwargs):
            issued.append(True)
            os.kill(os.getpid(), signal.SIGINT)
            self.fail("default cancellation was not delivered")

        try:
            with patch.object(signing, "local_signing_lease", side_effect=lambda **kw: lease(**{**kw, "home": home})), \
                 patch.object(signing, "run_owned", side_effect=interrupt), redirect_stdout(output), redirect_stderr(errors):
                result = cli.main(["local-signing", "recover", "--session", TOKEN, "--confirm", signing.CONFIRMATION])
            self.assertEqual(result, 130)
            self.assertEqual(issued, [True])
            self.assertFalse(output.getvalue())
            self.assertEqual(errors.getvalue(), "mobile-release: interrupted\n")
            self.assertEqual((session_path / "intent.json").read_bytes(), original)
            self.assertEqual(signing.signing_status(home=home)["status"], "pending")
            self.assertEqual({sig: signal.getsignal(sig) for sig in handlers}, handlers)
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
        self.fresh_recovery(home, model)

    def test_actual_cli_reports_fatal_status_and_recovery_without_success_json(self):
        for command in ("recover", "status"):
            with self.subTest(command=command):
                root, home, _, model = self.case()
                lease = signing.local_signing_lease
                output, errors = io.StringIO(), io.StringIO()
                with DescriptorFault(root, lambda e: e["name"] == signing.LEASE_DIRECTORY) as fault:
                    with patch.object(signing, "os", fault.os), \
                         patch.object(signing, "local_signing_lease", side_effect=lambda **kw: lease(**{**kw, "home": home})), \
                         patch.object(signing, "run_owned", model), redirect_stdout(output), redirect_stderr(errors):
                        argv = ["local-signing", command]
                        if command == "recover":
                            argv += ["--session", TOKEN, "--confirm", signing.CONFIRMATION]
                        result = cli.main(argv)
                    self.assertEqual(result, 2)
                    self.assertFalse(output.getvalue())
                    self.assertIn("cleanup is unconfirmed", errors.getvalue())
                    self.assertNotIn("fictional-private-close-canary", errors.getvalue())
                    fault.assert_observed(self)
                self.fresh_recovery(home, model, expected="absent" if command == "recover" else "recovered")

    def test_multiple_close_errors_preserve_nonfatal_entry_dispatch_and_all_other_closes(self):
        for after in (False, True):
            with self.subTest(after=after):
                root, home, _, model = self.case(seed=False)
                targets = {"session-" + TOKEN, signing.LEASE_DIRECTORY}
                with DescriptorFault(root, lambda e: e["name"] in targets, after=after, maximum=2) as fault:
                    with patch.object(signing, "os", fault.os), self.assertRaises(owned.ProcessError) as caught:
                        with signing.local_signing_lease(home=home) as lease:
                            session = lease.session(token=TOKEN)
                            session.open(create=True)
                            raise owned.ProcessError("fictional completed nonfatal body", dispatched=True)
                    self.assert_fatal(caught.exception, dispatched=True)
                    fault.assert_observed(self)
                    self.assertEqual(signing.signing_status(home=home)["status"], "pending" if after else "busy")
                self.fresh_recovery(home, model)

    def test_even_settled_missing_executable_query_revokes_this_manual_recovery_attempt(self):
        root, home, _, model = self.case()
        failures, calls = [], []
        def runner(argv, **kwargs):
            calls.append(argv)
            try:
                return owned.run_owned([str(root / "absent-executable")],
                    cancellation=kwargs["cancellation"], execution_scope=kwargs["execution_scope"],
                    journal_binding=kwargs.get("journal_binding"), environ=kwargs["environ"])
            except owned.ProcessError as error:
                failures.append(error)
                raise
        input_stream, output = TTY(), TTY()
        with self.assertRaises(CredentialError):
            signing.recover_signing(TOKEN, signing.CONFIRMATION, home=home, runner=runner,
                                    manual=True, input_stream=input_stream, output_stream=output)
        self.assertEqual(input_stream.reads, 0)
        self.assertEqual(len(failures), 1)
        self.assertEqual(len(calls), 1)
        self.assertFalse(output.getvalue())
        self.assertEqual(signing.signing_status(home=home)["status"], "pending")
        self.fresh_recovery(home, model)

    def test_ordinary_changed_borrowed_profile_remains_preserved_conflict_not_fatal(self):
        _, home, destination, model = self.case(borrowed=True)
        destination.write_bytes(b"independently changed fictional profile")
        result = signing.recover_signing(TOKEN, signing.CONFIRMATION, home=home, runner=model)
        self.assertEqual(result["status"], "recovered-with-conflict")
        self.assertEqual(destination.read_bytes(), b"independently changed fictional profile")
        self.assertEqual(model.preferences, model.original)
        self.assertEqual(signing.signing_status(home=home)["status"], "idle")


class InertAccountCleanupTests(unittest.TestCase):
    """Actual wrapper exits; no child process or native signing operation.

    Selected-input paths use task-private files/owners; descriptor-fault paths
    retain inert acquisition returns. They prove admission, error precedence and
    guard routing, never fabricated native authentication or finality receipts.
    """

    @staticmethod
    def regular_state(*, directory=False):
        return SimpleNamespace(st_mode=(stat.S_IFDIR | 0o700) if directory else (stat.S_IFREG | 0o600),
                               st_uid=os.getuid(), st_gid=os.getgid(), st_dev=1, st_ino=10,
                               st_nlink=1, st_size=0, st_mtime_ns=1, st_ctime_ns=1)

    def reader_os(self, primary, *, close_failure=True):
        state, closes = self.regular_state(), []
        model = SimpleNamespace(**vars(os))
        model.open = lambda *_args, **_kwargs: 211
        model.fstat = lambda _fd: state
        model.stat = lambda *_args, **_kwargs: state
        def read(_fd, _size):
            if primary is not None:
                raise primary
            return b""
        def close(fd):
            closes.append(fd)
            if close_failure:
                raise OSError("modeled close return failure")
        model.read, model.close = read, close
        return model, closes

    def test_original_zero_handler_reader_guard_retains_ordinary_primary_and_late_close_failure(self):
        from .test_lifetime_evidence import handler_model

        for primary in (None, CredentialError("ordinary body"),
                        owned.ProcessError("earlier owner", dispatched=True, contained=False),
                        KeyboardInterrupt("first"), SystemExit(19)):
            with self.subTest(primary=type(primary).__name__), handler_model() as (handlers, calls, _):
                handlers.update({signum: (lambda *_: None) for signum in handlers})
                guard = DefaultCancellation(owned.ProcessCleanupError, "fixed restore")
                guard.install(); guard.activate()
                modeled, closes = self.reader_os(primary)
                expected = type(primary) if isinstance(primary, (KeyboardInterrupt, SystemExit)) else owned.ProcessError
                with patch.object(signing, "os", modeled), self.assertRaises(expected) as caught:
                    signing._read_regular(210, "control.json", 100, private=True, cancellation=guard)
                self.assertEqual(closes, [211])
                self.assertTrue(guard.lifetime_ledger.fatal)
                if isinstance(primary, (KeyboardInterrupt, SystemExit)):
                    self.assertIs(caught.exception, primary)
                else:
                    self.assertTrue(caught.exception.fatal)
                    self.assertFalse(caught.exception.cleanup_complete)
                    self.assertEqual(caught.exception.dispatched, isinstance(primary, owned.ProcessError))
                    self.assertEqual(caught.exception.contained, not isinstance(primary, owned.ProcessError))
                if primary is not None:
                    self.assertIs(guard.lifetime_ledger._primary, primary)
                self.assertEqual(guard.handler_state, "ACTIVE")
                guard.restore()
                self.assertEqual(calls, [])

    def test_reader_ordinary_primary_cannot_hide_later_owned_handler_restoration_failure(self):
        from .test_lifetime_evidence import handler_model

        primary = CredentialError("ordinary read error")
        modeled, closes = self.reader_os(primary, close_failure=False)
        with handler_model() as (_, calls, setter):
            def restore_loss(signum, token):
                result = setter(signum, token)
                if signum == signal.SIGTERM and token is signal.SIG_DFL:
                    raise OSError("modeled restoration return loss")
                return result
            with patch.object(signing, "os", modeled), \
                    patch.object(cancellation.signal, "signal", side_effect=restore_loss), \
                    self.assertRaises(owned.ProcessError) as caught:
                signing._read_regular(210, "control.json", 100, private=True)
            self.assertTrue(caught.exception.fatal)
            self.assertFalse(caught.exception.dispatched)
            self.assertEqual(closes, [211])
            self.assertEqual(calls[-2:], [signal.SIGTERM, signal.SIGINT])

    def test_actual_lease_wrapper_projects_complete_cleanup_after_ordinary_or_successful_body(self):
        from .test_lifetime_evidence import handler_model

        for primary in (None, CredentialError("ordinary lease body"), KeyboardInterrupt("first"), SystemExit(7)):
            with self.subTest(primary=type(primary).__name__), handler_model():
                modeled, closes = self.reader_os(None)
                def acquire(lease, **_kwargs):
                    lease.home_fd = 211  # Modeled original acquisition only.
                expected = type(primary) if isinstance(primary, (KeyboardInterrupt, SystemExit)) else owned.ProcessError
                with patch.object(signing.SigningLease, "acquire", acquire), patch.object(signing, "os", modeled), \
                        self.assertRaises(expected) as caught:
                    with signing.local_signing_lease() as lease:
                        if primary is not None:
                            raise primary
                self.assertEqual(closes, [211])
                self.assertIsNone(lease.home_fd)
                self.assertTrue(lease.cancellation.lifetime_ledger.fatal)
                self.assertEqual(lease.cancellation.handler_state, "RESTORED")
                if isinstance(primary, (KeyboardInterrupt, SystemExit)):
                    self.assertIs(caught.exception, primary)
                else:
                    self.assertTrue(caught.exception.fatal)
                    self.assertFalse(caught.exception.dispatched)

    def test_profile_directory_direct_exit_projects_late_close_not_ordinary_body_only(self):
        from .test_lifetime_evidence import handler_model

        with handler_model():
            guard = DefaultCancellation(owned.ProcessCleanupError, "fixed")
            guard.install(); guard.activate()
            lease = signing.SigningLease(guard)
            lease.home_fd = 210
            modeled = SimpleNamespace(**vars(os))
            modeled.dup = lambda _fd: 211
            modeled.fstat = lambda _fd: self.regular_state(directory=True)
            next_fd, closes = iter((212, 213, 214)), []
            def close(fd):
                closes.append(fd)
                if fd == 214:
                    raise OSError("modeled final directory close failure")
            modeled.close = close
            with patch.object(signing, "os", modeled), patch.object(lease, "assert_owner"), \
                    patch.object(signing, "_open_dir", side_effect=lambda *_args, **_kw: next(next_fd)), \
                    self.assertRaises(owned.ProcessError) as caught:
                with lease.profile_directory() as directory:
                    self.assertEqual(directory, 214)
                    raise CredentialError("ordinary directory body")
            self.assertTrue(caught.exception.fatal)
            self.assertEqual(closes, [211, 212, 213, 214])
            self.assertTrue(guard.lifetime_ledger.fatal)
            guard.restore()

    def test_installer_ordinary_body_cannot_hide_late_owned_directory_close_failure(self):
        from .test_lifetime_evidence import handler_model

        with handler_model():
            state, closes = self.regular_state(), []
            modeled = SimpleNamespace(**vars(os))
            modeled.stat = lambda *_args, **_kwargs: state
            modeled.fsync = lambda _fd: None
            def close(fd):
                closes.append(fd)
                raise OSError("modeled installed-directory close failure")
            modeled.close = close
            with patch.object(credentials, "os", modeled), \
                    patch.object(credentials, "_open_profile_directory", return_value=(Path("/modeled/profiles"), 311)), \
                    patch.object(credentials, "_read_regular_at", return_value=(CONTENT, state)), \
                    self.assertRaises(owned.ProcessError) as caught:
                with credentials._temporary_profile_installation(CONTENT, UUID, Path("/modeled/home")):
                    raise CredentialError("ordinary installer body")
            self.assertTrue(caught.exception.fatal)
            self.assertFalse(caught.exception.dispatched)
            self.assertEqual(closes, [311])

    def test_apple_entry_primary_cannot_hide_independent_session_close_failure(self):
        from .test_lifetime_evidence import handler_model

        with completed_case_directory(prefix="mrk-inert-entry-") as root, handler_model():
            project, private = root / "project", root / "private"
            project.mkdir(mode=0o700)
            private.mkdir(mode=0o700)
            p12, source = private / "input.p12", private / "input.profile"
            p12.write_bytes(b"fictional-p12")
            source.write_bytes(CONTENT)
            p12.chmod(0o600)
            source.chmod(0o600)
            guard = DefaultCancellation(owned.ProcessCleanupError, "fixed")
            guard.install(); guard.activate()
            primary = CredentialError("ordinary session entry")
            closes = []
            def opened(**_kwargs):
                raise primary
            def close():
                closes.append("close")
                raise owned.ProcessCleanupError("independent modeled session close")
            session = SimpleNamespace(fd=None, state=None, keychain=Path("/modeled/keychain"),
                                      unresolved=False, journal_failed=False, cleaning=False,
                                      bind_runner=lambda *_args, **_kwargs: None, open=opened, close=close)
            lease = SimpleNamespace(cancellation=guard, active=None, home=Path("/modeled/home"),
                                    assert_owner=lambda: None, _admit_execution=lambda: None, session=lambda: session)
            with patch.object(credentials, "_authenticated_signing_profile", return_value=(CONTENT, {"UUID": UUID})), \
                    self.assertRaises(owned.ProcessError) as caught:
                with credentials._temporary_apple_signing_environment(
                    p12=p12, password="fictional", profile=source,
                    directory=private, project_root=project, lease=lease,
                ):
                    self.fail("entry error was suppressed")
            self.assertTrue(caught.exception.fatal)
            self.assertFalse(caught.exception.dispatched)
            self.assertEqual(closes, ["close"])
            self.assertTrue(guard.lifetime_ledger.fatal)
            self.assertIs(guard.lifetime_ledger._primary, primary)
            guard.restore()

    def test_materializer_refuses_busy_active_quarantined_and_mismatched_owners_before_material_work(self):
        from .test_lifetime_evidence import handler_model

        for rejection in ("busy", "active", "quarantined", "mismatched"):
            with self.subTest(rejection=rejection), handler_model():
                guard = DefaultCancellation(owned.ProcessCleanupError, "fixed")
                guard.install(); guard.activate()
                admissions, platform_reads = [], []
                primary = signing.SigningBusy("modeled busy") if rejection == "busy" else CredentialError("modeled quarantine")
                def acquire(_lease, **_kwargs):
                    raise primary
                def admit():
                    admissions.append("admit")
                    if rejection in {"quarantined", "mismatched"}:
                        raise primary
                def platforms():
                    platform_reads.append("read")
                    if rejection in {"quarantined", "mismatched"}:
                        raise AssertionError("platform iterable evaluated before owner refusal")
                    yield "ios"
                owner = SimpleNamespace(cancellation=guard, active=object(), _admit_execution=admit,
                                        close=lambda: self.fail("borrowed lease was closed"))
                supplied = None if rejection == "busy" else owner
                given_guard = DefaultCancellation(owned.ProcessCleanupError, "other") if rejection == "mismatched" else guard
                expected = {"busy": "modeled busy", "active": "already has an active signing context",
                            "quarantined": "modeled quarantine", "mismatched": "cancellation owner differs"}[rejection]
                try:
                    with ExitStack() as stack:
                        factory = stack.enter_context(patch.object(credentials, "local_signing_lease", wraps=signing.local_signing_lease))
                        invocations = stack.enter_context(patch.object(credentials, "invocation_custody", wraps=build_inputs.invocation_custody))
                        stack.enter_context(patch.object(signing.SigningLease, "acquire", acquire))
                        sentinels = [stack.enter_context(patch.object(component, name, side_effect=AssertionError("material work before admission")))
                                     for component, name in ((credentials, "read_external_bytes"),
                                                             (build_inputs.InvocationCustody, "project"),
                                                             (build_inputs.FiniteScratch, "acquire"),
                                                             (build_inputs.BuildInputs, "replace_all"),
                                                             (credentials, "_materialize"),
                                                             (credentials, "_temporary_apple_signing_environment"))]
                        with self.assertRaisesRegex(CredentialError, expected) as caught:
                            with credentials.materialize_build_inputs(
                                SimpleNamespace(root=Path("/modeled/project")),
                                values={"MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PATH": "/modeled/private.p12"},
                                platforms=platforms(), prepare_ios_signing=True,
                                signing_lease=supplied, cancellation=given_guard,
                            ):
                                self.fail("rejected materializer yielded")
                        if rejection in {"busy", "quarantined"}:
                            self.assertIs(caught.exception, primary)
                        self.assertEqual(admissions, [] if rejection in {"busy", "mismatched"} else ["admit"])
                        self.assertEqual(platform_reads, [] if rejection in {"quarantined", "mismatched"} else ["read"])
                        self.assertEqual(factory.call_count, int(rejection == "busy"))
                        self.assertEqual(invocations.call_count, int(rejection == "busy"))
                        for sentinel in sentinels:
                            sentinel.assert_not_called()
                        self.assertFalse(guard.lifetime_ledger.fatal)
                finally:
                    guard.restore()

    def test_materializer_routes_one_exact_lease_through_all_cleanup_and_leaves_borrowed_owner_open(self):
        from mobile_release.config import load_config
        from .helpers import android_config, ios_config, write_project
        from .test_lifetime_evidence import handler_model

        cases = (("standalone", ("ios",), True, None),
                 ("interrupted", ("ios",), True, KeyboardInterrupt("original materializer body")),
                 ("borrowed", ("ios",), True, None),
                 ("unsigned", ("ios",), False, None),
                 ("android", ("android",), True, None))
        for mode, selected, prepare, primary in cases:
            with self.subTest(mode=mode), completed_case_directory(prefix="mrk-inert-materializer-") as root, handler_model():
                guard = DefaultCancellation(owned.ProcessCleanupError, "fixed")
                guard.install(); guard.activate()
                home = root / "home"
                home.mkdir(mode=0o700)
                platform = selected[0]
                configuration = ios_config() if platform == "ios" else android_config()
                configuration["services"][platform + "Firebase"] = "required"
                config = load_config(write_project(root / "project", configuration, platform=platform))
                target = config.root / ("iosApp/GoogleService-Info.plist" if platform == "ios" else "app/google-services.json")
                if platform == "ios":
                    target.with_suffix(".plist.example").write_bytes(b"public Firebase marker")
                target.write_bytes(b"original client bytes")
                target.chmod(0o640)
                original_inode = target.stat().st_ino
                selected_client = (plistlib.dumps({"BUNDLE_ID": configuration["ios"]["bundleId"]})
                    if platform == "ios" else json.dumps({"client": [{"client_info": {"android_client_info": {
                        "package_name": configuration["android"]["applicationId"]}}}]}).encode())
                values = {
                    "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64": base64.b64encode(b"fictional-p12").decode(),
                    "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64": base64.b64encode(CONTENT).decode(),
                    "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD": "fictional",
                    ("MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64" if platform == "ios" else
                     "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64"): base64.b64encode(selected_client).decode(),
                }
                events, owners, children, consumed, yielded = [], [], [], [], []
                original_acquire, original_close = signing.SigningLease.acquire, signing.SigningLease.close
                original_admit = signing.SigningLease._admit_execution
                original_scratch_acquire = build_inputs.FiniteScratch.acquire
                original_restore, original_dispose = build_inputs.BuildInputs._restore, build_inputs.FiniteScratch._dispose
                original_invocation_acquire = build_inputs.InvocationCustody.acquire
                original_invocation_cleanup = build_inputs.InvocationCustody.cleanup
                original_project_acquire = build_inputs._Project.acquire
                original_project_cleanup = build_inputs._Project.cleanup
                invocation_owners = []

                def acquire_invocation(invocation):
                    self.assertIs(invocation.cancellation, guard)
                    self.assertIsNone(invocation.project_owner)
                    result = original_invocation_acquire(invocation)
                    self.assertIs(build_inputs._ENV_OWNER, invocation)
                    invocation_owners.append(invocation)
                    events.append("environment-enter")
                    return result

                def cleanup_invocation(invocation):
                    self.assertIs(invocation, invocation_owners[0])
                    self.assertIsNone(invocation.child)
                    self.assertIsNone(invocation.project_owner)
                    self.assertEqual(guard.handler_state, "ACTIVE")
                    result = original_invocation_cleanup(invocation)
                    self.assertFalse(invocation.reserved)
                    self.assertIsNone(build_inputs._ENV_OWNER)
                    events.append("environment-exit")
                    return result

                def acquire_project(project):
                    invocation = invocation_owners[0]
                    self.assertIs(build_inputs._ENV_OWNER, invocation)
                    self.assertIs(invocation.project_owner, project)
                    self.assertIs(project.guard, guard)
                    self.assertIs(invocation.signing_lease, owners[0] if owners else None)
                    result = original_project_acquire(project)
                    events.append("project-enter")
                    return result

                def cleanup_project(project):
                    self.assertIs(build_inputs._ENV_OWNER, invocation_owners[0])
                    self.assertEqual(guard.handler_state, "ACTIVE")
                    result = original_project_cleanup(project)
                    self.assertTrue(project.claimed)
                    self.assertIsNone(project.meta.number)
                    events.append("project-exit")
                    return result

                @contextmanager
                def observe_custody():
                    with ExitStack() as stack:
                        stack.enter_context(patch.object(build_inputs.InvocationCustody, "acquire", new=acquire_invocation))
                        stack.enter_context(patch.object(build_inputs.InvocationCustody, "cleanup", new=cleanup_invocation))
                        stack.enter_context(patch.object(build_inputs._Project, "acquire", new=acquire_project))
                        stack.enter_context(patch.object(build_inputs._Project, "cleanup", new=cleanup_project))
                        yield

                def acquire(owner, **kwargs):
                    self.assertIs(owner.cancellation, guard)
                    self.assertIs(build_inputs._ENV_OWNER, invocation_owners[0])
                    self.assertIsNone(invocation_owners[0].project_owner)
                    result = original_acquire(owner, **kwargs)
                    owners.append(owner)
                    events.append("lease-enter")
                    return result

                def close(owner):
                    self.assertIs(owner, owners[0])
                    self.assertEqual(guard.handler_state, "ACTIVE")
                    self.assertIs(build_inputs._ENV_OWNER, invocation_owners[0])
                    self.assertIsNone(invocation_owners[0].project_owner)
                    result = original_close(owner)
                    events.append("lease-exit")
                    return result

                def admit(owner, *args, **kwargs):
                    self.assertIs(owner, owners[0])
                    events.append("admit")
                    return original_admit(owner, *args, **kwargs)

                def acquire_scratch(scratch):
                    result = original_scratch_acquire(scratch)
                    self.assertIs(scratch.cancellation, guard)
                    self.assertEqual(scratch.layout, "build")
                    child = scratch.journal
                    self.assertIsInstance(child, build_inputs.BuildInputs)
                    self.assertIs(child.invocation.cancellation, guard)
                    self.assertIs(child.invocation.signing_lease, owners[0] if owners else None)
                    children.append(child)
                    events.append("scratch-create")
                    return result

                def restore(child, row):
                    self.assertIs(child, children[0])
                    self.assertIs(child.cancellation, guard)
                    self.assertEqual(guard.handler_state, "ACTIVE")
                    result = original_restore(child, row)
                    self.assertEqual(target.read_bytes(), b"original client bytes")
                    events.append("targets-exit")
                    return result

                def dispose(scratch, **kwargs):
                    self.assertIs(scratch, children[0].scratch)
                    self.assertEqual(target.read_bytes(), b"original client bytes")
                    self.assertEqual(guard.handler_state, "ACTIVE")
                    result = original_dispose(scratch, **kwargs)
                    events.append("scratch-exit")
                    return result

                @contextmanager
                def signer(**kwargs):
                    # Inert signing seam only; real account/project/input owners
                    # below never receive a fabricated native completion record.
                    self.assertIs(kwargs["lease"], owners[0])
                    self.assertIs(kwargs["cancellation"], guard)
                    self.assertIs(kwargs["directory"], children[0].scratch)
                    for name, expected in (("p12", b"fictional-p12"), ("profile", CONTENT)):
                        snapshot = kwargs[name]
                        self.assertIsInstance(snapshot, build_inputs.InputSnapshot)
                        self.assertEqual(kwargs["directory"].require(snapshot).read_bytes(), expected)
                    self.assertEqual(guard.handler_state, "ACTIVE")
                    self.assertEqual(target.read_bytes(), selected_client)
                    events.append("signing-enter")
                    try:
                        yield {"MOBILE_RELEASE_IOS_PROFILE_SPECIFIER": UUID}
                    finally:
                        self.assertEqual(guard.handler_state, "ACTIVE")
                        events.append("signing-exit")

                def platforms():
                    for platform in selected:
                        consumed.append(platform)
                        yield platform

                def body(supplied):
                    with credentials.materialize_build_inputs(
                        config, values=values, platforms=platforms(), prepare_ios_signing=prepare,
                        signing_lease=supplied, cancellation=guard,
                    ) as materialized:
                        yielded.append(dict(materialized))
                        self.assertEqual(target.read_bytes(), selected_client)
                        if primary is not None:
                            raise primary

                try:
                    borrowed = (signing.local_signing_lease(home=home, cancellation=guard)
                                if mode == "borrowed" else nullcontext(None))
                    with borrowed as supplied:
                        if supplied is not None:
                            owners.append(supplied)
                            borrowed_fd = supplied.fd
                        with patch.object(credentials, "local_signing_lease",
                                side_effect=lambda **kwargs: signing.local_signing_lease(home=home, **kwargs)) as factory, \
                                patch.object(credentials, "invocation_custody", wraps=build_inputs.invocation_custody) as invocations, \
                                patch.object(signing.SigningLease, "acquire", new=acquire), \
                                patch.object(signing.SigningLease, "close", new=close), \
                                patch.object(signing.SigningLease, "_admit_execution", new=admit), \
                                observe_custody(), \
                                patch.object(build_inputs.FiniteScratch, "acquire", new=acquire_scratch), \
                                patch.object(build_inputs.BuildInputs, "_restore", new=restore), \
                                patch.object(build_inputs.FiniteScratch, "_dispose", new=dispose), \
                                patch.object(credentials, "_temporary_apple_signing_environment", side_effect=signer) as signing_context, \
                                patch("mobile_release.discovery.discover_project", return_value={}), \
                                patch("mobile_release.discovery.selected_android_module", return_value=":app"):
                            if primary is None:
                                body(supplied)
                            else:
                                with self.assertRaises(KeyboardInterrupt) as caught:
                                    body(supplied)
                                self.assertIs(caught.exception, primary)
                            signed = prepare and "ios" in selected
                            owned_lease = signed and supplied is None
                            self.assertEqual(consumed, list(selected))
                            self.assertEqual(yielded, [{"MOBILE_RELEASE_IOS_PROFILE_SPECIFIER": UUID}] if signed else [{}])
                            self.assertEqual(factory.call_count, int(owned_lease))
                            self.assertEqual(signing_context.call_count, int(signed))
                            self.assertEqual(invocations.call_count, 1)
                            self.assertEqual(len(owners), int(signed))
                            self.assertEqual(len(children), 1)
                            self.assertEqual(events.count("admit"), 2 if supplied is not None else int(signed))
                            expected = (["signing-exit"] if signed else []) + ["targets-exit", "scratch-exit", "project-exit"]
                            if owned_lease:
                                expected.append("lease-exit")
                                self.assertLess(events.index("lease-enter"), events.index("scratch-create"))
                                factory.assert_called_once_with(cancellation=guard)
                            expected.append("environment-exit")
                            self.assertEqual([event for event in events if event in {
                                "environment-enter", "lease-enter", "project-enter", "scratch-create"}],
                                ["environment-enter"] + (["lease-enter"] if owned_lease else [])
                                + ["project-enter", "scratch-create"])
                            self.assertEqual([event for event in events if event.endswith("-exit")], expected)
                            self.assertEqual(target.read_bytes(), b"original client bytes")
                            self.assertEqual((target.stat().st_ino, stat.S_IMODE(target.stat().st_mode)), (original_inode, 0o640))
                            child = children[0]
                            self.assertTrue(child.claimed)
                            self.assertFalse(child.created or child.scratch.created)
                            self.assertIsNone(child.slot.number)
                            self.assertIsNone(child.scratch.slot.number)
                            self.assertIsNone(child.invocation.child)
                            self.assertTrue(child.invocation.claimed)
                            if supplied is not None:
                                supplied.assert_owner()
                                self.assertEqual(supplied.fd, borrowed_fd)
                                self.assertTrue(supplied.locked)
                            self.assertEqual(guard.handler_state, "ACTIVE")
                            self.assertFalse(guard.lifetime_ledger.fatal)
                finally:
                    guard.restore()


class InertPkcs12CallerTests(unittest.TestCase):
    """Actual caller fallback policy, not process/profile/finality qualification.

    Native/session prerequisites and runners below are explicitly inert. Real
    task-private files and snapshots exercise the caller input contract; no
    native custody or profile-authentication/finality evidence is issued.
    """

    @contextmanager
    def caller(self, site, outcomes):
        from .test_lifetime_evidence import handler_model

        with completed_case_directory(prefix="mrk-inert-pkcs12-") as root, handler_model():
            project, private, home = root / "project", root / "private", root / "home"
            for directory in (project, private, home):
                directory.mkdir(mode=0o700)
            p12, source = private / "input.p12", private / "input.profile"
            p12.write_bytes(b"fictional-p12")
            source.write_bytes(CONTENT)
            p12.chmod(0o600)
            source.chmod(0o600)
            values = {"MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PATH": str(p12),
                      "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_PATH": str(source),
                      "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD": "fictional"}
            guard = DefaultCancellation(owned.ProcessCleanupError, "fixed")
            guard.install(); guard.activate()
            trace = SimpleNamespace(extractions=[], commands=[], lifecycle=[], guard=guard)
            results = iter(outcomes)
            execution_source = object()

            def run(argv, **kwargs):
                trace.commands.append(list(argv))
                if site == "validator":
                    self.assertIs(kwargs["cancellation"], guard)
                    self.assertIs(kwargs["execution_source"], execution_source)
                if argv[:2] == ["openssl", "pkcs12"]:
                    trace.extractions.append(list(argv))
                    self.assertNotIn("-out", argv)
                    outcome = next(results, 0)
                    if isinstance(outcome, BaseException):
                        raise outcome
                    # Inert return values only, not completed native receipts.
                    # Empty validator stdout retains its post-extraction INVALID
                    # gate; signing needs bytes to exercise later caller cleanup.
                    output = "-----BEGIN CERTIFICATE-----\nfictional\n" if site == "signing" else ""
                    return SimpleNamespace(returncode=outcome, stdout=output, stderr="")
                self.assertEqual(argv[0], "security")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            def finish():
                trace.lifecycle.append("finish")
                return False

            session = SimpleNamespace(
                fd=311, state={"inflight": None}, intent={"profile": {"stage": "modeled-stage"}},
                keychain=home / "modeled-keychain", unresolved=False, journal_failed=False, cleaning=False,
                bind_runner=lambda *_args, **_kwargs: None, open=lambda **_kwargs: None,
                prepare=lambda *_args: None, profile_event=lambda *_args, **_kwargs: None,
                run=run, activate=lambda: trace.lifecycle.append("activate"),
                cleanup_native=lambda: trace.lifecycle.append("cleanup-native"),
                cleanup_profile=lambda: trace.lifecycle.append("cleanup-profile"), finish=finish,
                close=lambda: trace.lifecycle.append("close"),
            )  # Modeled FD311 is never passed to an OS or native owner.
            trace.session = session
            lease = SimpleNamespace(cancellation=guard, active=None, home=home,
                                    _admit_execution=lambda: None, session=lambda: session)

            def invoke(body=None):
                if site == "signing":
                    with credentials._temporary_apple_signing_environment(
                        p12=p12, password="fictional", profile=source, directory=private,
                        project_root=project, lease=lease, cancellation=guard,
                    ) as updates:
                        if body is not None:
                            body()
                        return updates
                return credentials._validate_apple_signing_material(
                    SimpleNamespace(root=project, section=lambda _name: {}), values,
                    scratch, execution_source=execution_source, cancellation=guard,
                )

            try:
                # Borrowing the real validator scratch keeps this test at the
                # original private caller boundary. Its mocked run method never
                # registers native work or changes the guard's process ledger.
                selected_scratch = (build_inputs.finite_scratch(layout="signing-validation", parent=private,
                                    cancellation=guard) if site == "validator" else nullcontext(None))
                with selected_scratch as scratch, \
                        patch.object(credentials, "_authenticated_signing_profile", return_value=(CONTENT, {"UUID": UUID})), \
                        patch.object(credentials, "_temporary_profile_installation", side_effect=lambda *_args, **_kwargs: nullcontext()), \
                        patch("mobile_release.ios_profiles.load_authenticated_profile", return_value={}), \
                        patch("mobile_release.ios._profile_validity"), \
                        patch.object(credentials, "consume_profile_evidence"), \
                        patch.object(credentials, "_run_private", side_effect=run), \
                        patch.object(credentials, "run_owned", side_effect=AssertionError("inert caller attempted native execution")):
                    yield invoke, trace
            finally:
                guard.restore()

    @staticmethod
    def extraction_roles(commands):
        return [(next(flag for flag in ("-clcerts", "-nocerts", "-cacerts") if flag in command),
                 "-legacy" in command) for command in commands]

    def test_public_fatal_body_flags_quarantine_the_actual_inert_signing_caller(self):
        self.assertEqual(len(FATAL_BODY_INERT_VARIANTS), 4)
        for variant in FATAL_BODY_INERT_VARIANTS:
            with self.subTest(variant=variant[0]):
                self.run_inert_fatal_body_variant(variant)

    def run_inert_fatal_body_variant(self, variant):
        self.assertIn(variant, FATAL_BODY_INERT_VARIANTS)
        _name, dispatched, contained = variant
        primary = owned.ProcessCleanupError("fictional body cleanup", dispatched=dispatched, contained=contained)
        with self.caller("signing", ()) as (invoke, trace), refuse_signing_execution() as attempts:
            before_cleanup = []

            def body():
                self.assertEqual(trace.lifecycle, ["activate"])
                self.assertFalse(trace.guard.lifetime_ledger.fatal)
                self.assertFalse(trace.session.unresolved)
                before_cleanup.extend(tuple(command) for command in trace.commands)
                raise primary

            with self.assertRaises(owned.ProcessError) as caught:
                invoke(body)
            # The actual cleanup_signing callback must quarantine before any
            # native/profile reconciliation, yet still close independently once.
            self.assertTrue(trace.session.cleaning)
            self.assertTrue(trace.session.unresolved)
            self.assertTrue(trace.guard.lifetime_ledger.fatal)
            self.assertIs(trace.guard.lifetime_ledger._primary, primary)
            self.assertEqual(trace.guard.handler_state, "ACTIVE")
            self.assertEqual(trace.lifecycle, ["activate", "close"])
            self.assertTrue(before_cleanup, "the actual caller never reached its body")
            self.assertEqual([tuple(command) for command in trace.commands], before_cleanup)
            self.assertEqual((caught.exception.dispatched, caught.exception.contained,
                              caught.exception.cleanup_complete, caught.exception.fatal),
                             (dispatched, contained, False, True))
            # These are explicitly inert prerequisite returncode values, not
            # native outcomes. The retained native00 case proves prior dispatch.
            self.assertEqual((primary.dispatched, primary.contained, primary.cleanup_complete),
                             (dispatched, contained, False))
            self.assertEqual(attempts, [])

    def test_both_callers_limit_legacy_to_one_positive_retry_and_preserve_negative_dispatch(self):
        cases = (("zero", (0,)), ("legacy-success", (7, 0)), ("legacy-failure", (7, 9)),
                 ("negative-first", (-15,)), ("negative-legacy", (7, -15)))
        for site in ("signing", "validator"):
            for mode, outcomes in cases:
                with self.subTest(site=site, mode=mode), self.caller(site, outcomes) as (invoke, trace):
                    negative = mode.startswith("negative")
                    if negative:
                        with self.assertRaises(owned.ProcessError) as caught:
                            invoke()
                        error = caught.exception
                        self.assertEqual((error.dispatched, error.contained, error.cleanup_complete, error.fatal),
                                         (True, True, True, False))
                    elif mode == "legacy-failure" and site == "signing":
                        with self.assertRaisesRegex(CredentialError, "extract the Apple distribution certificate"):
                            invoke()
                    else:
                        result = invoke()
                        if site == "signing":
                            self.assertEqual(result, {"MOBILE_RELEASE_IOS_PROFILE_SPECIFIER": UUID})
                            self.assertIn("activate", trace.lifecycle)
                        else:
                            self.assertEqual([(finding.code, finding.status) for finding in result],
                                             [("credential-material.apple-p12", credentials.Status.INVALID)])
                    fallback = mode not in {"zero", "negative-first"}
                    expected = [("-clcerts", False)] + ([("-clcerts", True)] if fallback else [])
                    if not negative and not (mode == "legacy-failure" and site == "signing"):
                        expected += [("-nocerts", False)]
                        if site == "signing":
                            expected += [("-cacerts", False)]
                    else:
                        self.assertNotIn("activate", trace.lifecycle)
                        self.assertFalse(any(command[:2] == ["security", "import"] for command in trace.commands))
                    self.assertEqual(self.extraction_roles(trace.extractions), expected)
                    if fallback:
                        self.assertEqual(trace.extractions[1], trace.extractions[0][:2] + ["-legacy"] + trace.extractions[0][2:])
                    self.assertFalse(trace.guard.lifetime_ledger.fatal)
                    if site == "signing":
                        self.assertEqual(trace.lifecycle.count("close"), 1)

    def test_both_callers_propagate_original_outcome_fatality_or_interruption_without_retry(self):
        errors = (
            ("unknown", lambda: owned.ProcessOutcomeUnknown("modeled outcome", dispatched=True)),
            ("fatal", lambda: owned.ProcessError("modeled original custody", dispatched=True,
                                                contained=False, cleanup_complete=False)),
            ("interrupt", lambda: KeyboardInterrupt("original P12 interruption")),
        )
        for site in ("signing", "validator"):
            for phase in ("initial", "legacy"):
                for kind, make_error in errors:
                    primary = make_error()
                    outcomes = (primary,) if phase == "initial" else (7, primary)
                    with self.subTest(site=site, phase=phase, kind=kind), self.caller(site, outcomes) as (invoke, trace):
                        with self.assertRaises(KeyboardInterrupt if kind == "interrupt" else owned.ProcessError) as caught:
                            invoke()
                        if site == "validator" or kind != "fatal":
                            self.assertIs(caught.exception, primary)
                        if kind != "interrupt":
                            self.assertEqual((caught.exception.dispatched, caught.exception.contained,
                                              caught.exception.cleanup_complete, caught.exception.fatal),
                                             (True, kind != "fatal", kind != "fatal", kind == "fatal"))
                        expected = [("-clcerts", False)] + ([("-clcerts", True)] if phase == "legacy" else [])
                        self.assertEqual(self.extraction_roles(trace.extractions), expected)
                        self.assertNotIn("activate", trace.lifecycle)
                        self.assertFalse(any(command[:2] == ["security", "import"] for command in trace.commands))
                        if site == "signing":
                            self.assertIs(trace.guard.lifetime_ledger._primary, primary)
                            self.assertEqual(trace.lifecycle.count("close"), 1)


class FatalClassificationTests(unittest.TestCase):
    def test_typed_chain_facts_cycles_and_ordinary_controls(self):
        for error in (None, OSError("ordinary"), CredentialError("conflict"), KeyboardInterrupt(),
                      owned.ProcessError("contained", dispatched=True), owned.ProcessInterrupted(dispatched=True, contained=True)):
            with self.subTest(error=type(error).__name__):
                self.assertIsNone(owned.fatal_lifetime_error(error, "fixed fallback"))
        primary = owned.ProcessError("unknown group", dispatched=True, contained=False)
        secondary = owned.ProcessCleanupError("independent close")
        secondary.__context__ = primary
        wrapper = CredentialError("private wrapper canary")
        wrapper.__cause__ = secondary
        primary.__context__ = wrapper  # Defensive traversal terminates even with a cycle.
        result = owned.fatal_lifetime_error(wrapper, "fixed fallback")
        self.assertEqual(str(result), "fixed fallback")
        self.assertEqual((result.dispatched, result.contained, result.cleanup_complete), (True, False, False))
        self.assertIs(owned.fatal_lifetime_error(secondary, "unused"), secondary)


if __name__ == "__main__":
    unittest.main()
