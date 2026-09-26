"""Focused inert iOS DATA/control regressions, not Mac/native qualification.

No project, descriptor, signal handler, tool, command, account, Store or network
resource is acquired. Original Python types carry explicit predicate DATA only;
effectful seams are refused/patched before a tested method can reach them.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import subprocess
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mobile_release import _desktop_ios_archive_protocol as wire
from mobile_release import _desktop_ios_archive_selection as selection
from mobile_release import ios, ios_archive_operation as operation_module, ios_artifacts, build_inputs, macho, _command_process as commands
from mobile_release._desktop_ios_archive_control import IOSArchiveInput
from mobile_release.desktop_ios_archive import IOSArchiveRun
from mobile_release._desktop_saved_command_control import SavedCommandDomain, source_domain, _protocol
from mobile_release.cancellation import DefaultCancellation
from mobile_release.config import ReleaseVersion
from mobile_release.owned_process import ProcessCleanupError


def configuration():
    return {"schemaVersion": 1,
        "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "main"},
        "android": {"enabled": False},
        "ios": {"enabled": True, "bundleId": "org.example.inert", "identityStatus": "unverified",
                "project": "ios/Inert.xcodeproj", "scheme": "Inert", "archiveConfiguration": "Release",
                "symbols": {"policy": "retain"}},
        "metadata": {"root": "release/store", "androidLocales": [], "iosLocales": ["en-US"]},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []}}


def encode(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def comparison(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def request_data():
    raw, version = encode(configuration()), b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n"
    directory = {"device": "1", "inode": "2", "mode": stat.S_IFDIR | 0o755, "uid": 0, "gid": 0}
    developer = "/Applications/Xcode_Inert.app/Contents/Developer"
    return {"protocol": wire.PROTOCOL, "operationId": "a" * 32, "ownerGeneration": "b" * 32,
        "context": {"projectId": "inert-ios", "draftRevision": 1, "baselineGeneration": 2,
            "platform": "ios", "operation": "ios-unsigned-archive", "savedConfig": comparison(raw),
            "savedVersion": {"source": "release/version.properties", **comparison(version), "name": "1.2.3", "build": 7}},
        "native": {"profile": "macos-arm64", "projectRoot": "/inert/project", "rootIdentity": directory,
            "cwd": "/inert/runtime", "toolchain": {"schemaVersion": 1, "profile": wire.TOOLCHAIN_PROFILE,
                "developerDir": developer, "developerIdentity": directory,
                "sdk": developer + "/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.0.sdk",
                "sdkIdentity": {**directory, "inode": "3"},
                "xcodebuildIdentity": {**directory, "inode": "4", "mode": stat.S_IFREG | 0o755,
                    "links": 1, "size": 1024, "mtimeNs": "100", "ctimeNs": "100"}}}}


def parsed_request():
    return wire.parse_request(encode(request_data()) + b"\n")


@contextmanager
def original():
    guard, source = DefaultCancellation(ProcessCleanupError, "inert"), IOSArchiveInput(100)
    source.acquired = source.active = source.request_returned = True  # Predicate DATA, no pipe.
    guard._install_ios_archive_source(source)
    guard.depth = 0  # No real signal handler installation occurred.
    with patch.object(operation_module.time, "monotonic", return_value=100), patch.object(source, "poll"), \
            patch.object(os, "open", side_effect=AssertionError("no native open in DATA tests")), \
            patch.object(os, "close", side_effect=AssertionError("no native close in DATA tests")), \
            patch.object(operation_module, "run_owned", side_effect=AssertionError("no native command in DATA tests")):
        yield operation_module.IOSArchiveOperation(parsed_request(), guard, source)


def complete_terminal(request):
    return {"schemaVersion": 1, "context": request.context, "outcome": "complete", "reason": "none",
        "activity": {"stage": "disposing-work", "selection": {
            "containerKind": "project", "container": "ios/Inert.xcodeproj", "scheme": "Inert", "configuration": "Release",
            "bundleId": "org.example.inert", "symbolsPolicy": "retain", "preparationConfigured": False},
            "commands": {role: {"outcome": "not-configured" if role == "prepare" else "exited",
                                "exitCode": None if role == "prepare" else 0} for role in wire.ROLES},
            "findings": [{"check": "archive-identity", "status": "PASS"}, {"check": "archive-dsym", "status": "PASS"}]},
        "disposition": {"snapshot": "removed", "work": "removed", "output": "retained-local-result",
                        "relativeDirectory": ".mobile-release/desktop-ios-archive/" + "a" * 32},
        "result": {"schemaVersion": 1, "scope": wire.SCOPE, "usedConfig": request.context["savedConfig"],
            "usedVersion": request.context["savedVersion"], "entries": 10, "bytes": 1000,
            "archive": ".mobile-release/desktop-ios-archive/" + "a" * 32 + "/archive.xcarchive", "limitations": list(wire.LIMITATIONS)},
        "lifetime": {"complete": True, "fatal": False, "contained": True, "commandDispatched": True,
            "commands": 3, "profileCalls": 0, "stopObserved": "none", **{key: True for key in wire.CLOSE_FIELDS}}}


def terminal_data(operation, error):
    """Supply inert independent-closure DATA, never close a real resource."""
    service = object.__new__(IOSArchiveRun)
    service.operation, service.request = operation, operation.request
    service.guard, service.source = operation.guard, operation.source
    service.primary, service._candidate, service.findings = error, None, []
    operation.source.closed = True
    operation.guard._restoration = "RESTORED"  # DATA; no handlers were installed.
    with patch.object(operation, "closed", return_value=True), patch.object(operation, "snapshot_closed", return_value=True), \
            patch.object(operation.files, "closed", return_value=True):
        return service.terminal()


def command_slot_data(operation, role, *, kind="no-target"):
    """Original Python types with explicit finality DATA, no execution proof.

    _Outer constructor creates only ungranted in-memory reservations. No body,
    cleanup, native binding, process, descriptor, command or signal API runs.
    Only this DATA fixture sets CLOSED/publishes synthetic owner observations.
    """
    operation._pending, operation._roles[role] = role, "attempted"
    with patch.object(commands.os, "urandom", return_value=b"i" * 16), \
            patch.object(operation.guard, "check", side_effect=AssertionError("slot hook must not poll STOP")), \
            patch.object(commands.native, "_Native", side_effect=AssertionError("no native bindings")):
        engine = commands._Outer(operation.guard, False, 30, None, None, suppress_cancel=False)
    if kind == "unpublished":
        return engine
    final = object.__new__(commands.OriginalCommandFinality)
    final._engine = engine
    no_target = commands.NoTargetProof(engine, "NO_W_CREATION", _key=commands._KEY) if kind == "no-target" else None
    outcome = commands.OriginalCommandOutcome(engine, engine.nonce,
        commands.RouteHistory(kind != "no-target", True), commands.RouteHistory(kind != "no-target", True),
        no_target, "normal-exit" if kind == "exit" else "unavailable", 0 if kind == "exit" else None,
        "complete" if kind in {"exit", "no-target"} else "incomplete", final)
    engine.phase = "CLOSED"
    engine.slot._publish(engine, outcome)
    operation.guard.lifetime_ledger._finish_command(engine.slot, dispatched=kind != "no-target", contained=True, cleanup_complete=True)
    return engine


class IOSSelectionTests(unittest.TestCase):
    def test_saved_policy_and_one_version_are_exactly_bound_without_discovery(self):
        raw, version = encode(configuration()), b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n"
        with patch.object(ios, "discover_project", side_effect=AssertionError("no repository discovery")):
            data, selected = selection.select_saved_ios_configuration(raw, comparison(raw))
            bound = selection.bind_saved_ios_version(selected, version, request_data()["context"]["savedVersion"])
        self.assertEqual(selected.container, ("project", "ios/Inert.xcodeproj"))
        self.assertEqual(selected.symbols_policy, "retain")
        self.assertIs(bound.configuration, selected)
        self.assertIs(bound.configuration.raw, raw)
        self.assertEqual(bound.release, ReleaseVersion("1.2.3", 7))
        data["ios"]["scheme"] = "Changed draft"
        self.assertEqual(bound.configuration.scheme, "Inert")

    def test_missing_explicit_selection_and_stale_display_refuse_before_io(self):
        for key, reason in (("project", "container-required"), ("scheme", "scheme-required")):
            data = configuration()
            del data["ios"][key]
            raw = encode(data)
            with self.assertRaises(selection.IOSSelectionRefused) as raised:
                selection.select_saved_ios_configuration(raw, comparison(raw))
            self.assertEqual(raised.exception.reason, reason)
        raw = encode(configuration())
        _, selected = selection.select_saved_ios_configuration(raw, comparison(raw))
        expected = request_data()["context"]["savedVersion"]
        with self.assertRaises(selection.IOSSelectionRefused) as raised:
            selection.bind_saved_ios_version(selected, b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n", {**expected, "build": 8})
        self.assertEqual(raised.exception.reason, "saved-version-changed")

    def test_shared_archive_argv_preserves_version_and_unsigned_flags_are_not_signing(self):
        command = ios._archive_command(("workspace", "ios/Inert.xcworkspace"), Path("/inert/project/ios/Inert.xcworkspace"),
            "Inert", "Release", Path("/inert/output/archive.xcarchive"), ReleaseVersion("1.2.3", 7))
        self.assertEqual(command, ["xcodebuild", "-workspace", "/inert/project/ios/Inert.xcworkspace", "-scheme", "Inert",
            "-configuration", "Release", "-destination", "generic/platform=iOS", "-archivePath", "/inert/output/archive.xcarchive",
            "archive", "MARKETING_VERSION=1.2.3", "CURRENT_PROJECT_VERSION=7"])
        with original() as operation, patch.object(operation, "require") as admission:
            for kwargs in ({"signed": True}, {"signed": False, "signing_session": object()},
                           {"signed": False, "execution_source": object()}):
                with self.assertRaises(wire.ProtocolError):
                    ios.run_ios_build(None, operation=operation, **kwargs)
            admission.assert_not_called()


class IOSWireTests(unittest.TestCase):
    def test_closed_third_domain_cannot_adopt_another_domain_or_subclass(self):
        source = IOSArchiveInput(100)
        self.assertIs(source_domain(source), SavedCommandDomain.IOSArchive)
        self.assertIs(_protocol(source.domain), wire)
        class Lookalike(IOSArchiveInput):
            pass
        with self.assertRaises(ValueError):
            source_domain(Lookalike(100))
        source._domain = SavedCommandDomain.AndroidBuild
        with self.assertRaises(ValueError):
            source_domain(source)

    def test_request_rejects_clt_foreign_sdk_duplicates_and_renderer_tools(self):
        good = request_data()
        for change in (lambda value: value["native"]["toolchain"].update(developerDir="/Library/Developer/CommandLineTools"),
                       lambda value: value["native"]["toolchain"].update(sdk="/inert/foreign.sdk"),
                       lambda value: value["context"].update(argv=["xcodebuild"]),
                       lambda value: value["native"].update(profile="linux-gnu-x86_64")):
            value = copy.deepcopy(good)
            change(value)
            with self.assertRaises(wire.ProtocolError):
                wire.parse_request(encode(value) + b"\n")
        raw = encode(good)
        with self.assertRaises(wire.ProtocolError):
            wire.parse_request(b'{"protocol":"wrong",' + raw[1:] + b"\n")

    def test_terminal_requires_each_original_closure_and_truthful_validation(self):
        request = parsed_request()
        value = complete_terminal(request)
        wire.validate_terminal(value, request)
        mutations = [lambda row, key=key: row["lifetime"].update({key: False}) for key in wire.CLOSE_FIELDS]
        mutations += [lambda row: row["activity"]["findings"][1].update(status="FAIL"),
                      lambda row: row["activity"].update(findings=[]),
                      lambda row: row["disposition"].update(work="retained-work"),
                      lambda row: row["lifetime"].update(commands=2),
                      lambda row: row["lifetime"].update(commandDispatched=False),
                      lambda row: row["disposition"].update(snapshot="unknown"),
                      lambda row: row["result"].update(bytes=8 * 1024**3 + 1),
                      lambda row: row["result"].update(archive="/inert/arbitrary.xcarchive")]
        for mutate in mutations:
            row = copy.deepcopy(value)
            mutate(row)
            with self.assertRaises(wire.ProtocolError):
                wire.validate_terminal(row, request)

    def test_frame_replay_is_permanently_refused(self):
        request = parsed_request()
        frames = wire.IOSArchiveFrames(request)
        frames.response("accepted", {"schemaVersion": 1, "context": request.context})
        frames.response("progress", {"schemaVersion": 1, "stage": "inputs-bound"})
        with self.assertRaises(wire.ProtocolError):
            frames.response("progress", {"schemaVersion": 1, "stage": "inputs-bound"})
        with self.assertRaises(wire.ProtocolError):
            frames.response("terminal", complete_terminal(request))

    def test_complete_unused_prepare_is_exactly_not_configured_not_an_unknown_call(self):
        request = parsed_request()
        value = complete_terminal(request)
        wire.validate_terminal(value, request)
        for outcome, exit_code in (("unknown", None), ("not-dispatched", None), ("exited", 0)):
            with self.subTest(outcome=outcome):
                row = copy.deepcopy(value)
                row["activity"]["commands"]["prepare"] = {"outcome": outcome, "exitCode": exit_code}
                with self.assertRaises(wire.ProtocolError):
                    wire.validate_terminal(row, request)
        value["activity"]["selection"]["preparationConfigured"] = True
        value["activity"]["commands"]["prepare"] = {"outcome": "exited", "exitCode": 0}
        value["lifetime"]["commands"] = 4
        wire.validate_terminal(value, request)

    def test_settled_no_target_counts_one_but_never_accepts_unknown_or_two_calls(self):
        with original() as operation:
            engine = command_slot_data(operation, "xcode-version")
            operation._observe_command("xcode-version")
            terminal = terminal_data(operation, operation_module.IOSArchiveError("command-incomplete"))
            self.assertEqual(terminal["outcome"], "refused")
            self.assertEqual(terminal["lifetime"]["commands"], 1)
            self.assertIs(terminal["lifetime"]["commandDispatched"], False)
            self.assertIs(operation._command_slots["xcode-version"], engine.slot)
            for mutate in (lambda row: row["lifetime"].update(commands=2),
                           lambda row: row["activity"]["commands"]["archive"].update(outcome="unknown"),
                           lambda row: row["activity"]["commands"]["archive"].update(outcome="exited", exitCode=0)):
                row = copy.deepcopy(terminal)
                mutate(row)
                with self.assertRaises(wire.ProtocolError):
                    wire.validate_terminal(row, operation.request)


class IOSOwnershipDataTests(unittest.TestCase):
    def test_precall_cancellation_and_refusal_have_valid_known_no_attempt_terminal(self):
        for cancelled in (True, False):
            with self.subTest(cancelled=cancelled), original() as operation:
                failure = KeyboardInterrupt() if cancelled else operation_module.IOSArchiveError("saved-version-changed")
                def before_call():
                    if cancelled:
                        operation.source.stop("cancelled")
                    raise failure
                with patch.object(operation, "check_inputs"), patch.object(operation, "checkpoint"), \
                        patch.object(operation.files, "check_tools"), patch.object(operation, "command_environment", side_effect=before_call), \
                        patch.object(operation_module, "run_owned", side_effect=AssertionError("pre-call must not invoke runner")) as invoke:
                    with self.assertRaises(type(failure)):
                        operation._run("xcode-version", ("/inert/xcodebuild", "-version"))
                    invoke.assert_not_called()
                self.assertEqual(operation.guard.lifetime_ledger.verdict().commands, 0)
                terminal = terminal_data(operation, failure)
                self.assertEqual(terminal["outcome"], "cancelled" if cancelled else "refused")
                self.assertIs(terminal["lifetime"]["commandDispatched"], False)
                self.assertEqual(terminal["activity"]["commands"]["xcode-version"], {"outcome": "not-dispatched", "exitCode": None})
                for role in ("xcode-version", "ios-sdk"):
                    with self.assertRaises((KeyboardInterrupt, operation_module.IOSArchiveError)):
                        operation._arm(role)

    def test_readonly_slot_hook_requires_exact_originals_and_does_not_poll_stop(self):
        with original() as operation, patch.object(operation.source, "poll", side_effect=AssertionError("no STOP in hook")):
            engine = command_slot_data(operation, "xcode-version")
            self.assertIs(operation._command_outcome("xcode-version"), engine.slot.read())
            with self.assertRaises(wire.ProtocolError):
                operation.bind_command_slot(engine, engine.slot)
            original_slot = operation._command_slots["xcode-version"]
            for different in (None, SimpleNamespace(_engine=engine, _nonce=engine.nonce),
                              commands.CommandOutcomeSlot(None, engine.nonce, _key=commands._KEY)):
                operation._command_slots["xcode-version"] = different
                self.assertIsNone(operation._command_outcome("xcode-version"))
            operation._command_slots["xcode-version"] = original_slot
            engine.slot.read().original_finality._engine = object()
            self.assertIsNone(operation._command_outcome("xcode-version"))
        # Ordinary non-iOS commands retain their existing original-slot route;
        # they must not call the iOS operation hook or poll a guard here.
        guard = DefaultCancellation(ProcessCleanupError, "inert-non-ios")
        with patch.object(operation_module.IOSArchiveOperation, "bind_command_slot", side_effect=AssertionError("wrong domain")), \
                patch.object(guard, "check", side_effect=AssertionError("constructor STOP")), \
                patch.object(commands.os, "urandom", return_value=b"n" * 16):
            engine = commands._Outer(guard, False, 30, None, None, suppress_cancel=False)
        self.assertIs(guard.lifetime_ledger._command, engine.slot)

    def test_unreturned_calls_require_original_finality_even_after_an_earlier_exit(self):
        for earlier in (False, True):
            for publication in ("absent", "unpublished"):
                with self.subTest(earlier=earlier, publication=publication), original() as operation:
                    role = "ios-sdk" if earlier else "xcode-version"
                    if earlier:
                        command_slot_data(operation, "xcode-version", kind="exit")
                        operation._observe_command("xcode-version")
                    def failed_call(*args, **kwargs):
                        if publication == "unpublished":
                            command_slot_data(operation, role, kind="unpublished")
                        raise RuntimeError("a return was lost; this is not no-effect evidence")
                    with patch.object(operation, "check_inputs"), patch.object(operation, "checkpoint"), \
                            patch.object(operation.files, "check_tools"), patch.object(operation, "command_environment", return_value={}), \
                            patch.object(operation_module, "run_owned", side_effect=failed_call):
                        with self.assertRaises(RuntimeError) as raised:
                            operation._run(role, ("/inert/xcodebuild", "-version"))
                    self.assertFalse(operation.commands_settled())
                    terminal = terminal_data(operation, raised.exception)
                    self.assertEqual((terminal["outcome"], terminal["reason"]), ("unknown", "cleanup-unknown"))
                    self.assertFalse(terminal["lifetime"]["complete"])
                    self.assertIs(terminal["lifetime"]["commandDispatched"], True if earlier else None)
                    self.assertEqual(terminal["activity"]["commands"][role]["outcome"], "unknown")

    def test_return_and_exception_observe_original_outcomes_not_wrapper_claims(self):
        for kind in ("no-target", "exit", "incomplete"):
            with self.subTest(kind=kind), original() as operation:
                def invoke(*args, **kwargs):
                    command_slot_data(operation, "xcode-version", kind=kind)
                    if kind != "exit":
                        raise RuntimeError("actual command call failed")
                    return subprocess.CompletedProcess(args[0], 0, stdout="Xcode 26\nBuild version 26A000\n", stderr="")
                with patch.object(operation, "check_inputs"), patch.object(operation, "checkpoint"), \
                        patch.object(operation.files, "check_tools"), patch.object(operation, "command_environment", return_value={}), \
                        patch.object(operation_module, "run_owned", side_effect=invoke):
                    if kind == "exit":
                        self.assertEqual(operation._run("xcode-version", ("/inert/xcodebuild", "-version")).returncode, 0)
                    else:
                        with self.assertRaises(RuntimeError):
                            operation._run("xcode-version", ("/inert/xcodebuild", "-version"))
                self.assertTrue(operation.commands_settled())
                self.assertEqual(operation.command_outcomes()["xcode-version"]["outcome"],
                    {"no-target": "not-dispatched", "exit": "exited", "incomplete": "unknown"}[kind])

    def test_original_native_root_is_bound_before_lock_rename_or_private_state(self):
        import fcntl
        @contextmanager
        def inert_scope(owner, guard, owns):
            yield owner
        with original() as operation, patch.object(build_inputs.InvocationCustody, "_owner"), \
                patch.object(build_inputs, "_scope", inert_scope):
            invocation = build_inputs.InvocationCustody(operation.root, "build", operation.guard)
            with invocation.project(signing_lease=None):
                project = invocation.project_owner
                expected = request_data()["native"]["rootIdentity"]
                self.assertEqual(project.expected_root, (int(expected["device"]), int(expected["inode"]),
                    expected["mode"], expected["uid"], expected["gid"]))
                project.directory = SimpleNamespace(acquire=Mock(), fd=197)
                fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")
                for index in range(5):
                    observed = list(project.expected_root)
                    observed[index] += 1
                    with patch.object(build_inputs.os, "fstat", return_value=SimpleNamespace(**dict(zip(fields, observed)))), \
                            patch.object(build_inputs, "_rename_function") as rename, patch.object(fcntl, "flock") as flock, \
                            patch.object(project, "check") as check, patch.object(build_inputs, "_init_pending_names_locked") as names, \
                            patch.object(project, "_open_meta") as meta:
                        with self.assertRaises(build_inputs.BuildInputRootChanged):
                            project.acquire()
                        for forbidden in (rename, flock, check, names, meta):
                            forbidden.assert_not_called()
            self.assertIs(invocation._original_project, project)
            self.assertIsNone(invocation.project_owner)

    def test_original_invocation_binds_before_any_acquisition_and_cannot_rebind(self):
        with original() as operation, patch.object(build_inputs.InvocationCustody, "acquire") as acquire:
            invocation = build_inputs.InvocationCustody(operation.root, "build", operation.guard)
            self.assertIs(operation.invocation, invocation)
            with self.assertRaises(wire.ProtocolError):
                build_inputs.InvocationCustody(operation.root, "build", operation.guard)
            acquire.assert_not_called()
            with self.assertRaises(build_inputs.BuildInputError):
                invocation._offline_preflight_root(operation.guard)

    def test_one_clock_checks_original_stop_failure_and_cleanup_endpoint(self):
        with original() as operation:
            clock = operation_module.InspectionDeadline()
            adapter = operation_module._IOSInspectionDeadline(operation, clock)
            operation.inspection_deadline = adapter
            operation.snapshot_binding.consumer_active = True
            adapter.check()
            operation.source.failure_observed()
            first = operation.source.first_failure
            with self.assertRaises(operation_module.IOSArchiveError):
                adapter.check()
            operation.guard.depth = 1
            operation.snapshot_binding.finish_claimed = True
            with patch.object(operation_module.time, "monotonic", return_value=first + 9):
                adapter.check()
            with patch.object(operation_module.time, "monotonic", return_value=first + 10):
                with self.assertRaises(operation_module.IOSArchiveError):
                    adapter.check()
            self.assertEqual(operation.source.first_failure, first)
            self.assertEqual(clock.expires_at, 100 + 900)

    def test_snapshot_finish_is_not_invocation_close_and_unknown_consumers_never_idle(self):
        with original() as operation:
            binding = operation.snapshot_binding
            binding.consumer_entered = binding.consumer_active = True
            with self.assertRaises(wire.ProtocolError):
                binding.finish_consumers(cancellation=operation.guard)
            self.assertTrue(binding.finish_claimed)
            self.assertFalse(binding.finished)
            self.assertFalse(operation.close_claimed)
            self.assertFalse(build_inputs._consumer_idle(operation.guard, desktop_binding=binding, owner=None))
            binding.consumer_active, binding.consumer_returned = False, True
            with self.assertRaises(wire.ProtocolError):
                binding.finish_consumers(cancellation=operation.guard)  # No repair/retry after unknown finish.
        with original() as operation:
            operation.snapshot_binding.finish_consumers(cancellation=operation.guard)
            self.assertFalse(operation.close_claimed)
            self.assertTrue(build_inputs._consumer_idle(operation.guard, desktop_binding=operation.snapshot_binding, owner=None))
            self.assertFalse(build_inputs._consumer_idle(operation.guard, lane_binding=object(),
                desktop_binding=operation.snapshot_binding, owner=None))

    def test_failed_finish_still_enters_independent_snapshot_cleanup(self):
        with original() as operation:
            operation.inspection_deadline = operation_module._IOSInspectionDeadline(operation, operation_module.InspectionDeadline())
            owner = ios_artifacts._IOSSnapshotOwner(operation.guard, None,
                deadline=operation.inspection_deadline, desktop_operation=operation)
            self.assertIs(ios_artifacts._LaneSnapshotOwner, ios_artifacts._IOSSnapshotOwner)
            scope = ios_artifacts._SnapshotScope(owner)
            error = RuntimeError("inert finish failed")
            with patch.object(scope, "finish", side_effect=error), patch.object(scope, "owner_cleanup") as cleanup:
                with self.assertRaises(RuntimeError) as raised:
                    scope._close_owner()
                self.assertIs(raised.exception, error)
                cleanup.assert_called_once_with()

    def test_parser_borrows_exact_recorded_snapshot_not_arbitrary_path_or_deadline(self):
        @contextmanager
        def number(value):
            yield value

        with original() as operation:
            adapter = operation_module._IOSInspectionDeadline(operation, operation_module.InspectionDeadline())
            operation.inspection_deadline = adapter
            owner = ios_artifacts._IOSSnapshotOwner(operation.guard, None, deadline=adapter, desktop_operation=operation)
            operation.snapshot_binding.consumer_active = True
            operation._returned["archive"] = 0  # Inert predicate DATA, not a command receipt.
            details = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o400, st_uid=0, st_gid=0,
                                      st_nlink=1, st_size=4, st_mtime_ns=10, st_ctime_ns=11)
            owner.entries[("known",)] = {"kind": "file", "state": "READY", "binding": build_inputs._file(details)}
            path = owner._path / "known"
            with patch.object(owner, "directory", side_effect=lambda _: number(71)) as directories, \
                    patch.object(owner, "descriptor", side_effect=lambda *args, **kwargs: number(72)) as descriptors, \
                    patch.object(os, "fstat", return_value=details), patch.object(os, "stat", return_value=details):
                with adapter.descriptor(path) as observed:
                    self.assertEqual(observed, 72)
                directories.assert_called_once_with(path.parent)
                self.assertEqual(descriptors.call_args.args[0], "known")
                self.assertEqual(descriptors.call_args.kwargs, {"parent": 71})
                with self.assertRaises(ios_artifacts.ValidationError):
                    with adapter.descriptor(Path("/inert/outside")):
                        self.fail("outside snapshot was admitted")
                operation.snapshot_binding.consumer_active = False
                with self.assertRaises(wire.ProtocolError):
                    with adapter.descriptor(path):
                        self.fail("retired consumer was admitted")
                self.assertEqual(descriptors.call_count, 1)
            with patch.object(adapter, "descriptor", side_effect=lambda _: number(73)) as borrow:
                with macho._macho_descriptor(path, adapter) as observed:
                    self.assertEqual(observed, 73)
                borrow.assert_called_once_with(path)
            # Ordinary clock behavior remains its one original open/close; both
            # APIs are patched DATA here, so no file or native descriptor exists.
            with patch.object(os, "open", return_value=74) as opened, patch.object(os, "close") as closed:
                with macho._macho_descriptor(path, operation_module.InspectionDeadline()) as observed:
                    self.assertEqual(observed, 74)
                opened.assert_called_once()
                closed.assert_called_once_with(74)

    def test_unknown_parser_close_stays_charged_and_never_finishes_consumers(self):
        with original() as operation:
            adapter = operation_module._IOSInspectionDeadline(operation, operation_module.InspectionDeadline())
            operation.inspection_deadline = adapter
            owner = ios_artifacts._IOSSnapshotOwner(operation.guard, None, deadline=adapter, desktop_operation=operation)
            lease = ios_artifacts._SnapshotLease(operation.guard, 0)
            lease.slot.number, lease.slot.open_state = 987654, "OPEN"  # Synthetic only: close API below cannot reach OS.
            owner._leases[0], owner._reserved = lease, 1
            with patch.object(lease.scope, "__exit__", return_value=False), \
                    patch.object(os, "close", side_effect=RuntimeError("inert original close lost")) as closed:
                with self.assertRaises(ProcessCleanupError):
                    owner._finish_lease(lease)
                self.assertEqual(closed.call_count, 1)
                self.assertEqual(lease.slot.close_state, "UNKNOWN")
                self.assertIs(owner._leases[0], lease)
                self.assertEqual((owner._reserved, owner._retired), (1, 0))
                with self.assertRaises(wire.ProtocolError):
                    operation.snapshot_binding.finish_consumers(cancellation=operation.guard)
                self.assertFalse(build_inputs._consumer_idle(operation.guard,
                    desktop_binding=operation.snapshot_binding, owner=owner))
                self.assertFalse(operation.snapshot_closed())
                self.assertEqual(closed.call_count, 1)

    def test_unknown_iterator_prevents_further_snapshot_disposal_and_arbitrary_fd_is_refused(self):
        with original() as operation, patch.object(os, "scandir", side_effect=AssertionError("no native scan")) as scan:
            with self.assertRaises(wire.ProtocolError):
                with operation.files.entries(987654):
                    self.fail("foreign descriptor was admitted")
            scan.assert_not_called()
            adapter = operation_module._IOSInspectionDeadline(operation, operation_module.InspectionDeadline())
            operation.inspection_deadline = adapter
            operation.snapshot_binding.finish_claimed = True
            operation.guard.depth = 1
            iterator = operation_module._IOSIterator(operation.files)
            iterator.state, iterator.close_state = "OPEN", "UNKNOWN"
            operation.files.iterators.append(iterator)
            with self.assertRaises(wire.ProtocolError):
                adapter.check()

    def test_work_refuses_alias_or_symlink_before_consuming_and_preserves_output(self):
        @contextmanager
        def entries(values):
            yield iter(values)

        for alias in (True, False):
            with original() as operation:
                files = operation.files
                details = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFDIR | 0o700,
                    st_uid=os.geteuid(), st_gid=0, st_nlink=1, st_mtime_ns=10, st_ctime_ns=11, st_size=0)
                child = SimpleNamespace(**{**vars(details), "st_mode": stat.S_IFREG | 0o600 if alias else stat.S_IFLNK | 0o777})
                values = [SimpleNamespace(name="same", stat=lambda **_: child)]
                if alias:
                    values.append(SimpleNamespace(name="SAME", stat=lambda **_: child))
                files.work = operation_module._Held(71, "work", build_inputs._FD(operation.guard), True,
                    identity=build_inputs._directory(details), creation={"state": "CREATED"})
                files.work.slot.number, files.work.slot.open_state = 72, "OPEN"  # No actual descriptor acquired.
                files.namespace = SimpleNamespace(check=lambda: None)
                with patch.object(files, "require_work_consumers"), patch.object(files, "check_held"), \
                        patch.object(files, "entries", side_effect=lambda _: entries(values)), \
                        patch.object(os, "fstat", return_value=details), \
                        patch.object(os, "unlink", side_effect=AssertionError("no removal")) as unlink, \
                        patch.object(os, "rmdir", side_effect=AssertionError("no removal")) as rmdir:
                    with self.assertRaises(operation_module.IOSArchiveError) as raised:
                        files.finish_work()
                    self.assertEqual(raised.exception.reason, "work-retained")
                    self.assertEqual(files.work_disposition(), "retained-work")
                    self.assertFalse(operation.guard.lifetime_ledger.fatal)
                    self.assertEqual(files.removals, [])
                    unlink.assert_not_called()
                    rmdir.assert_not_called()

    def test_work_unknown_consumption_has_no_retry_and_known_retention_still_closes(self):
        with original() as operation:
            files = operation.files
            held = operation_module._Held(71, "work-file", build_inputs._FD(operation.guard), False,
                identity={"mode": 0o600})
            held.slot.number, held.slot.open_state = 72, "OPEN"  # Synthetic fd; every OS API below is patched.
            removal = operation_module._IOSRemoval(files, held)
            with patch.object(files, "require_work_consumers"), patch.object(files, "check_held"), \
                    patch.object(os, "unlink", return_value=None) as unlink, \
                    patch.object(os, "fstat", side_effect=RuntimeError("inert postcondition lost")):
                with self.assertRaises(RuntimeError):
                    removal.remove()
                self.assertEqual(removal.state, "UNKNOWN")
                with self.assertRaises(wire.ProtocolError):
                    removal.remove()
                unlink.assert_called_once_with("work-file", dir_fd=71)
                self.assertTrue(operation.guard.lifetime_ledger.fatal)
        with original() as operation, patch.object(operation, "snapshot_closed", return_value=True), \
                patch.object(operation.files, "finish_work", side_effect=operation_module.IOSArchiveError("work-retained")), \
                patch.object(operation.files, "close") as close, patch.object(operation.files, "closed", return_value=True):
            with self.assertRaises(operation_module.IOSArchiveError):
                operation.close()
            close.assert_called_once_with()
            self.assertTrue(operation.resources_closed)
            self.assertFalse(operation.guard.lifetime_ledger.fatal)


if __name__ == "__main__":
    unittest.main()
