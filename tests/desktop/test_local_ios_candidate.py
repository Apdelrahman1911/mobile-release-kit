"""Actual tiny file/original custody and service cut; native/signing are inert.

No Xcode, signing account, subprocess, network or Apple service is entered.
Original IOSArchiveRun.run/terminal and all handoff reads/closes are real; the
producer command/signature/pairing and invocation finality are explicit fixtures,
not evidence of native qualification.
"""
from contextlib import ExitStack, contextmanager, nullcontext
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_ios_archive as data
import test_ios_signed as signed
from mobile_release import local_ios_candidate as C, desktop_ios_archive as service
from mobile_release import ios_archive_operation as O, ios_artifacts as A, local_signing
from mobile_release._desktop_ios_archive_control import IOSArchiveInput
from mobile_release._desktop_ios_archive_selection import select_saved_ios_configuration, bind_saved_ios_version
from mobile_release.build_inputs import _Directory, _FD
from mobile_release.cancellation import DefaultCancellation
from mobile_release.config import ReleaseConfig
from mobile_release.owned_process import ProcessCleanupError
from mobile_release.reporting import Finding, Status


class LocalIOSHandoffTests(unittest.TestCase):
    def setUp(self):
        self.assertNotEqual(os.getuid(), 0)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temp = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="mrk-ios-handoff-"))
        self.serial = 0

    def patch(self, owner, name, **kw):
        return self.stack.enter_context(patch.object(owner, name, **kw))

    def fixture(self, *, configuration=None, request_map=None, register=None, invocation_factory=None, ipa_body=None):
        self.serial += 1
        root = Path(self.temp) / str(self.serial)
        root.mkdir(mode=0o700)
        configuration = signed.signed_configuration() if configuration is None else configuration
        initial = signed.signed_request(configuration)
        wire = {"protocol": data.wire.SIGNED_PROTOCOL, "operationId": initial.operation_id,
                "ownerGeneration": initial.owner_generation, "context": initial.context,
                "native": {**initial.native, "projectRoot": str(root), "cwd": os.getcwd()}}
        if request_map is not None: wire = request_map(root, wire)
        request = data.wire.parse_request(data.encode(wire) + b"\n")
        guard, source = DefaultCancellation(ProcessCleanupError, "inert original iOS producer"), IOSArchiveInput(time.monotonic())
        source.acquired = source.active = source.request_returned = True
        source._request_material(request)
        guard._install_ios_archive_source(source)
        guard.depth = 0
        self.patch(source, "poll", return_value=None)
        self.patch(source, "progress", return_value=None)  # Original IPC transport boundary.
        run = service.IOSArchiveRun(request, guard, source)
        op, files, events = run.operation, run.operation.files, []
        if register is not None: register(run)
        self.patch(op, "checkpoint", side_effect=guard.check)  # No account/project native admission.
        self.patch(op, "check_inputs", side_effect=guard.check)
        self.patch(files, "check_tools", return_value=None)
        self.patch(op, "commands_settled", return_value=True)  # Native process boundary only.
        self.patch(op, "command_dispatch", return_value=True)
        self.patch(op, "prepare", return_value=None)
        self.patch(source, "receive_material", return_value=None)
        self.patch(op.signing, "inputs_closed", return_value=True)
        self.patch(op.signing, "account_closed", return_value=True)
        source.material_pending = False
        op.signing.session = SimpleNamespace(closed=True, _disposal_complete=True, fd=None, native_fd=None)
        op.signing.lease = lease = SimpleNamespace(active=None, locked=True, home_fd=901, fd=902,
            _hold_slot=SimpleNamespace(state="OPEN"), assert_owner=lambda: None)  # Inert account-boundary census.
        op.signing.phase = "inspecting"
        rootdir = _Directory(root, guard); rootdir.acquire()
        self.stack.callback(rootdir.close)
        project = SimpleNamespace(directory=rootdir, meta=_FD(guard))
        self.stack.callback(project.meta.close)
        invocation = (SimpleNamespace(_original_project=project, project_owner=project, closed=False) if invocation_factory is None
                      else invocation_factory(op, project, lease))
        invocation._ios_archive_closed = lambda _: invocation.closed
        invocation.project = lambda **_: nullcontext(project)
        @contextmanager
        def custody(*args, **kw):
            op.invocation = invocation
            try:
                yield invocation
            finally:
                project.meta.close(); rootdir.close(); invocation.closed = True
        self.patch(service, "invocation_custody", new=custody)
        self.patch(local_signing, "local_signing_lease", return_value=nullcontext(lease))
        path = root / ".mobile-release/desktop-ios-archive" / request.operation_id
        archivepath, exportpath = path / "archive.xcarchive", path / "export"
        (archivepath / "Products/Applications").mkdir(mode=0o700, parents=True)
        exportpath.mkdir(mode=0o700)
        contents = {"Info.plist": b"inert plist NOT parsed", "Products/Applications/Inert": b"inert executable NOT run"}
        for name, body in contents.items():
            (archivepath / name).write_bytes(body)
        ipa = exportpath / "Inert.ipa"
        body = b"PK\x03\x04inert IPA NOT parsed or signed" if ipa_body is None else ipa_body
        ipa.write_bytes(body)
        namespace_dir = _Directory(path, guard); namespace_dir.acquire()
        self.stack.callback(namespace_dir.close)
        namespace = SimpleNamespace(path=path, fd=namespace_dir.fd, slots=namespace_dir.slots,
            ios_operation=op, check=namespace_dir.check, cleanup=namespace_dir.close,
            closed=lambda: all(s.close_state == "CLOSED" for s in namespace_dir.slots))
        files.namespace = namespace
        archive = files._hold(namespace.fd, "archive.xcarchive", directory=True)
        export = files._hold(namespace.fd, "export", directory=True)
        iparow = files._hold(export.slot.number, ipa.name, directory=False, parent_record=export)
        op._artifact = O.OriginalIOSArchive(op, archive)
        op._ipa = O.OriginalIOSIPA(op, export, iparow)
        for row in (archive, export, iparow): self.stack.callback(row.slot.close)
        inventory = {"Products": None, "Products/Applications": None, **{
            name: A._File(len(value), hashlib.sha256(value).hexdigest(), value[:4]) for name, value in contents.items()}}
        op._artifact.inventory = inventory
        op._ipa.inventory = A._File(len(body), hashlib.sha256(body).hexdigest(), body[:4])
        raw = json.dumps(configuration, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
        config, selected = select_saved_ios_configuration(raw, request.context["savedConfig"])
        version = b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n"
        saved = bind_saved_ios_version(selected, version, request.context["savedVersion"])
        op.inputs = O.BoundIOSInputs(ReleaseConfig(root / "release/mobile-release.json", root, config), saved)
        self.patch(op, "bind_inputs", return_value=op.inputs)
        def signed_body(_):
            events.append("signed-body")
            op._roles = {role: "returned" for role in op.roles}
            op._roles["prepare"] = "not-configured"
            op._returned = {role: 0 for role in op.roles if role != "prepare"}
            guard.lifetime_ledger._commands = len(op._returned)
            guard.lifetime_ledger._command_dispatched = True
            guard.lifetime_ledger._profile_calls = 3
            run.findings = [Finding(code, Status.PASS, "Inert native boundary") for code in (
                "credential-material.apple-p12", "credential-material.apple-profile", "ios.artifacts.correspondence",
                "ios.ipa.structure", "ios.ipa.profile", "ios.ipa.entitlements", "ios.ipa.signer")]
            run.pairing = {"nativePaths": 1, "nativeIdentities": 1, "presentSymbolSlices": 0}
            op.snapshot_binding.finish_claimed = op.snapshot_binding.finished = True
        self.patch(run, "_signed_body", side_effect=signed_body)
        def finish():
            events.append("work-closed"); files.work_claimed = True
        self.patch(files, "finish_work", side_effect=finish)
        self.patch(files, "work_disposition", return_value="removed")
        self.patch(op, "disposition", return_value={"output": "retained-incomplete", "work": "removed", "snapshot": "removed",
            "relativeDirectory": f".mobile-release/desktop-ios-archive/{op.operation_id}"})
        actual_close = op.close
        def close():
            events.append("producer-close"); actual_close()
        self.patch(op, "close", side_effect=close)
        # Patch the platform gate ONLY while service.run executes; real Linux
        # checked ancestry is used outside it. No actual native API is patched in.
        def execute():
            with patch.object(service.sys, "platform", "darwin"), patch.object(C._Directory, "_physical_role", return_value=None):
                run.run()
        def terminal():
            source.close_claimed = source.closed = True
            guard._saved_command_source = None
            guard._saved_command_source_removed = True
            guard._restoration = "RESTORED"  # Explicit outer handler/input boundary.
            value = run.terminal()
            self.assertEqual(value["outcome"], "complete")
            return value
        return SimpleNamespace(run=run, op=op, source=source, guard=guard, path=path, archive=archivepath, ipa=ipa, invocation=invocation, project=project,
            bound=op.inputs, config_raw=raw, version_raw=version,
            body=body, inventory=inventory, events=events, execute=execute, terminal=terminal)

    def test_actual_service_cut_retains_originals_before_close_and_terminal_joins(self):
        f = self.fixture()
        before = len(os.listdir("/proc/self/fd"))
        real = C.LocalIOSBuildHandoff._capture
        def capture(handoff, run):
            self.assertIn("work-closed", f.events)
            self.assertNotIn("producer-close", f.events)
            real(handoff, run)
        with patch.object(C.LocalIOSBuildHandoff, "_capture", new=capture), C.retain_ios_build_inputs(f.run) as handoff:
            f.execute()
            self.assertTrue(handoff.captured)
            self.assertFalse(handoff.producer_joined)
            with self.assertRaises(C.LocalIOSCandidateError): handoff.observation()
            f.terminal()
            observation = handoff.observation()
            self.assertFalse(observation["candidatePrepared"] or observation["storeAuthorized"])
            self.assertEqual(observation["freshness"], "not-established")
            self.assertEqual(handoff.archive_inventory(), f.inventory)
            with handoff.ipa_blocks() as blocks: self.assertEqual(b"".join(blocks), f.body)
            self.assertEqual(handoff.saved_inputs()[0], f.op.inputs.saved.configuration.raw)
            self.assertLessEqual(handoff.owned_fd_quote, 256)
        self.assertLess(len(os.listdir("/proc/self/fd")), before)
        self.assertEqual(f.ipa.read_bytes(), f.body)
        with self.assertRaises(C.LocalIOSCandidateError): handoff.saved_inputs()

    def test_registration_is_exact_signed_new_nonrecovery_owner(self):
        f = self.fixture()
        for subject in (None, {"result": "old"}):
            with self.assertRaises(C.LocalIOSCandidateError): C.LocalIOSBuildHandoff(subject)
        for field, value in (("_run_claimed", True), ("_close_claimed", True), ("primary", ValueError())):
            with patch.object(f.run, field, value), self.assertRaises(C.LocalIOSCandidateError): C.LocalIOSBuildHandoff(f.run)
        for field in ("signed", "recovery"):
            with patch.object(f.source, field, field == "recovery"), self.assertRaises(C.LocalIOSCandidateError): C.LocalIOSBuildHandoff(f.run)
        with C.retain_ios_build_inputs(f.run):
            with self.assertRaises(C.LocalIOSCandidateError): C.LocalIOSBuildHandoff(f.run)

    def test_changed_tree_or_export_originals_refuse_and_preserve(self):
        for fault in ("file", "same-bytes-new-inode", "extra", "missing", "symlink", "archive", "ipa", "export"):
            with self.subTest(fault=fault):
                f = self.fixture()
                with self.assertRaises((C.LocalIOSCandidateError, ProcessCleanupError, O.IOSArchiveError, OSError, ValidationError)):
                    with C.retain_ios_build_inputs(f.run) as handoff:
                        f.execute(); f.terminal()
                        leaf = f.archive / "Info.plist"
                        if fault == "file": leaf.write_bytes(b"changed")
                        elif fault == "same-bytes-new-inode":
                            body = leaf.read_bytes(); leaf.unlink(); leaf.write_bytes(body)
                        elif fault == "extra": (f.archive / "foreign").write_bytes(b"do not remove")
                        elif fault == "missing": leaf.unlink()
                        elif fault == "symlink": leaf.unlink(); leaf.symlink_to(f.ipa)
                        elif fault in {"archive", "export"}:
                            path = f.archive if fault == "archive" else f.ipa.parent
                            path.rename(path.with_name(path.name + "-old")); path.mkdir()
                        else:
                            body = f.ipa.read_bytes(); f.ipa.unlink(); f.ipa.write_bytes(body)
                        handoff.archive_inventory()
                self.assertTrue(handoff.failed)
                self.assertTrue(f.path.exists())

    def test_source_result_prequote_and_capture_acquisition_refusals(self):
        for fault in ("config", "fd-limit", "control-limit", "replacement"):
            with self.subTest(fault=fault):
                f = self.fixture()
                actual_capture = C.LocalIOSBuildHandoff._capture
                actual_acquire = C._Directory.acquire
                def capture(handoff, run):
                    if fault == "config": run._candidate["usedConfig"]["sha256"] = "0" * 64
                    return actual_capture(handoff, run)
                def acquire(directory):
                    if fault == "replacement" and directory.lexical_path == f.path:
                        f.path.rename(f.path.with_name(f.path.name + "-old")); f.path.mkdir()
                    return actual_acquire(directory)
                with patch.object(C.LocalIOSBuildHandoff, "_capture", new=capture), \
                     patch.object(C._Directory, "acquire", new=acquire), \
                     patch.object(C, "MAX_OWNED_FDS", 1 if fault == "fd-limit" else 256), \
                     patch.object(C, "MAX_CONTROL_BYTES", 1 if fault == "control-limit" else 32 * 1024**2):
                    with self.assertRaises((C.LocalIOSCandidateError, ProcessCleanupError, OSError)):
                        with C.retain_ios_build_inputs(f.run) as handoff: f.execute()
                self.assertTrue(handoff.failed)
                self.assertFalse(handoff.captured)
                if fault in {"fd-limit", "control-limit", "config"}: self.assertIsNone(handoff.parent)

    def test_negative_terminal_is_absorbing_and_original_deadline_is_not_renewed(self):
        for fault in ("negative", "deadline"):
            with self.subTest(fault=fault):
                f = self.fixture()
                with C.retain_ios_build_inputs(f.run) as handoff:
                    f.execute()
                    if fault == "negative":
                        self.assertEqual(f.run.terminal()["outcome"], "unknown")
                        f.terminal()
                        self.assertFalse(handoff.producer_joined)
                    else:
                        f.terminal(); f.source.work_end = time.monotonic() - 1
                    with self.assertRaises(C.LocalIOSCandidateError): handoff.observation()
                    self.assertTrue(handoff.failed)

    def test_reads_are_finite_and_abandoned_ipa_never_succeeds(self):
        for fault in ("unstarted", "partial", "over-limit"):
            f = self.fixture()
            with self.assertRaises((C.LocalIOSCandidateError, ProcessCleanupError)):
                with C.retain_ios_build_inputs(f.run) as handoff:
                    f.execute(); f.terminal()
                    if fault == "over-limit":
                        handoff.archive_inventory(); handoff.archive_inventory(); handoff.archive_inventory()
                    else:
                        with handoff.ipa_blocks() as blocks:
                            if fault == "partial": next(blocks)
            self.assertTrue(handoff.failed)

    def test_scan_close_unknown_stays_charged_but_independent_files_close(self):
        f = self.fixture()
        native_scandir = os.scandir
        closes = []
        class Scan:
            def __init__(self, number): self.original = native_scandir(number)
            def __iter__(self): return self
            def __next__(self): return next(self.original)
            def close(self):
                closes.append(self)
                self.original.close()
                raise OSError("inert lost iterator close return")
        with self.assertRaises((ProcessCleanupError, OSError, ValidationError)):
            with C.retain_ios_build_inputs(f.run) as handoff:
                f.execute(); f.terminal()
                with patch.object(C.os, "scandir", new=Scan): handoff.archive_inventory()
        self.assertEqual(len(closes), 1)
        self.assertEqual(len(handoff.iterators), 1)
        self.assertEqual(handoff.iterators[0][1], "CLOSING")
        self.assertTrue(all(row.slot.close_state == "CLOSED" for row in (handoff.archive, handoff.export, handoff.ipa)))
        self.assertTrue(handoff.failed and f.guard.lifetime_ledger.fatal)

    def test_original_read_error_aborts_and_cannot_be_reused(self):
        f = self.fixture()
        with self.assertRaises((ProcessCleanupError, OSError)):
            with C.retain_ios_build_inputs(f.run) as handoff:
                f.execute(); f.terminal()
                with patch.object(C.os, "pread", side_effect=OSError("inert read failure")):
                    with handoff.ipa_blocks() as blocks: list(blocks)
        self.assertTrue(handoff.failed and f.guard.lifetime_ledger.fatal)
        with self.assertRaises(C.LocalIOSCandidateError): handoff.archive_inventory()

    def test_consuming_close_unknown_is_not_retried_and_other_originals_close(self):
        f = self.fixture()
        with self.assertRaises(ProcessCleanupError):
            with C.retain_ios_build_inputs(f.run) as handoff:
                f.execute(); f.terminal()
                original_close, selected, calls = os.close, handoff.ipa.slot.number, []
                def close(number):
                    calls.append(number)
                    original_close(number)
                    if number == selected: raise OSError("inert lost close return")
                self.stack.enter_context(patch.object(os, "close", new=close))
        self.assertEqual(calls.count(selected), 1)
        self.assertEqual(handoff.ipa.slot.close_state, "UNKNOWN")
        self.assertTrue(all(row.slot.close_state == "CLOSED" for row in (handoff.archive, handoff.export)))
        self.assertTrue(all(row.close_state == "CLOSED" for row in handoff.parent.slots))
        self.assertTrue(f.guard.lifetime_ledger.fatal)


from mobile_release.errors import ValidationError
