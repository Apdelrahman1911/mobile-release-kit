"""Filesystem-only Store reader/fence regressions with modeled command finality.

All paths are disposable, credential-free children of this test's unique temp
directory. No Ruby, command, signal, native task or Store operation is executed.
The original _Outer publisher consumes explicit inert state, NOT a native receipt.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release import _command_process as command
from mobile_release import _store_lane_contract as wire
from mobile_release import _store_lane_files as files_module
from mobile_release import cancellation as cancellation_module
from mobile_release._store_lane_evidence import StoreLaneCallEvidence, StoreLaneEvidenceError
from mobile_release.cancellation import DefaultCancellation
from mobile_release.owned_process import PRIVATE_OUTPUT_LIMIT, ProcessCleanupError, ProcessError
from unit.test_lifetime_evidence import fork_registry_model


LANE = "ios_testflight_internal"
RUNNER = Path("/fictional/tooling/fastlane/run_lane.rb")
INTENT = hashlib.sha256(b"credential-free synthetic intent").digest()
AUTHORITY = {"attempt": 1, "callerPath": ".github/workflows/candidate.yml",
    "event": "workflow_dispatch", "headSha": "a" * 40, "ref": "refs/heads/main",
    "reusableCommit": "b" * 40, "reusablePath": ".github/workflows/candidate.yml",
    "reusableRepository": "synthetic/project", "runId": 1, "workflow": "candidate"}


def identity(value):
    return {"device": value.st_dev, "inode": value.st_ino, "uid": value.st_uid,
            "gid": value.st_gid, "mode": stat.S_IMODE(value.st_mode)}


def write_exclusive(path, content):
    number = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        data = memoryview(content)
        while data:
            count = os.write(number, data)
            if count <= 0:
                raise OSError("synthetic fixture writer made no progress")
            data = data[count:]
        os.fsync(number)
        return identity(os.fstat(number))
    finally:
        os.close(number)


class StoreLaneFilesTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(fork_registry_model())
        self.temporary = tempfile.TemporaryDirectory(prefix="mrk-store-files-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.owners, self.engines, self.fixtures = [], [], []
        for name in ("kill", "killpg", "fork", "execve", "pipe"):
            veto = patch.object(command.os, name, side_effect=AssertionError("filesystem-only test attempted process effect"))
            veto.start(); self.addCleanup(veto.stop)
        for target, name in ((command.native, "create"), (command.threading.Thread, "start"),
                             (command.subprocess, "Popen"), (cancellation_module.signal, "signal")):
            veto = patch.object(target, name, side_effect=AssertionError("filesystem-only test attempted worker/handler effect"))
            veto.start(); self.addCleanup(veto.stop)
        self.addCleanup(self.close_original_owners)

    def close_original_owners(self):
        # Failures intentionally retain product scratch. These fixture-only
        # owners have no live consumers; independently close known original FDs.
        for owner in reversed(self.owners):
            owner.close_handles()
        files_module._RETAINED[:] = [owner for owner in files_module._RETAINED
            if not any(owner is mine for mine in self.owners)]
        command._RETAINED[:] = [owner for owner in command._RETAINED
            if not any(owner is mine for mine in self.engines)]

    def fixture(self, *, app=None, marker=True, shell_home=False):
        index = len(self.fixtures) + 1
        if app is None:
            app = self.root / f"app-{index}"
            app.mkdir(mode=0o700)
        output_dir = app / f"output-{index}"
        output_dir.mkdir(mode=0o700)
        output = output_dir / "raw.json"
        guard = DefaultCancellation(ProcessCleanupError, "synthetic file-owner error")
        record = StoreLaneCallEvidence(guard, lane=LANE, output=output, nonce=index.to_bytes(16, "big"))
        files = files_module.StoreLaneFiles(record, guard, app_root=app, mode="execute", shell_home=shell_home)
        attempt = files_module.StoreLaneAttempt(record, guard, app_root=app, mode="execute",
            intent_sha256=INTENT, executed_by=AUTHORITY)
        self.owners.extend((files, attempt))
        files.acquire()
        if marker:
            attempt.acquire()
        environment = files.prepare_environment({"MOBILE_RELEASE_OPERATION": LANE,
            "MOBILE_RELEASE_STORE_MODE": "execute", "MOBILE_RELEASE_STORE_RECEIPT_PATH": str(output),
            "MOBILE_RELEASE_ASC_APP_ID": "123456789", "MOBILE_RELEASE_ASC_KEY_ID": "ABCDEF1234"})
        value = SimpleNamespace(app=app, output=output, guard=guard, record=record, files=files,
                                attempt=attempt, environment=environment)
        self.fixtures.append(value)
        return value

    def group(self, fixture, *, code=0, no_target=False, confirmed=True):
        argv = fixture.record.seal_command(runner=RUNNER, cwd=fixture.files.cwd,
            environ=fixture.environment, cancellation=fixture.guard)
        evidence = fixture.record.command_evidence(cancellation=fixture.guard)
        evidence._attempt(fixture.guard, timeout=3600, ordinary=True)
        engine = command._Outer(fixture.guard, False, 3600, None, None,
                                suppress_cancel=False, evidence=evidence)
        self.engines.append(engine)
        evidence._bind(engine); engine.evidence = evidence
        engine.frozen = command._freeze_command(argv, environ=fixture.environment, cwd=fixture.files.cwd,
            capture=False, output_limit=PRIVATE_OUTPUT_LIMIT, nonce=engine.nonce)
        evidence._match(engine)
        engine.handlers_complete, engine.local_cleanup_complete = True, confirmed
        engine.create_route.retired = engine.run_route.retired = True
        if not no_target:
            engine.create_route.attempted = engine.run_route.attempted = True
            engine.wait = command.native.WaitReceipt(1001, "exit", command.HELPER_OK, 0)
            engine.child = SimpleNamespace(receipt=engine.wait)
            engine.sealed, engine.wire = True, SimpleNamespace(eof=True, poisoned=False)
            engine.readers, engine.output_eof = [object(), object()], [True, True]
            engine.terminal = {"producer": True, "no_target": None, "stdout": 0, "stderr": 0,
                               "result": True, "wait": {"kind": "exit", "code": code}}
        fixture.outcome = engine.publish()
        return fixture.outcome

    def terminal(self, fixture, *, success=True, inventory=()):
        receipt = None
        if success:
            content = b'{"synthetic":true}\n'
            receipt = {**write_exclusive(fixture.output, content), "size": len(content),
                       "sha256": hashlib.sha256(content).hexdigest()}
        part = fixture.files.root_path / "terminal.part"
        number = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        try:
            value = {"version": 1, "nonce": fixture.record._nonce.hex(), "lane": LANE, "mode": "execute",
                "output": str(fixture.output), "clock": fixture.files.timing.clock,
                "run_deadline_ns": fixture.files.timing.run, "hard_deadline_ns": fixture.files.timing.hard,
                "outcome": "success" if success else "failed", "launches_closed": True,
                "adapter_settled": True, "nested_settled": True,
                "terminal_identity": identity(os.fstat(number)), "receipt": receipt, "inventory": list(inventory)}
            data = (json.dumps(value, separators=(",", ":")) + "\n").encode("utf-8")
            self.assertEqual(os.write(number, data), len(data))
            os.fsync(number)
        finally:
            os.close(number)
        os.link(part, part.with_name("terminal.json"))
        return value

    def key_inventory(self, fixture):
        root = fixture.files.root_path / "tmp" / ("deliver-" + "a" * 32)
        root.mkdir(mode=0o700)
        key = root / "AuthKey_ABCDEF1234.p8"
        key_identity = write_exclusive(key, b"synthetic non-key fixture\n")
        return [dict(role="key-dir", parent="tmp", name=root.name, kind="directory", **identity(root.stat())),
                dict(role="key", parent="key-dir", name=key.name, kind="file", **key_identity)]

    def finish(self, fixture):
        verdict = fixture.record.finish(cancellation=fixture.guard)
        self.assertTrue(verdict.dependents_settled)
        self.assertFalse(verdict.receipt_acceptable)
        fixture.files.dispose()
        fixture.attempt.retire()
        return fixture.record.verdict(cancellation=fixture.guard)

    def test_reader_verifies_actual_links_output_and_close_before_final_receipt(self):
        fixture = self.fixture(shell_home=True)
        self.assertEqual(fixture.environment["HOME"], str(fixture.files.root_path / "home"))
        self.group(fixture)
        self.terminal(fixture)
        terminal = fixture.files.read_terminal()
        self.assertEqual(fixture.files.checked_document(), fixture.output.read_bytes())
        self.assertEqual(terminal.receipt_sha256, hashlib.sha256(fixture.files.checked_document()).digest())
        unlinks, original_unlink = [], os.unlink
        def observe(name, *args, **kwargs):
            if name in ("terminal.json", "terminal.part"):
                unlinks.append((name, os.stat(name, dir_fd=kwargs["dir_fd"], follow_symlinks=False).st_nlink))
            return original_unlink(name, *args, **kwargs)
        with patch.object(files_module.os, "unlink", side_effect=observe):
            self.assertTrue(self.finish(fixture).receipt_acceptable)
        self.assertEqual(unlinks, [("terminal.json", 2), ("terminal.part", 1)])
        self.assertFalse(fixture.files.root_path.exists())
        self.assertTrue(fixture.output.is_file())  # Required Store output survives scratch disposal.
        self.assertTrue(all(owner.handles_closed() for owner in self.owners))

    def test_settled_failure_can_remove_declared_generated_files_but_never_accept_receipt(self):
        fixture = self.fixture()
        self.group(fixture, code=75)
        self.terminal(fixture, success=False, inventory=self.key_inventory(fixture))
        self.assertIsNone(fixture.files.read_terminal().receipt_sha256)
        self.assertFalse(self.finish(fixture).receipt_acceptable)
        self.assertFalse(fixture.files.root_path.exists())

    def test_no_target_needs_no_terminal_and_arbitrary_status_never_first_binds_one(self):
        fixture = self.fixture()
        self.group(fixture, no_target=True)
        self.assertIsNone(fixture.files.read_terminal())
        self.assertFalse(self.finish(fixture).receipt_acceptable)
        for code in (7, 76):
            unknown = self.fixture()
            self.group(unknown, code=code)
            self.terminal(unknown, success=False)
            with patch.object(files_module, "_read", side_effect=AssertionError("unadmitted terminal was opened")), \
                 self.assertRaises(StoreLaneEvidenceError):
                unknown.files.read_terminal()
            self.assertIsNone(unknown.record._terminal)
            self.assertTrue((unknown.files.root_path / "terminal.json").exists())

    def test_terminal_close_lost_return_preserves_scratch_and_closes_independent_descriptors(self):
        fixture = self.fixture()
        self.group(fixture); self.terminal(fixture)
        wanted = (fixture.files.root_path / "terminal.part").stat().st_ino
        original_close, attempted = os.close, []
        def close(number):
            value = os.fstat(number)
            original_close(number)
            if value.st_ino == wanted and not attempted:
                attempted.append(number)
                raise OSError("synthetic original close return lost")
        with patch.object(files_module.os, "close", side_effect=close):
            with self.assertRaises(StoreLaneEvidenceError):
                fixture.files.read_terminal()
        self.assertEqual(len(attempted), 1)
        self.assertIsNone(fixture.record._terminal)
        self.assertTrue(all(slot.state in ("CLOSED", "UNKNOWN") and slot.number is None
                            for slot in fixture.files.slots))
        self.assertTrue((fixture.files.root_path / "terminal.json").exists())

    def test_terminal_open_failure_preserves_original_interruption_and_runs_other_closes(self):
        fixture = self.fixture()
        self.group(fixture); self.terminal(fixture)
        original_open, primary = os.open, KeyboardInterrupt()
        def refuse(name, *args, **kwargs):
            if name == "terminal.part":
                raise OSError("synthetic terminal read admission failure")
            return original_open(name, *args, **kwargs)
        with patch.object(files_module.os, "open", side_effect=refuse), self.assertRaises(KeyboardInterrupt) as caught:
            fixture.files.read_terminal(primary=primary)
        self.assertIs(caught.exception, primary)
        self.assertIsNone(fixture.record._terminal)
        self.assertTrue(all(slot.state in ("CLOSED", "UNKNOWN") and slot.number is None
                            for slot in fixture.files.slots))

    def test_replaced_generated_entry_survives_and_independent_terminal_cleanup_continues(self):
        fixture = self.fixture()
        self.group(fixture, code=75)
        entries = self.key_inventory(fixture)
        self.terminal(fixture, success=False, inventory=entries)
        fixture.files.read_terminal()
        fixture.record.finish(cancellation=fixture.guard)
        key = fixture.files.root_path / "tmp" / entries[0]["name"] / entries[1]["name"]
        key.rename(fixture.app / "original-key-fixture")
        foreign = b"foreign fixture must survive\n"
        write_exclusive(key, foreign)
        with self.assertRaises(StoreLaneEvidenceError):
            fixture.files.dispose()
        self.assertEqual(key.read_bytes(), foreign)
        self.assertFalse((fixture.files.root_path / "terminal.part").exists())
        self.assertFalse((fixture.files.root_path / "terminal.json").exists())
        self.assertTrue((fixture.app / ".mobile-release/store/lane-attempts-v1" / fixture.attempt.name).exists())
        self.assertTrue(fixture.files.handles_closed())

    def test_root_replacement_or_undeclared_file_never_authorizes_recursive_removal(self):
        for replace in (True, False):
            fixture = self.fixture()
            self.group(fixture, code=75); self.terminal(fixture, success=False)
            fixture.files.read_terminal(); fixture.record.finish(cancellation=fixture.guard)
            if replace:
                fixture.files.root_path.rename(fixture.app / "retained-original-root")
                fixture.files.root_path.mkdir(mode=0o700)
            foreign = fixture.files.root_path / "foreign"
            write_exclusive(foreign, b"must survive\n")
            with self.assertRaises(StoreLaneEvidenceError):
                fixture.files.dispose()
            self.assertEqual(foreign.read_bytes(), b"must survive\n")
            self.assertTrue(fixture.files.handles_closed())

    def test_output_change_and_incomplete_or_replaced_terminal_links_cannot_publish(self):
        for change in ("document-bytes", "terminal-link", "terminal-symlink"):
            fixture = self.fixture()
            self.group(fixture); self.terminal(fixture)
            terminal = fixture.files.root_path / "terminal.json"
            if change == "document-bytes":
                fixture.output.write_bytes(b"different synthetic bytes\n")
            else:
                terminal.unlink()
                if change == "terminal-link":
                    write_exclusive(terminal, b"foreign terminal fixture\n")
                else:
                    terminal.symlink_to(fixture.output)
            with self.subTest(change=change), self.assertRaises(StoreLaneEvidenceError):
                fixture.files.read_terminal()
            self.assertIsNone(fixture.record._terminal)
            self.assertTrue(terminal.exists())
            self.assertTrue(fixture.files.handles_closed())

    def test_lost_directory_creation_return_retains_reservation_without_path_adoption(self):
        name = (1).to_bytes(16, "big").hex()
        original = os.mkdir
        def lost_return(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if path == name:
                raise OSError("synthetic original mkdir return lost")
            return result
        with patch.object(files_module.os, "mkdir", side_effect=lost_return), \
             self.assertRaises(StoreLaneEvidenceError):
            self.fixture()
        files = self.owners[0]
        self.assertEqual(files.creations[-1].state, "UNKNOWN")
        self.assertIsNone(files.creations[-1].directory)
        self.assertTrue((self.root / "app-1/.mobile-release/store/lane-private-v1" / name).is_dir())
        self.assertTrue(files.handles_closed())
        self.assertFalse(files.record._attempted)

    def test_marker_collision_and_replacement_survive_changed_output_and_new_owner(self):
        first = self.fixture()
        original_path = first.app / ".mobile-release/store/lane-attempts-v1" / first.attempt.name
        original = original_path.read_bytes()
        second = self.fixture(app=first.app, marker=False)
        self.assertNotEqual(second.output, first.output)
        with self.assertRaises(StoreLaneEvidenceError):
            second.attempt.acquire()
        self.assertEqual(original_path.read_bytes(), original)
        first.record.finish(cancellation=first.guard); first.files.dispose()
        original_path.rename(first.app / "original-marker-fixture")
        write_exclusive(original_path, b"foreign marker\n")
        with self.assertRaises(StoreLaneEvidenceError):
            first.attempt.retire()
        self.assertEqual(original_path.read_bytes(), b"foreign marker\n")

    def test_absence_probe_and_copied_raw_bytes_supply_no_live_invocation_authority(self):
        fixture = self.fixture(marker=False)
        fixture.attempt.require_absent()
        write_exclusive(fixture.output, b'{"copied":true}\n')
        with self.assertRaises(StoreLaneEvidenceError):
            fixture.record.seal_command(runner=RUNNER, cwd=fixture.files.cwd,
                environ=fixture.environment, cancellation=fixture.guard)
        self.assertFalse(fixture.record._attempted)
        fixture.record.finish(cancellation=fixture.guard)
        with self.assertRaises(ProcessError):
            fixture.record.require_receipt(lane=LANE, output=fixture.output,
                sha256=hashlib.sha256(fixture.output.read_bytes()).digest(), cancellation=fixture.guard)
        self.assertTrue(fixture.output.is_file())


if __name__ == "__main__":
    unittest.main()
