"""Own temporary input files + synthetic Git/C-A-W/duplex data, never execution.

The real fixed readers, invocation scopes, command admission and original slot
binding run. A fake run_command supplies bounded Git responses; its injected
outcome is deliberately NOT a native finality receipt or a real Git repository.
No subprocess, credential, HTTP, Store, native worker or project mutation runs.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager, ExitStack
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mobile_release import _command_process as commands
from mobile_release import _desktop_version_allocation_protocol as allocation_wire
from mobile_release import _desktop_version_allocation_runtime as runtime
from mobile_release import _desktop_version_allocation_source_protocol as wire
from mobile_release import build_inputs, checked_files, local_release_source
from mobile_release import version_allocation as allocation
from mobile_release import version_allocation_source as source
from mobile_release import version_allocation_state as state
from mobile_release import version_policy as policy
from mobile_release._desktop_version_allocation_source_control import BorrowedAllocationInput
from mobile_release.cancellation import CleanupScope, DefaultCancellation
from mobile_release.config import default_config_data
from mobile_release.errors import ValidationError
from mobile_release.owned_process import ProcessCleanupError, ProcessError

from test_version_allocation import COMMIT, NOW, initial, observations, request
from test_version_allocation_state import LOCAL_PROJECT, NativePortFixture


class SourceFixture:
    CONTROL, OUTPUT = 3000, 3001  # Inert numbers; never opened, read or closed.

    def __init__(self, root):
        self.root = root
        self.data = default_config_data({"android": {"applicationId": "com.example.inert"}})
        self.data["source"]["localStoreEnabled"] = False
        self.version = b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n"
        self.save()
        for directory in (".git/objects/info", ".git/info", ".git/refs/heads"):
            (root / directory).mkdir(parents=True, exist_ok=True)
        self.write(".git/config", b"[core]\nrepositoryformatversion = 0\nbare = false\n")
        self.write(".git/HEAD", b"ref: refs/heads/main\n")
        self.write(".git/index", b"INERT: no real Git index\n")
        self.write(".git/refs/heads/main", ("2" * 40 + "\n").encode())
        self.now = 10.0
        self.incoming, self.outgoing = bytearray(), bytearray()
        self.frames, self.calls, self.engines, self.events = [], [], [], []
        self.eof = False
        self.control_reads = self.control_closes = 0
        self.status = b""
        self.outcome_enabled = True
        self.after_command = lambda run: None
        self.before_fin = lambda call: None
        self.malformed_go = False
        self.native = self.native_journal = None
        self.guard = self.input = self.operation = self.dialogue = None
        self.outcomes = {}

    def write(self, relative, body):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        path.chmod(0o600)

    def save(self):
        self.config = json.dumps(self.data).encode()
        self.write("release/mobile-release.json", self.config)
        self.write(self.data["version"]["source"], self.version)

    def source_request(self):
        value = self.root.stat()
        return wire.SourceRequest.parse({"projectId": "project-1", "projectRoot": str(self.root),
            "rootIdentity": {"device": str(value.st_dev), "inode": str(value.st_ino), "mode": value.st_mode,
                             "uid": value.st_uid, "gid": value.st_gid},
            "savedConfig": {"bytes": len(self.config), "sha256": hashlib.sha256(self.config).hexdigest()},
            "savedVersion": {"source": self.data["version"]["source"], "bytes": len(self.version),
                             "sha256": hashlib.sha256(self.version).hexdigest()}, "ref": "refs/heads/main"})

    def binding(self):
        r = self.source_request()
        return policy.SourceBinding("2" * 40, "3" * 40, r.ref, r.configuration_sha256, r.version_sha256)

    @staticmethod
    def clock():
        return {"name": "CLOCK_UPTIME_RAW", "workEndNs": "70000000000", "hardEndNs": "80000000000"}

    def initial(self, source_request=None):
        return allocation_wire.encoded({"protocol": wire.PROTOCOL, "id": "source-1", "action": {
            "source": (source_request or self.source_request()).value(), "clock": self.clock()}}, wire.REQUEST_LIMIT)

    def _fstat(self, fd):
        if fd in (self.CONTROL, self.OUTPUT):
            return SimpleNamespace(st_dev=17, st_ino=fd, st_mode=stat.S_IFIFO | 0o600)
        return self.real_fstat(fd)

    def _read(self, fd, count):
        if fd != self.CONTROL:
            assert fd != self.OUTPUT
            return self.real_read(fd, count)
        self.control_reads += 1
        if self.incoming:
            block = bytes(self.incoming[:min(count, 37)])
            del self.incoming[:len(block)]
            return block
        if self.eof:
            return b""
        raise BlockingIOError()

    def _write(self, fd, raw):
        if fd != self.OUTPUT:
            assert fd != self.CONTROL
            return self.real_write(fd, raw)
        size = min(43, len(raw))
        self.outgoing.extend(raw[:size])
        if b"\n" in self.outgoing:
            row = allocation_wire.frame(bytes(self.outgoing), allocation_wire.FIN_LIMIT)
            self.outgoing.clear()
            self.frames.append(row)
            if "ready" in row:
                digest = "0" * 64 if self.malformed_go else row["ready"]["requestSha256"]
                self.incoming.extend(allocation_wire.encoded({"protocol": wire.PROTOCOL, "id": row["id"],
                    "go": {"requestSha256": digest}}, wire.GO_LIMIT))
            elif "finished" in row:
                self.before_fin(source._RETAINED[-1])
                self.eof = True
            else:
                assert self.native is not None and row["state"]["transition"]["kind"] == "pending"
                step = row["state"]
                self.events.append("pending-frame")
                pending = allocation.PendingAllocation.parse(policy.canonical(step["transition"]["pending"]) + b"\n")
                self.native_journal.record_pending(pending)
                assert self.native.snapshot.revision == step["expectedRevision"] + 1
                assert hashlib.sha256(self.native.snapshot.payload).hexdigest() == step["payloadSha256"]
                self.events.append("simulated-native-pending-ack")
                self.incoming.extend(allocation_wire.encoded({"protocol": allocation_wire.PROTOCOL, "id": row["id"],
                    "ack": {"requestSha256": step["requestSha256"], "sequence": step["sequence"],
                            "revision": self.native.snapshot.revision, "payloadSha256": step["payloadSha256"],
                            "effect": "committed", "durability": "durable", "cleanup": "settled"}}, allocation_wire.ACK_LIMIT))
        return size

    def _close(self, fd):
        if fd in (self.CONTROL, self.OUTPUT):
            self.control_closes += 1
            raise AssertionError("A borrower tried to close a bootstrap descriptor")
        return self.real_close(fd)

    def _select(self, readers, writers, exceptional, timeout):
        assert readers in ([], [self.CONTROL]) and writers in ([], [self.OUTPUT]) and not exceptional
        ready = bool(readers and (self.incoming or self.eof))
        if not ready and not writers:
            self.now += timeout
        return readers if ready else [], writers, []

    def _command(self, argv, **kw):
        """Only DATA: construct the actual pre-IO slot, never acquire/launch it."""
        run = kw["cancellation"]._version_allocation_source.require_operation()
        engine = commands._Outer(run.guard, False, kw["timeout"], None, None, suppress_cancel=False, text=False)
        self.engines.append(engine)
        assert run.pending["slot"] is engine.slot
        self.calls.append((argv, kw.copy()))
        role = argv[17:]
        names = {"release/mobile-release.json": self.config, self.data["version"]["source"]: self.version}
        blobs = {key: hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
                 for key, body in names.items()}
        if role[0] == "config":
            body = b"core.repositoryformatversion\n0\0core.bare\nfalse\0"
        elif role[0] == "rev-parse":
            body = ("2" * 40 + "\n" + "3" * 40 + "\n").encode()
        elif role[:2] == ["ls-files", "--stage"]:
            body = b"".join(f"100644 {digest} 0\t{name}\0".encode() for name, digest in blobs.items())
        elif role[0] == "ls-files":
            body = b"".join(f"H {name}\0".encode() for name in names)
        elif role[0] == "ls-tree":
            body = b"".join(f"100644 blob {digest}\t{name}\0".encode() for name, digest in blobs.items())
        else:
            assert role == ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"]
            self.events.append("status")
            body = self.status
        # Fixture-only outcome/folding. Neither this SimpleNamespace nor the
        # untouched NEW engine can pass the real original_outcome predicate.
        self.outcomes[engine.slot] = SimpleNamespace(result_integrity="complete", termination="normal-exit", returncode=0)
        run.guard.lifetime_ledger._finish_command(engine.slot, dispatched=True, contained=True, cleanup_complete=True)
        self.after_command(run)
        return subprocess.CompletedProcess(argv, 0, body, b"")

    @contextmanager
    def mocks(self):
        self.real_fstat, self.real_read, self.real_write, self.real_close = os.fstat, os.read, os.write, os.close
        with ExitStack() as stack:
            stack.enter_context(patch.object(os, "fstat", self._fstat))
            stack.enter_context(patch.object(os, "read", self._read))
            stack.enter_context(patch.object(os, "write", self._write))
            stack.enter_context(patch.object(os, "close", self._close))
            stack.enter_context(patch.object(os, "set_blocking", lambda fd, flag: None))
            stack.enter_context(patch.object(runtime.select, "select", self._select))
            stack.enter_context(patch.object(time, "monotonic", lambda: self.now))
            stack.enter_context(patch.object(time, "CLOCK_UPTIME_RAW", 33, create=True))
            stack.enter_context(patch.object(time, "clock_gettime_ns", lambda clock: int(self.now * 1e9)))
            # No native rename implementation or real command is invoked.
            stack.enter_context(patch.object(build_inputs, "_rename_function", return_value=None))
            stack.enter_context(patch.object(commands, "run_command", self._command))
            stack.enter_context(patch.object(source.AllocationSourceRun, "_outcome",
                lambda run, row: self.outcomes.get(row["slot"]) if self.outcome_enabled else None))
            yield

    @contextmanager
    def owned(self, *, selected=None, requested=None):
        requested = requested or self.source_request()
        if selected is None:
            start = wire.parse_initial(self.initial(requested))
            requested = start.source
        else:
            _, authority = initial()
            start = allocation_wire.parse_initial(allocation_wire.encoded({"protocol": allocation_wire.PROTOCOL,
                "id": "allocation-1", "action": {"kind": "reserve", "localProjectId": LOCAL_PROJECT,
                    "authority": authority.value(), "accountId": "17", "candidateId": selected.candidate_id,
                    "requestSha256": selected.sha256, "clock": self.clock()}}, allocation_wire.INITIAL_LIMIT))
        self.dialogue = runtime._Dialogue(self.CONTROL, self.OUTPUT, start, self.now)
        self.dialogue.bind()
        self.dialogue.phase = "active"
        self.guard = DefaultCancellation(ProcessCleanupError, "Synthetic source did not settle")
        self.input = BorrowedAllocationInput(self.dialogue, requested)

        def close():
            if self.input.operation is not None:
                self.input.operation.close()
            if self.input.acquired and not self.input.borrow_ended:
                self.input.end_borrow()

        scope = CleanupScope(self.guard, close, owns_cancellation=True, first_primary=True)
        try:
            with scope:
                self.guard.install()
                self.input.acquire_borrow()
                self.guard._install_saved_command_source(self.input)
                self.guard.activate()
                self.operation = source.AllocationSourceRun(requested, self.guard, self.input, selected=selected)
                yield self.operation
        finally:
            scope.__exit__(*sys.exc_info())

    def journal(self, selected):
        ledger, authority = initial()
        self.native = NativePortFixture()
        self.native_journal = state.NativeAllocationJournal(self.native, local_project_id=LOCAL_PROJECT)
        self.native_journal.enroll_authority(authority, allocation.Checkpoint(0, ledger.head_sha256, COMMIT))
        self.native_journal.select_candidate(authority, selected)
        go = allocation_wire.parse_go(allocation_wire.encoded({"protocol": allocation_wire.PROTOCOL,
            "id": self.dialogue.initial.id, "go": {"requestSha256": self.dialogue.initial.digest,
                "token": "INERT-not-a-credential", "request": selected.value(), "observations": [],
                "state": {"revision": self.native.snapshot.revision,
                          "payload": base64.b64encode(self.native.snapshot.payload).decode()}}}, allocation_wire.GO_LIMIT),
            self.dialogue.initial)
        journal = runtime._Journal(runtime._StatePort(self.dialogue, go))
        reservation = ledger.append(selected, observations(), now=NOW).reservations[-1]
        pending = allocation.PendingAllocation(authority, journal.checkpoint(authority), allocation.blob_sha(ledger.to_bytes()), reservation)
        return journal, pending


class VersionAllocationSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mrk-allocation-source-inert-")
        self.root = Path(self.tmp.name) / "project"
        self.root.mkdir()
        self.fixture = SourceFixture(self.root)
        self.retained = len(source._RETAINED)

    def tearDown(self):
        del source._RETAINED[self.retained:]  # Only these inert test invocations.
        self.tmp.cleanup()

    def test_source_protocol_exact_heads_root_and_saved_bytes_no_credential_or_state(self):
        f = self.fixture
        parsed = wire.parse_initial(f.initial())
        self.assertEqual(parsed.source.value(), f.source_request().value())
        self.assertEqual(set(allocation_wire.frame(wire.ready_frame(parsed), wire.READY_LIMIT)), {"protocol", "id", "ready"})
        wire.parse_go(allocation_wire.encoded({"protocol": wire.PROTOCOL, "id": parsed.id,
            "go": {"requestSha256": parsed.digest}}, wire.GO_LIMIT), parsed)
        row = json.loads(f.initial())
        for path, value in (("projectRoot", str(self.root) + "/../project"), ("projectRoot", "//tmp/project"),
                            ("ref", "refs/tags/v1.2.3"), ("ref", "HEAD"), ("token", "INERT"), ("state", {})):
            changed = json.loads(f.initial())
            changed["action"]["source"][path] = value
            with self.subTest(path=path, value=value), self.assertRaises(ValueError):
                wire.parse_initial(policy.canonical(changed) + b"\n")
        for value in (".git/index", "../outside", "release/mobile-release.json", "a/" * 16 + "version", "x" * 513):
            changed = json.loads(f.initial())
            changed["action"]["source"]["savedVersion"]["source"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                wire.parse_initial(policy.canonical(changed) + b"\n")
        row["action"]["clock"]["hardEndNs"] = "090000000000"
        with self.assertRaises(ValueError):
            wire.parse_initial(policy.canonical(row) + b"\n")
        with self.assertRaises(ValueError):
            wire.parse_initial(f.initial().replace(b'"source":{', b'"source":{},"source":{', 1))

    def test_mode_alone_cannot_admit_or_mutate_project(self):
        guard = DefaultCancellation(ProcessCleanupError, "inert")
        with patch.object(build_inputs._Project, "acquire") as opened, self.assertRaises(build_inputs.BuildInputError):
            build_inputs.InvocationCustody(self.root, "allocation-read", guard)
        opened.assert_not_called()

    def test_direct_invalid_request_object_cannot_bypass_the_fixed_input_parser(self):
        f = self.fixture
        initial_source = wire.parse_initial(f.initial())
        dialogue = runtime._Dialogue(f.CONTROL, f.OUTPUT, initial_source, f.now)
        with patch.object(os, "fstat") as observed, self.assertRaises(ValueError):
            BorrowedAllocationInput(dialogue, replace(initial_source.source, version_path="../other"))
        observed.assert_not_called()

    def test_source_only_real_scopes_fixed_seven_calls_and_fin_after_original_closes(self):
        f = self.fixture
        def before_fin(call):
            run = call.operation
            self.assertTrue(run.originals_closed())
            self.assertTrue(call.input.borrow_ended)
            self.assertEqual(call.guard.handler_state, "RESTORED")
            self.assertTrue(all(slot.state == "CLOSED" for reader in run.observation.readers for slot in reader.descriptors))
            self.assertEqual(run.binding, f.binding())
            self.assertFalse(run.observation.config.data["source"]["localStoreEnabled"])
        f.before_fin = before_fin
        with f.mocks():
            source.run_owned(f.CONTROL, f.OUTPUT, f.initial(), started=f.now, runtime_dir="/inert/runtime")
        self.assertEqual(len(f.calls), 7)
        self.assertEqual([set(row) - {"protocol", "id"} for row in f.frames], [{"ready"}, {"finished"}])
        self.assertEqual(f.control_closes, 0)
        self.assertFalse((self.root / ".mobile-release").exists())
        for argv, kw in f.calls:
            self.assertEqual(argv[0], "/usr/bin/git")
            self.assertIs(kw["text"], False)
            self.assertIsNone(kw["execution_scope"])
            self.assertLessEqual(kw["timeout"], 10)

    def test_same_installed_run_denies_other_invocations_signing_environment_and_materialization(self):
        f = self.fixture
        with f.mocks(), f.owned() as run, run.hold():
            for mode in ("build", "online", "store", "allocation-read"):
                with self.subTest(mode=mode), self.assertRaises((ValueError, build_inputs.BuildInputError)):
                    build_inputs.InvocationCustody(self.root, mode, run.guard)
            for context in (run.invocation.environment({"HOME": "/inert"}),
                            run.invocation.materialization(signing_lease=None),
                            run.invocation.project(signing_lease=object())):
                with self.assertRaises(build_inputs.BuildInputError), context:
                    self.fail("Source-only operation acquired a mutation/build scope")
            with self.assertRaises(build_inputs.BuildInputError):
                run.invocation.project_owner.ensure_meta()
            for _ in range(3):
                run.held_checkpoint()
            self.assertEqual(len(f.calls), 6)  # No Git call on ordinary HTTP checkpoints.

    def test_root_identity_precedes_private_inventory_and_saved_reads(self):
        f = self.fixture
        r = f.source_request()
        r = replace(r, identity=(r.identity[0], r.identity[1] + 1, *r.identity[2:]))
        with f.mocks(), patch.object(build_inputs, "_init_pending_names_locked") as inventory:
            with self.assertRaises(build_inputs.BuildInputRootChanged), f.owned(requested=r) as run, run.hold():
                self.fail("Wrong root admitted")
            inventory.assert_not_called()
        self.assertEqual(f.operation.readers, [])
        self.assertEqual(f.calls, [])

    def test_saved_hash_and_controlling_version_path_refuse_before_git(self):
        f = self.fixture
        wrong = replace(f.source_request(), configuration_sha256="a" * 64)
        with f.mocks(), self.assertRaises(ValueError), f.owned(requested=wrong) as run, run.hold():
            self.fail("Wrong saved bytes admitted")
        self.assertEqual(len(f.operation.readers), 1)
        self.assertEqual(f.calls, [])
        old = f.source_request()
        f.data["version"]["source"] = "release/other.properties"
        f.save()
        mismatch = replace(f.source_request(), version_path=old.version_path)
        with f.mocks(), self.assertRaises(ValueError), f.owned(requested=mismatch) as run, run.hold():
            self.fail("A different controlling version path admitted")
        self.assertEqual(len(f.operation.readers), 1)
        self.assertEqual(f.calls, [])

    def test_saved_leaf_symlink_refused_and_owned_reader_closes(self):
        f = self.fixture
        selected = f.source_request()
        path = self.root / selected.version_path
        path.unlink()
        path.symlink_to(self.root / "release/mobile-release.json")
        with f.mocks(), self.assertRaises(ValidationError), f.owned(requested=selected) as run, run.hold():
            self.fail("Symlink admitted")
        self.assertEqual(f.calls, [])
        self.assertTrue(f.operation.originals_closed())

    def test_allocating_source_must_match_the_entire_selected_commit_and_tree(self):
        f = self.fixture
        selected = request(source=replace(f.binding(), commit="9" * 40))
        with f.mocks(), self.assertRaises(ValueError), f.owned(selected=selected) as run, run.hold():
            self.fail("Hashes/ref alone accepted a different pre-edit commit")
        self.assertEqual(len(f.calls), 6)
        self.assertTrue(f.operation.failed)
        self.assertIsNone(f.operation.binding)
        self.assertEqual(f.frames, [])

    def test_plausible_result_and_counts_do_not_replace_original_slot_finality(self):
        f = self.fixture
        with f.mocks(), self.assertRaises(ValueError):
            with f.owned() as run:
                f.outcome_enabled = False
                with self.assertRaises(ValueError), run.hold():
                    self.fail("Fake CompletedProcess became original finality")
                self.assertEqual(len(f.calls), 1)
                self.assertIsNotNone(run.pending)
                self.assertFalse(run.originals_closed())
        # The fixture's untouched NEW engine would fail the actual predicate too.
        from mobile_release._desktop_ios_signed_operation import original_outcome
        self.assertIsNone(original_outcome(f.engines[0].slot, f.guard, None, None))

    def test_unplanned_git_or_arbitrary_command_cannot_use_the_source_borrow(self):
        f = self.fixture
        with f.mocks(), f.owned() as run:
            with self.assertRaises(ValueError), run.hold():
                run.observation.check()  # Only the scheduled final/pre-PUT status may run.
            self.assertEqual(len(f.calls), 6)
        from mobile_release.owned_process import run_owned
        with f.mocks(), f.owned() as run, self.assertRaises(ValueError):
            run_owned(["/usr/bin/true"], cancellation=run.guard, timeout=1, capture=True, text=False)
        self.assertEqual(len(f.calls), 6)

    def test_pre_put_requires_actual_pending_ack_then_one_check_and_final_eight_calls(self):
        f = self.fixture
        selected = request(source=f.binding())
        with f.mocks(), f.owned(selected=selected) as run, run.hold():
            journal, pending = f.journal(selected)
            with self.assertRaises(ValueError):
                run.before_put(journal)
            self.assertFalse(run.pre_put_spent)
            journal.record_pending(pending)
            self.assertEqual(f.events[-1], "simulated-native-pending-ack")
            run.before_put(journal)
            self.assertEqual(f.events[-2:], ["simulated-native-pending-ack", "status"])
            self.assertEqual(len(f.calls), 7)
            with self.assertRaises(ValueError):
                run.before_put(journal)
        self.assertEqual(len(f.calls), 8)
        retained = state.AllocationState.parse(f.native.snapshot.payload).selected(pending.authority)
        self.assertEqual(retained.pending, pending)

    def test_dirty_final_after_simulated_put_preserves_pending_no_result_or_recycle(self):
        f = self.fixture
        selected = request(source=f.binding())
        with f.mocks(), self.assertRaises(local_release_source.LocalSourceError):
            with f.owned(selected=selected) as run, run.hold():
                journal, pending = f.journal(selected)
                journal.record_pending(pending)
                run.before_put(journal)
                f.events.append("simulated-only-put")
                f.status = b"?? changed-after-put.txt\0"
        self.assertTrue(f.operation.failed)
        self.assertEqual(len(f.calls), 8)
        retained = state.AllocationState.parse(f.native.snapshot.payload).selected(pending.authority)
        self.assertEqual(retained.pending, pending)
        self.assertFalse(any("finished" in row for row in f.frames))

    def test_changed_held_saved_bytes_refuse_without_another_git_call(self):
        f = self.fixture
        with f.mocks():
            with self.assertRaises(ValidationError):
                with f.owned() as run, run.hold():
                    f.write(f.data["version"]["source"], b"VERSION_NAME=1.2.3\nBUILD_NUMBER=8\n")
                    run.held_checkpoint()
            self.assertEqual(len(f.calls), 6)
            self.assertTrue(f.operation.failed)
            self.assertTrue(f.operation.originals_closed())

    def test_ack_stop_poll_has_zero_extra_input_reads_and_never_closes_pipe(self):
        f = self.fixture
        with f.mocks(), self.assertRaises(KeyboardInterrupt):
            with f.owned() as run:
                run.input.dialogue.phase = "ack"
                f.incoming.extend(b"an ACK owned by the original cursor\n")
                run.guard.cancelled = True
                run.guard.check()
        self.assertEqual(f.control_reads, 0)
        self.assertEqual(f.control_closes, 0)
        self.assertTrue(f.input.borrow_ended)
        self.assertEqual(f.guard.handler_state, "RESTORED")

    def test_active_eof_uses_sole_cursor_once_and_cannot_reacquire_or_claim_a_close(self):
        f = self.fixture
        with f.mocks():
            with self.assertRaises(ProcessCleanupError), f.owned() as run:
                f.eof = True
                run.guard.check()
            self.assertEqual(f.control_reads, 1)
            with self.assertRaises(ValueError):
                f.input.acquire_borrow()
        self.assertTrue(f.input.unknown)
        self.assertTrue(f.dialogue.poisoned)
        self.assertFalse(f.input.borrow_ended)
        self.assertEqual(f.control_closes, 0)
        self.assertEqual(f.guard.handler_state, "RESTORED")

    def test_malformed_go_releases_only_unused_borrow_and_emits_no_fin(self):
        f = self.fixture
        f.malformed_go = True
        with f.mocks(), self.assertRaises(ValueError):
            source.run_owned(f.CONTROL, f.OUTPUT, f.initial(), started=f.now, runtime_dir="/inert/runtime")
        call = source._RETAINED[-1]
        self.assertIsNone(call.operation)
        self.assertTrue(call.input.borrow_ended)
        self.assertTrue(call.dialogue.poisoned)
        self.assertEqual(call.guard.handler_state, "RESTORED")
        self.assertEqual(f.control_closes, 0)
        self.assertEqual(f.calls, [])
        self.assertFalse(any("finished" in row for row in f.frames))
        with f.mocks(), self.assertRaises(ValueError):
            source.run_owned(f.CONTROL, f.OUTPUT, f.initial(), started=f.now, runtime_dir="/inert/runtime")
        self.assertIs(source._RETAINED[-1], call)  # No replacement/retry after refused GO.

    def test_reader_close_loss_after_source_closed_true_is_not_borrow_finality(self):
        f = self.fixture
        real_reader_close = checked_files._Reader.close
        attempts = []
        def lose_close(reader):
            call = source._RETAINED[-1]
            run = call.operation
            if run is not None and run.observation is not None and reader in run.observation.readers:
                self.assertTrue(run.observation.closed)  # Its attempt flag is already set.
                fd = next(slot.number for slot in reversed(reader.descriptors) if slot.state == "OWNED")
                def close(number):
                    f._close(number)
                    if number == fd:
                        attempts.append(number)
                        raise OSError("synthetic consuming-close return loss")
                with patch.object(os, "close", close):
                    return real_reader_close(reader)
            return real_reader_close(reader)
        with f.mocks(), patch.object(checked_files._Reader, "close", lose_close), self.assertRaises(ProcessError) as caught:
            source.run_owned(f.CONTROL, f.OUTPUT, f.initial(), started=f.now, runtime_dir="/inert/runtime")
        self.assertFalse(caught.exception.cleanup_complete)
        call = source._RETAINED[-1]
        self.assertTrue(call.operation.observation.closed)
        self.assertFalse(call.input.borrow_ended)
        self.assertEqual(len(attempts), 1)
        self.assertEqual(call.guard.handler_state, "RESTORED")
        with self.assertRaises(ProcessCleanupError):
            call.operation.originals_closed()
        self.assertFalse(any("finished" in row for row in f.frames))


if __name__ == "__main__":
    unittest.main()
