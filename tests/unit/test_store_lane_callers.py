"""Caller/composite FS regressions, explicitly not native Store execution.

Only credential-free files below the test-owned root and an inert _Outer model
are used. Child creation, signals, process termination and threads are vetoed.
These definitions require reviewed integration before any execution.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest
import weakref
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release import _command_process as command
from mobile_release import build_inputs as inputs
from mobile_release import cancellation as cancellation_module
from mobile_release import stores
from mobile_release._store_lane_evidence import StoreLaneEvidenceError
from mobile_release.cancellation import DefaultCancellation
from mobile_release.config import load_config
from mobile_release.credentials import _selected_store_material
from mobile_release import ios_artifacts as ios
from mobile_release.ios_artifacts import _LaneSnapshotOwner, _snapshot_scope
from mobile_release.inspection import InspectionDeadline
from mobile_release.metadata import build_metadata_archive
from mobile_release.owned_process import ProcessCleanupError, ProcessError
from mobile_release.provenance import copy_immutable_file, workflow_authority, write_evidence
from mobile_release.errors import StoreOperationError, ValidationError

from .helpers import android_config, write_project
from .evidence_helpers import android_precondition, fixture_chain, workflow_environment
from .store_lane_model import StoreLaneModel


class StoreLaneCallerTests(unittest.TestCase):
    def setUp(self):
        from mobile_release import _profile_process, ios_profiles
        # Inert fixture registrations share one test-owned registry. Register
        # restorations first so original aliases return only after every
        # fixture/model cleanup, including failed setup or body execution.
        registry = weakref.WeakSet()
        for module in (cancellation_module, ios_profiles, _profile_process, inputs):
            self.enterContext(patch.object(module, "_FORK_RESOURCES", registry))
        temporary = tempfile.TemporaryDirectory(prefix="mrk-store-callers-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.private_material = self.root / "private-material"
        self.private_material.mkdir(mode=0o700)
        self.counter = 0
        for name in ("kill", "killpg", "fork", "execve", "pipe"):
            veto = patch.object(command.os, name, side_effect=AssertionError("caller unit model attempted process effect"))
            veto.start(); self.addCleanup(veto.stop)
        for target, name in ((command.native, "create"), (command.threading.Thread, "start"),
                             (command.subprocess, "Popen"), (cancellation_module.signal, "signal")):
            veto = patch.object(target, name, side_effect=AssertionError("caller unit model attempted worker/handler effect"))
            veto.start(); self.addCleanup(veto.stop)
        environment = patch.dict(os.environ, {**workflow_environment(), "TMPDIR": str(self.root)}, clear=True)
        environment.start(); self.addCleanup(environment.stop)

    def fixture(self, *, metadata=True, snapshot=False, stage="candidate",
                output_dir=".mobile-release/output"):
        self.counter += 1
        app = self.root / str(self.counter); app.mkdir(mode=0o700)
        config = load_config(write_project(app, android_config()))
        guard = DefaultCancellation(ProcessCleanupError, "synthetic caller owner")
        # Explicit zero-handler model: no signal setter runs in this FS suite.
        guard._installation, guard._activated, guard.depth = "INSTALLED", True, 0
        request = stores.StoreRequest(stage=stage, platform="android", confirmation="synthetic",
            execute=False, prepare=True, output_dir=app / output_dir)
        record = stores.new_store_lane_evidence(config, request, guard)
        resources = ExitStack(); self.addCleanup(resources.close)
        invocation = resources.enter_context(inputs.invocation_custody(
            app, mode="store", cancellation=guard, lane_evidence=record))
        meta = resources.enter_context(inputs.finite_scratch(layout="store-metadata",
            cancellation=guard, lane_evidence=record)) if metadata else None
        if meta is not None:
            meta.put("metadata", b"synthetic metadata input")
        snap = None
        if snapshot:
            snap = _LaneSnapshotOwner(guard, record, deadline=InspectionDeadline())
            resources.enter_context(_snapshot_scope(snap))
            snap.mkdir(snap._path / "tree")
            snap.write_chunks(snap._path / "tree/original", iter((b"synthetic artifact",)), maximum=32, executable=False)
            snap.protect_directory(snap._path / "tree")
        adc = self.private_material / (app.name + ".json")
        adc.write_bytes(b'{"type":"authorized_user","synthetic":true}'); adc.chmod(0o600)
        material = resources.enter_context(_selected_store_material(config,
            values={"GOOGLE_APPLICATION_CREDENTIALS": str(adc)}, platforms=("android",),
            invocation=invocation, cancellation=guard, lane_evidence=record))
        material.validate()
        return SimpleNamespace(config=config, guard=guard, request=request, record=record,
            resources=resources, invocation=invocation, metadata=meta, snapshot=snap, material=material)

    def run_model(self, fixture, *, code=0, terminal=True, after=None):
        document = {"synthetic": True} if code == 0 else None
        model = StoreLaneModel(lambda _argv, _env: (document, code), terminal=terminal, after=after)
        self.addCleanup(model.close)
        fixture.model = model
        with patch.object(stores, "run_owned", side_effect=model):
            try:
                content = stores._run_store_lane(config=fixture.config, release=fixture.config.release_version(),
                    request=fixture.request, lane_evidence=fixture.record, cancellation=fixture.guard,
                    material=fixture.material, invocation=fixture.invocation,
                    resources=fixture.resources, source_environment=dict(os.environ),
                    authority=workflow_authority(fixture.request.stage),
                    tooling_root=fixture.config.root / "tooling", operation_intent=None)
            except BaseException as error:
                # Production wrappers intentionally omit private diagnostics.
                # Preserve this inert fixture's original site, never values or locals.
                try:
                    primary = fixture.record._primary
                    if primary is None:
                        primary = error
                    source = Path(__file__).resolve().parents[2]
                    frames, trace = [], primary.__traceback__
                    for _ in range(16):
                        if trace is None:
                            break
                        code_object = trace.tb_frame.f_code
                        try:
                            filename = Path(code_object.co_filename).relative_to(source).as_posix()
                        except ValueError:
                            filename = "<outside-source>"
                        frames.append(f"{filename}:{trace.tb_lineno}:{code_object.co_name}")
                        trace = trace.tb_next
                    note = f"synthetic StoreLaneModel original primary: {type(primary).__name__}"
                    number = getattr(primary, "errno", None)
                    if type(number) is int:
                        note += f" errno={number}"
                    note += "; frames=" + " -> ".join(frames)
                    if trace is not None:
                        note += " [truncated]"
                    error.add_note(note[:4096])
                except BaseException:
                    pass  # Diagnostic loss must never replace the original failure.
                raise
        return stores.StoreLaneReadback(fixture.record, Path(fixture.record._output), content, document)

    def close(self, fixture, primary=None):
        stores.close_store_operation_resources(fixture.resources, fixture.record,
                                               cancellation=fixture.guard, primary=primary)

    def pending_path(self, fixture):
        pending = fixture.record._pending_attempt
        return fixture.config.root / ".mobile-release/store/lane-attempts-v1" / pending.name

    def test_original_outer_resources_close_before_pending_retirement_and_receipt(self):
        fixture = self.fixture(snapshot=True)
        namespaces = []
        acquire = inputs._StoreNamespace.acquire
        def capture_namespace(owner):
            acquire(owner)
            if owner.path == Path(fixture.record._output).parent:
                namespaces.append(owner)
        with patch.object(inputs._StoreNamespace, "acquire", new=capture_namespace):
            readback = self.run_model(fixture)
        self.assertEqual(len(namespaces), 1)
        namespace = namespaces[0]
        namespace.check()
        self.assertFalse(namespace.claimed)
        marker = self.pending_path(fixture)
        self.assertTrue(marker.is_file())
        self.assertTrue(fixture.metadata._path.exists() and fixture.snapshot._path.exists())
        self.assertFalse(fixture.record.verdict(cancellation=fixture.guard).receipt_acceptable)
        pending, order = fixture.record._pending_attempt, []
        original_retire = pending.retire
        def retire():
            self.assertFalse(fixture.metadata._path.exists() or fixture.snapshot._path.exists())
            self.assertTrue(fixture.invocation._lane_closed_for(fixture.record, fixture.guard))
            self.assertTrue(namespace.closed())
            order.append("retire")
            original_retire()
        with patch.object(pending, "retire", side_effect=retire):
            self.close(fixture)
            # Completion uses already-checked bytes, not a fresh output lookup.
            with patch.object(Path, "read_bytes", side_effect=AssertionError("late pathname reread")):
                value = stores.complete_store_operation(readback, lane_evidence=fixture.record,
                                                         cancellation=fixture.guard)
        self.assertEqual(value, {"synthetic": True})
        self.assertEqual(order, ["retire"])
        self.assertFalse(marker.exists())
        self.assertTrue(Path(fixture.record._output).is_file())

    def test_group_finality_without_terminal_preserves_all_dependent_paths(self):
        fixture = self.fixture(snapshot=True)
        with self.assertRaises(ProcessError) as caught:
            self.run_model(fixture, terminal=False)
        self.assertTrue(caught.exception.fatal)
        self.assertTrue(fixture.guard.lifetime_ledger.verdict().contained)
        self.assertFalse(inputs._consumer_idle(fixture.guard,
            lane_binding=fixture.metadata._lane_binding, owner=fixture.metadata))
        with self.assertRaises(ProcessError):
            self.close(fixture, caught.exception)
        self.assertTrue(fixture.metadata._path.exists() and fixture.snapshot._path.exists())
        self.assertTrue(self.pending_path(fixture).is_file())
        self.assertTrue(fixture.record._pending_attempt.handles_closed())
        self.assertTrue(all(slot.number is None for slot in fixture.metadata.writer_slots))

    def test_settled_ordinary_failure_closes_originals_but_cannot_accept_receipt(self):
        fixture = self.fixture()
        with self.assertRaises(StoreOperationError) as caught:
            self.run_model(fixture, code=75)
        self.close(fixture, caught.exception)
        self.assertFalse(self.pending_path(fixture).exists())
        self.assertFalse(fixture.metadata._path.exists())
        self.assertTrue(fixture.record.verdict(cancellation=fixture.guard).dependents_settled)
        self.assertFalse(fixture.record.verdict(cancellation=fixture.guard).receipt_acceptable)

    def test_original_interruption_survives_later_dependent_close_failure(self):
        fixture = self.fixture(snapshot=True)
        self.run_model(fixture)
        primary = KeyboardInterrupt()
        target = fixture.metadata.slot.number
        close, failed = os.close, []
        def lose_return(number):
            close(number)
            if number == target and not failed:
                failed.append(number)
                raise OSError("synthetic original close return loss")
        with patch.object(inputs.os, "close", side_effect=lose_return), self.assertRaises(KeyboardInterrupt) as caught:
            self.close(fixture, primary)
        self.assertIs(caught.exception, primary)
        self.assertEqual(failed, [target])
        self.assertTrue(self.pending_path(fixture).is_file())
        self.assertTrue(fixture.record._pending_attempt.handles_closed())
        self.assertTrue(fixture.invocation.claimed)
        self.assertFalse(fixture.snapshot._path.exists())

    def test_pending_fence_cannot_retire_while_actual_invocation_is_open(self):
        fixture = self.fixture(metadata=False)
        self.run_model(fixture)
        # Premature finalization is not an invitation to finish with a different
        # record: it permanently fails this original and preserves its fence.
        with self.assertRaises(ProcessError):
            stores.settle_store_operation(fixture.record, cancellation=fixture.guard)
        with self.assertRaises(ProcessError):
            self.close(fixture)
        self.assertTrue(self.pending_path(fixture).is_file())

    def test_wrong_guard_or_copied_readback_cannot_rebind_final_completion(self):
        fixture = self.fixture()
        readback = self.run_model(fixture)
        self.close(fixture)
        foreign = DefaultCancellation(ProcessCleanupError, "different original")
        with self.assertRaises(StoreLaneEvidenceError):
            stores.complete_store_operation(readback, lane_evidence=fixture.record, cancellation=foreign)
        other = stores.new_store_lane_evidence(fixture.config, fixture.request, fixture.guard)
        with self.assertRaises(StoreLaneEvidenceError):
            stores.complete_store_operation(readback, lane_evidence=other, cancellation=fixture.guard)
        self.assertEqual(stores.complete_store_operation(readback, lane_evidence=fixture.record,
            cancellation=fixture.guard), {"synthetic": True})

    def test_pure_output_collision_precedes_file_and_marker_reservation(self):
        fixture = self.fixture()
        output = Path(fixture.record._output); output.parent.mkdir(parents=True)
        output.write_bytes(b"preserve foreign diagnostic")
        with self.assertRaisesRegex(StoreOperationError, "already exists"):
            self.run_model(fixture)
        self.assertIsNone(fixture.record._pending_attempt)
        self.assertNotIn("terminal", fixture.record._resources)
        self.close(fixture)
        self.assertEqual(output.read_bytes(), b"preserve foreign diagnostic")

    def test_replaced_snapshot_leaf_survives_and_independent_sibling_retires(self):
        fixture = self.fixture(snapshot=True)
        snap = fixture.snapshot
        # The original tree was protected; add an independent root sibling.
        sibling = snap._path / "sibling"
        snap.write_chunks(sibling, iter((b"owned sibling",)), maximum=32, executable=False)
        self.run_model(fixture)
        original = snap._path / "tree/original"
        # Fixture injection owns this entire namespace; product never chmods a
        # replacement or infers ownership from this test's surviving pathname.
        original.parent.chmod(0o700)
        original.rename(fixture.config.root / "saved-original")
        original.write_bytes(b"foreign replacement")
        original.parent.chmod(0o500)
        with self.assertRaises(ProcessError):
            self.close(fixture)
        self.assertEqual(original.read_bytes(), b"foreign replacement")
        self.assertFalse(sibling.exists())
        self.assertTrue(self.pending_path(fixture).exists())

    def test_snapshot_producer_cannot_write_after_store_command_sealing(self):
        fixture = self.fixture(snapshot=True)
        self.run_model(fixture)
        target = fixture.snapshot._path / "late"
        with self.assertRaisesRegex(ValidationError, "publication is closed"):
            fixture.snapshot.write_chunks(target, iter((b"late",)), maximum=4, executable=False)
        self.assertFalse(target.exists())
        self.close(fixture)

    def test_snapshot_walks_and_inventory_are_bounded_without_retired_lease_history(self):
        fixture = self.fixture(metadata=False, snapshot=True)
        snap, references = fixture.snapshot, []
        original_lease, original_scan = ios._SnapshotLease, os.scandir
        scans = []
        def lease(*args):
            value = original_lease(*args)
            references.append(weakref.ref(value))
            return value
        def scan(number):
            scans.append(number)
            return original_scan(number)
        with patch.object(ios, "_SnapshotLease", side_effect=lease), patch.object(ios.os, "scandir", side_effect=scan):
            for depth in (8, 16, 32, 64):
                parent = snap._path.joinpath(f"depth{depth}", *(f"d{n}" for n in range(depth - 1)))
                before = snap._reserved
                snap.mkdir(parent, parents=True)
                self.assertEqual(snap._reserved - before, depth)
                for index in range(4):
                    before = snap._reserved
                    snap.mkdir(parent, parents=True, exist_ok=True)
                    snap.write_chunks(parent / f"f{index}", iter((b"x",)), maximum=1, executable=False)
                    self.assertEqual(snap._reserved - before, 2 * depth + 1)
                    self.assertTrue(all(value is None for value in snap._leases))
                    self.assertEqual(snap._reserved, snap._retired)
            for width in (8, 16, 32):
                parent = snap._path / f"width{width}"
                snap.mkdir(parent)
                before = snap._reserved
                for index in range(width):
                    snap.write_chunks(parent / f"f{index}", iter((b"x",)), maximum=1, executable=False)
                self.assertEqual(snap._reserved - before, 2 * width)
            self.assertEqual(scans, [])  # No growing-directory scan per creation.
            snap.audit()
            directories = 1 + sum(entry["kind"] == "directory" for entry in snap.entries.values())
            self.assertEqual(len(scans), directories)
        self.assertEqual(len(snap._leases), ios.MAX_SNAPSHOT_FDS)
        self.assertLessEqual(snap._peak, 65)
        self.assertEqual(snap._reserved, snap._retired)
        self.assertTrue(all(reference() is None for reference in references))
        self.close(fixture)
        self.assertTrue(snap._lane_closed_for(fixture.record, snap._lane_binding, fixture.guard))

    def test_snapshot_unknown_open_and_close_returns_retain_original_debt_without_retry(self):
        for phase in ("open", "close"):
            with self.subTest(phase=phase):
                fixture = self.fixture(metadata=False, snapshot=True)
                snap, calls, target = fixture.snapshot, [], [None]
                original_close = os.close
                def close(number):
                    calls.append(number)
                    original_close(number)
                    if number == target[0]:
                        raise OSError("modeled loss after actual original close")
                if phase == "open":
                    # Explicit model: wrapper fails before any actual open.
                    # Product correctly cannot infer that no-effect fact from
                    # this non-builtin exception. No real FD is leaked.
                    with patch.object(ios.os, "open", side_effect=OSError("modeled unknown open result")), \
                         self.assertRaises(OSError):
                        with snap.descriptor("not-created", os.O_RDONLY, parent=snap.slot.number):
                            self.fail("unknown acquisition yielded")
                else:
                    with patch.object(ios.os, "close", side_effect=close), self.assertRaises(ProcessError):
                        with snap.descriptor(snap._path / "tree/original", os.O_RDONLY | os.O_NOFOLLOW) as number:
                            target[0] = number
                    self.assertEqual(calls.count(target[0]), 1)
                debt = [value for value in snap._leases if value is not None]
                self.assertEqual(len(debt), 1)
                original = debt[0]
                self.assertFalse(original.close.returned)
                self.assertIsNone(original.slot.number)
                self.assertFalse(snap._lane_closed_for(fixture.record, snap._lane_binding, fixture.guard))
                with self.assertRaises(ProcessError):
                    self.close(fixture)
                self.assertIs(snap._leases[original.index], original)
                self.assertEqual(snap.slot.close_state, "CLOSED")
                self.assertTrue(all(slot.close_state == "CLOSED" for slot in snap.parent.slots))

    def test_snapshot_scope_and_accounting_return_loss_cannot_manufacture_retirement(self):
        for phase in ("scope", "accounting"):
            with self.subTest(phase=phase):
                fixture = self.fixture(metadata=False, snapshot=True)
                snap = fixture.snapshot
                lease = snap._reserve_lease()  # Explicit never-opened original model.
                if phase == "scope":
                    original_exit = lease.scope.__exit__
                    def lost_exit(*args):
                        original_exit(*args)
                        raise KeyboardInterrupt()
                    with patch.object(lease.scope, "__exit__", side_effect=lost_exit), self.assertRaises(KeyboardInterrupt) as first:
                        snap._finish_lease(lease)
                    self.assertTrue(lease.scope_failed)
                    self.assertIs(snap._leases[lease.index], lease)
                else:
                    class LostClear(list):
                        def __setitem__(self, index, value):
                            super().__setitem__(index, value)
                            if value is None:
                                raise MemoryError("modeled accounting clear return loss")
                    snap._leases = LostClear(snap._leases)
                    with self.assertRaises(MemoryError) as first:
                        snap._finish_lease(lease)
                    self.assertTrue(snap._accounting_pending and snap._accounting_failed)
                    self.assertNotEqual(snap._reserved, snap._retired)
                    self.assertIsNone(snap._leases[lease.index])
                primary = first.exception
                self.assertIs(lease.failures.first, primary)
                self.assertIs(fixture.guard.lifetime_ledger._primary, primary)
                self.assertTrue(fixture.guard.lifetime_ledger.fatal)
                self.assertEqual(lease.slot.close_state, "CLOSED")
                self.assertFalse(snap._lane_closed_for(fixture.record, snap._lane_binding, fixture.guard))
                # The initial assertRaises consumed the failure. Forward that
                # actual original as the caller's primary into final cleanup.
                with self.assertRaises(KeyboardInterrupt if phase == "scope" else ProcessError) as closed:
                    self.close(fixture, primary)
                if phase == "scope":
                    self.assertIs(closed.exception, primary)
                else:
                    self.assertTrue(closed.exception.fatal)
                    self.assertFalse(closed.exception.cleanup_complete)
                self.assertIs(fixture.guard.lifetime_ledger._primary, primary)
                self.assertTrue(fixture.guard.lifetime_ledger.fatal)
                self.assertEqual(snap.slot.close_state, "CLOSED")
                self.assertTrue(all(slot.close_state == "CLOSED" for slot in snap.parent.slots))

    def test_snapshot_capacity_refuses_before_open_and_cleanup_still_closes_known_originals(self):
        fixture = self.fixture(metadata=False, snapshot=True)
        snap = fixture.snapshot
        self.run_model(fixture)
        # These142 slots deliberately model unknown acquisitions without any
        # real open. No borrowed/shared descriptor is used or later closed.
        for _ in range(ios.MAX_SNAPSHOT_FDS):
            lease = snap._reserve_lease()
            lease.slot.open_state = "UNKNOWN"
        with patch.object(ios.os, "open", side_effect=AssertionError("capacity failed after open")), \
             self.assertRaisesRegex(ValidationError, "capacity"):
            with snap.descriptor("no-effect", os.O_RDONLY, parent=snap.slot.number):
                self.fail("exhausted pool yielded")
        with self.assertRaises(ProcessError):
            self.close(fixture)
        self.assertEqual(snap._peak, ios.MAX_SNAPSHOT_FDS)
        self.assertTrue(all(value is not None for value in snap._leases))
        self.assertEqual(snap.slot.close_state, "CLOSED")
        self.assertTrue(all(slot.close_state == "CLOSED" for slot in snap.parent.slots))
        self.assertFalse(snap._cleanup_complete)
        self.assertTrue(snap._path.exists())  # Disposal's own acquisition also refused.

    def test_snapshot_outer_finish_and_diagnostic_failure_cannot_skip_owner_cleanup(self):
        fixture = self.fixture(metadata=False)
        self.close(fixture)
        for primary, diagnostics in ((KeyboardInterrupt(), True), (SystemExit(9), False)):
            with self.subTest(primary=type(primary).__name__):
                guard = DefaultCancellation(ProcessCleanupError, "synthetic outer snapshot owner")
                guard._installation, guard._activated, guard.depth = "INSTALLED", True, 0
                record = stores.new_store_lane_evidence(fixture.config, fixture.request, guard)
                owner = _LaneSnapshotOwner(guard, record, deadline=InspectionDeadline())
                with ExitStack() as patches:
                    # Patch BEFORE scope construction: its actual fixed
                    # original callback is prearmed before any acquisition.
                    patches.enter_context(patch.object(record, "finish", side_effect=MemoryError("finish entry failure")))
                    if diagnostics:
                        patches.enter_context(patch.object(guard, "_abort", side_effect=MemoryError("diagnostic failure")))
                    with self.assertRaises(type(primary)) as caught:
                        with _snapshot_scope(owner):
                            raise primary
                self.assertIs(caught.exception, primary)
                self.assertTrue(owner.claimed)
                self.assertEqual(owner.slot.close_state, "CLOSED")
                self.assertTrue(all(slot.close_state == "CLOSED" for slot in owner.parent.slots))
                self.assertFalse(owner._cleanup_complete)

    def test_snapshot_claimed_scope_deferral_failure_still_closes_original_owner(self):
        fixture = self.fixture(metadata=False)
        self.close(fixture)
        for primary, lost_close in ((KeyboardInterrupt(), False), (SystemExit(9), True)):
            with self.subTest(primary=type(primary).__name__, lost_close=lost_close):
                guard = DefaultCancellation(ProcessCleanupError, "synthetic snapshot dispatch owner")
                guard._installation, guard._activated, guard.depth = "INSTALLED", True, 0
                record = stores.new_store_lane_evidence(fixture.config, fixture.request, guard)
                owner = _LaneSnapshotOwner(guard, record, deadline=InspectionDeadline())
                scopes, injected, calls, order = [], [], [], []
                dispatch_failure = MemoryError("snapshot claimed before deferred callback entry")
                original_init, original_deferred = ios._SnapshotScope.__init__, guard.deferred
                original_finish, original_close = record.finish, os.close

                def capture_scope(scope, value):
                    original_init(scope, value)
                    scopes.append(scope)

                def finish(**kwargs):
                    order.append("finish")
                    return original_finish(**kwargs)

                def deferred(**kwargs):
                    if not injected:
                        self.assertTrue(scopes[0].claimed)
                        self.assertIs(scopes[0]._first_error, primary)
                        self.assertFalse(owner.claimed)
                        self.assertEqual(order, [])  # Registered callback has not run.
                        injected.append(dispatch_failure)
                        raise dispatch_failure
                    return original_deferred(**kwargs)

                def close(number):
                    self.assertEqual(order, ["finish"])
                    self.assertTrue(record._finished)  # No-command admission closes first.
                    calls.append(number)
                    original_close(number)
                    if lost_close and number == selected:
                        raise OSError("modeled loss after actual original close")

                with ExitStack() as patches:
                    patches.enter_context(patch.object(ios._SnapshotScope, "__init__", new=capture_scope))
                    patches.enter_context(patch.object(record, "finish", new=finish))
                    with self.assertRaises(type(primary)) as caught:
                        with _snapshot_scope(owner):
                            # One real original registry slot remains live at
                            # outer exit; no borrowed/shared FD is fabricated.
                            lease = owner._reserve_lease()
                            selected = lease.slot.open(owner._path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                            numbers = [selected, owner.slot.number, *(slot.number for slot in owner.parent.slots)]
                            self.assertTrue(all(type(number) is int for number in numbers))
                            patches.enter_context(patch.object(guard, "deferred", new=deferred))
                            patches.enter_context(patch.object(ios.os, "close", side_effect=close))
                            raise primary
                self.assertIs(caught.exception, primary)
                self.assertEqual(injected, [dispatch_failure])
                self.assertIs(scopes[0]._first_error, primary)
                self.assertIs(scopes[0]._cleanup_errors[0], dispatch_failure)
                self.assertEqual(order, ["finish"])
                self.assertCountEqual(calls, numbers)  # One actual close per original, never a retry.
                self.assertTrue(owner.claimed)
                self.assertEqual(owner.slot.close_state, "CLOSED")
                self.assertTrue(all(slot.close_state == "CLOSED" for slot in owner.parent.slots))
                self.assertEqual(lease.slot.close_state, "UNKNOWN" if lost_close else "CLOSED")
                self.assertIsNone(lease.slot.number)
                if lost_close:
                    self.assertIs(owner._leases[lease.index], lease)
                    self.assertFalse(lease.close.returned)
                self.assertFalse(owner._cleanup_complete)
                self.assertFalse(owner._lane_closed_for(record, owner._lane_binding, guard))
                self.assertFalse(record.verdict(cancellation=guard).receipt_acceptable)
                self.assertIs(guard.lifetime_ledger._primary, primary)
                self.assertTrue(guard.lifetime_ledger.fatal)
                self.assertEqual(guard.depth, 0)
                self.assertEqual(guard._restoration, "NOT_ATTEMPTED")

    def test_snapshot_full_inventory_rejects_modeled_alias_with_unchanged_revision_before_seal(self):
        fixture = self.fixture(metadata=False, snapshot=True)
        snap = fixture.snapshot
        spare = snap._path / "spare"
        snap.write_chunks(spare, iter((b"owned",)), maximum=5, executable=False)
        revisions = {snap.identity["inode"]: snap.root_entry["revision"]}
        revisions.update({entry["binding"]["inode"]: entry["revision"]
                          for entry in snap.entries.values() if entry["kind"] == "directory"})
        original_revision = ios._revision
        def unchanged(value):
            return revisions.get(value.st_ino, original_revision(value))
        alias = snap._path / "foreign-alias"
        alias.write_bytes(b"foreign alias")
        original_scan = os.scandir
        @contextmanager
        def inventory(number):
            # Model the returned alias spelling explicitly, so this contract
            # case is meaningful on both case-sensitive and insensitive FS.
            # Real enumeration/closure and the foreign file remain owned by
            # this fixture; this is not a native alias-behavior receipt.
            with original_scan(number) as entries:
                yield (SimpleNamespace(name="TREE", stat=entry.stat)
                       if entry.name == "foreign-alias" else entry for entry in entries)
        with patch.object(ios, "_revision", side_effect=unchanged), \
             patch.object(ios.os, "scandir", side_effect=inventory):
            with self.assertRaises(ProcessError):
                self.run_model(fixture)
            self.assertEqual(fixture.model.calls, [])  # Actual pre-seal owner audit rejected.
            with self.assertRaises(ProcessError):
                self.close(fixture)
        self.assertEqual(alias.read_bytes(), b"foreign alias")
        self.assertTrue((snap._path / "tree/original").is_file())
        self.assertFalse(spare.exists())
        self.assertEqual(snap.slot.close_state, "CLOSED")

    def test_snapshot_cached_view_and_expired_original_deadline_do_not_skip_admission(self):
        for phase in ("cached", "deadline"):
            with self.subTest(phase=phase):
                fixture = self.fixture(metadata=False, snapshot=True)
                snap = fixture.snapshot
                view = ios.IOSArtifactSnapshot({"ios-archive": snap._path / "tree"}, {}, {},
                    snap._path, snap.deadline, cancellation=fixture.guard, _owner=snap)
                view.unpacked["ios-archive"] = snap._path / "tree"
                if phase == "cached":
                    foreign = snap._path / "foreign"
                    foreign.write_bytes(b"foreign")
                    with self.assertRaises(ValidationError):
                        view.unpack("ios-archive")
                else:
                    other = DefaultCancellation(ProcessCleanupError, "wrong original")
                    with self.assertRaisesRegex(ValidationError, "different original"):
                        snap.admit(fixture.record, other)
                    deadline = snap.deadline
                    deadline._expires_at = 0
                    with self.assertRaisesRegex(ValidationError, "time bound"):
                        snap.admit(fixture.record, fixture.guard)
                    self.assertIs(snap.deadline, deadline)
                    self.assertEqual(deadline.expires_at, 0)
                with self.assertRaises(ProcessError):
                    self.close(fixture)
                self.assertEqual(snap.slot.close_state, "CLOSED")

    def test_snapshot_modeled_child_cleanup_attempts_independent_originals_without_parent_accounting(self):
        calls = []
        class ChildSlot:
            def __init__(self, name, fails=False):
                self.name, self.fails = name, fails
            def after_fork_child(self):
                calls.append(self.name)
                if self.fails:
                    raise OSError("modeled unresolved child-copy slot")
        # Data-only child-copy model: no fork, signal or real FD operation.
        owner = object.__new__(_LaneSnapshotOwner)
        owner.active = True
        owner._reserved, owner._retired, owner._cleanup_complete = 5, 3, False
        owner._leases = [None] * ios.MAX_SNAPSHOT_FDS
        owner._leases[-1] = SimpleNamespace(slot=ChildSlot("unknown", True))
        owner._leases[0] = SimpleNamespace(slot=ChildSlot("known"))
        owner.slot = ChildSlot("root")
        owner.parent = SimpleNamespace(slots=[ChildSlot("parent")])
        owner._fork_failures = ios._SnapshotFailures(SimpleNamespace(pid=-1))
        owner._registry_close_callback = owner._close_registry
        owner._parents_close_callback = owner._close_parents
        with self.assertRaises(OSError):
            owner.fork_close()
        self.assertEqual(calls, ["unknown", "known", "root", "parent"])
        self.assertEqual((owner._reserved, owner._retired, owner._cleanup_complete), (5, 3, False))

    def test_snapshot_replacement_at_actual_removal_boundary_is_preserved(self):
        fixture = self.fixture(metadata=False, snapshot=True)
        snap = fixture.snapshot
        spare = snap._path / "spare"
        snap.write_chunks(spare, iter((b"owned",)), maximum=5, executable=False)
        self.run_model(fixture)
        original_remove = snap._remove_entry
        replaced = []
        def remove(parts, entry, epoch):
            if parts == ("tree", "original"):
                # Actual full inventory and writable pass already finished.
                # Only this fixture's original namespace is being mutated.
                path = snap._path.joinpath(*parts)
                path.rename(fixture.config.root / "saved-at-removal")
                path.write_bytes(b"foreign at removal")
                replaced.append(path)
            original_remove(parts, entry, epoch)
        with patch.object(snap, "_remove_entry", side_effect=remove), self.assertRaises(ProcessError):
            self.close(fixture)
        self.assertEqual(len(replaced), 1)
        self.assertEqual(replaced[0].read_bytes(), b"foreign at removal")
        self.assertFalse(spare.exists())
        self.assertEqual(snap.slot.close_state, "CLOSED")
        self.assertTrue(self.pending_path(fixture).exists())

    def test_failed_input_entry_closes_no_command_admission_before_its_cleanup(self):
        fixture = self.fixture(metadata=False)
        # Remove the selected material callback first: a separate exact record
        # is needed because each fixed input role is one-use.
        self.close(fixture)
        record = stores.new_store_lane_evidence(fixture.config, fixture.request, fixture.guard)
        owner = inputs.FiniteScratch("store-metadata", fixture.guard, self.root, lane_evidence=record)
        primary = KeyboardInterrupt()
        acquire = owner.acquire
        def fail_after_acquire():
            acquire()
            raise primary
        with patch.object(owner, "acquire", side_effect=fail_after_acquire), self.assertRaises(KeyboardInterrupt) as caught:
            with inputs._scope(owner, fixture.guard, False):
                self.fail("failed entry yielded")
        self.assertIs(caught.exception, primary)
        self.assertIs(record._primary, primary)
        self.assertFalse(owner._path.exists())
        self.assertTrue(owner._lane_closed_for(record, owner._lane_binding, fixture.guard))

    def test_metadata_archive_matches_existing_deterministic_bytes(self):
        fixture = self.fixture(metadata=False)
        metadata = fixture.resources.enter_context(inputs.finite_scratch(layout="store-metadata",
            cancellation=fixture.guard, lane_evidence=fixture.record))
        root = fixture.config.project_path(fixture.config.section("metadata").get("root", "release/store"))
        snapshot = metadata.metadata_archive(root, platform="android")
        old = fixture.config.root / "public-metadata-reference.zip"
        build_metadata_archive(root, old, platform="android")
        self.assertEqual(metadata.require(snapshot).read_bytes(), old.read_bytes())
        self.assertEqual(snapshot.sha256, hashlib.sha256(old.read_bytes()).hexdigest())
        self.close(fixture)

    def test_first_prepare_creates_private_namespace_under_0022_before_output_writes(self):
        previous = os.umask(0o022)
        try:
            documents = fixture_chain()
            for stage, receipt_key in (("candidate", "candidate_receipt"),
                                       ("external-testing", "external_receipt"),
                                       ("production-submit", "production_receipt")):
                for private in (True, False):
                    with self.subTest(stage=stage, private=private), \
                         patch.dict(os.environ, workflow_environment(stage)):
                        prefix = ".mobile-release" if private else "public"
                        fixture = self.fixture(stage=stage,
                            output_dir=f"{prefix}/staging/{stage}/android")
                        output = fixture.request.output_dir
                        self.assertFalse(output.exists())
                        readback = self.run_model(fixture)
                        self.close(fixture)
                        self.assertEqual(stores.complete_store_operation(readback,
                            lane_evidence=fixture.record, cancellation=fixture.guard), {"synthetic": True})
                        for path in (fixture.config.root / prefix, output.parent.parent,
                                     output.parent, output):
                            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if private else 0o755)
                        # Exercise the actual follow-on private writers, not a
                        # fixture chmod/precreated staging parent. These sealed
                        # fixture documents are not real Store authority.
                        original_intent = fixture.config.root / "original-intent.json"
                        write_evidence(original_intent, documents[receipt_key.replace("receipt", "intent")],
                            app_root=fixture.config.root, cancellation=fixture.guard)
                        intent_copy = output / f"{stage}-operation-intent.json"
                        copy_immutable_file(original_intent, intent_copy,
                            app_root=fixture.config.root, cancellation=fixture.guard)
                        receipt_path = output / f"{stage}-receipt.json"
                        write_evidence(receipt_path, documents[receipt_key],
                            app_root=fixture.config.root, cancellation=fixture.guard)
                        self.assertEqual(intent_copy.read_bytes(), original_intent.read_bytes())
                        self.assertEqual(json.loads(receipt_path.read_bytes()), documents[receipt_key])
        finally:
            os.umask(previous)

    def test_private_output_parent_refuses_incompatible_mode_before_launch(self):
        fixture = self.fixture(output_dir=".mobile-release/staging/candidate/android")
        legacy = fixture.config.root / ".mobile-release/staging"
        legacy.mkdir(mode=0o755); legacy.chmod(0o755)
        (legacy / "keep").write_bytes(b"unrelated retained output")
        identity = legacy.stat().st_ino
        with self.assertRaisesRegex(ValidationError, "incompatible legacy layout") as caught:
            self.run_model(fixture)
        self.assertEqual(fixture.model.calls, [])
        self.assertIsNone(fixture.record._pending_attempt)
        self.assertNotIn("terminal", fixture.record._resources)
        self.close(fixture, caught.exception)
        self.assertEqual((legacy.stat().st_ino, stat.S_IMODE(legacy.stat().st_mode)), (identity, 0o755))
        self.assertEqual((legacy / "keep").read_bytes(), b"unrelated retained output")
        self.assertEqual(set(legacy.iterdir()), {legacy / "keep"})

    def test_output_namespace_close_loss_cannot_finalize_receipt(self):
        for primary in (None, KeyboardInterrupt()):
            with self.subTest(interrupted=primary is not None):
                fixture = self.fixture()
                namespaces = []
                acquire = inputs._StoreNamespace.acquire
                def capture_namespace(owner):
                    acquire(owner)
                    if owner.path == Path(fixture.record._output).parent:
                        namespaces.append(owner)
                with patch.object(inputs._StoreNamespace, "acquire", new=capture_namespace):
                    self.run_model(fixture)
                self.assertEqual(len(namespaces), 1)
                namespace = namespaces[0]
                target, close, lost = namespace.slots[-1].number, os.close, []
                self.assertIsInstance(target, int)
                def lose_return(number):
                    close(number)
                    if number == target and not lost:
                        lost.append(number)
                        raise OSError("modeled original output-parent close return loss")
                with patch.object(inputs.os, "close", side_effect=lose_return), \
                     self.assertRaises(KeyboardInterrupt if primary is not None else ProcessError) as caught:
                    self.close(fixture, primary)
                self.assertEqual(lost, [target])
                if primary is not None:
                    self.assertIs(caught.exception, primary)
                    self.assertIs(fixture.record._primary, primary)
                else:
                    self.assertTrue(caught.exception.fatal)
                self.assertFalse(namespace.closed())
                self.assertTrue(all(slot.number is None for slot in namespace.slots))
                self.assertTrue(all(slot.number is None for slot in namespace.parent.slots))
                self.assertTrue(fixture.invocation.claimed)
                self.assertTrue(self.pending_path(fixture).is_file())
                self.assertTrue(fixture.record._pending_attempt.handles_closed())
                self.assertFalse(fixture.record.verdict(cancellation=fixture.guard).receipt_acceptable)

    def test_online_namespace_then_store_mode_remain_private_under_0022(self):
        app = self.root / "online-first"; app.mkdir(mode=0o700)
        config = load_config(write_project(app, android_config()))
        guard = DefaultCancellation(ProcessCleanupError, "synthetic online owner")
        guard._installation, guard._activated, guard.depth = "INSTALLED", True, 0
        previous = os.umask(0o022)
        try:
            # This is the exact standalone online-preflight default-output
            # producer. No Store credential or native query is required to
            # prove its persistent namespace handoff into a later Store call.
            directory = stores._private_app_directory(config, ".mobile-release/store", cancellation=guard)
            for path in (app / ".mobile-release", directory):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            request = stores.StoreRequest("candidate", "android", "synthetic", False, app / "output", prepare=True)
            record = stores.new_store_lane_evidence(config, request, guard)
            with inputs.invocation_custody(app, mode="store", cancellation=guard, lane_evidence=record) as invocation:
                invocation.require(root=app, cancellation=guard)
            self.assertTrue(invocation._lane_closed_for(record, guard))
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        finally:
            os.umask(previous)

    def test_explicit_online_path_admits_private_namespace_without_reclassifying_public_outputs(self):
        for private in (True, False):
            with self.subTest(private=private):
                app = self.root / ("explicit-private" if private else "explicit-public")
                app.mkdir(mode=0o700)
                config = load_config(write_project(app, android_config()))
                guard = DefaultCancellation(ProcessCleanupError, "synthetic explicit-path owner")
                guard._installation, guard._activated, guard.depth = "INSTALLED", True, 0
                output = app / (".mobile-release" if private else "public") / "readbacks" / "android.json"
                adc = self.private_material / (app.name + ".json")
                adc.write_bytes(b'{"type":"authorized_user","synthetic":true}'); adc.chmod(0o600)
                previous = os.umask(0o022)
                try:
                    with inputs.invocation_custody(app, mode="online", cancellation=guard) as invocation, \
                         _selected_store_material(config, values={"GOOGLE_APPLICATION_CREDENTIALS": str(adc)},
                             platforms=("android",), invocation=invocation, cancellation=guard) as material:
                        material.validate()
                        with patch.dict(os.environ, {"MOBILE_RELEASE_PREFLIGHT_READBACK_PATH": str(output)}), \
                             patch.object(stores, "resolve_tooling_root", return_value=app / "tooling"), \
                             patch.object(stores, "_complete_tooling_root", return_value=True), \
                             patch.object(stores, "_require_fastlane_bundle"), \
                             patch.object(stores, "finite_scratch", side_effect=RuntimeError("stop before runner")), \
                             self.assertRaisesRegex(RuntimeError, "stop before runner"):
                            stores.online_preflight_findings(config=config, release=config.release_version(),
                                platforms=("android",), material=material, invocation=invocation)
                    self.assertTrue(output.parent.is_dir())
                    self.assertFalse(output.exists())
                    if private:
                        for path in (app / ".mobile-release", app / ".mobile-release/store"):
                            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
                    else:
                        self.assertFalse((app / ".mobile-release").exists())
                finally:
                    os.umask(previous)

    def test_legacy_nonprivate_namespace_refuses_without_chmod_or_output_effects(self):
        app = self.root / "legacy"; app.mkdir(mode=0o700)
        private = app / ".mobile-release"; private.mkdir(mode=0o755); private.chmod(0o755)
        (private / "keep").write_bytes(b"legacy output")
        config = load_config(write_project(app, android_config()))
        guard = DefaultCancellation(ProcessCleanupError, "synthetic namespace owner")
        guard._installation, guard._activated, guard.depth = "INSTALLED", True, 0
        request = stores.StoreRequest("candidate", "android", "synthetic", False, app / "output", prepare=True)
        record = stores.new_store_lane_evidence(config, request, guard)
        with self.assertRaisesRegex(ValidationError, "incompatible legacy layout"):
            with inputs.invocation_custody(app, mode="store", cancellation=guard, lane_evidence=record):
                self.fail("unsafe legacy namespace admitted")
        self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o755)
        self.assertEqual((private / "keep").read_bytes(), b"legacy output")
        self.assertFalse((app / "output").exists())


if __name__ == "__main__":
    unittest.main()
