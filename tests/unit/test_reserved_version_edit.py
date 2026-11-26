"""Real own-temp RELEASE_VERSION transactions with synthetic Git/HTTP/ACK.

No process, provider, credential, native receipt or user project is exercised.
Only the existing checked file/Init owners perform real temporary filesystem
work; C/A/W and the native dialogue use the explicitly inert ReserveFixture.
"""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mobile_release import checked_files
from mobile_release import init_workspace_custody as custody
from mobile_release import release_version_edit as edit
from mobile_release import reserved_version_edit as reserved
from mobile_release import version_allocation as allocation
from mobile_release import version_allocation_source as source
from mobile_release import version_allocation_state as state
from mobile_release._desktop_edit_engine import _Engine
from mobile_release.cancellation import CleanupScope
from mobile_release.config_payloads import prepare_edit_ignore
from mobile_release.init_transaction import TypedEditProfile

from test_desktop_version_reserve import ReserveFixture
from test_version_allocation import NOW
from test_version_allocation_state import LOCAL_PROJECT


class EditFixture(ReserveFixture):
    def __init__(self, root):
        super().__init__(root)
        self.write(".gitignore", prepare_edit_ignore(b"")[0])
        self.editing = False
        self.edit_input_closes = 0
        self.engine = self.owner = self.checkout = None

    def _fstat(self, fd):
        if self.editing and fd == 0:
            return SimpleNamespace(st_dev=17, st_ino=91, st_mode=stat.S_IFIFO | 0o600)
        return super()._fstat(fd)

    def _read(self, fd, count):
        if self.editing and fd == 0:
            raise BlockingIOError()
        return super()._read(fd, count)

    def _close(self, fd):
        if self.editing and fd == 0:
            self.edit_input_closes += 1  # The fixture never closes process stdin.
            return
        return super()._close(fd)

    def _command(self, argv, **kwargs):
        if self.editing and argv[17:18] == ["status"] and self.status == b"":
            changed = (self.root / self.data["version"]["source"]).read_bytes() != self.version
            if changed:
                self.status = b" M " + self.data["version"]["source"].encode() + b"\0"
        return super()._command(argv, **kwargs)

    def handoff(self):
        outcome = self.fin["outcome"]
        assert outcome["status"] == "reserved"
        return {"schemaVersion": 1, "source": self.source_request().value(), "provider": self.provider_value(),
                "reservation": outcome["reservation"], "authority": self.authority.value(),
                "checkpoint": outcome["checkpoint"], "observation": self.observation.value(), "clock": self.clock()}

    @contextmanager
    def opened(self):
        self.editing = True
        with self.mocks(), patch.object(reserved.time, "time", lambda: NOW):
            self.engine = _Engine(self.now, domain="release_version")
            e = self.engine
            scope = CleanupScope(e.guard, e.cleanup, owns_cancellation=True, first_primary=True)
            try:
                with scope:
                    e.guard.install()
                    e.input.acquire()
                    e.guard._install_edit_source(e.input)
                    e.guard.activate()
                    # Fixed private Open arrival is DATA here; no native receipt
                    # is invented. The actual EditInput/guard remains sole owner.
                    e.input.active = True
                    e.input.frames = 1
                    self.owner = reserved.ReservedVersionEdit(e, self.handoff())
                    identity = self.source_request().value()["rootIdentity"]
                    identity = {key: int(value) for key, value in identity.items()}
                    e.lease = custody.InitRootLease(self.root, cancellation=e.guard,
                        profile=TypedEditProfile.RELEASE_VERSION, registered_identity=identity)
                    e.lease.acquire()
                    self.checkout = edit.capture_release_version_edit(e.lease)
                    e.authority = self.checkout
                    self.owner.check_saved(self.checkout)
                    yield self.owner
            finally:
                scope.__exit__(*sys.exc_info())
            self.settled = self.owner.settled()

    def prepare(self):
        plan = self.owner.prepare(self.checkout, {"revision": self.checkout.revision,
            "expectedBaseline": self.checkout.baseline, "intent": "edit",
            "values": {"name": "1.2.3", "build": "8"}})
        self.engine.authority = plan
        return plan


class ReservedVersionEditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mrk-reserved-edit-inert-")
        root = Path(self.tmp.name) / "project"
        root.mkdir()
        self.f = EditFixture(root)
        self.retained = len(source._RETAINED)

    def tearDown(self):
        del source._RETAINED[self.retained:]
        self.tmp.cleanup()

    def test_reserve_real_preview_apply_and_retry_retains_exact_candidate_without_another_put(self):
        f = self.f
        f.run()
        original_source = f.selected.source
        modes = {}
        original_close = custody.LockedInitScope.close

        def close(scope):
            if scope.claimed:
                return original_close(scope)
            borrower = scope.reserved_version
            source_fd = borrower.require_operation().invocation.project_owner.fd if borrower else None
            result = original_close(scope)
            if borrower is not None:
                # Closing the Init scope's separate FD must not release the
                # still-held original Source flock/open description.
                modes[borrower.phase] = os.fstat(source_fd).st_mode
                other = os.open(f.root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(other)
            return result

        with patch.object(custody.LockedInitScope, "close", close), f.opened() as owner:
            before = (f.root / f.data["version"]["source"]).stat()
            plan = f.prepare()
            self.assertTrue(edit._authentic_plan(plan))
            self.assertEqual((f.root / f.data["version"]["source"]).read_bytes(), f.version)
            outcome = owner.apply(plan)
            self.assertEqual((outcome.effect, outcome.journal, outcome.resources, outcome.reason),
                             ("committed", "clean", "settled", "none"))
            self.assertEqual((f.root / f.data["version"]["source"]).read_bytes(),
                             b"VERSION_NAME=1.2.3\nBUILD_NUMBER=8\n")
            self.assertEqual((f.root / f.data["version"]["source"]).stat().st_mode, before.st_mode)
            self.assertEqual({b.phase for b in owner.borrowers}, {"prepare", "apply"})
            self.assertTrue(all(b.borrow_ended and b.operation.originals_closed() for b in owner.borrowers))
            with self.assertRaises(ValueError):
                owner.apply(plan)
        self.assertTrue(f.settled)
        self.assertEqual(f.edit_input_closes, 1)
        self.assertEqual(set(modes), {"prepare", "apply"})
        self.assertEqual(f.engine.guard.handler_state, "RESTORED")
        self.assertEqual(f.engine.guard.lifetime_ledger.verdict().commands, 14)
        self.assertFalse(any(p.name.startswith(".mobile-release-version") for p in f.root.iterdir()))
        # A separate restarted journal can return only the same allocated DATA;
        # changed edited source is not silently a new candidate/release grant.
        journal = state.NativeAllocationJournal(f.native, local_project_id=LOCAL_PROJECT)
        result = allocation.allocate_version(f.selected, f.authority, f.repository, journal,
            observations=(f.observation,), clock=lambda: NOW)
        self.assertEqual(result.status, "reserved")
        self.assertEqual(result.reservation.request.source, original_source)
        self.assertEqual(result.reservation.version.build, 8)
        self.assertEqual(result.reservation.value(), f.fin["outcome"]["reservation"])
        self.assertEqual(len(f.repository.writes), 1)

    def test_unrelated_source_change_after_prepare_never_writes_or_reuses_spent_plan(self):
        f = self.f
        f.run()
        with f.opened() as owner:
            plan = f.prepare()
            f.write(".git/HEAD", b"ref: refs/heads/foreign\n")
            with self.assertRaises(BaseException):
                owner.apply(plan)
            self.assertIsNone(owner.outcome)
            self.assertEqual((f.root / f.data["version"]["source"]).read_bytes(), f.version)
            with self.assertRaises(ValueError):
                owner.apply(plan)
        self.assertEqual(len(f.repository.writes), 1)

    def test_foreign_closed_or_mismatched_workspace_cannot_borrow_source_flock(self):
        f = self.f
        f.run()
        with f.opened() as owner:
            with owner.source("prepare"):
                borrower = owner.active
                with self.assertRaises(ValueError):
                    borrower.borrow_workspace(SimpleNamespace(lease=owner.lease))
                foreign = custody.LockedInitScope(owner.lease)
                with self.assertRaises(ValueError):
                    borrower.borrow_workspace(foreign)
                self.assertIsNone(borrower.workspace)
            self.assertTrue(borrower.borrow_ended)
            with self.assertRaises(ValueError):
                borrower.borrow_workspace(foreign)
            with self.assertRaises(ValueError):
                borrower.check_workspace(foreign)
        self.assertTrue(f.settled)

    def test_actual_postwrite_close_failure_retains_committed_effect_and_cannot_claim_settled(self):
        f = self.f
        f.run()
        original = checked_files._Reader.close
        failed = []

        def close(reader):
            result = original(reader)
            active = f.owner.active if f.owner else None
            if active and active.phase == "apply" and active.operation.observation is not None \
                    and reader is active.operation.observation.successor and not failed:
                failed.append(reader)
                raise OSError("synthetic return-lost source close")
            return result

        with self.assertRaises(BaseException), patch.object(checked_files._Reader, "close", close):
            with f.opened() as owner:
                plan = f.prepare()
                owner.apply(plan)
        self.assertEqual(len(failed), 1)
        self.assertEqual(f.engine.outcome.effect, "committed")
        self.assertEqual((f.root / f.data["version"]["source"]).read_bytes(),
                         b"VERSION_NAME=1.2.3\nBUILD_NUMBER=8\n")
        self.assertTrue(f.owner.active is not None or f.engine.guard.lifetime_ledger.fatal)
        self.assertFalse(getattr(f, "settled", False))
        self.assertEqual(len(f.repository.writes), 1)

    def test_real_foreign_root_descriptor_is_rejected_before_init_borrows_source_lock(self):
        f = self.f
        f.run()
        foreign = Path(self.tmp.name) / "foreign"
        foreign.mkdir()
        original = custody._FD.open
        cut = []

        def opened(slot, path, flags, **kwargs):
            # Replace only the real new Init scope's directory open. Both FDs
            # have ordinary custody and really close; no positive borrower or
            # source authority is constructed by this failure injection.
            scope = f.owner.lease._active if f.owner else None
            if f.owner.active is not None and scope is not None and slot is scope.lock and not cut:
                cut.append(slot)
                return original(slot, str(foreign), flags)
            return original(slot, path, flags, **kwargs)

        with f.opened() as owner, patch.object(custody._FD, "open", opened):
            with self.assertRaises(BaseException):
                f.prepare()
            self.assertIsNone(owner.plan)
            self.assertIsNone(owner.outcome)
            self.assertEqual((f.root / f.data["version"]["source"]).read_bytes(), f.version)
            self.assertFalse(tuple(foreign.iterdir()))
            self.assertEqual(len(cut), 1)
            self.assertEqual(cut[0].close_state, "CLOSED")
        self.assertEqual(len(f.repository.writes), 1)

    def test_original_source_closed_before_workspace_borrow_cannot_be_reopened_or_replaced(self):
        f = self.f
        f.run()
        original = reserved.BorrowedReservedVersionInput.borrow_workspace
        cut = []

        def borrow(borrower, scope):
            if not cut:
                project = borrower.require_operation().invocation.project_owner
                cut.append(project)
                project.cleanup()  # The actual original consumes its FDs/flock.
            return original(borrower, scope)

        with f.opened() as owner, patch.object(reserved.BorrowedReservedVersionInput, "borrow_workspace", borrow):
            with self.assertRaises(BaseException):
                f.prepare()
            self.assertIsNone(owner.plan)
            self.assertIsNone(owner.outcome)
            self.assertEqual((f.root / f.data["version"]["source"]).read_bytes(), f.version)
            self.assertEqual(len(cut), 1)
            self.assertTrue(cut[0].claimed)
            self.assertIs(owner.borrowers[0].operation.invocation._original_project, cut[0])
            self.assertIsNone(owner.active)
        self.assertEqual(len(f.repository.writes), 1)


if __name__ == "__main__":
    unittest.main()
