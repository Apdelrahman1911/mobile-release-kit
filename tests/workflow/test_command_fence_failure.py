"""Eleven literal C-fence singleton witnesses and small inert contracts."""
from __future__ import annotations

import errno
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mobile_release import _command_process as command
from workflow import command_bootstrap_fixture as bootstrap
from workflow import command_fence_failure_fixture as fixture
from workflow.profile_process_fixture import FixtureWorkspace


class CommandFenceFailureContractTests(unittest.TestCase):
    def test_closed_inventory_keeps_only_state_distinct_c_losses(self):
        actual = {value[:2] for value in fixture.CASES.values() if value[2] == "loss"}
        self.assertEqual(len(fixture.CASES), 11)
        self.assertEqual(sum(value[3] for value in fixture.CASES.values()), 3)
        self.assertEqual(actual, {
            ("PENDING_CREATE", "BEFORE"), ("PENDING_CREATE", "AFTER"),
            ("PENDING_WRITE", "PARTIAL"), ("PENDING_WRITE", "AFTER"),
            ("DATA_FSYNC", "AFTER"), ("PENDING_CLOSE", "AFTER"),
            ("FINAL_LINK", "AFTER"), ("DIRECTORY_FSYNC", "AFTER"),
        })
        self.assertEqual(len(fixture.EQUIVALENT_C_EDGES), 5)
        self.assertFalse(actual & fixture.EQUIVALENT_C_EDGES.keys())
        self.assertTrue(set(fixture.EQUIVALENT_C_EDGES.values()) <= actual)
        original = command._BOOTSTRAP
        for selected in fixture.CASES:
            settings = ("fence-" + selected, "/fixed/command_bootstrap_fixture.py", "/fixed/root",
                        ((1, 2, 3), (1, 4, 3), (1, 5, 3)))
            text = bootstrap.build_bootstrap(original, settings)
            self.assertLessEqual(len(text.encode()), 8192)
            self.assertEqual(text.count("_stage = 1"), 1)
            self.assertEqual(text.count("_stage = 2"), 1)
        with self.assertRaises(AssertionError):
            bootstrap.build_bootstrap(original, ("fence-pending-write-before", *settings[1:]))

    @staticmethod
    def writer():
        # A bare inert file-effect harness, NOT a fabricated C/producer/finality.
        context = SimpleNamespace(primary=None, cleanup_unknown=False, errors=[])
        context.owner_check = lambda: None

        def record(error, *, unknown=False):
            if context.primary is None:
                context.primary = error
            context.errors.append(error)
            context.cleanup_unknown |= unknown

        context.record = record
        writer = command.FenceWriter.__new__(command.FenceWriter)
        writer.ctx, writer.effects, writer.files, writer.retired = context, [], [], False
        return writer

    def test_original_effect_and_slots_own_return_and_unknown_transitions(self):
        for failed, mutating in ((False, True), (True, True), (True, False)):
            with self.subTest(failed=failed, mutating=mutating):
                writer, error, entered = self.writer(), OSError(errno.EIO, "inert effect"), []

                def action():
                    self.assertEqual(writer.effects[-1].operation, "selected")
                    self.assertEqual(writer.effects[-1].state, "IN_FLIGHT")
                    entered.append(True)
                    if failed:
                        raise error
                    return 7

                if failed:
                    with self.assertRaises(OSError) as raised:
                        writer.effect("selected", action, mutating=mutating)
                    self.assertIs(raised.exception, error)
                    self.assertIs(writer.ctx.primary, error)
                else:
                    self.assertEqual(writer.effect("selected", action, mutating=mutating), 7)
                self.assertEqual(entered, [True])
                self.assertEqual(writer.effects[0].state, "UNKNOWN" if failed else "RETURNED")
                self.assertEqual(writer.ctx.cleanup_unknown, failed and mutating)

        for fault in (None, "open", "close"):
            with self.subTest(slot_fault=fault):
                writer, calls, error = self.writer(), [], OSError(errno.EIO, "inert slot return")
                slot = command._FileSlot(writer)

                def opened(*args, **kwargs):
                    calls.append("open")
                    self.assertEqual(slot.state, "OPENING")
                    self.assertEqual(writer.effects[-1].state, "IN_FLIGHT")
                    if fault == "open":
                        raise error
                    return 77  # Inert scalar, never a real opened descriptor.

                def closed(descriptor):
                    calls.append(("close", descriptor))
                    self.assertEqual(slot.state, "CLOSING")
                    self.assertIsNone(slot.fd)
                    self.assertEqual(writer.effects[-1].state, "IN_FLIGHT")
                    if fault == "close":
                        raise error

                with patch.object(command, "os", SimpleNamespace(open=opened, close=closed)):
                    if fault == "open":
                        with self.assertRaises(OSError):
                            slot.open("inert", 0, parent=88)
                    else:
                        self.assertEqual(slot.open("inert", 0, parent=88), 77)
                        self.assertEqual(slot.state, "OPEN")
                        if fault == "close":
                            with self.assertRaises(OSError):
                                slot.close()
                        else:
                            slot.close()
                            slot.close()  # Positively closed is an inert no-op.
                    self.assertIsNone(slot.fd)
                    self.assertEqual(slot.state, "UNKNOWN" if fault else "CLOSED")
                    before = calls[:]
                    self.assertEqual(writer.close(), not bool(fault))
                    self.assertEqual(calls, before)  # UNKNOWN never retries the number.
                    if fault:
                        self.assertIs(writer.ctx.primary, error)
                        self.assertTrue(writer.ctx.cleanup_unknown)


class CommandFenceFailureTests(unittest.TestCase):
    """Literal one-fault captures; no native/shared-host direct suite entry."""
    def _case(self, selected):
        with FixtureWorkspace(prefix="mrk-command-fence-") as workspace:
            identity = workspace._identity
            result = fixture.run_case(workspace.path, selected)
            self.assertEqual(result["disposition"], "recovered" if fixture.CASES[selected][3] else "refused")
            self.assertEqual(result["original"]["resultIntegrity"], "incomplete")
            self.assertTrue(result["original"]["unresolved"] and result["original"]["fatal"])
            wait = result["originalWait"]
            self.assertTrue(wait["originalAnchorWait"] and wait["originalWorkerWait"]
                            and wait["originalStatusEOF"] and wait["groupAbsentBeforeAnchorWait"])
            workspace.retain()
            self.assertTrue(workspace.retained)
            self.assertFalse(workspace.removal_allowed)
            self.assertEqual(workspace._identity, identity)

    def test_original_c_loss_pending_create_before(self):
        self._case("pending-create-before")

    def test_original_c_loss_pending_create_after(self):
        self._case("pending-create-after")

    def test_original_c_loss_pending_write_partial(self):
        self._case("pending-write-partial")

    def test_original_c_loss_pending_write_after(self):
        self._case("pending-write-after")

    def test_original_c_loss_data_fsync_after(self):
        self._case("data-fsync-after")

    def test_original_c_loss_pending_close_after(self):
        self._case("pending-close-after")

    def test_original_c_loss_final_link_after(self):
        self._case("final-link-after")

    def test_original_c_loss_directory_fsync_after(self):
        self._case("directory-fsync-after")

    def test_original_c_pending_close_lost_return(self):
        self._case("pending-close-lost-return")

    def test_original_c_final_link_lost_return(self):
        self._case("final-link-lost-return")

    def test_original_c_foreign_pending_collision(self):
        self._case("foreign-pending-collision")
