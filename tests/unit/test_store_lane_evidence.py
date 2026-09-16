"""Inert Store-lane record contracts, not process/native verification.

The real CommandCallEvidence matcher and _Outer publisher consume explicitly
modeled owner state. No child, signal, descriptor or terminal file is created.
Modeled file-reader/marker state is explicit; these tests do not qualify
the real filesystem reader, Ruby publisher, native clocks or process behavior.
"""
from __future__ import annotations

import dataclasses
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release import _command_process as command
from mobile_release import _store_lane_evidence as lane_evidence
from mobile_release import _store_lane_files as lane_files
from mobile_release import _store_lane_contract as wire
from mobile_release import cancellation as cancellation_module
from mobile_release.cancellation import DefaultCancellation
from mobile_release.owned_process import PRIVATE_OUTPUT_LIMIT, ProcessCleanupError, ProcessError
from unit.test_lifetime_evidence import fork_registry_model


LANE = "ios_testflight_internal"
OUTPUT = Path("/fictional/output/raw-store-receipt.json")
RUNNER = Path("/fictional/tooling/fastlane/run_lane.rb")
CWD = Path("/fictional/private/runner")
NONCE = b"l" * 16
DIGEST = b"r" * 32
NOW = 1_000_000_000_000
AUTHORITY = {"attempt": 1, "callerPath": ".github/workflows/candidate.yml",
    "event": "workflow_dispatch", "headSha": "a" * 40, "ref": "refs/heads/main",
    "reusableCommit": "b" * 40, "reusablePath": ".github/workflows/candidate.yml",
    "reusableRepository": "synthetic/project", "runId": 1, "workflow": "candidate"}


class StoreLaneEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(fork_registry_model())
        self.engines = []
        self.file_owners = []
        fixed_time = patch.object(command.time, "monotonic_ns", return_value=NOW)
        fixed_time.start(); self.addCleanup(fixed_time.stop)
        for name in ("kill", "killpg", "fork", "execve", "pipe", "open", "close"):
            veto = patch.object(command.os, name, side_effect=AssertionError("inert record check attempted OS effect"))
            veto.start(); self.addCleanup(veto.stop)
        veto = patch.object(command.native, "create", side_effect=AssertionError("inert record check attempted native creation"))
        veto.start(); self.addCleanup(veto.stop)
        veto = patch.object(command.threading.Thread, "start", side_effect=AssertionError("inert record check started thread"))
        veto.start(); self.addCleanup(veto.stop)
        veto = patch.object(cancellation_module.signal, "signal", side_effect=AssertionError("inert record check changed handler"))
        veto.start(); self.addCleanup(veto.stop)
        fixed = patch.object(command.os, "urandom", return_value=b"c" * 16)
        fixed.start(); self.addCleanup(fixed.stop)
        # Remove only references to these modeled objects, never another task's
        # retained owners. No native resources exist in these fixtures.
        self.addCleanup(lambda: command._RETAINED.__setitem__(slice(None), [
            value for value in command._RETAINED if not any(value is item for item in self.engines)
        ]))

        self.addCleanup(lambda: lane_files._RETAINED.__setitem__(slice(None), [
            value for value in lane_files._RETAINED if not any(value is item for item in self.file_owners)
        ]))

    def fixture(self, *, seal=True):
        guard = DefaultCancellation(ProcessCleanupError, "inert owner error")
        record = lane_evidence.StoreLaneCallEvidence(guard, lane=LANE, output=OUTPUT, nonce=NONCE)
        files = lane_files.StoreLaneFiles(record, guard, app_root=Path("/fictional"), mode="execute")
        attempt = lane_files.StoreLaneAttempt(record, guard, app_root=Path("/fictional"), mode="execute",
                                              intent_sha256=DIGEST, executed_by=AUTHORITY)
        self.file_owners.extend((files, attempt))
        owners = {role: files for role in files.bindings}
        owners.update({role: object() for role in ("metadata", "ios-snapshot")})
        bindings = dict(files.bindings)
        for role in ("metadata", "ios-snapshot"):
            bindings[role] = record.bind_resource(role, owners[role], cancellation=guard)
        timing = wire.Timing(wire.clock_label(), NOW + wire.RUN_NS, NOW + wire.RUN_NS + wire.CLEANUP_NS)
        environ = {
            "MOBILE_RELEASE_STORE_RECEIPT_PATH": str(OUTPUT), "MOBILE_RELEASE_OPERATION": LANE,
            "MOBILE_RELEASE_STORE_MODE": "execute", wire.PREFIX + "NONCE": NONCE.hex(),
            wire.PREFIX + "ROOT": str(CWD.parent), wire.PREFIX + "ROOT_ID": "1:2",
            wire.PREFIX + "CLOCK": timing.clock, wire.PREFIX + "RUN_DEADLINE_NS": str(timing.run),
            wire.PREFIX + "HARD_DEADLINE_NS": str(timing.hard),
            "DEVELOPER_DIR": "/fictional/Xcode.app/Contents/Developer", "PRIVATE": "synthetic-only",
        }
        files.root_path, files.phase, files.timing = CWD.parent, "PREPARED", timing
        files.environment = tuple(sorted(environ.items()))
        # This suite models original file custody explicitly. Real filesystem
        # acquisition/read/close/retirement is covered by the separate FS suite.
        inventory = patch.object(files, "_check_inventory", return_value=None)
        inventory.start(); self.addCleanup(inventory.stop)
        attempt.phase, attempt.directory = "PENDING", object()
        attempt.identity, attempt.content = wire.Identity(1, 3, 0, 0, 0o600), b"modeled marker"
        read = patch.object(lane_files, "_read", return_value=(attempt.content, attempt.identity))
        read.start(); self.addCleanup(read.stop)
        argv = record.seal_command(runner=RUNNER, cwd=CWD, environ=environ, cancellation=guard) if seal else None
        return SimpleNamespace(guard=guard, record=record, owners=owners, bindings=bindings,
                               environ=environ, argv=argv, files=files, attempt=attempt)

    def finish(self, fixture, *, primary=None, resources_closed=True):
        verdict = fixture.record.finish(cancellation=fixture.guard, primary=primary)
        if verdict.dependents_settled and resources_closed:
            # Explicit modeled original disposal, not a production capability.
            fixture.files.phase, fixture.files._cleanup_complete = "DISPOSED", True
            fixture.attempt.phase = "RETIRED"
        return verdict

    def bound_engine(self, fixture, *, environ=None, cwd=CWD, capture=False):
        evidence = fixture.record.command_evidence(cancellation=fixture.guard)
        evidence._attempt(fixture.guard, timeout=3600, ordinary=True)
        engine = command._Outer(fixture.guard, False, 3600, None, None, suppress_cancel=False, evidence=evidence)
        self.engines.append(engine)
        evidence._bind(engine)
        engine.evidence = evidence
        engine.frozen = command._freeze_command(
            fixture.argv, environ=fixture.environ if environ is None else environ, cwd=cwd,
            capture=capture, output_limit=PRIVATE_OUTPUT_LIMIT, nonce=engine.nonce,
        )
        evidence._match(engine)
        return engine

    def publish_group_model(self, fixture, *, returncode=0, no_target=False, confirmed=True):
        engine = self.bound_engine(fixture)
        # Only modeled pure fields: no native wait or public finality factory.
        # The existing original publisher issues its actual slot/outcome types.
        engine.handlers_complete = True
        engine.local_cleanup_complete = confirmed
        engine.create_route.retired = engine.run_route.retired = True
        if not no_target:
            engine.create_route.attempted = engine.run_route.attempted = True
            engine.wait = command.native.WaitReceipt(1001, "exit", command.HELPER_OK, 0)
            engine.child = SimpleNamespace(receipt=engine.wait)
            engine.sealed = True
            engine.wire = SimpleNamespace(eof=True, poisoned=False)
            engine.readers = [object(), object()]
            engine.output_eof = [True, True]
            engine.terminal = {"producer": True, "no_target": None, "stdout": 0, "stderr": 0,
                               "result": True, "wait": {"kind": "exit", "code": returncode}}
        outcome = engine.publish()
        fixture.engine, fixture.outcome = engine, outcome
        return outcome

    def terminal(self, fixture, **updates):
        value = lane_evidence.StoreLaneTerminal(fixture.bindings["terminal"], 1, NONCE, LANE,
                                                str(OUTPUT), True, True, True,
                                                None if fixture.outcome.returncode == wire.SETTLED_FAILURE else DIGEST)
        return dataclasses.replace(value, **updates)

    def publish_terminal(self, fixture, terminal=None):
        value = self.terminal(fixture) if terminal is None else terminal
        fixture.files.terminal, fixture.files.original_outcome = value, fixture.outcome
        fixture.files.phase = "OBSERVED"
        fixture.record.publish_terminal(
            fixture.bindings["terminal"], owner=fixture.owners["terminal"],
            terminal=value, cancellation=fixture.guard,
        )

    def assert_cleanup(self, fixture, expected):
        for role in ("runner", "tmp", "metadata", "ios-snapshot"):
            self.assertIs(fixture.record.dependents_settled_for(
                fixture.bindings[role], owner=fixture.owners[role], cancellation=fixture.guard,
            ), expected, role)

    def receipt(self, fixture, digest=DIGEST):
        return fixture.record.receipt_acceptable(lane=LANE, output=OUTPUT, sha256=digest,
                                                 cancellation=fixture.guard)

    def test_not_attempted_allows_only_original_resource_cleanup_not_receipt_reuse(self):
        fixture = self.fixture()
        self.assert_cleanup(fixture, False)
        self.assertFalse(fixture.record.verdict(cancellation=fixture.guard).finished)
        # Launch remains admitted: absence of an attempt is not yet finality.
        self.assertIsNotNone(fixture.record.command_evidence(cancellation=fixture.guard))
        verdict = self.finish(fixture)
        self.assertFalse(verdict.attempted or verdict.failed or verdict.command_finality_confirmed)
        self.assert_cleanup(fixture, True)
        self.assertFalse(self.receipt(fixture))
        with self.assertRaises(ProcessError):
            fixture.record.require_receipt(lane=LANE, output=OUTPUT, sha256=DIGEST, cancellation=fixture.guard)
        self.assert_cleanup(fixture, True)
        facts = fixture.guard.lifetime_ledger.verdict()
        self.assertEqual(facts.commands, 0)
        self.assertTrue(facts.contained)

    def test_armed_call_cannot_return_to_not_attempted_after_missing_engine(self):
        fixture = self.fixture()
        evidence = fixture.record.command_evidence(cancellation=fixture.guard)
        evidence._attempt(fixture.guard, timeout=3600, ordinary=True)
        verdict = self.finish(fixture)
        self.assertTrue(verdict.attempted and verdict.failed)
        self.assert_cleanup(fixture, False)
        self.assertFalse(self.receipt(fixture))
        with self.assertRaises(ProcessError):
            evidence._attempt(fixture.guard, timeout=3600, ordinary=True)
        self.assertTrue(self.finish(fixture).failed)

    def test_group_finality_without_nested_terminal_preserves_dependent_inputs(self):
        fixture = self.fixture()
        outcome = self.publish_group_model(fixture)
        self.assertIs(type(outcome.original_finality), command.OriginalCommandFinality)
        self.assertTrue(fixture.guard.lifetime_ledger.verdict().contained)
        verdict = self.finish(fixture)
        self.assertTrue(verdict.command_finality_confirmed and verdict.failed)
        self.assertFalse(verdict.terminal_confirmed)
        self.assert_cleanup(fixture, False)
        self.assertFalse(self.receipt(fixture))
        # Aborting the composite gate did not falsify the real command result.
        facts = fixture.guard.lifetime_ledger.verdict()
        self.assertTrue(facts.contained)
        self.assertEqual(facts.commands, 1)
        with self.assertRaises(ProcessError):
            self.publish_terminal(fixture)

    def test_terminal_fields_and_original_reader_binding_are_not_boolean_authority(self):
        values = [
            {"version": True}, {"nonce": b"x" * 16}, {"lane": "ios_app_store_submit"},
            {"output": "/copied/raw.json"}, {"launches_closed": False}, {"adapter_settled": False},
            {"nested_settled": False}, {"nested_settled": 1}, {"receipt_sha256": b"short"},
        ]
        for updates in values:
            with self.subTest(fields=tuple(updates)):
                fixture = self.fixture()
                self.publish_group_model(fixture)
                with self.assertRaises(ProcessError):
                    self.publish_terminal(fixture, self.terminal(fixture, **updates))
                self.assertTrue(self.finish(fixture).failed)
                self.assert_cleanup(fixture, False)
                self.assertFalse(self.receipt(fixture))
                with self.assertRaises(ProcessError):
                    self.publish_terminal(fixture)

        for invalid in ("raw-dictionary", "foreign-reader"):
            fixture = self.fixture()
            self.publish_group_model(fixture)
            with self.assertRaises(ProcessError):
                fixture.record.publish_terminal(fixture.bindings["terminal"],
                    owner=fixture.owners["terminal"] if invalid == "raw-dictionary" else object(),
                    terminal={"nested_settled": True} if invalid == "raw-dictionary" else self.terminal(fixture),
                    cancellation=fixture.guard)
            self.assert_cleanup(fixture, False)

    def test_complete_composite_requires_finalization_and_exact_receipt_digest(self):
        fixture = self.fixture()
        self.publish_group_model(fixture)
        self.publish_terminal(fixture)
        self.assert_cleanup(fixture, False)
        self.assertFalse(self.receipt(fixture))
        verdict = self.finish(fixture)
        self.assertTrue(verdict.command_finality_confirmed and verdict.terminal_confirmed)
        self.assert_cleanup(fixture, True)
        self.assertTrue(self.receipt(fixture))
        with patch.object(fixture.guard, "check", wraps=fixture.guard.check) as actual_check:
            self.assertIsNone(fixture.record.require_receipt(lane=LANE, output=OUTPUT, sha256=DIGEST,
                                                           cancellation=fixture.guard))
            actual_check.assert_called_once_with()
        self.assertFalse(self.receipt(fixture, b"s" * 32))

    def test_exact_terminal_value_without_original_reader_issuance_is_rejected(self):
        fixture = self.fixture()
        self.publish_group_model(fixture)
        with self.assertRaises(ProcessError):
            fixture.record.publish_terminal(fixture.bindings["terminal"], owner=fixture.files,
                terminal=self.terminal(fixture), cancellation=fixture.guard)
        self.assertFalse(self.finish(fixture).dependents_settled)

    def test_arbitrary_nonzero_or_receipt_status_disagreement_is_not_settled_transport(self):
        for status, digest in ((7, DIGEST), (wire.UNKNOWN, None),
                               (wire.SETTLED_FAILURE, DIGEST), (wire.SUCCESS, None)):
            with self.subTest(status=status, receipt=digest is not None):
                fixture = self.fixture()
                self.publish_group_model(fixture, returncode=status)
                with self.assertRaises(ProcessError):
                    self.publish_terminal(fixture, self.terminal(fixture, receipt_sha256=digest))
                self.assertFalse(self.finish(fixture).dependents_settled)
                # The true, complete original C/A/W outcome is not rewritten.
                self.assertTrue(fixture.guard.lifetime_ledger.verdict().contained)

    def test_receipt_waits_for_original_file_and_marker_retirement(self):
        fixture = self.fixture()
        self.publish_group_model(fixture)
        self.publish_terminal(fixture)
        verdict = self.finish(fixture, resources_closed=False)
        self.assertTrue(verdict.dependents_settled)
        self.assertFalse(self.receipt(fixture))
        fixture.files.phase, fixture.files._cleanup_complete = "DISPOSED", True
        self.assertFalse(self.receipt(fixture))
        fixture.attempt.phase = "RETIRED"
        self.assertTrue(self.receipt(fixture))

    def test_original_pending_marker_is_required_not_an_absence_probe(self):
        for state in ("NEW", "ABSENT", "RETIRED"):
            with self.subTest(state=state):
                fixture = self.fixture(seal=False)
                fixture.attempt.phase = state
                with self.assertRaises(ProcessError):
                    fixture.record.seal_command(runner=RUNNER, cwd=CWD, environ=fixture.environ,
                                                cancellation=fixture.guard)
                self.assertFalse(fixture.record._attempted)

    def test_presealed_deadline_enters_context_without_renewal_and_cannot_be_reused(self):
        fixture = self.fixture()
        original = fixture.files.timing
        with patch.object(command.time, "monotonic_ns", return_value=NOW + 27_000_000_000):
            engine = self.bound_engine(fixture)
        self.assertIs(engine._store_timing, original)
        self.assertEqual((engine.ctx.run, engine.ctx.hard), (original.run, original.hard))
        with self.assertRaises(ProcessError):
            command._Outer(fixture.guard, False, 3600, None, None, suppress_cancel=False,
                           evidence=fixture.record._command)

        expired = self.fixture()
        with patch.object(command.time, "monotonic_ns", return_value=expired.files.timing.run), \
             patch.object(command, "_Context", side_effect=AssertionError("expired context constructed")):
            with self.assertRaises(ValueError):
                self.bound_engine(expired)
        self.assertTrue(self.finish(expired).failed)

    def test_no_target_is_still_an_attempt_but_not_a_ruby_or_receipt_success(self):
        fixture = self.fixture()
        outcome = self.publish_group_model(fixture, no_target=True)
        self.assertIs(type(outcome.no_target), command.NoTargetProof)
        verdict = self.finish(fixture)
        self.assertTrue(verdict.attempted and verdict.command_finality_confirmed)
        self.assertFalse(verdict.terminal_confirmed or verdict.failed)
        self.assert_cleanup(fixture, True)
        self.assertFalse(self.receipt(fixture))

    def test_original_interruption_stays_primary_after_terminal_read_error_and_final_gate(self):
        for primary in (KeyboardInterrupt(), SystemExit(23)):
            with self.subTest(primary=type(primary).__name__):
                fixture = self.fixture()
                self.publish_group_model(fixture)
                # Only modeled root custody: _read raises before inspecting it;
                # no descriptor or pathname operation is admitted by this suite.
                fixture.files.root = object()
                later = OSError("inert terminal reader failed after caller interruption")
                with patch.object(lane_files, "_read", side_effect=later), \
                     self.assertRaises(type(primary)) as caught:
                    fixture.files.read_terminal(primary=primary)
                self.assertIs(caught.exception, primary)
                self.finish(fixture, primary=primary)
                self.assertIs(fixture.record._primary, primary)
                self.assertTrue(any(error is later for error in fixture.record._secondary))
                self.assertFalse(self.receipt(fixture))
                with self.assertRaises(type(primary)) as final:
                    fixture.record.require_receipt(lane=LANE, output=OUTPUT, sha256=DIGEST,
                                                   cancellation=fixture.guard)
                self.assertIs(final.exception, primary)

    def test_settled_nonzero_or_unrelated_primary_keeps_cleanup_but_not_success(self):
        wrapped = ValueError("ordinary wrapper around original fatal lifetime")
        wrapped.__cause__ = ProcessCleanupError("original uncontained lifetime", dispatched=True, contained=False)
        for returncode, primary, contained, cleaned in (
            (wire.SETTLED_FAILURE, None, True, True), (0, ValueError("ordinary failure"), True, True),
            (0, ProcessCleanupError("settled group but unconfirmed handle cleanup"), True, False),
            (0, ProcessError("original containment failure", contained=False), False, True),
            (0, wrapped, False, False), (0, KeyboardInterrupt(), True, True), (0, SystemExit(4), True, True),
        ):
            with self.subTest(returncode=returncode, primary=type(primary).__name__):
                fixture = self.fixture()
                self.publish_group_model(fixture, returncode=returncode)
                self.publish_terminal(fixture)
                self.finish(fixture, primary=primary)
                self.assert_cleanup(fixture, True)
                self.assertFalse(self.receipt(fixture))
                expected = type(primary) if isinstance(primary, (KeyboardInterrupt, SystemExit)) else ProcessError
                with self.assertRaises(expected) as caught:
                    fixture.record.require_receipt(lane=LANE, output=OUTPUT, sha256=DIGEST,
                                                   cancellation=fixture.guard)
                if isinstance(primary, (KeyboardInterrupt, SystemExit)):
                    self.assertIs(caught.exception, primary)
                else:
                    self.assertIs(caught.exception.contained, contained)
                    self.assertIs(caught.exception.cleanup_complete, cleaned)
                    self.assertIs(caught.exception.fatal, not (contained and cleaned))
                self.assertFalse(fixture.record.verdict(cancellation=fixture.guard).failed)
                self.assert_cleanup(fixture, True)

    def test_unrelated_guard_failure_does_not_turn_settled_consumers_into_live_ones(self):
        for cause, contained in (
            (OSError("unrelated resource failure"), True),
            (ProcessCleanupError("original handle failure"), True),
            (ProcessError("other original containment failure", contained=False), False),
            (KeyboardInterrupt(), True),
        ):
            with self.subTest(cause=type(cause).__name__):
                fixture = self.fixture()
                self.publish_group_model(fixture)
                self.publish_terminal(fixture)
                self.finish(fixture)
                fixture.guard._abort(cause)
                self.assertTrue(fixture.guard.lifetime_ledger.verdict().contained)
                self.assert_cleanup(fixture, True)
                self.assertFalse(self.receipt(fixture))
                with self.assertRaises(KeyboardInterrupt if isinstance(cause, KeyboardInterrupt) else ProcessError) as caught:
                    fixture.record.require_receipt(lane=LANE, output=OUTPUT, sha256=DIGEST,
                                                   cancellation=fixture.guard)
                if isinstance(cause, KeyboardInterrupt):
                    self.assertIs(caught.exception, cause)
                else:
                    self.assertTrue(caught.exception.fatal)
                    self.assertIs(caught.exception.contained, contained)
                    self.assertFalse(caught.exception.cleanup_complete)
                self.assert_cleanup(fixture, True)
                self.assertFalse(fixture.record.verdict(cancellation=fixture.guard).failed)

    def test_pending_cancellation_refuses_receipt_but_not_already_settled_cleanup(self):
        fixture = self.fixture()
        self.publish_group_model(fixture)
        self.publish_terminal(fixture)
        self.finish(fixture)
        self.assertTrue(self.receipt(fixture))
        fixture.guard.cancelled = True
        self.assertTrue(fixture.guard.lifetime_ledger.verdict().cleanup_complete)
        self.assertFalse(self.receipt(fixture))
        with self.assertRaises(KeyboardInterrupt) as first:
            fixture.record.require_receipt(lane=LANE, output=OUTPUT, sha256=DIGEST,
                                           cancellation=fixture.guard)
        with self.assertRaises(KeyboardInterrupt) as repeated:
            fixture.record.require_receipt(lane=LANE, output=OUTPUT, sha256=DIGEST,
                                           cancellation=fixture.guard)
        self.assertIs(first.exception, repeated.exception)
        self.assertFalse(fixture.record.verdict(cancellation=fixture.guard).failed)
        self.assertTrue(fixture.guard.lifetime_ledger.verdict().cleanup_complete)
        self.assert_cleanup(fixture, True)

    def test_actual_guard_rechecks_changed_handler_ownership_after_passive_receipt_view(self):
        fixture = self.fixture()
        self.publish_group_model(fixture)
        self.publish_terminal(fixture)
        self.finish(fixture)
        original_view = fixture.record.receipt_acceptable
        observed = []

        def changed_handler(**kwargs):
            observed.append(original_view(**kwargs))
            # Inert ownership fields only. No actual install/restore operation:
            # the real guard.check/handler_state must observe the mocked read.
            fixture.guard._installation = "INSTALLED"
            fixture.guard._signals[cancellation_module.signal.SIGINT] = cancellation_module._SignalOwnership(
                cancellation_module.signal.default_int_handler, fixture.guard.interrupt, install="INSTALLED")
            return observed[-1]

        with patch.object(cancellation_module.signal, "getsignal", return_value=lambda *_: None), \
             patch.object(fixture.record, "receipt_acceptable", side_effect=changed_handler), \
             patch.object(fixture.guard, "check", wraps=fixture.guard.check) as actual_check:
            with self.assertRaises(ProcessError) as caught:
                fixture.record.require_receipt(lane=LANE, output=OUTPUT, sha256=DIGEST,
                                               cancellation=fixture.guard)
            actual_check.assert_called_once_with()
            self.assertEqual(observed, [True])
            self.assertTrue(caught.exception.fatal)
            self.assertTrue(caught.exception.contained)
            self.assertFalse(caught.exception.cleanup_complete)
            self.assertFalse(fixture.record.verdict(cancellation=fixture.guard).failed)
            self.assert_cleanup(fixture, True)

    def test_resource_tokens_and_new_records_cannot_adopt_original_proof(self):
        first = self.fixture()
        self.publish_group_model(first)
        self.publish_terminal(first)
        self.finish(first)
        replacement = self.fixture()
        self.assertFalse(self.receipt(replacement))
        with self.assertRaises(ProcessError):
            replacement.record.dependents_settled_for(first.bindings["metadata"],
                owner=first.owners["metadata"], cancellation=replacement.guard)
        self.assertTrue(replacement.record.verdict(cancellation=replacement.guard).failed)
        replacement = self.fixture()
        self.publish_group_model(replacement)
        with self.assertRaises(ProcessError):
            self.publish_terminal(replacement, first.record._terminal)
        self.assert_cleanup(replacement, False)
        duplicate = dataclasses.replace(first.bindings["metadata"])
        with self.assertRaises(ProcessError):
            first.record.dependents_settled_for(duplicate, owner=first.owners["metadata"],
                                               cancellation=first.guard)

    def test_receipt_cannot_change_selected_lane_or_output_by_reusing_its_digest(self):
        for changed in ("lane", "output"):
            with self.subTest(changed=changed):
                fixture = self.fixture()
                self.publish_group_model(fixture)
                self.publish_terminal(fixture)
                self.finish(fixture)
                with self.assertRaises(ProcessError):
                    fixture.record.receipt_acceptable(
                        lane="ios_app_store_submit" if changed == "lane" else LANE,
                        output=Path("/copied/raw-store-receipt.json") if changed == "output" else OUTPUT,
                        sha256=DIGEST, cancellation=fixture.guard)

    def test_foreign_pid_thread_and_guard_are_rejected_before_parent_guard_callbacks(self):
        fixture = self.fixture()
        foreign = DefaultCancellation(ProcessCleanupError, "foreign inert guard")
        with self.assertRaises(ProcessError):
            fixture.record.verdict(cancellation=foreign)
        for target, value in (("getpid", fixture.record._pid + 1), ("current_thread", object())):
            module = lane_evidence.os if target == "getpid" else lane_evidence.threading
            with patch.object(fixture.guard, "_abort", side_effect=AssertionError("parent guard called")) as abort, \
                 patch.object(module, target, return_value=value):
                with self.assertRaises(ProcessError):
                    fixture.record.verdict(cancellation=fixture.guard)
                abort.assert_not_called()
        self.assertFalse(fixture.record._failed or fixture.guard.lifetime_ledger.fatal)

    def test_command_request_mismatch_and_wrong_role_deadline_cannot_publish_lane_proof(self):
        for mismatch in ("environment", "cwd", "capture", "timeout"):
            with self.subTest(mismatch=mismatch):
                fixture = self.fixture()
                with self.assertRaises(ProcessError):
                    if mismatch == "timeout":
                        fixture.record.command_evidence(cancellation=fixture.guard)._attempt(
                            fixture.guard, timeout=900, ordinary=True)
                    else:
                        self.bound_engine(fixture,
                            environ={**fixture.environ, "PRIVATE": "changed"} if mismatch == "environment" else None,
                            cwd=Path("/different") if mismatch == "cwd" else CWD,
                            capture=mismatch == "capture")
                self.assertTrue(self.finish(fixture).failed)
                self.assert_cleanup(fixture, False)

    def test_wrong_outcome_or_reverse_engine_binding_cannot_be_adopted(self):
        for changed in ("boolean-finality", "outcome-nonce", "engine-evidence", "slot"):
            with self.subTest(changed=changed):
                fixture = self.fixture()
                outcome = self.publish_group_model(fixture)
                if changed == "boolean-finality":
                    fixture.engine.slot._value = dataclasses.replace(outcome, original_finality=True)
                elif changed == "outcome-nonce":
                    fixture.engine.slot._value = dataclasses.replace(outcome, nonce=b"x" * 16)
                elif changed == "engine-evidence":
                    fixture.engine.evidence = object()
                else:
                    fixture.engine.slot = object()
                with self.assertRaises(ProcessError):
                    self.publish_terminal(fixture)
                self.assert_cleanup(fixture, False)
                self.assertFalse(self.receipt(fixture))

    def test_legacy_online_role_remains_exactly_nine_hundred_seconds(self):
        for timeout in (900, 3600):
            guard = DefaultCancellation(ProcessCleanupError, "inert online guard")
            evidence = command.CommandCallEvidence(guard)
            evidence._reserve_readback(object(), "ios", Path("/fictional/ios.json"), guard)
            argv = evidence.seal_readback(runner=RUNNER, cwd=CWD,
                environ={"MOBILE_RELEASE_PREFLIGHT_READBACK_PATH": "/fictional/ios.json"})
            self.assertEqual(argv[-1], "ios_online_preflight")
            if timeout == 900:
                evidence._attempt(guard, timeout=timeout, ordinary=True)
            else:
                with self.assertRaises(ProcessError):
                    evidence._attempt(guard, timeout=timeout, ordinary=True)
            self.assertIsNone(evidence._lane_reservation)


if __name__ == "__main__":
    unittest.main()
