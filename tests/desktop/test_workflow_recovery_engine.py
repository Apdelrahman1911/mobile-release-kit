"""Inert Desktop recovery dispatch/outcome contract tests.

These fakes acquire no descriptor, lock, cancellation handler or child. They
exercise the existing engine's dispatch and retained-fact mapping only, never
claiming native settlement, successful rollback or installed qualification.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager, nullcontext
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mobile_release import _desktop_edit_engine as engine
from mobile_release import _desktop_edit_protocol as wire
from mobile_release.github_workflow_recovery import recovery_outcome


SESSION = "0123456789abcdef0123456789abcdef"
REVISION = "a" * 32
TOKEN = "b" * 32
IDENTITY = {"device": "1", "inode": "2", "mode": 0o40755, "uid": 1000, "gid": 1001}
IDS = ("preflight", "candidate", "external-testing", "production-submit")


def request(seq, op, params):
    raw = json.dumps({"protocol": wire.WORKFLOW_PROTOCOL, "session": SESSION,
                      "seq": seq, "op": op, "params": params}).encode() + b"\n"
    return wire.parse_request(raw, sequence=seq, session=None if seq == 0 else SESSION,
                              protocol=wire.WORKFLOW_PROTOCOL)


def opening(recover=True):
    return request(0, "open", {"root": "/inert/registered-project", "registeredIdentity": IDENTITY,
                              **({"intent": "recover"} if recover else {})})


def preparing(recover=True):
    return request(1, "prepare", {"revision": REVISION, **({"intent": "recover"} if recover else
        {"draft": {}, "toolingRepository": "example/toolkit", "toolingSha": "c" * 40})})


def applying(recover=True):
    return request(2, "apply", {"planToken": TOKEN, **({"intent": "recover"} if recover else {})})


class _RoutingGuard:
    def __init__(self):
        self.handler_state = "RESTORED"
        self.lifetime_ledger = SimpleNamespace(fatal=False)

    def install(self):
        pass

    def activate(self):
        pass

    def check(self):
        pass

    def _install_edit_source(self, source):
        pass

    def deferred(self, **kwargs):
        return nullcontext()


class _RoutingInput:
    def __init__(self, requests):
        self.requests = iter(requests)
        self.closed = False

    def acquire(self):
        pass

    def idle(self):
        pass

    def request(self, sequence, session):
        value = next(self.requests)
        if value.seq != sequence or session not in (None, value.session):
            raise AssertionError("inert request sequence differs")
        return value

    def close(self):
        self.closed = True


class _RoutingLease:
    def __init__(self, guard):
        self.guard = guard
        self.closed = False
        self._workflow_recovery_effect = "not_started"
        self._workflow_recovery_journal = "unknown"
        self._workflow_recovery_reason = "none"

    @property
    def last_outcome(self):
        return recovery_outcome(self)

    def acquire(self):
        pass

    def close(self):
        self.closed = True


@contextmanager
def routing(requests, *, effect="committed"):
    guard = _RoutingGuard()
    control = _RoutingInput(requests)
    lease = _RoutingLease(guard)
    action = "committed_cleanup" if effect == "committed" else "rollback"
    view = {"schemaVersion": 1, "kind": "recovery", "state": "recoverable", "action": action,
            "transactionId": "d" * 32,
            "files": [{"id": item, "path": ".github/workflows/mobile-" + item + ".yml",
                       "action": "preserve" if effect == "committed" else "remove", "before": None,
                       "after": {"size": 1, "mode": 0o644, "sha256": "e" * 64}} for item in IDS],
            "privateCleanup": {"fileCount": 6, "directoryCount": 1, "scope": "inspected-workflow-journal-only"}}
    checkout = SimpleNamespace(revision=REVISION, view=view,
                               observed=[{"id": item, "state": "absent"} for item in IDS])
    plan = SimpleNamespace(revision=REVISION, token=TOKEN, view=view)
    frames = []

    def capture(_lease):
        lease._workflow_recovery_effect = effect
        lease._workflow_recovery_journal = "recovery_required"
        return checkout

    def apply(_lease, _plan):
        lease._workflow_recovery_effect = "committed" if effect == "committed" else "rolled_back"
        lease._workflow_recovery_journal = "clean"
        return recovery_outcome(lease)

    with ExitStack() as stack:
        stack.enter_context(patch.object(engine, "DefaultCancellation", return_value=guard))
        stack.enter_context(patch.object(engine, "EditInput", return_value=control))
        constructor = stack.enter_context(patch.object(engine, "InitRootLease", return_value=lease))
        blocking = stack.enter_context(patch.object(engine.os, "set_blocking"))
        # Only routing of the original cleanup action list is under test here.
        stack.enter_context(patch.object(engine, "_attempt_all",
            side_effect=lambda _guard, actions: [action() for action in actions]))
        calls = {}
        for name, options in {
            "capture_github_workflow_recovery": {"side_effect": capture},
            "prepare_github_workflow_recovery": {"return_value": plan},
            "apply_github_workflow_recovery": {"side_effect": apply},
            "discard_github_workflow_recovery": {},
            "capture_github_workflow_edit": {"return_value": checkout},
            "prepare_github_workflow_edit": {"return_value": plan},
            "apply_github_workflow_edit": {},
            "discard_github_workflow_edit": {},
        }.items():
            calls[name] = stack.enter_context(patch.object(engine, name, **options))
        child = engine._Engine(0.0, domain="github_workflows")
        child.write = lambda raw, **kwargs: frames.append(json.loads(raw))
        yield SimpleNamespace(child=child, lease=lease, guard=guard, control=control, checkout=checkout,
                              plan=plan, calls=calls, frames=frames, constructor=constructor, blocking=blocking)


class WorkflowRecoveryEngineRoutingTests(unittest.TestCase):
    def test_only_recovery_facade_receives_closed_prepare_and_one_apply(self):
        with routing([opening(), preparing(), applying()], effect="not_started") as r:
            r.child.run()
            r.constructor.assert_called_once_with(Path("/inert/registered-project"), cancellation=r.guard,
                profile=engine.TypedEditProfile.GITHUB_WORKFLOWS,
                registered_identity={"device": 1, "inode": 2, "mode": 0o40755, "uid": 1000, "gid": 1001},
                workflow_recovery=True)
            r.calls["capture_github_workflow_recovery"].assert_called_once_with(r.lease)
            r.calls["prepare_github_workflow_recovery"].assert_called_once_with(r.lease, r.checkout, REVISION)
            r.calls["apply_github_workflow_recovery"].assert_called_once_with(r.lease, r.plan)
            self.assertEqual([row["kind"] for row in r.frames], ["opened", "prepared"])
            for frame in r.frames:
                self.assertIn("recovery", frame["result"])
                self.assertNotIn("view", frame["result"])
                self.assertNotIn("observed", frame["result"])
            self.assertEqual(r.child.published_token, TOKEN)
            self.assertEqual((r.child.outcome.effect, r.child.outcome.journal), ("rolled_back", "clean"))
            r.child.cleanup()
            r.calls["discard_github_workflow_recovery"].assert_called_once_with(r.plan)
            for name, call in r.calls.items():
                if name.endswith("_edit"):
                    call.assert_not_called()
            r.blocking.assert_called_once_with(1, False)  # Mock; descriptor 1 was never changed.

    def test_prepare_and_apply_cannot_exchange_intent_on_an_original_session(self):
        cases = [([opening(), preparing(False)], False, 0),
                 ([opening(False), preparing()], False, 0),
                 ([opening(), preparing(), applying(False)], True, 0),
                 ([opening(False), preparing(False), applying()], False, 1)]
        for requests, prepared_recovery, prepared_edit in cases:
            with self.subTest(requests=[(r.seq, r.params.get("intent")) for r in requests]), routing(requests) as r:
                with self.assertRaises(wire.ProtocolError):
                    r.child.run()
                self.assertEqual(r.calls["prepare_github_workflow_recovery"].call_count, int(prepared_recovery))
                self.assertEqual(r.calls["prepare_github_workflow_edit"].call_count, prepared_edit)
                r.calls["apply_github_workflow_recovery"].assert_not_called()
                r.calls["apply_github_workflow_edit"].assert_not_called()

    def test_discard_before_or_after_prepare_retains_historical_commit_and_pending_journal(self):
        for prepared in (False, True):
            requests = [opening(), preparing(), request(2, "discard", {})] if prepared else [
                opening(), request(1, "discard", {})]
            with self.subTest(prepared=prepared), routing(requests) as r:
                r.child.run()
                self.assertEqual((r.child.outcome.effect, r.child.outcome.journal, r.child.outcome.reason),
                                 ("committed", "recovery_required", "pending_state"))
                r.child.cleanup()
                r.child.terminal()
                terminal = r.frames[-1]["result"]
                self.assertEqual((terminal["effect"], terminal["journal"], terminal["reason"]),
                                 ("committed", "recovery_required", "pending_state"))
                self.assertEqual(terminal["planToken"], TOKEN if prepared else None)
                r.calls["apply_github_workflow_recovery"].assert_not_called()

    def test_display_pending_state_never_masks_first_actual_protocol_or_close_failure(self):
        with routing([opening(), request(1, "discard", {})]) as r:
            r.child.run()
            first = wire.ProtocolError("inert first failure")
            r.child._remember(first)
            r.child._remember(OSError("inert later close failure"))
            self.assertIs(r.child.first, first)
            self.assertEqual((r.child.outcome.effect, r.child.outcome.journal, r.child.outcome.reason),
                             ("committed", "recovery_required", "invalid_params"))
            r.guard.lifetime_ledger.fatal = True
            r.child._remember(OSError("inert later custody failure"))
            self.assertEqual((r.child.outcome.effect, r.child.outcome.resources, r.child.outcome.reason),
                             ("committed", "unknown", "invalid_params"))

    def test_terminal_requires_each_original_outer_close_fact_and_keeps_commit(self):
        # Synthetic facts deliberately fail one condition at a time. This is
        # coverage of the production predicate, not a real close receipt.
        for missing in ("input", "lease", "handler", "ledger"):
            with self.subTest(missing=missing), routing([opening(), request(1, "discard", {})]) as r:
                r.child.run()
                r.child.cleanup()
                if missing == "input":
                    r.control.closed = False
                elif missing == "lease":
                    r.lease.closed = False
                elif missing == "handler":
                    r.guard.handler_state = "UNKNOWN"
                else:
                    r.guard.lifetime_ledger.fatal = True
                r.child._remember(OSError("inert original close failure"))
                r.child.terminal()
                terminal = r.frames[-1]["result"]
                self.assertEqual((terminal["effect"], terminal["journal"], terminal["resources"], terminal["reason"]),
                                 ("committed", "recovery_required", "unknown", "filesystem_error"))


if __name__ == "__main__":
    unittest.main()
