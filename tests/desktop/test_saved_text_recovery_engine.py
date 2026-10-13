"""Closed saved-text protocol/routing DATA, not native lifetime evidence.

The routing stand-ins below are deliberately inert. The separate restart test
uses real EditInput, cancellation, leases, IO and the actual joined process
owner; these stand-ins never qualify that route or native finality.
"""
from __future__ import annotations

import copy
import json
import unittest
from contextlib import ExitStack, contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release import _desktop_edit_engine as engine
from mobile_release import _desktop_edit_protocol as wire
from mobile_release import config_edit as shared
from mobile_release import init_transaction as tx
from mobile_release import metadata_text as text
from mobile_release import version_text as version
from mobile_release.saved_text_recovery import recovery_outcome

SESSION, REVISION, TOKEN = "1" * 32, "2" * 32, "3" * 32
IDENTITY = {"device": "1", "inode": "2", "mode": 0o40755, "uid": 1000, "gid": 1001}
DOMAINS = {"metadata_text": (wire.METADATA_PROTOCOL, tx.TypedEditProfile.METADATA_TEXT),
           "release_version": (wire.VERSION_PROTOCOL, tx.TypedEditProfile.RELEASE_VERSION)}
BASELINE = text.baseline(b"{}", text.REQUIRED_LOCALE_TEXT["android"], (None, None, None))
VERSION_BASELINE = version.baseline(b"{}", b"VERSION_NAME=1.2\nBUILD_NUMBER=7\n")


def request(domain, sequence, op, params):
    raw = json.dumps({"protocol": DOMAINS[domain][0], "session": SESSION, "seq": sequence,
                      "op": op, "params": params}).encode() + b"\n"
    return wire.parse_request(raw, sequence=sequence, session=None if sequence == 0 else SESSION,
                              protocol=DOMAINS[domain][0])


def opening(domain, *, recover=True):
    params = {"root": "/inert/registered-project", "registeredIdentity": IDENTITY}
    if recover: params["intent"] = "recover"
    elif domain == "metadata_text": params.update(platform="android", locale="en-US")
    return request(domain, 0, "open", params)


def preparing(domain, *, recover=True):
    params = {"revision": REVISION}
    if recover: params["intent"] = "recover"
    elif domain == "metadata_text": params.update(expectedBaseline=BASELINE,
        fields=[{"id": identity, "text": "Public fixture copy"} for identity in text.REQUIRED_LOCALE_TEXT["android"]])
    else: params.update(expectedBaseline=VERSION_BASELINE, intent="edit", values={"name": "2.0", "build": "8"})
    return request(domain, 1, "prepare", params)


def applying(domain, *, recover=True):
    return request(domain, 2, "apply", {"planToken": TOKEN, **({"intent": "recover"} if recover else {})})


def view(domain, action="committed_cleanup"):
    selected = ({"platform": "android", "locale": "en-US", "metadataRoot": "public/store"} if domain == "metadata_text" else
                {"source": "public/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER", "iosEnabled": True})
    paths = (["public/store/android/en-US/" + name for name in text.REQUIRED_LOCALE_TEXT["android"]]
             if domain == "metadata_text" else ["public/version.properties"])
    before = {"byteLength": 1, "sha256": "a" * 64, "mode": 0o640}
    return {"schemaVersion": 1, "kind": "saved-text-recovery", "domain": domain, "state": "recoverable", "reason": "none",
        "action": action, "transactionId": "d" * 32, "selection": selected,
        "files": [{"path": path, "effect": "keep_committed" if action == "committed_cleanup" else
                   "restore_original" if action == "rollback" else "preserve", "before": before, "after": before} for path in paths],
        "privateCleanup": {"fileCount": 4 + len(paths), "directoryCount": 0, "scope": "inspected-owned-journal-only"}}


class _Guard:
    def __init__(self):
        self.handler_state = "RESTORED"
        self.lifetime_ledger = SimpleNamespace(fatal=False)
    def install(self): pass
    def activate(self): pass
    def check(self): pass
    def _install_edit_source(self, source): pass
    def deferred(self, **kwargs): return nullcontext()


class _Input:
    def __init__(self, requests):
        self.requests, self.closed = iter(requests), False
    def acquire(self): pass
    def idle(self): pass
    def request(self, sequence, session):
        value = next(self.requests)
        assert value.seq == sequence and session in {None, value.session}
        return value
    def close(self): self.closed = True


class _Lease:
    def __init__(self, guard):
        self.guard, self.closed = guard, False
        self._saved_text_recovery_effect = "not_started"
        self._saved_text_recovery_journal = "not_created"
        self._saved_text_recovery_reason = "none"
    @property
    def last_outcome(self): return recovery_outcome(self)
    def acquire(self): pass
    def close(self): self.closed = True


@contextmanager
def routing(domain, requests, *, action="committed_cleanup"):
    guard, control = _Guard(), _Input(requests)
    lease = _Lease(guard)
    checkout = SimpleNamespace(revision=REVISION, view=view(domain, action), baseline=BASELINE if domain == "metadata_text" else VERSION_BASELINE,
        metadata_root="public/store", values={"name": "1.2", "build": "7"}, selection=SimpleNamespace(
            source="public/version.properties", name_key="VERSION_NAME", build_key="BUILD_NUMBER", ios_enabled=True))
    plan = SimpleNamespace(revision=REVISION, token=TOKEN, view=checkout.view)
    frames = []
    def capture(actual):
        assert actual is lease
        lease._saved_text_recovery_effect = {"committed_cleanup": "committed", "rolled_back_cleanup": "rolled_back"}.get(action, "not_started")
        lease._saved_text_recovery_journal = "recovery_required"
        return checkout
    def apply(actual, planned):
        assert actual is lease and planned is plan
        lease._saved_text_recovery_effect = {"committed_cleanup": "committed", "preparing_cleanup": "not_started"}.get(action, "rolled_back")
        lease._saved_text_recovery_journal = "clean"
        o = recovery_outcome(lease)
        return shared.CoreEditOutcome(o.effect, o.journal, o.resources, o.reason)
    with ExitStack() as stack:
        stack.enter_context(patch.object(engine, "DefaultCancellation", return_value=guard))
        stack.enter_context(patch.object(engine, "EditInput", return_value=control))
        constructor = stack.enter_context(patch.object(engine, "InitRootLease", return_value=lease))
        blocking = stack.enter_context(patch.object(engine.os, "set_blocking"))
        stack.enter_context(patch.object(engine, "_attempt_all", new=lambda _guard, actions: [fn() for fn in actions]))
        calls = {}
        for name, options in {
            "capture_saved_text_recovery": {"side_effect": capture},
            "prepare_saved_text_recovery": {"return_value": plan},
            "apply_saved_text_recovery": {"side_effect": apply},
            "discard_saved_text_recovery": {},
            "capture_metadata_text_edit": {"return_value": checkout},
            "prepare_metadata_text_edit": {"return_value": plan},
            "apply_metadata_text_edit": {}, "discard_metadata_text_edit": {},
            "capture_release_version_edit": {"return_value": checkout},
            "prepare_release_version_edit": {"return_value": plan},
            "apply_release_version_edit": {}, "discard_release_version_edit": {},
        }.items(): calls[name] = stack.enter_context(patch.object(engine, name, **options))
        child = engine._Engine(0.0, domain=domain)
        child.write = lambda raw, **kwargs: frames.append(json.loads(raw))
        yield SimpleNamespace(child=child, lease=lease, guard=guard, input=control, checkout=checkout, plan=plan,
                              calls=calls, constructor=constructor, blocking=blocking, frames=frames)


class SavedTextRecoveryEngineDataTests(unittest.TestCase):
    def test_exact_two_domain_intent_shapes_and_response_exclusion_keep_normal_contracts(self):
        for domain in DOMAINS:
            for original in (opening(domain), preparing(domain), applying(domain)):
                self.assertEqual(original.params["intent"], "recover")
                for key, value in (("force", True), ("source", "other/file"), ("action", "rollback"), ("files", []),
                                   ("platform", "android"), ("expectedBaseline", {})):
                    changed = {**original.params, key: value}
                    with self.subTest(domain=domain, sequence=original.seq, key=key), self.assertRaises(wire.ProtocolError):
                        request(domain, original.seq, original.op, changed)
                for value in (None, True, ["recover"], {"intent": "recover"}, "Recover", "edit"):
                    with self.subTest(domain=domain, sequence=original.seq, value=value), self.assertRaises(wire.ProtocolError):
                        request(domain, original.seq, original.op, {**original.params, "intent": value})
            opened = {"revision": REVISION, "recovery": view(domain), "scopeResources": "settled"}
            self.assertEqual(json.loads(wire.response(opening(domain), "opened", opened))["result"], opened)
            for changed in ({**opened, "baseline": {}}, {**opened, "scopeResources": "unknown"},
                            {**opened, "recovery": view("release_version" if domain == "metadata_text" else "metadata_text")}):
                with self.assertRaises(wire.ProtocolError): wire.response(opening(domain), "opened", changed)
            with self.assertRaises(wire.ProtocolError): wire.response(opening(domain, recover=False), "opened", opened)
            over = copy.deepcopy(opened); over["recovery"]["extra"] = "x" * (16 * 1024)
            with self.assertRaises(wire.ProtocolError): wire.response(opening(domain), "opened", over)
        # The original normal result model still rejects pending-without-error.
        with self.assertRaises(ValueError): shared.CoreEditOutcome("committed", "recovery_required", "settled", "none")

    def test_original_engine_routes_only_captured_recovery_and_exact_prepared_action(self):
        effects = {"rollback": "rolled_back", "committed_cleanup": "committed",
                   "rolled_back_cleanup": "rolled_back", "preparing_cleanup": "not_started"}
        for domain in DOMAINS:
            for action, effect in effects.items():
                with self.subTest(domain=domain, action=action), routing(domain, [opening(domain), preparing(domain), applying(domain)], action=action) as r:
                    r.child.run(); r.child.cleanup(); r.child.terminal()
                    r.constructor.assert_called_once_with(Path("/inert/registered-project"), cancellation=r.guard,
                        profile=DOMAINS[domain][1], registered_identity={"device": 1, "inode": 2, "mode": 0o40755, "uid": 1000, "gid": 1001},
                        saved_text_recovery=True)
                    r.calls["capture_saved_text_recovery"].assert_called_once_with(r.lease)
                    r.calls["prepare_saved_text_recovery"].assert_called_once_with(r.lease, r.checkout, REVISION)
                    r.calls["apply_saved_text_recovery"].assert_called_once_with(r.lease, r.plan)
                    r.calls["discard_saved_text_recovery"].assert_called_once_with(r.plan)
                    self.assertEqual([f["kind"] for f in r.frames], ["opened", "prepared", "terminal"])
                    self.assertEqual(r.frames[0]["result"]["recovery"], r.frames[1]["result"]["recovery"])
                    self.assertNotIn("baseline", r.frames[0]["result"])
                    self.assertNotIn("view", r.frames[1]["result"])
                    self.assertEqual(r.frames[2]["result"], {"kind": "outcome", "planToken": TOKEN, "effect": effect,
                        "journal": "clean", "resources": "settled", "reason": "none"})
                    for name, call in r.calls.items():
                        if name.endswith("_edit"): call.assert_not_called()
                    r.blocking.assert_called_once_with(1, False)

    def test_mixed_normal_recovery_requests_and_cross_tokens_stop_before_apply(self):
        for domain in DOMAINS:
            for requests, prepared_recovery, prepared_normal in (
                ([opening(domain), preparing(domain, recover=False)], 0, 0),
                ([opening(domain, recover=False), preparing(domain)], 0, 0),
                ([opening(domain), preparing(domain), applying(domain, recover=False)], 1, 0),
                ([opening(domain, recover=False), preparing(domain, recover=False), applying(domain)], 0, 1),
                ([opening(domain), preparing(domain), request(domain, 2, "apply", {"planToken": "9" * 32, "intent": "recover"})], 1, 0),
            ):
                with self.subTest(domain=domain, operations=[r.params for r in requests]), routing(domain, requests) as r:
                    with self.assertRaises(wire.ProtocolError): r.child.run()
                    self.assertEqual(r.calls["prepare_saved_text_recovery"].call_count, prepared_recovery)
                    self.assertEqual(r.calls["prepare_" + domain + "_edit"].call_count, prepared_normal)
                    r.calls["apply_saved_text_recovery"].assert_not_called()
                    r.calls["apply_" + domain + "_edit"].assert_not_called()
                    r.child.cleanup()

    def test_discard_inspection_cannot_hide_actual_errors_or_promote_unknown_close(self):
        for domain in DOMAINS:
            for prepared in (False, True):
                requests = [opening(domain), preparing(domain), request(domain, 2, "discard", {})] if prepared else [
                    opening(domain), request(domain, 1, "discard", {})]
                with self.subTest(domain=domain, prepared=prepared), routing(domain, requests) as r:
                    r.child.run()
                    self.assertIs(type(r.child.outcome), tx.InitApplyOutcome)
                    self.assertEqual(r.child.outcome, tx.InitApplyOutcome("committed", "recovery_required", "settled", "none"))
                    r.child.cleanup(); r.child.terminal()
                    self.assertEqual(r.frames[-1]["result"], {"kind": "outcome", "planToken": TOKEN if prepared else None,
                        "effect": "committed", "journal": "recovery_required", "resources": "settled", "reason": "none"})
                    r.calls["apply_saved_text_recovery"].assert_not_called()
            for missing in ("input", "lease", "handler", "ledger", "first_error"):
                with self.subTest(domain=domain, missing=missing), routing(domain, [opening(domain), request(domain, 1, "discard", {})]) as r:
                    r.child.run(); r.child.cleanup()
                    if missing == "input": r.input.closed = False
                    elif missing == "lease": r.lease.closed = False
                    elif missing == "handler": r.guard.handler_state = "UNKNOWN"
                    elif missing == "ledger": r.guard.lifetime_ledger.fatal = True
                    else:
                        first = wire.ProtocolError("synthetic first protocol failure")
                        r.child._remember(first); r.child._remember(OSError("synthetic later close failure"))
                        self.assertIs(r.child.first, first)
                    r.child.terminal()
                    terminal = r.frames[-1]["result"]
                    self.assertEqual((terminal["effect"], terminal["journal"]), ("committed", "recovery_required"))
                    self.assertEqual(terminal["reason"], "invalid_params" if missing == "first_error" else "custody_unknown")
                    self.assertEqual(terminal["resources"], "settled" if missing == "first_error" else "unknown")
                    r.calls["apply_saved_text_recovery"].assert_not_called()


if __name__ == "__main__":
    unittest.main()
