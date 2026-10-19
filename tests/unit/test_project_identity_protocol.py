"""Closed identity DATA fixtures; no child, native receipt or Store authority."""
from __future__ import annotations

import copy
import json
import unittest

from mobile_release import _desktop_edit_protocol as shared
from mobile_release import _desktop_identity_protocol as wire
from mobile_release import project_identity as core
from tests.unit.test_project_identity import ANDROID, IOS, OLD, NEW, android, ios

SESSION, TOKEN = "1" * 32, "3" * 32
REGISTERED = {"device": "1", "inode": "2", "mode": 0o40755, "uid": 1000, "gid": 1001}


def raw(sequence, op, params):
    return json.dumps({"protocol": wire.PROTOCOL, "session": SESSION, "seq": sequence,
                       "op": op, "params": params}, separators=(",", ":")).encode() + b"\n"


def request(sequence, op, params):
    return shared.parse_request(raw(sequence, op, params), sequence=sequence,
        session=None if sequence == 0 else SESSION, protocol=wire.PROTOCOL)


def opening(selection=ANDROID, *, recover=False):
    return {"root": "/synthetic/project", "registeredIdentity": REGISTERED, "intent": "recover" if recover else "edit",
            **({} if recover else {"selection": selection.as_dict()})}


def idle_recovery():
    return {"schemaVersion": 1, "kind": "project-identity-recovery", "state": "idle", "reason": "none",
            "action": None, "transactionId": None, "desiredIdentity": None, "files": [],
            "help": "There is no interrupted app identity change to recover.",
            "privateCleanup": {"fileCount": 0, "directoryCount": 0, "scope": "inspected-owned-journal-only"},
            "retainVersionReservations": True}


class IdentityProtocolTests(unittest.TestCase):
    def test_actual_core_android_ios_analysis_and_preview_views_have_exact_closed_envelopes(self):
        for selection, sources in ((ANDROID, android()), (IOS, ios())):
            with self.subTest(platform=selection.platform):
                analysis = core.analyze_project_identity(sources, selection)
                prepared = core.prepare_project_identity(analysis, NEW, expected_revision=analysis.revision, intent="new-application")
                op = request(0, "open", opening(selection))
                result = {"intent": "edit", "revision": analysis.revision, "view": analysis.view, "scopeResources": "settled"}
                self.assertEqual(json.loads(shared.response(op, "opened", result))["result"], result)
                p = request(1, "prepare", {"revision": analysis.revision, "intent": "edit", "desiredIdentity": NEW, "identityIntent": "new-application"})
                result.update(planToken=TOKEN, view=prepared.view)
                self.assertEqual(json.loads(shared.response(p, "prepared", result))["result"], result)
                self.assertEqual(result["view"]["warnings"], [wire.NEW_WARNING])

    def test_root_facts_and_selection_cannot_be_broadened_by_a_private_request(self):
        self.assertEqual(request(0, "open", opening()).params["registeredIdentity"], REGISTERED)
        cases = []
        for key in REGISTERED:
            missing = copy.deepcopy(opening()); del missing["registeredIdentity"][key]; cases.append(missing)
        for key, value in (("device", 1), ("inode", "0"), ("mode", 0o100644), ("uid", True), ("gid", -1)):
            bad = copy.deepcopy(opening()); bad["registeredIdentity"][key] = value; cases.append(bad)
        for value in ("published", "absent", None, [], True):
            bad = copy.deepcopy(opening()); bad["selection"]["continuity"] = value; cases.append(bad)
        for key, value in (("target", ":app/../other"), ("project", "other.xcodeproj"), ("namespace", OLD), ("platform", "flutter")):
            bad = copy.deepcopy(opening()); bad["selection"][key] = value; cases.append(bad)
        for bad in cases:
            with self.subTest(bad=bad), self.assertRaises(shared.ProtocolError): request(0, "open", bad)

    def test_finite_sequence_original_session_duplicate_keys_and_scalar_bounds(self):
        good = raw(0, "open", opening())
        for bad in (good.replace(b'"seq":0', b'"seq":0,"seq":0'), good + b"\n",
                    good.replace(b'"seq":0', b'"seq":false'), good[:-1], good.replace(b'"edit"', b'NaN', 1),
                    good.replace(SESSION.encode(), b"9" * 32), b"{" + b" " * wire.REQUEST_LIMIT + b"}\n"):
            with self.subTest(raw=bad[:120]), self.assertRaises(shared.ProtocolError):
                shared.parse_request(bad, sequence=0, session=SESSION, protocol=wire.PROTOCOL)
        for sequence in (-1, 3, True):
            with self.assertRaises(shared.ProtocolError): wire.parse_request(good, sequence=sequence, session=None)
        for protocol in (shared.PROTOCOL, shared.VERSION_PROTOCOL, shared.INITIALIZATION_PROTOCOL):
            with self.assertRaises(shared.ProtocolError): shared.parse_request(good, sequence=0, session=None, protocol=protocol)

    def test_edit_recovery_modes_are_disjoint_without_payload_path_or_rollback_grants(self):
        for seq, op, params in ((0, "open", opening(recover=True)),
                (1, "prepare", {"revision": "2" * 32, "intent": "recover"}),
                (2, "apply", {"planToken": TOKEN, "intent": "recover"})):
            self.assertEqual(request(seq, op, params).params, params)
            for key, value in (("desiredIdentity", NEW), ("selection", ANDROID.as_dict()), ("files", []),
                               ("force", True), ("action", "rollback"), ("identityIntent", "new-application")):
                with self.subTest(seq=seq, key=key), self.assertRaises(shared.ProtocolError): request(seq, op, {**params, key: value})
        for seq in (1, 2): self.assertEqual(request(seq, "discard", {}).op, "discard")
        with self.assertRaises(shared.ProtocolError): request(0, "discard", {})
        with self.assertRaises(shared.ProtocolError): request(1, "prepare", {"revision": "2" * 32, "intent": "edit"})

    def test_new_identity_warning_invalidations_and_exact_roles_cannot_disappear(self):
        observed = core.analyze_project_identity(android(), ANDROID)
        preview = core.prepare_project_identity(observed, NEW, expected_revision=observed.revision, intent="new-application").view
        wire.preview_view(preview)
        for key, value in (("warnings", []), ("invalidations", []), ("retainVersionReservations", False),
                ("buildVerificationRequired", False), ("intent", "preserve"), ("state", "unchanged")):
            with self.subTest(key=key), self.assertRaises(shared.ProtocolError): wire.preview_view({**preview, key: value})
        for key, value in (("path", ".private-fixture/raw.txt"), ("role", "namespace"), ("beforeId", NEW)):
            bad = copy.deepcopy(preview); bad["changes"][0][key] = value
            with self.assertRaises(shared.ProtocolError): wire.preview_view(bad)
        bad = copy.deepcopy(preview); bad["selection"]["continuity"] = "existing"
        with self.assertRaises(shared.ProtocolError): wire.preview_view(bad)

    def test_fixed_diagnostic_and_no_exception_source_or_unknown_success_reflection(self):
        diagnostic = core.Diagnostic("existing-application", core.CONFIG_PATH, 1, 1).as_dict()
        result = {"intent": "edit", "planToken": None, "effect": "not_started", "journal": "not_created",
                  "resources": "settled", "reason": "invalid_params", "diagnostic": diagnostic}
        opened = request(0, "open", opening())
        self.assertEqual(json.loads(shared.response(opened, "terminal", result))["result"], result)
        for key, value in (("help", "Synthetic raw provider/source exception must never surface"), ("code", "dynamic-user-exception")):
            bad = copy.deepcopy(result); bad["diagnostic"][key] = value
            with self.assertRaises(shared.ProtocolError): shared.response(opened, "terminal", bad)
        for key, value in (("intent", "recover"), ("planToken", TOKEN), ("reason", "none"), ("exception", "not allowed")):
            with self.assertRaises(shared.ProtocolError): shared.response(opened, "terminal", {**result, key: value})

    def test_recovery_view_never_grants_path_token_or_unknown_action_authority(self):
        view = idle_recovery(); wire.recovery_view(view)
        opened = request(0, "open", opening(recover=True))
        result = {"intent": "recover", "revision": "2" * 32, "view": view, "scopeResources": "settled"}
        self.assertEqual(json.loads(shared.response(opened, "opened", result))["result"], result)
        for key, value in (("revision", "2" * 32), ("planToken", TOKEN), ("root", "/synthetic/project"), ("action", "rollback")):
            with self.assertRaises(shared.ProtocolError): wire.recovery_view({**view, key: value})
        with self.assertRaises(shared.ProtocolError): shared.response(opened, "prepared", {**result, "planToken": TOKEN})


if __name__ == "__main__": unittest.main()
