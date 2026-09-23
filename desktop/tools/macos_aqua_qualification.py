#!/usr/bin/env python3
"""Four fixed, source-bound installed Mac Aqua cases; never a general runner.

Importing this module loads only stdlib DATA/parsers. The native main alone
admits the hosted user/source, prepares exclusive synthetic fixtures, and loads
the unchanged source run_owned. No Store, release, alternate command or cleanup
controller is provided. Unknown invocation finality preserves the fixtures.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
from importlib.machinery import ModuleSpec
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from types import FunctionType, ModuleType

CASES = ("first-save", "noop-stale", "picker-loss", "save-loss")
EXECUTABLE = "/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app/Contents/MacOS/mobile-release-kit-desktop"
REPOSITORY = "Apdelrahman1911/mobile-release-kit"
REF = "refs/heads/verify/desktop-macos-aqua"
WORKFLOW = REPOSITORY + "/.github/workflows/desktop-macos-aqua.yml@" + REF
MARKER = b"MRK_MACOS_AQUA_RESULT="
OUTPUT_LIMIT = 2 * 1024 * 1024
JSON_LIMIT = 16383
FAILURE_CONTEXT_LIMIT = 4096
TRACEBACK_LIMIT = 64
SCOPE = "programmatic genuine controls; no Store, release, distribution or physical-device evidence"
FAILURE_STEPS = frozenset((
    "Bootstrap Environment ReadEnvironment Dashboard ChooseCancel CancelProject CancelSettled ReadCancelled "
    "ChooseProject SetProject OpenProject ProjectSettled Snapshot Settings Suggest Suggestion Adopt Draft "
    "Validate Validation Preview Previewed RequirementsPage LoadRequirements Requirements GitHubPage "
    "GitHubRepository GitHubSha GitHubPropose GitHubProposal ReturnSettings KeepReviewing KeptReview "
    "ReadbackPage Refresh Readback SavedSettings ChangeDraft ChangedDraft MutateIgnore CloseCancel "
    "QuitCancel QuitCancelled RetainedReview Close Quit Exit PickerPending Reload Lost"
).split()) | frozenset(f"{name}({number})" for name in (
    "Prepare", "Review", "OpenConfirmation", "Confirmation", "Acknowledge", "Acknowledged", "Apply", "Applied") for number in (0, 1))
FAILURE_REASONS = frozenset((
    "observer-invariant observer-deadline observer-record-unavailable observer-data-check "
    "dom-dispatch-refused dom-pending-custody dom-callback-size dom-callback-json "
    "dom-callback-object dom-callback-state picker-unexpected-result "
    "native-wrong-thread native-step native-pending-custody native-original-id native-kind native-not-started "
    "native-ineligible native-action-attempted native-action-returned native-callback-returned "
    "native-response-present native-selection-present native-close-attempted native-closed "
    "native-attachment-lost native-preaction-history native-dismissed native-duplicate-action "
    "native-ax-not-trusted native-ax-trust native-default-binding native-default-input native-default-custody native-default-deadline "
    "cancel-unexpected-project cancel-duplicate-result adapter-wrong-thread adapter-book-borrow "
    "adapter-original-call adapter-original-owner adapter-original-binding adapter-missing-facts "
    "adapter-missing-panel adapter-ineligible adapter-native-observation adapter-native-action "
    "asset_invalid_request asset_closed asset_unqualified asset_unsupported_platform "
    "asset_unsupported_filesystem asset_unsupported_format asset_busy asset_source_refused "
    "asset_source_changed asset_material_limit asset_parser_limit asset_project_overlap "
    "asset_exclusion_unconfirmed asset_capacity assessment_context_stale asset_user_cancelled "
    "asset_review_expired asset_deadline asset_document_lost asset_shutdown asset_cleanup_unknown"
).split())
NATIVE_STEPS = frozenset("CancelProject SetProject OpenProject QuitCancel Quit PickerPending".split())
# Closed same-origin action DATA, not a panel query or an action/finality permit.
NATIVE_ACTION_STEPS = {
    "CancelProject": ("project-cancel", "project", (1,), 1),
    "SetProject": ("project-directory", "project", (1, 2), 2),
    "OpenProject": ("project-open", "project", (1, 2), 4),
    "QuitCancel": ("quit-cancel", "quit", (3,), 8),
    "Quit": ("quit-confirm", "quit", (2, 4), 16),
}
# site: (original native-return error, permitted action mask, can catch ObjC).
# None denotes an exception-only site. Keep aligned with the native decoder.
NATIVE_ACTION_SITES = {
    "main-thread": ("invalid-input", 31, False), "state-pointer": ("invalid-input", 31, False),
    "action-code": ("invalid-input", 31, False), "directory-argument": ("invalid-input", 31, False),
    "original-unknown": ("io", 31, False), "not-started": ("permission-denied", 31, False),
    "window-absent": ("permission-denied", 31, False), "parent-absent": ("permission-denied", 31, False),
    "completion-absent": ("permission-denied", 31, False), "responded": ("permission-denied", 31, False),
    "callback-active": ("permission-denied", 31, False), "close-attempted": ("permission-denied", 31, False),
    "closed": ("permission-denied", 31, False), "action-attempted": ("permission-denied", 31, False),
    "panel-kind": ("permission-denied", 31, False), "attachment": ("would-block", 31, True),
    "directory-already-bound": ("permission-denied", 2, False), "directory-path": ("invalid-input", 2, False),
    "directory-text": ("invalid-input", 2, True), "directory-url": ("invalid-input", 2, True),
    "directory-set": ("none", 2, True), "directory-unbound": ("permission-denied", 4, False),
    "directory-not-returned": ("permission-denied", 4, False), "directory-ready": ("would-block", 4, True),
    "alert-buttons": (None, 24, True), "alert-absent": ("permission-denied", 24, False),
    "button-count": ("permission-denied", 24, True), "button-index": (None, 24, True),
    "button-window": ("permission-denied", 24, True), "button-enabled": ("would-block", 24, True),
    "button-hidden": ("would-block", 24, True), "project-cancel": ("none", 1, True),
    "project-open": ("none", 4, True), "quit-cancel": ("none", 8, True), "quit-confirm": ("none", 16, True),
}
ACCESSIBILITY_SITES = frozenset("binding entry initial-original-proof confirm-eligibility original-proof confirm-recheck admission confirm".split())
ACCESSIBILITY_ERRORS = frozenset((
    "none wrong-thread invalid-input ineligible unsupported ambiguous malformed limit deadline custody "
    "not-triggered changed objc-exception cleanup-unknown"
).split())
ACCESSIBILITY_BINDING_CLASSES = frozenset(("nil", "match", "different", "type-invalid"))
ACCESSIBILITY_BINDING_SITES = frozenset((
    "objects", "parent-tag", "parent-set", "parent-get", "complete",
))
ACCESSIBILITY_PANEL_CLASSES = frozenset((
    "nil", "type-invalid", "empty", "byte-limit", "nul", "encoding-invalid", "valid", "match", "different",
))
ACCESSIBILITY_PROOF_CHECKS = (
    "eligible", "attached", "directory", "parentIdentifier", "panelIdentifier", "parentSingleton",
    "noNestedSheet", "nativeChild", "nativeParent", "nativeRole", "stableIdentifier", "finalEligibility",
)
ACCESSIBILITY_PROOF_SITES = frozenset((
    "objects attachment directory parent-identifier panel-identifier parent-sheets panel-sheets "
    "panel-attached-sheet native-children native-parent native-role stable-identifier final-eligibility complete"
).split())
ACCESSIBILITY_CONFIRM_CHECKS = ("eligible", "openPanel", "capability", "confirmAllowed", "stableOriginal")
ACCESSIBILITY_CONFIRM_FLAGS = ("attempted",)
ACCESSIBILITY_CONFIRM_SITES = frozenset("objects open-panel capability confirm-allowed stable-original complete".split())
SOURCE = (b'plugins { id("com.android.application") }\n'
          b'android { defaultConfig { applicationId = "org.example.mrk.observed" } }\n')
VERSION = b"VERSION_NAME=1.2.3\nBUILD_NUMBER=7\n"
KEEP = b"MRK_MACOS_AQUA_KEEP\n"
IGNORE_PREFIX = b"# MRK Mac Aqua user ignore\nuser-output/\n"
IGNORE_RULES = (b".mobile-release/\n.mobile-release-init-prepare/\n.mobile-release-init/\n"
                b".mobile-release-init-cleanup/\n.mobile-release-metadata-text-prepare/\n"
                b".mobile-release-metadata-text/\n.mobile-release-metadata-text-cleanup/\n")
STALE = b"# MRK Mac Aqua stale base\n"
# Literal public fixture DATA, not another core configuration serializer.
CONFIG = b'''{
  "android": {
    "applicationId": "org.example.mrk.observed",
    "enabled": true,
    "identityStatus": "unverified"
  },
  "ios": {
    "enabled": false
  },
  "metadata": {
    "androidLocales": [
      "en-US"
    ],
    "iosLocales": [],
    "root": "release/store"
  },
  "projectChecks": {
    "androidArtifact": [],
    "iosArtifact": [],
    "preflight": []
  },
  "schemaVersion": 1,
  "services": {
    "androidFirebase": "disabled",
    "iosFirebase": "disabled"
  },
  "source": {
    "candidateBranch": "main",
    "productionBranch": "main"
  },
  "version": {
    "buildKey": "BUILD_NUMBER",
    "nameKey": "VERSION_NAME",
    "source": "version.properties"
  }
}
'''
OWNER_PINS = {
    "owned_process.py": "430a596c5069b7acf248334d1f60fdd12ad8212cf9c2e9dfef717c9ba2179c02",
    "_command_process.py": "075fa6e9838017feb6a1716ab3a75074e3a65dffe8b217613aff7e87c0201f68",
    "_native_process.py": "70c380adde3c2bc06a0985761f0f877355bb56ef09ad506440da93fd4e4ba3b4",
    "cancellation.py": "1840232213e877e26c4cebd1434b3b851f9fa4c6961baa26eeaae9fa1442db78",
}


class Refused(Exception):
    """A fixed public diagnostic label, never an OS/path/child transcript."""


def need(condition, label):
    if not condition:
        raise Refused(label)


def digest(body):
    return hashlib.sha256(body).hexdigest()


@dataclass(frozen=True)
class Binding:
    source: str
    run: str
    attempt: str

    def checked(self):
        need(type(self.source) is str and re.fullmatch(r"[0-9a-f]{40}", self.source), "source-binding")
        need(all(type(v) is str and re.fullmatch(r"[1-9][0-9]{0,19}", v) for v in (self.run, self.attempt)), "run-binding")
        return self

    def root(self):
        self.checked()
        return Path("/private/tmp") / f"mrk-macos-aqua-{self.source}-{self.run}-{self.attempt}"

    def public(self):
        return {"sourceCommit": self.source, "runId": self.run, "runAttempt": self.attempt}


def _expected_identity_proof():
    # Literal successful DATA shape, never a substitute for a native receipt.
    return {"returned": True, "attempted": True, "checks": dict.fromkeys(ACCESSIBILITY_PROOF_CHECKS, True),
            "parent": "match", "panel": "match", "children": 1, "originals": "one", "site": "complete", "error": "none"}


def _expected_confirm_proof():
    return {"returned": True, "attempted": True,
            "checks": dict.fromkeys(ACCESSIBILITY_CONFIRM_CHECKS, True), "site": "complete", "error": "none"}


def expected_result(binding, case):
    binding.checked()
    need(case in CASES, "case-binding")
    first, stale, lost = case == "first-save", case == "noop-stale", case in ("picker-loss", "save-loss")
    plans = {
        "create": [("release/mobile-release.json", "create", None, 684), (".gitignore", "append", 40, 248)],
        "preserve": [("release/mobile-release.json", "preserve", 684, 684), (".gitignore", "preserve", 248, 248)],
        "replace": [("release/mobile-release.json", "replace", 684, 690), (".gitignore", "preserve", 248, 248)],
    }
    rows = {
        "first-save": [(1, 1, "create", 2, True, "committed", "clean", "none", "none"),
                       (1, 2, "preserve", 0, False, "not_started", "not_created", "cancelled", "shutdown")],
        "noop-stale": [(1, 1, "preserve", 1, True, "unchanged", "not_created", "none", "none"),
                       (2, 1, "replace", 1, True, "not_started", "not_created", "stale_revision", "none")],
        "picker-loss": [],
        "save-loss": [(1, 1, "create", 0, False, "not_started", "not_created", "cancelled", "window_lost")],
    }
    sessions = []
    for draft, baseline, plan, confirmations, applied, effect, journal, reason, native in rows[case]:
        sessions.append({"draftRevision": draft, "baselineGeneration": baseline,
            "files": [dict(zip(("path", "action", "beforeBytes", "afterBytes"), row)) for row in plans[plan]],
            "createReleaseDirectory": plan == "create", "reviewMatched": True, "confirmationsOpened": confirmations,
            "acknowledged": applied, "apply": applied,
            "outcome": {"effect": effect, "journal": journal, "resources": "settled", "reason": reason},
            "nativeReason": native, "nativeFinality": "settled", "writerFrames": 3 if applied else 2,
            "stdoutFrames": 3, "originalsJoined": True})
    return {"schemaVersion": 1, **binding.public(), "case": case, "instrumentedEngineeringApp": True,
        "shippingBinaryQualified": False, "distributionQualified": False, "methods": "eight-passive", "actionsAvailable": False,
        "native": {"projectCancelSettled": first, "selectedPathMatched": case != "picker-loss",
            "originalWindow": {"mechanism": "passive-original-window-callback-v1", "accessorReturned": True,
                "nativeReturned": True, "result": "ok", "admitted": True,
                "state": {"applicationPresent": True, "active": True, "mainPresent": True,
                    "originalMain": True, "ordinaryWindow": True, "noAttachedSheet": True}},
            "panelAttachments": [True, True, first, first],
            "controlReturns": [first, case != "picker-loss", case != "picker-loss", first, True],
            "accessibilityTrustedWithoutPrompt": True,
            "projectOpenInput": None if case == "picker-loss" else {
                "mechanism": "accessibility-confirm-original-open-panel-v1", "step": "OpenProject", "id": 2 if first else 1,
                "prepared": True, "requested": True, "dispatchAttempted": True, "state": "retired",
                "bodyEntered": True, "nativeEntered": True, "bodyReturned": True, "receiptJoined": True,
                "barrierRetired": True, "expired": False, "timely": True, "custodyKnown": True,
                "attempted": True, "confirmReturned": True, "triggered": True,
                "initialOriginalProof": _expected_identity_proof(), "originalProof": _expected_identity_proof(),
                "confirmEligibility": _expected_confirm_proof(),
                "confirmRecheck": _expected_confirm_proof(), "site": "confirm", "error": "none"},
            "projectOpenBinding": None if case == "picker-loss" else {
                "mechanism": "public-original-sheet-v1", "case": case, "id": 2 if first else 1, "kind": "project",
                "start": {"returned": True, "result": "ok"},
                "configuration": {"attempted": True, "parentSetterEntered": True, "parentSetterReturned": True,
                    "parent": "match", "site": "complete", "error": "none"},
                "binding": _expected_identity_proof()},
            "quitCancelKeptOriginalReview": first, "originalDocumentAndQuitSettled": True},
        "saveSessions": sessions, "freshCoreReadback": first, "syntheticFileReadback": True,
        "staleMarkerWriterReturnedAndClosed": stale,
        "reload": {"requested": lost, "dispatchReturned": lost, "navigationDenied": lost, "secondStarted": False,
            "originalLossSettled": lost, "webProcessCrashTested": False},
        "originalRelayJoined": True, "actualExit": True, "scope": SCOPE}


def _pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate-result-key")
        result[key] = value
    return result


def _exact(actual, expected):
    # Python's True == 1 (and 1.0 == 1) must not accept substituted evidence.
    need(type(actual) is type(expected), "result-type")
    if type(expected) is dict:
        need(actual.keys() == expected.keys(), "result-keys")
        for key in expected:
            _exact(actual[key], expected[key])
    elif type(expected) is list:
        need(len(actual) == len(expected), "result-count")
        for left, right in zip(actual, expected):
            _exact(left, right)
    else:
        need(actual == expected, "result-value")


def parse_result(stdout, stderr, binding, case):
    need(type(stdout) is bytes and type(stderr) is bytes and len(stdout) + len(stderr) <= OUTPUT_LIMIT, "result-capture")
    need(not any(token in stream for stream in (stdout, stderr)
                 for token in (b"MRK_MACOS_AQUA_FAILURE", b"MRK_MACOS_AQUA=")), "inner-failure-marker")
    need(stdout.count(MARKER) == 1 and MARKER not in stderr, "result-marker-count")
    lines = stdout.split(b"\n")
    records = [line[len(MARKER):] for line in lines[:-1] if line.startswith(MARKER)]
    need(len(records) == 1 and 0 < len(records[0]) <= JSON_LIMIT and b"\r" not in records[0], "result-record")
    try:
        value = json.loads(records[0].decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(Refused("result-constant")))
    except (ValueError, RecursionError, UnicodeError) as error:
        raise Refused("result-json") from error
    expected = expected_result(binding, case)
    if case != "picker-loss":
        need(type(value) is dict and type(value.get("native")) is dict, "native-object")
        identity = _accessibility_binding_context(value["native"].get("projectOpenBinding"), case)
        need(identity is not None and identity["start"]["result"] == "ok" and identity["binding"] is not None
             and identity["binding"]["attempted"] and identity["binding"]["error"] == "none",
             "project-open-binding")
        # Original preparation and exact semantic action/return/receipt are
        # separate mandatory proofs; child counts remain actual native DATA.
        expected["native"]["projectOpenBinding"] = identity
        input_data = _accessibility_context(value["native"].get("projectOpenInput"), None, None,
                                            expected_id=identity["id"])
        need(input_data is not None and _accessibility_succeeded(input_data),
             "project-open-input")
        expected["native"]["projectOpenInput"] = input_data
    if case in ("picker-loss", "save-loss"):
        need(type(value) is dict and type(value.get("reload")) is dict, "reload-object")
        reload = value["reload"]
        denied, started = reload.get("navigationDenied"), reload.get("secondStarted")
        need(type(denied) is bool and type(started) is bool and (denied or started), "reload-loss-route")
        expected["reload"]["navigationDenied"], expected["reload"]["secondStarted"] = denied, started
    _exact(value, expected)
    return value


def _failure_row(stdout, stderr, marker, limit):
    """One complete row; count malformed/embedded/partial candidates too."""
    if type(stdout) is not bytes or type(stderr) is not bytes or len(stdout) + len(stderr) > OUTPUT_LIMIT:
        return None
    if sum(stream.count(marker) for stream in (stdout, stderr)) != 1:
        return None
    prefix = marker + b"="
    stream = stdout if marker in stdout else stderr
    start = stream.index(marker)
    if (start != 0 and stream[start - 1] != 10) or not stream.startswith(prefix, start):
        return None
    start += len(prefix)
    end = stream.find(b"\n", start)
    if not 0 < end - start <= limit:
        return None
    row = stream[start:end]
    return None if b"\r" in row else row


def failure_step(stdout, stderr):
    # Finite Rust Step labels only; never publish arbitrary child log text.
    row = _failure_row(stdout, stderr, b"MRK_MACOS_AQUA_FAILURE_STEP", 40)
    if row is None:
        return None
    try:
        label = row.decode("ascii")
    except UnicodeError:
        return None
    return label if label in FAILURE_STEPS else None


def failure_reason(stdout, stderr):
    """Optional closed DATA only; malformed/partial output never grants success."""
    row = _failure_row(stdout, stderr, b"MRK_MACOS_AQUA_FAILURE_REASON", 48)
    if row is None:
        return None
    try:
        label = row.decode("ascii")
    except UnicodeError:
        return None
    return label if label in FAILURE_REASONS else None


def _native_action_context(value, native, panel):
    # Missing/malformed new DATA loses only this diagnostic. Never replace the
    # existing context, first error, original return or unknown-finality facts.
    if value is None:
        return None
    try:
        need(type(value) is dict and set(value) == {"step", "id", "action", "domain", "site", "error"}, "native-action-data")
        need(all(type(value[key]) is str for key in ("step", "action", "domain", "site", "error"))
             and type(value["id"]) is int, "native-action-data")
        spec = NATIVE_ACTION_STEPS.get(value["step"])
        need(spec is not None and value["action"] == spec[0] and value["id"] in spec[2], "native-action-data")
        need(native is not None and native["entered"] and native["returned"] and native["step"] == value["step"]
             and panel is not None and panel["step"] == value["step"] and panel["id"] == value["id"]
             and panel["kind"] == spec[1], "native-action-data")
        domain, site, error = value["domain"], value["site"], value["error"]
        if domain == "rust-precondition":
            need(site == "original-usability" and error == "other"
                 or value["action"] == "project-directory" and site in ("directory-utf8", "directory-path", "directory-cstring")
                 and error == "invalid-input", "native-action-data")
        else:
            rule = NATIVE_ACTION_SITES.get(site)
            need(rule is not None and rule[1] & spec[3], "native-action-data")
            need(domain == "native-return" and error == rule[0] and error not in (None, "none", "would-block")
                 or domain == "objc-exception" and rule[2] and error == "io", "native-action-data")
        return value
    except (Refused, TypeError, ValueError):
        return None


def _accessibility_native_proof(value):
    """Validate the closed DATA copied after one actual native body return."""
    label = "accessibility-native-proof"
    need(type(value) is dict and set(value) == {
        "returned", "attempted", "checks", "parent", "panel", "children", "originals", "site", "error"}, label)
    need(value["returned"] is True and type(value["attempted"]) is bool, label)
    checks = value["checks"]
    need(type(checks) is dict and set(checks) == set(ACCESSIBILITY_PROOF_CHECKS)
         and all(v is None or type(v) is bool for v in checks.values()), label)
    for field, allowed in (("parent", ACCESSIBILITY_BINDING_CLASSES), ("panel", ACCESSIBILITY_PANEL_CLASSES),
                           ("originals", {"zero", "one", "multiple"})):
        need(value[field] is None or type(value[field]) is str and value[field] in allowed, label)
    children, site, error = value["children"], value["site"], value["error"]
    need(children is None or type(children) is int and 0 <= children <= 17, label)
    need(type(site) is str and site in ACCESSIBILITY_PROOF_SITES
         and type(error) is str and error in ACCESSIBILITY_ERRORS, label)
    if not value["attempted"]:
        need(all(v is None for v in checks.values())
             and all(value[key] is None for key in ("parent", "panel", "children", "originals"))
             and (site, error) == ("objects", "custody"), label)
    else:
        # Preserve the earlier successful first-value observation separately
        # from the later failed stability check. Only this exact returned
        # negative frame permits a final class different from valid/match.
        stable_failure = (site == "stable-identifier" and error == "changed"
            and all(checks[key] is True for key in ACCESSIBILITY_PROOF_CHECKS[:10])
            and checks["stableIdentifier"] is False and checks["finalEligibility"] is None
            and value["panel"] in ACCESSIBILITY_PANEL_CLASSES - {"valid", "match"})
        need(checks["eligible"] is not None
             and (checks["parentIdentifier"] is not True or value["parent"] == "match")
             and (checks["panelIdentifier"] is not True or value["panel"] in ("valid", "match") or stable_failure)
             and (checks["nativeChild"] is not True or type(children) is int and 1 <= children <= 16
                  and value["originals"] == "one")
             and (checks["stableIdentifier"] is not True or value["panel"] == "match"), label)
        need((site == "complete") == (error == "none"), label)
        if error == "none":
            need(all(v is True for v in checks.values()) and value["parent"] == value["panel"] == "match"
                 and type(children) is int and 1 <= children <= 16 and value["originals"] == "one", label)
    return value


def _accessibility_confirm_proof(value):
    """Returned scalar facts; neither a lookup identity nor an action permit."""
    label = "accessibility-confirm-proof"
    need(type(value) is dict and set(value) == {"returned", *ACCESSIBILITY_CONFIRM_FLAGS, "checks", "site", "error"}, label)
    need(value["returned"] is True and value["attempted"] is True
         and all(type(value[key]) is bool for key in ACCESSIBILITY_CONFIRM_FLAGS), label)
    checks, site, error = value["checks"], value["site"], value["error"]
    need(type(checks) is dict and set(checks) == set(ACCESSIBILITY_CONFIRM_CHECKS)
         and all(v is None or type(v) is bool for v in checks.values()), label)
    need(type(site) is str and site in ACCESSIBILITY_CONFIRM_SITES
         and type(error) is str and error in ACCESSIBILITY_ERRORS, label)
    need(checks["eligible"] is not None, label)
    for index, key in enumerate(ACCESSIBILITY_CONFIRM_CHECKS):
        if checks[key] is not None:
            need(all(checks[earlier] is True for earlier in ACCESSIBILITY_CONFIRM_CHECKS[:index]), label)
    need((site == "complete") == (error == "none"), label)
    if error == "none":
        need(all(v is True for v in checks.values()), label)
    return value


def _accessibility_succeeded(value):
    return (all(value[key] is True for key in ("prepared", "requested", "dispatchAttempted", "bodyEntered", "nativeEntered",
             "bodyReturned", "receiptJoined", "barrierRetired", "timely", "custodyKnown", "attempted", "confirmReturned", "triggered"))
            and value["expired"] is False and value["state"] == "retired" and value["site"] == "confirm" and value["error"] == "none"
            and all(value[key] is not None and value[key]["error"] == "none"
                    for key in ("initialOriginalProof", "confirmEligibility", "originalProof", "confirmRecheck")))


def _accessibility_context(value, native, panel, *, expected_id=None):
    if value is None:
        return None
    label = "accessibility-data"
    try:
        flags = ("prepared", "requested", "dispatchAttempted", "bodyReturned", "receiptJoined", "barrierRetired", "expired")
        observed = ("bodyEntered", "nativeEntered", "attempted", "confirmReturned", "triggered", "timely", "custodyKnown")
        need(type(value) is dict and set(value) == {"mechanism", "step", "id", "state", "site", "error",
             "initialOriginalProof", "originalProof", "confirmEligibility", "confirmRecheck", *flags, *observed}, label)
        need(value["mechanism"] == "accessibility-confirm-original-open-panel-v1" and value["step"] == "OpenProject"
             and type(value["id"]) is int and value["id"] in (1, 2), label)
        if expected_id is not None:
            need(value["id"] == expected_id, label)
        else:
            need(native is not None, label)
            if native["step"] == "OpenProject":
                need(native["entered"] and native["returned"] and panel is not None and panel["step"] == "OpenProject"
                     and panel["kind"] == "project" and panel["id"] == value["id"], label)
        need(all(type(value[key]) is bool for key in flags)
             and all(value[key] is None or type(value[key]) is bool for key in observed), label)
        state, site, error = value["state"], value["site"], value["error"]
        need(type(state) is str and state in ("prepared", "requested", "queued", "entered", "returned", "joined", "retired", "unknown"), label)
        need(site is None or type(site) is str and site in ACCESSIBILITY_SITES, label)
        need(error is None or type(error) is str and error in ACCESSIBILITY_ERRORS, label)
        need((site is None) == (error is None), label)
        need(not value["requested"] or value["prepared"], label)
        need(not value["dispatchAttempted"] or value["requested"], label)
        need(value["bodyEntered"] is not True or value["dispatchAttempted"], label)
        need(value["nativeEntered"] is not True or value["bodyEntered"] is True, label)
        need(not value["bodyReturned"] or value["bodyEntered"] is True, label)
        need(not value["receiptJoined"] or value["bodyReturned"], label)
        need(not value["barrierRetired"] or value["prepared"] and (value["receiptJoined"]
             or not value["dispatchAttempted"] and value["bodyEntered"] is False
             and not value["bodyReturned"] and value["nativeEntered"] is False), label)
        # Phase is current custody; the flags are monotonic actual history.
        # Unknown cannot erase a real join/retirement or grant current custody.
        if state == "unknown":
            need(value["custodyKnown"] is False, label)
        elif state == "retired":
            need(value["barrierRetired"] and value["custodyKnown"] is True, label)
        else:
            need(not value["barrierRetired"], label)
            ordinal = ("prepared", "requested", "queued", "entered", "returned", "joined").index(state)
            need(value["requested"] == (ordinal >= 1) and value["dispatchAttempted"] == (ordinal >= 2)
                 and value["bodyReturned"] == (ordinal >= 4) and value["receiptJoined"] == (ordinal >= 5), label)
            need(value["bodyEntered"] is True if ordinal >= 3 else value["bodyEntered"] in (None, False), label)
            if ordinal < 4:
                need(value["custodyKnown"] is not True, label)
            elif ordinal == 4:
                need(value["custodyKnown"] is not False, label)
            else:
                need(value["custodyKnown"] is True, label)
        need(not value["expired"] or value["timely"] is not True, label)
        need(value["attempted"] is not True or value["nativeEntered"] is True and value["bodyReturned"], label)
        need(value["confirmReturned"] is not True or value["attempted"] is True, label)
        need(value["triggered"] is None or value["confirmReturned"] is True, label)
        need(error not in ("custody", "objc-exception", "cleanup-unknown") or value["custodyKnown"] is not True, label)
        need(error != "not-triggered" or value["triggered"] is False, label)
        need(value["triggered"] is not False or error in ("not-triggered", "custody"), label)
        proofs = (value["initialOriginalProof"], value["confirmEligibility"], value["originalProof"], value["confirmRecheck"])
        for index, proof in enumerate(proofs):
            if proof is not None:
                need(value["bodyReturned"] and value["nativeEntered"] is True, label)
                (_accessibility_native_proof if index in (0, 2) else _accessibility_confirm_proof)(proof)
                need(all(p is not None and p["error"] == "none" for p in proofs[:index]), label)
        need(value["attempted"] is not True or all(p is not None and p["error"] == "none" for p in proofs), label)
        if value["nativeEntered"] is False:
            need(all(p is None for p in proofs) and value["attempted"] is False and value["confirmReturned"] is False
                 and value["triggered"] is None, label)
        elif value["nativeEntered"] is None:
            need(all(p is None for p in proofs) and value["attempted"] is None and value["confirmReturned"] is None
                 and value["triggered"] is None, label)
        else:
            need(value["bodyReturned"], label)
        if not value["bodyReturned"]:
            need(all(p is None for p in proofs) and value["triggered"] is None, label)
        if error == "none":
            need(site == "confirm" and value["attempted"] is True and value["confirmReturned"] is True
                 and value["triggered"] is True and all(p is not None and p["error"] == "none" for p in proofs), label)
        for name, proof in (("initial-original-proof", proofs[0]), ("confirm-eligibility", proofs[1]),
                            ("original-proof", proofs[2]), ("confirm-recheck", proofs[3])):
            if site == name:
                need(proof is not None and proof["error"] == error, label)
        return value
    except (Refused, KeyError, TypeError, ValueError):
        return None


def _accessibility_binding_context(value, case):
    """Closed original-return DATA; never a permission, action or finality fact."""
    if value is None:
        return None
    try:
        label = "accessibility-binding-data"
        need(type(case) is str and case in CASES and case != "picker-loss", label)
        need(type(value) is dict and set(value) == {
            "mechanism", "case", "id", "kind", "start", "configuration", "binding"}, label)
        need(value["mechanism"] == "public-original-sheet-v1" and value["case"] == case
             and type(value["id"]) is int and value["id"] == (2 if case == "first-save" else 1)
             and value["kind"] == "project", label)
        start, configured, bound = value["start"], value["configuration"], value["binding"]
        need(type(start) is dict and set(start) == {"returned", "result"} and start["returned"] is True
             and type(start["result"]) is str
             and start["result"] in ("ok", "permission-denied", "io", "invalid-input", "already", "other"), label)
        flags = ("parentSetterEntered", "parentSetterReturned")
        need(type(configured) is dict and set(configured) == {"attempted", *flags, "parent", "site", "error"}
             and all(type(configured[key]) is bool for key in ("attempted", *flags)), label)
        parent, site, error = (configured[key] for key in ("parent", "site", "error"))
        need(parent is None or type(parent) is str and parent in ACCESSIBILITY_BINDING_CLASSES, label)
        need(site is None or type(site) is str and site in ACCESSIBILITY_BINDING_SITES, label)
        need(error is None or type(error) is str and error in ACCESSIBILITY_ERRORS, label)
        bits = tuple(configured[key] for key in flags)
        if not configured["attempted"]:
            need(not any(bits) and parent is site is error is None and start["result"] != "ok", label)
        else:
            need(start["result"] in ("ok", "io") and site is not None and error is not None, label)
            if site in ("objects", "parent-tag"):
                need(not any(bits) and parent is None
                     and error in (("ineligible",) if site == "objects" else ("invalid-input", "objc-exception")), label)
            elif site == "parent-set":
                need(bits == (True, False) and parent is None and error == "objc-exception", label)
            elif site == "parent-get":
                need(all(bits) and parent is None and error == "objc-exception", label)
            else:
                need(site == "complete" and all(bits) and parent is not None and error == "none", label)
            if start["result"] == "ok":
                need(site == "complete" and error == "none", label)
        if bound is not None:
            need(start["result"] == "ok", label)
            _accessibility_native_proof(bound)
        return value
    except (Refused, KeyError, TypeError, ValueError):
        return None


def _original_window_context(value):
    if value is None:
        return None  # No returned sample, not a nil/inactive native observation.
    label = "original-window-context"
    need(type(value) is dict and set(value) == {"mechanism", "accessorReturned", "nativeReturned",
                                               "result", "admitted", "state"}, label)
    need(type(value["mechanism"]) is str and value["mechanism"] == "passive-original-window-callback-v1"
         and type(value["accessorReturned"]) is bool and value["accessorReturned"]
         and type(value["nativeReturned"]) is bool and type(value["admitted"]) is bool
         and type(value["result"]) is str
         and value["result"] in ("ok", "accessor-error", "entry-refused", "native-error", "invalid-return"), label)
    need(value["nativeReturned"] == (value["result"] != "accessor-error"), label)
    state = value["state"]
    if value["result"] != "ok":
        need(state is None and not value["admitted"], label)
    else:
        need(type(state) is dict and set(state) == {"applicationPresent", "active", "mainPresent",
                                                  "originalMain", "ordinaryWindow", "noAttachedSheet"}
             and all(type(fact) is bool for fact in state.values()), label)
        need(state["applicationPresent"] or not any(state.values()), label)
        need(state["mainPresent"] or not any(state[key] for key in
             ("originalMain", "ordinaryWindow", "noAttachedSheet")), label)
        # A positive read returned after failure/expiry can be truthful DATA
        # with admitted=False; it still cannot satisfy successful case evidence.
        need(not value["admitted"] or all(state.values()), label)
    return value


def failure_context(stdout, stderr, case=None):
    row = _failure_row(stdout, stderr, b"MRK_MACOS_AQUA_FAILURE_CONTEXT", FAILURE_CONTEXT_LIMIT)
    if row is None:
        return None
    try:
        value = json.loads(row.decode("ascii"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(Refused("failure-context")))
        need(type(value) is dict and set(value) - {"accessibilityBinding", "snapshotSource", "originalWindow"} in (
            {"pending", "nativeHandler", "lastPanel"},
            {"pending", "nativeHandler", "lastPanel", "nativeAction"},
            {"pending", "nativeHandler", "lastPanel", "nativeAction", "accessibility"}), "failure-context")
        if "snapshotSource" in value:
            need(type(value["snapshotSource"]) is str and value["snapshotSource"] in ("record", "prearm-open-progress"), "failure-context")
        if "originalWindow" in value:
            value["originalWindow"] = _original_window_context(value["originalWindow"])
        pending, native, panel = value["pending"], value["nativeHandler"], value["lastPanel"]
        if pending is not None:
            need(type(pending) is dict and set(pending) == {"kind", "step"}
                 and type(pending["kind"]) is str, "failure-context")
            kind, step = pending["kind"], pending["step"]
            allowed = {"dom": FAILURE_STEPS, "native": NATIVE_STEPS, "accessibility": {"OpenProject"},
                       "close": {"Close", "CloseCancel"}}
            need(kind in ("reload", "failure-close") and step is None
                 or kind in allowed and type(step) is str and step in allowed[kind], "failure-context")
        if native is not None:
            need(type(native) is dict and set(native) == {"step", "entered", "returned"}
                 and type(native["step"]) is str and native["step"] in NATIVE_STEPS
                 and type(native["entered"]) is bool and type(native["returned"]) is bool
                 and (not native["returned"] or native["entered"]), "failure-context")
        if panel is not None:
            need(type(panel) is dict and set(panel) == {"step", "id", "kind", "parentPresent", "panelPresent",
                                                      "parentReferencesPanel", "panelReferencesParent", "panelVisible"}
                 and native is not None and native["entered"] and panel["step"] == native["step"]
                 and type(panel["id"]) is int and 1 <= panel["id"] <= 4
                 and type(panel["kind"]) is str and panel["kind"] in ("project", "quit")
                 and type(panel["parentPresent"]) is bool and type(panel["panelPresent"]) is bool, "failure-context")
            both = panel["parentPresent"] and panel["panelPresent"]
            need(all(type(panel[key]) is bool if both else panel[key] is None
                     for key in ("parentReferencesPanel", "panelReferencesParent"))
                 and (type(panel["panelVisible"]) is bool if panel["panelPresent"] else panel["panelVisible"] is None),
                 "failure-context")
        if "nativeAction" in value:
            value["nativeAction"] = _native_action_context(value["nativeAction"], native, panel)
        if "accessibility" in value:
            value["accessibility"] = _accessibility_context(value["accessibility"], native, panel)
        if value.get("snapshotSource") == "prearm-open-progress":
            sample = value.get("accessibility")
            # The fixed pre-arm original fields are historical, while only the
            # one atomic progress/expiry sample was refreshed at the deadline.
            need(pending == {"kind": "accessibility", "step": "OpenProject"}
                 and native == {"step": "OpenProject", "entered": True, "returned": True}
                 and sample is not None and sample["prepared"] and sample["requested"]
                 and sample["expired"] and sample["timely"] is False
                 and all(sample[key] is None for key in ("nativeEntered", "attempted", "confirmReturned", "triggered",
                     "initialOriginalProof", "confirmEligibility", "originalProof", "confirmRecheck", "site", "error")), "failure-context")
        if "accessibilityBinding" in value:
            # Early start failure legitimately has no nativeHandler/lastPanel
            # or Confirm sample. Bind to the known case, not to invented actions.
            value["accessibilityBinding"] = _accessibility_binding_context(value["accessibilityBinding"], case)
        return value
    except (Refused, ValueError, RecursionError, UnicodeError, TypeError):
        return None


def _original_exception_diagnostics(error, run_owned, case, cwd):
    """Private CI/source-pin seam: reduce only the original call's buffers.

    No import, engine method, cause traversal, outcome/finality query or raw
    output escape. Missing/changed owner contracts fail closed. The source is
    pinned by load_owner before this callable can be the original owner.
    """
    try:
        if type(case) is not str or case not in CASES:
            return None
        argv = (EXECUTABLE, case)  # Do not trust the mutable list supplied to the call.
        source = Path(__file__).absolute().parents[2] / "src" / "mobile_release"
        modules = []
        for name in ("owned_process", "_command_process"):
            module = sys.modules.get("mobile_release." + name)
            if type(module) is not ModuleType:
                return None
            namespace = vars(module)
            expected = str(source / (name + ".py"))
            spec = namespace.get("__spec__")
            if (namespace.get("__name__") != "mobile_release." + name
                    or namespace.get("__file__") != expected or type(spec) is not ModuleSpec or spec.origin != expected):
                return None
            modules.append(namespace)
        owner, command = modules
        function = command.get("run_command")
        if (type(run_owned) is not FunctionType or owner.get("run_owned") is not run_owned
                or run_owned.__globals__ is not owner or run_owned.__code__.co_filename != owner["__file__"]
                or type(function) is not FunctionType or function.__globals__ is not command
                or function.__code__.co_filename != command["__file__"]):
            return None
        original = None
        trace = error.__traceback__
        for _ in range(TRACEBACK_LIMIT):
            if trace is None:
                break
            frame = trace.tb_frame
            if frame.f_code is function.__code__:
                if frame.f_globals is not command or original is not None and frame is not original:
                    return None
                original = frame  # Re-raising can repeat this identical frame.
            trace = trace.tb_next
        if trace is not None or original is None:
            return None
        local = original.f_locals  # Python 3.14 can supply FrameLocalsProxy.
        engine = local.get("engine")
        if type(engine) is not command.get("_Outer"):
            return None
        actual = local.get("argv")
        if (type(actual) is not list or len(actual) != 2 or any(type(arg) is not str for arg in actual)
                or tuple(actual) != argv or type(local.get("cwd")) is not type(cwd) or local["cwd"] != cwd
                or type(local.get("timeout")) is not int or local["timeout"] != 60
                or local.get("capture") is not True or local.get("text") is not False
                or type(local.get("output_limit")) is not int or local["output_limit"] != OUTPUT_LIMIT):
            return None
        frozen = engine.frozen
        if type(frozen) is not command.get("FrozenCommand") or type(frozen.manifest) is not command.get("Manifest"):
            return None
        if (type(frozen.args) is not tuple or len(frozen.args) != 2
                or any(type(arg) is not str for arg in frozen.args) or frozen.args != argv
                or type(frozen.argv) is not tuple or len(frozen.argv) != 2 or any(type(arg) is not bytes for arg in frozen.argv)
                or frozen.argv != tuple(arg.encode("ascii") for arg in argv)
                or type(frozen.cwd) is not bytes or frozen.cwd != str(cwd).encode("ascii")
                or frozen.manifest.capture is not True or type(frozen.manifest.limit) is not int
                or frozen.manifest.limit != OUTPUT_LIMIT or engine.text is not False):
            return None
        outputs = engine.outputs
        if (type(outputs) is not list or len(outputs) != 2 or any(type(part) is not bytearray for part in outputs)
                or len(outputs[0]) + len(outputs[1]) > OUTPUT_LIMIT):
            return None
        stdout, stderr = bytes(outputs[0]), bytes(outputs[1])
        # The copies are immediately reduced; none is retained/exported by the
        # caller. Buffer availability never means EOF or original finality.
        reduced = (failure_step(stdout, stderr), failure_reason(stdout, stderr), failure_context(stdout, stderr, case))
        return reduced if any(part is not None for part in reduced) else None
    except BaseException:
        return None  # Extraction must never mask the original invocation error.


@dataclass(frozen=True)
class Node:
    # dev, inode, complete mode, uid, gid, nlink, size, mtime_ns, ctime_ns.
    identity: tuple
    sha256: str | None
    entries: tuple | None


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def fixture_data(case, final):
    need(case in CASES and type(final) is bool, "fixture-case")
    saved = case == "noop-stale" or final and case == "first-save"
    files = {"app/build.gradle.kts": SOURCE, "version.properties": VERSION, "keep.txt": KEEP,
             ".gitignore": IGNORE_PREFIX + (IGNORE_RULES if saved else b"") + (STALE if final and case == "noop-stale" else b"")}
    directories = {".": (0o700, (".gitignore", "app", "keep.txt", "version.properties")),
                   "app": (0o700, ("build.gradle.kts",))}
    if saved:
        files["release/mobile-release.json"] = CONFIG
        directories["."] = (0o700, (".gitignore", "app", "keep.txt", "release", "version.properties"))
        directories["release"] = (0o755, ("mobile-release.json",))
    return files, directories


def _shape(snapshot, case, final, uid, gid):
    files, directories = fixture_data(case, final)
    need(type(snapshot) is dict and snapshot.keys() == files.keys() | directories.keys(), "fixture-roster")
    for path, node in snapshot.items():
        need(type(node) is Node and type(node.identity) is tuple and len(node.identity) == 9
             and all(type(v) is int and v >= 0 for v in node.identity), "fixture-identity")
        facts = node.identity
        need(facts[3:5] == (uid, gid), "fixture-owner")
        if path in files:
            need(facts[2] == stat.S_IFREG | 0o600 and facts[5] == 1 and facts[6] == len(files[path])
                 and node.sha256 == digest(files[path]) and node.entries is None, "fixture-file")
        else:
            mode, entries = directories[path]
            need(facts[2] == stat.S_IFDIR | mode and node.sha256 is None and node.entries == entries, "fixture-directory")


def validate_snapshot(original, current, case, final, uid, gid):
    _shape(original, case, False, uid, gid)
    _shape(current, case, final, uid, gid)
    for path, before in original.items():
        after = current[path]
        if before.entries is not None:
            need(after.identity[:5] == before.identity[:5], "fixture-directory-replaced")
        elif final and case == "first-save" and path == ".gitignore":
            need(after.identity[:2] != before.identity[:2], "save-ignore-not-replaced")
        elif final and case == "noop-stale" and path == ".gitignore":
            need(after.identity[:6] == before.identity[:6], "stale-ignore-replaced")
        else:
            need(after.identity == before.identity, "fixture-original-changed")
    return {"completeRoster": True, "expectedBytesAndModes": True, "originalIdentitiesMatched": True,
            "transactionResidueAbsent": True, "files": len(fixture_data(case, final)[0]),
            "configSha256": current.get("release/mobile-release.json").sha256 if "release/mobile-release.json" in current else None,
            "ignoreSha256": current[".gitignore"].sha256, "ignoreBytes": current[".gitignore"].identity[6]}


def app_environment(state, uid, username):
    need(type(uid) is int and uid > 0 and type(username) is str
         and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", username), "native-user")
    return {"HOME": str(state / "home"), "TMPDIR": str(state / "tmp") + "/",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8", "TZ": "UTC",
            "USER": username, "LOGNAME": username, "__CF_USER_TEXT_ENCODING": f"0x{uid:X}:0:0"}


class Fixtures:
    """Finite helper-owned file custody, never process/Store custody."""

    def __init__(self, binding, uid, gid):
        self.binding, self.uid, self.gid = binding, uid, gid
        self.path = binding.root()
        self.fds = set()
        self.close_errors = 0
        self.first_close_error = None
        self.inflight = False
        self.last_returned = False
        self.app_returncode = self.inner_failure_step = self.inner_failure_reason = None
        self.inner_failure_context = self.inner_diagnostic_source = None
        self.case = None
        self.stage = "prepare"
        self.projects, self.states, self.originals = {}, {}, {}

    def _open(self, name, parent=None, *, directory=False, create=False):
        flags = os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        flags |= os.O_WRONLY | os.O_CREAT | os.O_EXCL if create else os.O_RDONLY
        if directory:
            flags |= os.O_DIRECTORY
        fd = os.open(name, flags, 0o600, dir_fd=parent)
        self.fds.add(fd)
        need(not os.get_inheritable(fd), "fixture-descriptor-inheritance")
        return fd

    def _close(self, fd):
        need(fd in self.fds, "fixture-close-not-original")
        self.fds.remove(fd)  # This original close is never repeated on error.
        try:
            os.close(fd)
            return True
        except BaseException as error:
            self.close_errors += 1
            if self.first_close_error is None:
                self.first_close_error = error
            return False

    @contextmanager
    def _temporary(self, fd):
        original_error = None
        try:
            yield fd
        except BaseException as error:
            original_error = error
            raise
        finally:
            closed = self._close(fd)
            if not closed and original_error is None:
                raise self.first_close_error

    def _mkdir(self, parent, name, mode=0o700):
        os.mkdir(name, 0o700, dir_fd=parent)  # Refuse occupied paths; never adopt.
        fd = self._open(name, parent, directory=True)
        original = signature(os.fstat(fd))
        need(signature(os.stat(name, dir_fd=parent, follow_symlinks=False)) == original
             and original[2] == stat.S_IFDIR | 0o700 and original[3] == self.uid,
             "fixture-created-directory-custody")
        # Darwin can inherit the parent's group even without setgid. Normalize
        # only this fresh, private, caller-owned original, before widening it.
        if original[4] != self.gid:
            os.fchown(fd, -1, self.gid)
        current = signature(os.fstat(fd))
        need(current[:4] == original[:4] and current[4] == self.gid,
             "fixture-created-directory-group")
        self._named(parent, name, fd, 0o700)
        if mode != 0o700:
            os.fchmod(fd, mode)  # Only this newly and exclusively created dir.
            self._named(parent, name, fd, mode)
        return fd

    def _named(self, parent, name, fd, mode):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        info = os.fstat(fd)
        need(signature(before) == signature(info) and info.st_mode == stat.S_IFDIR | mode
             and (info.st_uid, info.st_gid) == (self.uid, self.gid), "fixture-directory-custody")

    def _write(self, parent, name, body):
        with self._temporary(self._open(name, parent, create=True)) as fd:
            info = os.fstat(fd)
            need(info.st_mode == stat.S_IFREG | 0o600 and info.st_nlink == 1
                 and (info.st_uid, info.st_gid) == (self.uid, self.gid), "fixture-created-file")
            offset = 0
            while offset < len(body):
                count = os.write(fd, body[offset:])
                need(count > 0, "fixture-write")
                offset += count

    def prepare(self):
        self.parent = self._open("/private/tmp", directory=True)
        p = os.fstat(self.parent)
        need(p.st_mode == stat.S_IFDIR | 0o1777 and p.st_uid == 0, "temporary-parent")
        self.root = self._mkdir(self.parent, self.path.name)
        self.state = self._mkdir(self.root, "state")
        for case in CASES:
            project = self._mkdir(self.root, case)
            self.projects[case] = project
            with self._temporary(self._mkdir(project, "app")) as app:
                self._write(app, "build.gradle.kts", SOURCE)
            self._write(project, "version.properties", VERSION)
            self._write(project, "keep.txt", KEEP)
            self._write(project, ".gitignore", IGNORE_PREFIX + (IGNORE_RULES if case == "noop-stale" else b""))
            if case == "noop-stale":
                with self._temporary(self._mkdir(project, "release", 0o755)) as release:
                    self._write(release, "mobile-release.json", CONFIG)
            state = self._mkdir(self.state, case)
            self.states[case] = state
            for child in ("home", "tmp"):
                with self._temporary(self._mkdir(state, child)):
                    pass
            self.originals[case] = self._capture(case, False)
        self._namespace()

    def _namespace(self):
        need(signature(os.stat("/private/tmp", follow_symlinks=False))[:6] == signature(os.fstat(self.parent))[:6], "temporary-parent-replaced")
        self._named(self.parent, self.path.name, self.root, 0o700)
        self._named(self.root, "state", self.state, 0o700)
        self._roster(self.root, (*CASES, "state"), "fixture-namespace-roster")
        self._roster(self.state, CASES, "fixture-state-roster")
        for case in CASES:
            self._named(self.root, case, self.projects[case], 0o700)
            self._named(self.state, case, self.states[case], 0o700)

    def _roster(self, fd, expected, label):
        # A fresh openat(".") description, not dup(retained_fd), gives each
        # scan its own cursor. Never depend on a supplier's iterator rewind.
        before = signature(os.fstat(fd))
        with self._temporary(self._open(".", fd, directory=True)) as reader:
            need(signature(os.fstat(reader)) == before, "fixture-roster-original")
            iterator = os.scandir(reader)
            original_error = None
            try:
                names = []
                for entry in iterator:
                    need(len(names) < len(expected), label)  # Consume at most expected+1.
                    names.append(entry.name)
                observed = tuple(sorted(names))
                need(observed == tuple(sorted(expected)), label)
                need(signature(os.fstat(reader)) == before and signature(os.fstat(fd)) == before,
                     "fixture-roster-read-race")
                return observed
            except BaseException as error:
                original_error = error
                raise
            finally:
                try:
                    iterator.close()  # One consuming close; never retry it.
                except BaseException as error:
                    self.close_errors += 1
                    if self.first_close_error is None:
                        self.first_close_error = error
                    if original_error is None:
                        raise

    def _file(self, parent, name, body):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        need(before.st_mode == stat.S_IFREG | 0o600 and before.st_nlink == 1 and before.st_size == len(body), "fixture-file-shape")
        with self._temporary(self._open(name, parent)) as fd:
            original = signature(before)
            need(signature(os.fstat(fd)) == original, "fixture-file-open-race")
            chunks, remaining = [], len(body) + 1
            while remaining:
                part = os.read(fd, remaining)
                if not part:
                    break
                chunks.append(part)
                remaining -= len(part)
            actual = b"".join(chunks)
            need(actual == body and signature(os.fstat(fd)) == original
                 and signature(os.stat(name, dir_fd=parent, follow_symlinks=False)) == original, "fixture-file-readback")
            return Node(original, digest(actual), None)

    def _capture(self, case, final):
        files, directories = fixture_data(case, final)
        snapshot = {}
        project = self.projects[case]
        for path, (mode, entries) in directories.items():
            @contextmanager
            def directory():
                if path == ".":
                    yield project
                else:
                    with self._temporary(self._open(path, project, directory=True)) as opened:
                        self._named(project, path, opened, mode)
                        yield opened
            with directory() as fd:
                before = signature(os.fstat(fd))
                observed = self._roster(fd, entries, "fixture-directory-roster")
                for name, body in files.items():
                    parent, _, leaf = name.rpartition("/")
                    if (parent or ".") == path:
                        snapshot[name] = self._file(fd, leaf, body)
                need(signature(os.fstat(fd)) == before, "fixture-directory-read-race")
                snapshot[path] = Node(before, None, observed)
        _shape(snapshot, case, final, self.uid, self.gid)
        return snapshot

    def before_call(self, case):
        self.case, self.stage = case, "before-invocation"
        self._namespace()
        validate_snapshot(self.originals[case], self._capture(case, False), case, False, self.uid, self.gid)
        state = self.states[case]
        self._roster(state, ("home", "tmp"), "fresh-state-roster")
        for name in ("home", "tmp"):
            with self._temporary(self._open(name, state, directory=True)) as fd:
                self._named(state, name, fd, 0o700)
                self._roster(fd, (), "fresh-state-not-empty")

    def readback(self, case):
        need(not self.inflight and self.last_returned, "readback-without-return")
        self.stage = "independent-readback"
        self._namespace()
        return validate_snapshot(self.originals[case], self._capture(case, True), case, True, self.uid, self.gid)

    def close(self):
        need(not self.inflight, "fixture-finality-unknown")
        for fd in tuple(self.fds):
            self._close(fd)
        if self.first_close_error is not None:
            raise self.first_close_error


def run_cases(binding, fixtures, run_owned, uid, username, emit):
    """The sole invocation seam. Inert tests supply a non-executing callable."""
    for case in CASES:
        fixtures.before_call(case)
        state = binding.root() / "state" / case
        argv = [EXECUTABLE, case]
        fixtures.stage, fixtures.inflight, fixtures.last_returned = "invocation", True, False
        fixtures.app_returncode = fixtures.inner_failure_step = fixtures.inner_failure_reason = None
        fixtures.inner_failure_context = fixtures.inner_diagnostic_source = None
        # Only the original public return contract clears this flag. An
        # exception/interruption or foreign/malformed result leaves finality
        # unknown, with no readback, close or later invocation.
        try:
            result = run_owned(argv, environ=app_environment(state, uid, username), cwd=state,
                               timeout=60, capture=True, text=False, output_limit=OUTPUT_LIMIT)
        except BaseException as error:
            # Diagnostics only: preserve identical error, inflight, unknown
            # finality and the no-readback/no-close/no-next-call boundary.
            try:
                reduced = _original_exception_diagnostics(error, run_owned, case, state)
                if reduced is not None:
                    fixtures.inner_failure_step, fixtures.inner_failure_reason, fixtures.inner_failure_context = reduced
                    fixtures.inner_diagnostic_source = "original-exception-buffer"
            except BaseException:
                pass  # Even an unexpected diagnostic fault cannot replace this error.
            raise
        need(type(result) is subprocess.CompletedProcess and type(result.args) is list
             and len(result.args) == 2 and all(type(arg) is str for arg in result.args) and result.args == argv
             and type(result.returncode) is int and type(result.stdout) is bytes and type(result.stderr) is bytes
             and len(result.stdout) + len(result.stderr) <= OUTPUT_LIMIT, "owner-return-contract")
        fixtures.inflight, fixtures.last_returned, fixtures.stage = False, True, "result-validation"
        fixtures.app_returncode = result.returncode
        fixtures.inner_failure_step = failure_step(result.stdout, result.stderr)
        fixtures.inner_failure_reason = failure_reason(result.stdout, result.stderr)
        fixtures.inner_failure_context = failure_context(result.stdout, result.stderr, case)
        fixtures.inner_diagnostic_source = "completed-output"
        need(result.returncode == 0, "app-return")
        report = parse_result(result.stdout, result.stderr, binding, case)
        readback = fixtures.readback(case)
        emit({"schemaVersion": 1, "type": "macos-aqua-case", **binding.public(), "case": case,
              "originalCallReturned": True, "observer": report, "independentReadback": readback})


def admit(environment, root):
    # Platform/user APIs are evaluated only in the actual native entry.
    import platform
    import pwd
    import threading
    need(sys.platform == "darwin" and platform.machine() == "arm64" and platform.mac_ver()[0].split(".")[0] == "26", "native-platform")
    uid, gid = os.getuid(), os.getgid()
    need(uid == os.geteuid() and uid > 0 and gid == os.getegid()
         and threading.current_thread() is threading.main_thread(), "native-main-user")
    binding = Binding(environment.get("GITHUB_SHA"), environment.get("GITHUB_RUN_ID"), environment.get("GITHUB_RUN_ATTEMPT")).checked()
    required = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64",
                "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_REF": REF,
                "GITHUB_WORKFLOW_REF": WORKFLOW, "GITHUB_WORKFLOW_SHA": binding.source, "GITHUB_WORKSPACE": str(root)}
    need(all(environment.get(key) == value for key, value in required.items()), "hosted-source-route")
    # Actions' reviewed checkout is detached at this exact source. No Git
    # command/credential lookup or alternate worktree/ref parser is needed.
    head = root / ".git" / "HEAD"
    head_info = head.lstat()
    need(stat.S_ISREG(head_info.st_mode) and head_info.st_size == 41
         and head.read_bytes() == binding.source.encode("ascii") + b"\n", "checkout-source")
    username = pwd.getpwuid(uid).pw_name
    app_environment(binding.root() / "state" / CASES[0], uid, username)
    return binding, uid, gid, username


def load_owner(root):
    need(not any(name == "mobile_release" or name.startswith("mobile_release.") for name in sys.modules), "owner-already-imported")
    for name, expected in OWNER_PINS.items():
        path = root / "src" / "mobile_release" / name
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_size <= 256 * 1024 and digest(path.read_bytes()) == expected, "owner-source-pin")
    sys.path.insert(0, str(root / "src"))
    try:
        from mobile_release import owned_process
    finally:
        sys.path.pop(0)
    need(Path(owned_process.__file__).absolute() == root / "src" / "mobile_release" / "owned_process.py", "owner-source-route")
    return owned_process


def diagnostic(error, owner, fixtures):
    # Preserve individual typed public lifetime facts, not a synthesized pass
    # from a later exception. Missing fields remain unknown (JSON null).
    pending, seen, facts = [error], set(), []
    while pending and len(seen) < 16:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        if owner is not None and isinstance(current, (owner.ProcessError, owner.ProcessInterrupted)):
            row = {"type": "interrupted" if isinstance(current, owner.ProcessInterrupted) else "process-error"}
            for source, target in (("dispatched", "dispatched"), ("contained", "contained"), ("cleanup_complete", "cleanupComplete")):
                value = getattr(current, source, None)
                row[target] = value if type(value) is bool else None
            facts.append(row)
        pending.extend((current.__context__, current.__cause__))
    label = str(error) if type(error) is Refused else "interrupted" if isinstance(error, (KeyboardInterrupt, SystemExit)) else "helper-or-owner-error"
    if re.fullmatch(r"[a-z][a-z0-9-]{0,63}", label) is None:
        label = "helper-refused"
    return {"schemaVersion": 1, "type": "macos-aqua-failure", "status": "failed", "reason": label,
            "case": fixtures.case if fixtures else None, "stage": fixtures.stage if fixtures else "admission-or-source",
            "originalCallReturned": fixtures.last_returned if fixtures else False,
            "appReturncode": fixtures.app_returncode if fixtures else None,
            "innerFailureStep": fixtures.inner_failure_step if fixtures else None,
            "innerFailureReason": fixtures.inner_failure_reason if fixtures else None,
            "innerFailureContext": fixtures.inner_failure_context if fixtures else None,
            "innerDiagnosticSource": fixtures.inner_diagnostic_source if fixtures else None,
            "innerDiagnosticCompleteness": "complete" if fixtures and fixtures.last_returned else "unknown",
            "invocationFinality": "unknown" if fixtures and fixtures.inflight else "no-pending-invocation",
            "innerOutput": "unavailable" if fixtures and fixtures.inflight else "not-exported",
            "typedLifetimeFacts": facts, "exceptionChainTruncated": bool(pending),
            "fixtureCloseErrors": fixtures.close_errors if fixtures else 0,
            "fixturesPreserved": True, "laterCasesStopped": True}


def emit_record(value, stream):
    data = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    need(len(data.encode("ascii")) <= 24 * 1024, "outer-result-bound")
    stream.write(data + "\n")
    stream.flush()


def main():
    fixtures = owner = binding = None
    original_error = None
    try:
        need(len(sys.argv) == 1, "arguments-not-supported")
        root = Path(__file__).absolute().parents[2]
        binding, uid, gid, username = admit(os.environ, root)
        owner = load_owner(root)  # Native main only; no module-import-time core.
        os.umask(0o077)
        fixtures = Fixtures(binding, uid, gid)
        fixtures.prepare()
        run_cases(binding, fixtures, owner.run_owned, uid, username, lambda value: emit_record(value, sys.stdout))
    except BaseException as error:
        original_error = error
    if fixtures is not None and not fixtures.inflight:
        try:
            fixtures.close()
        except BaseException as error:
            if original_error is None:
                original_error = error  # Never overwrite an earlier failure.
    if original_error is not None:
        # The original exception object reaches this boundary unchanged. This
        # CLI emits bounded DATA and a nonzero status, never its traceback,
        # arbitrary message, child transcript or private source/project paths.
        try:
            emit_record(diagnostic(original_error, owner, fixtures), sys.stderr)
        except BaseException:
            pass  # Output loss remains failure; there is no diagnostic retry.
        return 130 if isinstance(original_error, KeyboardInterrupt) else 1
    try:
        emit_record({"schemaVersion": 1, "type": "macos-aqua-complete", **binding.public(), "cases": list(CASES),
                     "allOriginalCallsReturned": True, "independentReadbacks": True, "fixtureHandlesClosed": True,
                     "instrumentedEngineeringApp": True, "shippingBinaryQualified": False, "distributionQualified": False}, sys.stdout)
    except BaseException:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
