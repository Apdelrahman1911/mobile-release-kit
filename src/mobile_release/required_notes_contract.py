"""Content-free routine note-status contract, before any native/core emission.

Private Load/Prepare responses use a different contract. Integrators must build
this exact projection before emission; never broadcast private objects then ask
the renderer to redact them. No actual owner/publisher is added in Phase A.
"""
from __future__ import annotations

import re
from typing import Any

from .required_notes import RequiredNotesInputError, notes_context

STATUS_KEYS = frozenset({"schemaVersion", "domain", "projectId", "windowGeneration", "ownerGeneration",
    "sessionId", "planToken", "revision", "context", "draftRevision", "statusRevision", "phase",
    "applySubmitted", "coreOutcome", "nativeReason", "nativeFinality", "lateSettled"})
PHASES = ("opening", "editing", "preparing", "reviewing", "applying", "finalizing", "final", "unknown")
NATIVE_REASONS = ("none", "discarded", "cancelled", "active_timeout", "review_expired", "caller_lost",
    "window_lost", "shutdown", "runtime_unavailable", "spawn_failed", "protocol_error", "io_error",
    "output_limit", "cleanup_unknown")
CORE_REASONS = ("none", "invalid_params", "invalid_config", "ignore_conflict", "stale_revision",
    "pending_state", "busy", "cancelled", "filesystem_error", "custody_unknown", "unsupported_platform")
_TOKEN = re.compile(r"[0-9a-f]{32}\Z")
_PROJECT = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")


def _require(ok: bool) -> None:
    if not ok:
        raise RequiredNotesInputError("invalid_status")


def required_notes_routine_status(value: object) -> dict[str, Any]:
    """Admit/detach exact DATA with no text, paths, baseline or content digests."""
    _require(type(value) is dict and set(value) == STATUS_KEYS)
    _require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
             and type(value["domain"]) is str and value["domain"] == "required_notes")
    _require(type(value["projectId"]) is str and _PROJECT.fullmatch(value["projectId"]) is not None)
    for key in ("windowGeneration", "ownerGeneration", "sessionId"):
        _require(type(value[key]) is str and _TOKEN.fullmatch(value[key]) is not None)
    for key in ("planToken", "revision"):
        _require(value[key] is None or type(value[key]) is str and _TOKEN.fullmatch(value[key]) is not None)
    context = notes_context(value["context"])
    for key in ("draftRevision", "statusRevision"):
        _require(type(value[key]) is int and 0 <= value[key] < 2 ** 32)
    _require(type(value["phase"]) is str and value["phase"] in PHASES)
    _require(type(value["nativeReason"]) is str and value["nativeReason"] in NATIVE_REASONS)
    _require(type(value["nativeFinality"]) is str and value["nativeFinality"] in ("pending", "settled", "unknown"))
    _require(type(value["applySubmitted"]) is bool and type(value["lateSettled"]) is bool)
    core = value["coreOutcome"]
    if core is not None:
        _require(type(core) is dict and set(core) == {"effect", "journal", "resources", "reason"})
        _require(all(type(core[key]) is str for key in ("effect", "journal", "resources", "reason"))
                 and core["effect"] in ("not_started", "unchanged", "rolled_back", "committed", "unknown")
                 and core["journal"] in ("not_created", "clean", "recovery_required", "unknown")
                 and core["resources"] in ("settled", "unknown")
                 and core["reason"] in CORE_REASONS)
    _require(not value["applySubmitted"] or value["planToken"] is not None and value["revision"] is not None)
    _require(value["phase"] not in ("reviewing", "applying") or value["planToken"] is not None and value["revision"] is not None)
    _require(value["phase"] != "final" or value["nativeFinality"] == "settled")
    # Explicit reconstruction prevents accidental future private-field spreading.
    return {"schemaVersion": 1, "domain": "required_notes", "projectId": value["projectId"],
        "windowGeneration": value["windowGeneration"], "ownerGeneration": value["ownerGeneration"],
        "sessionId": value["sessionId"], "planToken": value["planToken"], "revision": value["revision"],
        "context": context.wire(), "draftRevision": value["draftRevision"], "statusRevision": value["statusRevision"],
        "phase": value["phase"], "applySubmitted": value["applySubmitted"],
        "coreOutcome": None if core is None else {"effect": core["effect"], "journal": core["journal"],
            "resources": core["resources"], "reason": core["reason"]},
        "nativeReason": value["nativeReason"], "nativeFinality": value["nativeFinality"], "lateSettled": value["lateSettled"]}
