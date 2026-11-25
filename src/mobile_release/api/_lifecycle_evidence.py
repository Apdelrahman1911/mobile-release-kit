"""Bounded local recorded history, never authenticated history or recovery power."""
from __future__ import annotations

from typing import Any, cast

from ..errors import ValidationError
from ..evidence_layout import STAGES, evidence_document_paths
from ..provenance import external_production_blocker, validate_receipt_chain
from . import _candidate_evidence as candidate, _snapshot
from .contracts import ApiError, LifecycleEvidenceGuidance, LifecycleEvidenceResult

MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 6 * 1024 * 1024
MAX_TOTAL_NODES = 60_000
_GUIDANCE = {
    "evidence-invalid": "Some saved documents are invalid. Recovery is undetermined; no retry or release is approved.",
    "evidence-incomplete": "Expected saved documents are missing. This does not prove that no Store operation occurred. Recovery is undetermined.",
    "evidence-inconsistent": "The saved documents disagree. Keep the original evidence; this inspection cannot approve recovery or a retry.",
    "candidate-only": "Only candidate evidence was supplied. Later stages and recovery remain undetermined; these saved documents do not approve another operation.",
    "recorded-external-gate": "The saved external receipt satisfies the recorded external-to-production predicate only. Workflow authenticity, current configuration and live Store state are unverified; no release or retry is approved.",
    "production-recorded": "A production receipt is recorded in this local chain. It is not a live Store observation or proof of publication, and does not approve replay or recovery.",
}
_ERRORS = {code: message.replace("Candidate evidence", "Release evidence").replace("candidate evidence", "release evidence")
           for code, message in candidate._ERRORS.items()}


def _guidance(code: str, message: str | None = None) -> LifecycleEvidenceGuidance:
    return cast(LifecycleEvidenceGuidance, {"code": code, "message": message if message is not None else _GUIDANCE[code]})


def _params(params: object) -> tuple[str, tuple[int, ...], str]:
    if (type(params) is not dict or any(type(key) is not str for key in params)
            or set(params) != {"root", "expectedRoot", "stage"}
            or type(params["stage"]) is not str or params["stage"] not in STAGES):
        candidate._refuse("invalid_params")
    root, expected = candidate._params({"root": params["root"], "expectedRoot": params["expectedRoot"]})
    return root, expected, params["stage"]


def _read_outcome(stage: str, reader: _snapshot._NamedTextReads,
                  inventory: _snapshot._Inventory) -> LifecycleEvidenceResult:
    documents: dict[str, dict[str, Any]] = {}
    payloads: dict[str, dict[str, Any]] = {}
    original_text: dict[str, str] = {}
    rows = []
    total_nodes = 0
    for relative in evidence_document_paths(stage):
        # Leave the ordinary reader's 8MiB ceiling/defaults untouched. Even a
        # limit+1 growth probe stays below it; exact limits still require EOF.
        remaining = MAX_TOTAL_BYTES - inventory.counts["sourceBytes"]
        if remaining < 0:
            raise candidate._Refusal("artifacts_limit")
        text = reader.read(relative, limit=min(MAX_DOCUMENT_BYTES, remaining))
        if inventory.counts["sourceBytes"] > MAX_TOTAL_BYTES:
            raise candidate._Refusal("artifacts_limit")
        row = {"path": relative, "state": "missing"}
        rows.append(row)
        if text is None:
            continue
        row["state"] = "invalid"
        try:
            document, count = candidate._decoded_document(text, inventory)
            # Charge every decoded copy BEFORE any kind/schema rejection.
            total_nodes += count
            if total_nodes > MAX_TOTAL_NODES:
                raise candidate._Refusal("artifacts_limit")
            if type(document) is not dict:
                raise candidate._InvalidDocument()
            name = relative.rsplit("/", 1)[-1]
            if name == "candidate-manifest.json":
                kind, document_type, version, expected_stage = "manifest", "candidate-manifest", 2, "candidate"
            elif name.endswith("-operation-intent.json"):
                kind, document_type, version, expected_stage = "intent", "store-operation-intent", 1, name[:-22]
            else:
                kind, document_type, version, expected_stage = "receipt", "store-receipt", 3, name[:-13]
            payload = candidate._validate(document, kind, document_type, version, inventory, stage=expected_stage)
        except (candidate._InvalidDocument, ValidationError):
            candidate._tick(inventory)
            continue
        documents[relative], payloads[relative], original_text[relative] = document, payload, text
        row["state"] = "valid"

    result = cast(LifecycleEvidenceResult, {"schemaVersion": 1, "stage": stage, "outcome": "invalid",
        "documents": rows, "summary": None, "history": [], "guidance": _guidance("evidence-invalid"),
        "assurance": candidate._assurance()})
    if any(row["state"] == "invalid" for row in rows):
        return result
    if any(row["state"] == "missing" for row in rows):
        result.update(outcome="incomplete", guidance=_guidance("evidence-incomplete"))
        return result

    prefix = "" if stage == "candidate" else "operation/candidate/"
    selected = {kind: documents[prefix + path] for kind, path, _, _ in candidate.DOCUMENTS}
    manifest = payloads[prefix + "candidate-manifest.json"]
    platform = next(iter(manifest["platforms"]))
    arguments: dict[str, Any] = {"candidate_manifest": selected["manifest"], "candidate_receipt": selected["receipt"],
        "candidate_intent": selected["intent"], "platform": platform, "config": None}
    stage_roots = [("candidate", prefix)]
    if stage != "candidate":
        external_prefix = "" if stage == "external-testing" else "operation/external/"
        arguments.update(external_receipt=documents[external_prefix + "external-testing-receipt.json"],
                         external_intent=documents[external_prefix + "operation/external-testing-operation-intent.json"])
        stage_roots.append(("external-testing", external_prefix))
    if stage == "production-submit":
        arguments.update(production_receipt=documents["production-submit-receipt.json"],
                         production_intent=documents["operation/production-submit-operation-intent.json"])
        stage_roots.append((stage, ""))
        if any(original_text[prefix + path] != original_text["operation/external/operation/candidate/" + path]
               for _, path, _, _ in candidate.DOCUMENTS):
            result.update(outcome="inconsistent", guidance=_guidance("evidence-inconsistent"))
            return result
    candidate._tick(inventory)
    try:
        validate_receipt_chain(**arguments)
    except ValidationError:
        result.update(outcome="inconsistent", guidance=_guidance("evidence-inconsistent"))
        candidate._tick(inventory)
        return result
    candidate._tick(inventory)
    result["summary"] = candidate._summary(manifest, selected)
    for recorded_stage, base in stage_roots:
        receipt = documents[base + recorded_stage + "-receipt.json"]
        result["history"].append({"stage": recorded_stage, "recordedOutcome": receipt["outcome"],
            "recordedReadback": candidate._display_text(receipt["readback"]["state"], characters=64, byte_limit=256),
            "recordedRuns": {role: {"runId": candidate._decimal(receipt[role]["runId"]),
                                     "attempt": candidate._decimal(receipt[role]["attempt"])}
                             for role in ("authorizedBy", "executedBy", "producedBy")},
            "receiptSha256": candidate._digest(receipt["integrity"]["sha256"]),
            "intentSha256": candidate._digest(receipt["operationIntentSha256"]),
            "previousReceiptSha256": None if recorded_stage == "candidate" else candidate._digest(receipt["previousReceiptSha256"])})
    code = "candidate-only" if stage == "candidate" else "production-recorded" if stage == "production-submit" else "recorded-external-gate"
    guidance = _guidance(code)
    if stage == "external-testing":
        blocker = external_production_blocker(arguments["external_receipt"], platform=platform)
        if blocker is not None:
            guidance = _guidance(*blocker)
    result.update(outcome="consistent", guidance=guidance)
    candidate._tick(inventory)
    return result


def observe_lifecycle_evidence(params: object) -> LifecycleEvidenceResult:
    try:
        root, expected, stage = _params(params)
        return cast(LifecycleEvidenceResult, candidate._observe_selected_evidence(
            root, expected, lambda reader, inventory: _read_outcome(stage, reader, inventory)))
    except ApiError as error:
        code = error.code if error.code in _ERRORS else "artifacts_unavailable"
        raise ApiError(code, _ERRORS[code]) from None
