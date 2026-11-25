"""Pure retained-evidence layout; no workflow, transport or filesystem owner.

The workflow keeps its public WorkflowError validation boundary. Passive
readers independently admit a closed stage and inspect only the JSON projection.
"""
from __future__ import annotations

from .provenance import WORKFLOW_PATHS

STAGES = tuple(WORKFLOW_PATHS)


def evidence_layout(stage: str, phase: str, prefix: str = "") -> dict[str, str]:
    if stage not in STAGES or phase not in {"intent", "final"}:
        raise ValueError("invalid evidence layout")
    if phase == "final":
        result = {
            prefix + "workflow-provenance.json": "final-provenance",
            prefix + f"{stage}-receipt.json": "final-receipt",
            prefix + "store-receipt.json": "raw-store-readback",
        }
        if stage == "candidate":
            result[prefix + "candidate-manifest.json"] = "candidate-manifest"
        result.update(evidence_layout(stage, "intent", prefix + "operation/"))
        return result
    result = {
        prefix + f"{stage}-operation-intent.json": "operation-intent",
        prefix + "intent-provenance.json": "intent-provenance",
    }
    if stage == "candidate":
        result[prefix + "store-metadata.zip"] = "candidate-store-metadata"
    if stage != "candidate":
        result.update({path: "candidate/" + role for path, role in
                       evidence_layout("candidate", "final", prefix + "candidate/").items()})
    if stage == "production-submit":
        result.update({path: "external/" + role for path, role in
                       evidence_layout("external-testing", "final", prefix + "external/").items()})
    return result


def evidence_document_paths(stage: str) -> tuple[str, ...]:
    """Fixed selected JSON projection, NOT the complete authenticated inventory."""
    return tuple(path for path, role in evidence_layout(stage, "final").items()
                 if role.rsplit("/", 1)[-1] in {"candidate-manifest", "final-receipt", "operation-intent"})
