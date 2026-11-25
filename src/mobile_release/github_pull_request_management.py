"""Historical closure of an acknowledged PR, never a second POST authority.

The original PR operation still owns authentication, its finite HTTP schedule,
the private journal, and every close. A saved closure is only a historical fact:
new creation must repeat the existing fresh open-PR query and explicit consent.
"""
from __future__ import annotations

from . import github_pull_request as p
from ._github_connection_transport import ReadFailure, _control
from .api._github_connection import _utc


def closed_observation(value: object, acknowledged: dict) -> dict:
    row = p.obj(value, {"id", "number", "closedAt", "merged"})
    p.require(row["id"] == acknowledged["id"] and row["number"] == acknowledged["number"]
              and type(row["merged"]) is bool)
    _utc(row["closedAt"])
    return dict(row)


def closure_leaf(value: object, prepared: p.Prepared, intent_sha256: str,
                 receipt_sha256: str, acknowledged: dict) -> dict:
    """Validate a complete immutable sidecar against its actual held receipts."""
    row = p.obj(value, {"protocol", "intentSha256", "receiptSha256", "closed"})
    p.require(row["protocol"] == p.PROTOCOL
              and row["intentSha256"] == p.hex_text(intent_sha256, 64)
              and row["receiptSha256"] == p.hex_text(receipt_sha256, 64))
    ack = p.acknowledgement(acknowledged, prepared)
    return closed_observation(row["closed"], ack)


def closed_from_reply(value: object, prepared: p.Prepared, acknowledged: dict) -> dict:
    # An actual stored 201 ID/number is essential. A matching branch pair,
    # correlation marker, browser URL, or a 404 can never replace that receipt.
    ack = p.acknowledgement(acknowledged, prepared)
    p.need(p._ack(value, prepared) == ack, "target-changed")
    p.need(value.get("state") == "closed", "unresolved")
    return closed_observation({"id": ack["id"], "number": ack["number"],
                               "closedAt": value.get("closed_at"), "merged": value.get("merged")}, ack)


def reconcile_acknowledged(original: dict, exchange, journal) -> dict:
    """One fresh GET-only reconciliation, on the existing original PR owner.

    Legitimate edits, conversion from draft, merging, and moved commit SHAs do
    not change the immutable acknowledged identity. Its repository IDs and
    original base/head repository+ref must still match. No provider CAS is
    inferred from these sequential reads.
    """
    prepared = p.Prepared.parse(original["prepared"])
    ack = p.acknowledgement(original["acknowledged"], prepared)
    p.require(original["claimed"] is True)
    op = p.Operation(prepared.target, exchange)
    result = {"effect": "unresolved", "reason": "unresolved", "claimed": True,
              "acknowledged": ack, "observed": None, "control": _control()}
    try:
        op.identity()
        raw = op.take("readback", op.base + "/pulls/" + ack["number"])
        if raw.get("state") == "closed":
            closed = closed_from_reply(raw, prepared, ack)
            op.repository("repository-after")
            p.need(journal is not None, "journal-unavailable")
            # This creates a new fixed leaf, never edits/deletes an intent,
            # claim or receipt. The custodian checks the original held record.
            journal.record_closed(prepared.value(), closed)
            result.update(effect="closed-confirmed", reason="none", observed=ack)
        else:
            observed = p._observed(raw, prepared)
            p.need(observed == ack, "target-changed")
            op.repository("repository-after")
            result.update(effect="created-observed", reason="none", observed=ack)
    except (p.Refused, ReadFailure) as error:
        result["reason"] = error.reason
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
        result["reason"] = "response-invalid"
    except OSError:
        result["reason"] = "journal-unavailable"
    result["control"] = op.control
    return result
