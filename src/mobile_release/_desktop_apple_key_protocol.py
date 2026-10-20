"""Closed local-key phases of the existing Apple saved-command protocol.

This module validates comparison DATA. It cannot attest vault absence, native
generation/custody, durable save, a current restored key or certificate consent.
"""
from __future__ import annotations

from datetime import timedelta
import json

from . import _desktop_apple_provisioning_protocol as common
from . import apple_provisioning_api as api
from ._desktop_preflight_protocol import _keys, _pairs
from ._desktop_apple_profile_protocol import key_ref
from .apple_provisioning import ProvisioningPlan, ProvisioningTarget

MODES = frozenset({"key-review", "key-prepare", "key-recover", "certificate-review", "certificate-create", "certificate-reconcile"})
LOCAL_MODES = frozenset({"key-review", "key-prepare"})
MAX_EVENTS, JSON_LIMIT = 5, 256 * 1024
STOP = b"\0"
DECISIONS = frozenset({"prepare-review", "recover-existing-key", "reuse-existing-identity", "bundle-required", "blocked", "produced", "compared"})
REASONS = frozenset({"local-key-required", "existing-certificate", "existing-key", "bundle-registration-required", "account-pending", "inventory-unavailable", "producer-returned", "stored-key-checked"})


def need(condition):
    common.require(condition)


def reference(value):
    value = _keys(value, {"operationId", "ownerGeneration"})
    need(all(common.token(part) for part in value.values()))
    return value


def context(value):
    need(type(value) is dict and value.get("mode") in MODES)
    # Reuse the exact saved iOS/P8 context grammar, not its mode/consent. New
    # key modes cannot enter that ordinary Bundle review or Store permission.
    base = dict(value)
    base.update(mode="review", reference=None, newApplication=False)
    common.context(base)
    if value["mode"] == "key-review":
        need(value["reference"] is None and value["newApplication"] is False)
    else:
        reference(value["reference"])
        need(value["newApplication"] is False)
    return dict(value)


def choice(value, selected_target):
    value = _keys(value, {"bundle", "beforeSha256", "planSha256"})
    bundle = _keys(value["bundle"], {"resourceId", "identifier", "platform", "seedId"})
    api.identifier(bundle["resourceId"])
    need(bundle["identifier"] == selected_target["bundleId"] and bundle["platform"] in {"IOS", "UNIVERSAL"}
         and bundle["seedId"] == selected_target["appIdPrefix"]
         and common.sha(value["beforeSha256"]) and common.sha(value["planSha256"]))
    return value


def validate_native(selected, native):
    scope = _keys(native["key"], {"sourceP8", "sourceKey", "destination", "entitlements", "review", "vaultInventory"})
    inventory = _keys(scope["vaultInventory"], {"records", "keys"})
    need(type(inventory["records"]) is int and 0 <= inventory["records"] <= 128
         and type(inventory["keys"]) is int and 0 <= inventory["keys"] <= inventory["records"])
    p8 = key_ref(scope["sourceP8"])
    need(p8.record_id == selected["recordId"] and p8.revision_counter == selected["recordRevision"]
         and type(scope["entitlements"]) is dict and len(api.canonical(scope["entitlements"])) <= 16 * 1024
         and native["target"]["teamId"] == native["target"]["appIdPrefix"])
    if selected["mode"] in LOCAL_MODES:
        need(scope["sourceKey"] is None)
    else:
        key = key_ref(scope["sourceKey"])
        need(key.vault_id == p8.vault_id and key.generation_id == p8.generation_id and key.record_id != p8.record_id)
    if selected["mode"] == "key-prepare":
        need(inventory["keys"] == 0)
        destination = key_ref(scope["destination"])
        need(destination.vault_id == p8.vault_id and destination.generation_id == p8.generation_id
             and destination.record_id != p8.record_id and destination.revision_counter == 1)
        review = _keys(scope["review"], {"reference", "observedAt", "validUntil", "selection"})
        need(reference(review["reference"]) == selected["reference"] and native["reviewedAt"] == review["observedAt"]
             and common.timestamp(review["validUntil"]) - common.timestamp(review["observedAt"]) == timedelta(seconds=300))
        choice(review["selection"], native["target"])
    else:
        need(scope["destination"] is None and scope["review"] is None and native["reviewedAt"] is None)
    need(native["prior"] is None)  # Certificate recovery gets a separate closed arm, never old Bundle prior.


def target(request):
    value = request.native["target"]
    return ProvisioningTarget(value["bundleId"], value["teamId"], value["appIdPrefix"], value["displayName"],
        value["existingApplication"], api.canonical(request.native["key"]["entitlements"]))


def expected_plan(request):
    need(request.context["mode"] == "key-prepare")
    review = request.native["key"]["review"]
    selected = choice(review["selection"], request.native["target"])
    row = selected["bundle"]
    bundle = api.BundleId(row["resourceId"], row["identifier"], row["platform"], row["seedId"])
    # The historical observation digest stays exactly the reviewed digest. We
    # do NOT fabricate a fresh complete observation for this local-only action.
    # The real parent rechecks the retained review and its original expiry.
    return ProvisioningPlan(common.core_context(request.native["provisioning"]), target(request), selected["beforeSha256"],
        common.timestamp(review["validUntil"]), "prepare_csr", "native_signing_key_and_csr_required", bundle=bundle)


def initial_update():
    return {"sequence": 1, "generation": "armed", "output": None, "save": "not-entered",
            "savedReference": None, "disposition": "running", "cancelRequested": False}


def output_metadata(value):
    from ._desktop_apple_distribution_key import PRIVATE_LIMIT, MAGIC
    value = _keys(value, {"frameBytes", "frameSha256", "csrSha256", "publicKeySha256"})
    need(type(value["frameBytes"]) is int and len(MAGIC) + 12 < value["frameBytes"] <= PRIVATE_LIMIT
         and all(common.sha(value[name]) for name in ("frameSha256", "csrSha256", "publicKeySha256")))
    return value


def validate_event(request, kind, payload, sequence):
    mode = request.context["mode"]
    need(mode in LOCAL_MODES)
    if kind == "key-observed":
        need(mode == "key-review" and sequence == 1)
        value = _keys(payload, {"observedAt", "validUntil", "decision", "reason", "selection"})
        need(common.timestamp(value["validUntil"]) - common.timestamp(value["observedAt"]) == timedelta(seconds=300))
        decision, reason = value["decision"], value["reason"]
        if decision == "prepare-review":
            need(reason == "local-key-required")
            choice(value["selection"], request.native["target"])
        else:
            need(value["selection"] is None and (decision, reason) in {
                ("recover-existing-key", "existing-certificate"), ("recover-existing-key", "existing-key"),
                ("reuse-existing-identity", "existing-certificate"), ("bundle-required", "bundle-registration-required"),
                ("blocked", "account-pending"), ("blocked", "inventory-unavailable")})
    elif kind == "key-pending":
        need(mode == "key-prepare" and sequence == 1)
        value = _keys(payload, {"observedAt", "validUntil", "beforeSha256", "planSha256", "update"})
        plan = expected_plan(request)
        need(value["observedAt"] == request.native["key"]["review"]["observedAt"]
             and value["validUntil"] == plan.valid_until.isoformat() and value["beforeSha256"] == plan.observation_sha256
             and value["planSha256"] == plan.sha256 and value["update"] == initial_update())
    elif kind == "key-output":
        need(mode == "key-prepare" and sequence == 2)
        output_metadata(payload)
    elif kind == "key-not-generated":
        need(mode == "key-prepare" and sequence == 2)
        value = _keys(payload, {"commands", "beforeCommand"})
        need(type(value["commands"]) is int and 6 <= value["commands"] <= 7 and type(value["beforeCommand"]) is bool
             and (not value["beforeCommand"] or value["commands"] == 6))
    else:
        need(False)
    need(len(api.canonical(payload)) <= common.EVENT_LIMIT)


def validate_result(value, request):
    value = _keys(value, {"schemaVersion", "scope", "mode", "decision", "reason", "saved", "certificateRequested", "credentialReady"})
    need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["scope"] == "local-ios-distribution-key"
         and value["mode"] == request.context["mode"] and value["mode"] in LOCAL_MODES
         and value["decision"] in DECISIONS and value["reason"] in REASONS
         and value["saved"] is False and value["certificateRequested"] is False and value["credentialReady"] is False)
    if value["mode"] == "key-prepare":
        need(value["decision"] == "produced" and value["reason"] == "producer-returned")
    else:
        need(value["decision"] in {"prepare-review", "recover-existing-key", "reuse-existing-identity", "bundle-required", "blocked"})
    return value


def reply(raw, request, sequence, expected_digest):
    need(type(raw) is bytes and 0 < len(raw) <= common.ACK_LIMIT and raw.endswith(b"\n")
         and raw.count(b"\n") == 1 and sequence in {1, 2} and common.sha(expected_digest))
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: need(False))
        value = _keys(value, {"protocol", "operationId", "ownerGeneration", "nonce", "requestSha256", "sequence", "kind", "journalRevision", "ackSha256"})
        need(value["protocol"] == common.PROTOCOL and value["operationId"] == request.operation_id
             and value["ownerGeneration"] == request.owner_generation and value["nonce"] == request.native["nonce"]
             and value["requestSha256"] == request.digest and type(value["sequence"]) is int and value["sequence"] == sequence
             and value["kind"] == ("key-pending-ack" if sequence == 1 else "key-retained")
             and type(value["journalRevision"]) is int and 0 < value["journalRevision"] <= 2**64 - 1
             and value["ackSha256"] == expected_digest)
        return value["journalRevision"], value["ackSha256"]
    except (UnicodeError, ValueError, RecursionError, TypeError):
        raise common.ProtocolError() from None
