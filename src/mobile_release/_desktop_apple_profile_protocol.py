"""Closed profile phases on the SAME Apple provisioning duplex stream.

Identity replies are native comparison DATA, not portable key/trust evidence.
Only the real operation combines the exact current P12/helper, offline chain,
fresh ASC type/DER and original native reply. No decoded object grants a save,
POST, new clock, account lease or recovered reservation.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from . import _desktop_apple_provisioning_protocol as common
from . import apple_provisioning_api as api
from . import apple_provisioning_signing as signing
from ._desktop_preflight_protocol import _keys, integer
from .apple_provisioning import CertificateBinding, NativeKeyRef, ProvisioningPlan, ProvisioningTarget
from .apple_provisioning_recovery import AttemptRecord

MODES = signing.MODES
SAVE_MODES = frozenset({"profile-reuse", "profile-create"})
MAX_EVENTS, IDENTITY_LIMIT, JSON_LIMIT = 4, 128 * 1024, 256 * 1024
CERTIFICATE_LIMIT, SPKI_LIMIT = 64 * 1024, 16 * 1024
LIMITATIONS = ["existing-p12-only", "no-key-or-certificate-creation", "no-build-or-store-release",
              "profile-scoped-offline-validation", "new-vault-record-not-assigned",
              "no-post-retry", "native-save-and-joins-required"]
DECISIONS = frozenset({"reuse-available", "create-available", "blocked", "download-returned", "creation-unconfirmed", "comparison-only"})
REASONS = frozenset({"reuse-existing-profile", "profile-create-review", "identity-required", "bundle-required", "profile-selection-required",
    "inventory-unavailable", "inventory-incomplete", "pending-setup", "capabilities-manual", "selection-changed", "profile-returned",
    "provider-unconfirmed", "same-response", "unattributed", "not-returned", "inconclusive"})
_KEY_NAMES = ("vaultId", "generationId", "recordId", "revisionId", "revisionCounter")


def need(condition):
    common.require(condition)


def key_ref(value):
    value = _keys(value, set(_KEY_NAMES))
    return NativeKeyRef(*(value[name] for name in _KEY_NAMES))


def key_wire(value):
    need(type(value) is NativeKeyRef)
    return dict(zip(_KEY_NAMES, asdict(value).values()))


def context(value):
    need(type(value) is dict and value.get("mode") in MODES)
    extra = {"p12RecordId", "p12RecordRevision"}
    need(extra <= value.keys() and common.token(value["p12RecordId"])
         and integer(value["p12RecordRevision"], 2**32 - 2, 1)
         and value.get("newApplication") is False)
    base = {name: part for name, part in value.items() if name not in extra}
    # Reuse the closed old syntax without extending ordinary Store grammars.
    base.update(mode="review", reference=None, newApplication=False)
    common.context(base)
    if value["mode"] == "profile-review":
        need(value.get("reference") is None)
    else:
        reference = _keys(value.get("reference"), {"operationId", "ownerGeneration"})
        need(all(common.token(part) for part in reference.values()))
    return dict(value)


def target(request):
    selected = common.target(request.native["target"])
    claims = request.native["signing"]["entitlements"]
    need(type(claims) is dict and len(api.canonical(claims)) <= 16 * 1024)
    return ProvisioningTarget(selected.bundle_id, selected.team_id, selected.app_id_prefix,
        selected.display_name, selected.existing_application, api.canonical(claims))


def validate_native(selected, native):
    value = _keys(native["signing"], {"sourceKey", "destination", "expectedCertificateSha256", "p12Sha256", "entitlements", "review", "prior"})
    source = key_ref(value["sourceKey"])
    need(source.record_id == selected["p12RecordId"] and source.revision_counter == selected["p12RecordRevision"]
         and common.sha(value["expectedCertificateSha256"]) and common.sha(value["p12Sha256"]))
    need(type(value["entitlements"]) is dict and len(api.canonical(value["entitlements"])) <= 16 * 1024)
    chosen = common.target(native["target"])
    need(chosen.app_id_prefix == chosen.team_id and native["prior"] is None)
    if selected["mode"] in SAVE_MODES:
        destination = key_ref(value["destination"])
        need(destination.vault_id == source.vault_id and destination.generation_id == source.generation_id
             and destination.record_id != source.record_id and destination.revision_id != source.revision_id
             and destination.revision_counter == 1)
        review = _keys(value["review"], {"reference", "observedAt", "validUntil", "selection"})
        need(review["reference"] == selected["reference"] and native["reviewedAt"] == review["observedAt"])
        observed, until = common.timestamp(review["observedAt"]), common.timestamp(review["validUntil"])
        need(until - observed == timedelta(seconds=300))
        selection(review["selection"], native["target"])
        need(review["selection"]["action"] == ("reuse-download" if selected["mode"] == "profile-reuse" else "create-profile"))
    else:
        need(value["destination"] is None and value["review"] is None and native["reviewedAt"] is None)
    if selected["mode"] == "profile-reconcile":
        # The parent has already validated the entire schema2 row against its
        # SAME initial AccountSnapshot. This second fixed comparison cannot
        # adopt it, issue an ACK or clear any native/provider/save uncertainty.
        prior = _keys(value["prior"], {"reference", "sourceKey", "target", "profileResourceId", "profileName", "profileSha256"})
        need(prior["reference"] == selected["reference"] and key_ref(prior["sourceKey"]) == source
             and prior["target"] == {**native["target"], "entitlementsSha256": api.digest(api.canonical(value["entitlements"]))})
        api._name(prior["profileName"])
        if prior["profileResourceId"] is not None:
            api.identifier(prior["profileResourceId"])
        need(prior["profileSha256"] is None or common.sha(prior["profileSha256"]))
    else:
        need(value["prior"] is None)


def _base64(value, limit):
    need(type(value) is str and value.isascii() and 0 < len(value) <= 4 * ((limit + 2) // 3))
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise common.ProtocolError() from None
    need(0 < len(raw) <= limit and base64.b64encode(raw).decode("ascii") == value)
    return raw


def identity_payload(request, leaf, spki, chain, checked_at):
    need(type(leaf) is bytes and type(spki) is bytes and type(chain) is tuple and 1 <= len(chain) <= 8)
    value = {"certificateDer": base64.b64encode(leaf).decode("ascii"),
        "publicKeySpkiDer": base64.b64encode(spki).decode("ascii"),
        "chainSha256": [api.digest(part) for part in chain], "chainCheckedAt": checked_at.isoformat(),
        "sourceKey": request.native["signing"]["sourceKey"], "p12Sha256": request.native["signing"]["p12Sha256"]}
    validate_identity(request, value)
    return value


def validate_identity(request, value):
    value = _keys(value, {"certificateDer", "publicKeySpkiDer", "chainSha256", "chainCheckedAt", "sourceKey", "p12Sha256"})
    leaf, spki = _base64(value["certificateDer"], CERTIFICATE_LIMIT), _base64(value["publicKeySpkiDer"], SPKI_LIMIT)
    need(api.digest(leaf) == request.native["signing"]["expectedCertificateSha256"]
         and value["sourceKey"] == request.native["signing"]["sourceKey"]
         and value["p12Sha256"] == request.native["signing"]["p12Sha256"]
         and type(value["chainSha256"]) is list and 1 <= len(value["chainSha256"]) <= 8
         and all(common.sha(part) for part in value["chainSha256"])
         and len(set(value["chainSha256"])) == len(value["chainSha256"]))
    common.timestamp(value["chainCheckedAt"])
    return leaf, spki


def identity_reply(raw, request, payload):
    value = _reply_envelope(raw, request, 1, "identity-ack")
    result = _keys(value["payload"], {"identitySha256", "certificateSha256", "publicKeySha256", "teamId", "notBefore", "notAfter", "checkedAt"})
    leaf, spki = validate_identity(request, payload)
    need(result["identitySha256"] == api.digest(api.canonical(payload)) and result["certificateSha256"] == api.digest(leaf)
         and result["publicKeySha256"] == api.digest(spki) and result["teamId"] == request.native["target"]["teamId"]
         and all(integer(result[name], 253402300799, 1) for name in ("notBefore", "notAfter", "checkedAt"))
         and result["notBefore"] <= result["checkedAt"] < result["notAfter"])
    # Native captures the wall clock, but it does not renew the original
    # monotonic work/deadline; the caller checks those immediately on receipt.
    return dict(result)


def _reply_envelope(raw, request, sequence, kind):
    need(type(raw) is bytes and 0 < len(raw) <= common.ACK_LIMIT and raw.endswith(b"\n") and raw.count(b"\n") == 1)
    value = _keys(api.document(raw), {"protocol", "operationId", "ownerGeneration", "nonce", "requestSha256", "kind", "step", "payload"})
    need(value["protocol"] == common.PROTOCOL and value["operationId"] == request.operation_id
         and value["ownerGeneration"] == request.owner_generation and value["nonce"] == request.native["nonce"]
         and value["requestSha256"] == request.digest and value["kind"] == kind
         and type(value["step"]) is int and value["step"] == sequence)
    return value


def journal_reply(raw, request, sequence, update):
    value = _reply_envelope(raw, request, sequence, "journal-ack")
    result = _keys(value["payload"], {"revision", "sequence", "recordSha256"})
    need(integer(result["revision"], 2**64 - 1, 1) and type(result["sequence"]) is int
         and result["sequence"] == update["sequence"] == sequence - 1
         and result["recordSha256"] == api.digest(api.canonical(update)))
    return result["revision"], api.digest(api.canonical(value))


def profile_wire(profile):
    need(type(profile) is api.Profile and len(profile.certificate_resources) == 1)
    return {"resourceId": profile.resource_id, "name": profile.name, "uuid": profile.uuid,
        "createdAt": profile.created_at.isoformat(), "expiresAt": profile.expires_at.isoformat(),
        "bundleIdResource": profile.bundle_id_resource, "certificateResource": profile.certificate_resources[0]}


def selection(value, target_value):
    value = _keys(value, {"action", "bundle", "certificate", "profile", "planSha256", "requestBodySha256"})
    need(value["action"] in {"reuse-download", "create-profile"} and common.sha(value["planSha256"]))
    bundle = _keys(value["bundle"], {"resourceId", "identifier", "platform", "seedId"})
    api.identifier(bundle["resourceId"])
    need(bundle["identifier"] == target_value["bundleId"] and bundle["platform"] in {"IOS", "UNIVERSAL"}
         and bundle["seedId"] == target_value["appIdPrefix"])
    certificate = _keys(value["certificate"], {"resourceId", "certificateType", "notBefore", "expiresAt", "certificateSha256", "publicKeySha256"})
    api.identifier(certificate["resourceId"])
    need(certificate["certificateType"] in api.CERTIFICATE_TYPES and common.sha(certificate["certificateSha256"])
         and common.sha(certificate["publicKeySha256"])
         and common.timestamp(certificate["notBefore"]) < common.timestamp(certificate["expiresAt"]))
    if value["action"] == "reuse-download":
        row = _keys(value["profile"], {"resourceId", "name", "uuid", "createdAt", "expiresAt", "bundleIdResource", "certificateResource"})
        api.identifier(row["resourceId"]); api._name(row["name"])
        need(type(row["uuid"]) is str and api.UUID_RE.fullmatch(row["uuid"]) is not None and row["uuid"].upper() == row["uuid"]
             and row["bundleIdResource"] == bundle["resourceId"] and row["certificateResource"] == certificate["resourceId"]
             and common.timestamp(row["createdAt"]) < common.timestamp(row["expiresAt"]) and value["requestBodySha256"] is None)
    else:
        need(value["profile"] is None and common.sha(value["requestBodySha256"]))
    return value


def selection_wire(plan):
    need(type(plan) is ProvisioningPlan and plan.action in {"download_profile", "create_profile"}
         and type(plan.binding) is CertificateBinding and plan.bundle is not None and plan.certificate is not None)
    bundle, certificate, binding = plan.bundle, plan.certificate, plan.binding
    return {"action": "reuse-download" if plan.action == "download_profile" else "create-profile",
        "bundle": {"resourceId": bundle.resource_id, "identifier": bundle.identifier, "platform": bundle.platform, "seedId": bundle.seed_id},
        "certificate": {"resourceId": certificate.resource_id, "certificateType": certificate.certificate_type,
            "notBefore": binding.not_before.isoformat(), "expiresAt": certificate.expires_at.isoformat(),
            "certificateSha256": binding.certificate_sha256, "publicKeySha256": binding.public_key_sha256},
        "profile": None if plan.profile is None else profile_wire(plan.profile), "planSha256": plan.sha256,
        "requestBodySha256": api.digest(plan.request.body) if plan.request.body is not None else None}


def same_choice(left, right):
    # A fresh operation changes its context/plan hash; creation's name is also
    # operation-derived. The explicit review still binds its exact resources.
    return all(left[name] == right[name] for name in ("action", "bundle", "certificate", "profile"))


def record_wire(record):
    need(type(record) is AttemptRecord and record.action == "create_profile")
    return {**dict(zip(common._RECORD_NAMES, asdict(record).values())), "context": common.core_context_wire(record.context)}


def validate_update(request, value, sequence):
    value = _keys(value, {"sequence", "provider", "download", "save", "savedReference", "cancelRequested"})
    need(type(value["sequence"]) is int and value["sequence"] == sequence - 1 and 2 <= sequence <= MAX_EVENTS
         and value["save"] == "not-entered" and value["savedReference"] is None and type(value["cancelRequested"]) is bool)
    provider = value["provider"]
    need(type(provider) is dict)
    if request.context["mode"] == "profile-create":
        provider = _keys(provider, {"kind", "record"}); need(provider["kind"] == "creation")
        record = _keys(provider["record"], set(common._RECORD_NAMES))
        need(common.core_context(record["context"]) == common.core_context(request.native["provisioning"])
             and common.sha(record["planSha256"]) and record["action"] == "create_profile"
             and record["status"] in common.ATTEMPT_STATUSES and record["reason"] in common.ATTEMPT_REASONS
             and type(record["possibleSend"]) is bool and type(record["cancelRequested"]) is bool)
        for name in ("responseResourceId", "observedResourceId"):
            if record[name] is not None:
                api.identifier(record[name])
        need(record["responseResourceSha256"] is None if record["responseResourceId"] is None else common.sha(record["responseResourceSha256"]))
        if sequence == 2:
            need(record["status"] == "running" and record["reason"] == "readback_required" and record["possibleSend"] is True
                 and record["responseResourceId"] is None and record["observedResourceId"] is None and value["download"] is None)
    else:
        provider = _keys(provider, {"kind"})
        need(request.context["mode"] == "profile-reuse" and provider["kind"] in ({"download-pending"} if sequence == 2 else
                {"download-returned", "download-refused", "download-unknown"}))
    if value["download"] is not None:
        row = _keys(value["download"], {"profile", "bytes", "sha256"})
        need(integer(row["bytes"], signing.PROFILE_LIMIT, 1) and common.sha(row["sha256"]))
        # The native journal validates exact selected bundle/certificate/profile
        # and transition continuity again before its durable ACK.
        p = row["profile"]
        need(type(p) is dict and set(p) == {"resourceId", "name", "uuid", "createdAt", "expiresAt", "bundleIdResource", "certificateResource"})
        api.identifier(p["resourceId"]); api._name(p["name"])


def validate_event(request, kind, payload, sequence):
    need(request.context["mode"] in MODES and integer(sequence, MAX_EVENTS, 1))
    if sequence == 1:
        need(kind == "identity"); validate_identity(request, payload); return
    if request.context["mode"] not in SAVE_MODES:
        need(sequence == 2 and kind == "profile-observed")
        payload = _keys(payload, {"observedAt", "validUntil", "beforeSha256", "available", "relationshipsComplete", "decision", "reason", "selection"})
        before, until = common.timestamp(payload["observedAt"]), common.timestamp(payload["validUntil"])
        need(until - before == timedelta(seconds=300) and common.sha(payload["beforeSha256"])
             and type(payload["available"]) is bool and type(payload["relationshipsComplete"]) is bool
             and payload["decision"] in DECISIONS and payload["reason"] in REASONS)
        if payload["selection"] is not None:
            need(payload["available"]); selection(payload["selection"], request.native["target"])
        return
    need(kind == ("profile-pending" if sequence == 2 else "profile-attempt"))
    if sequence == 2:
        payload = _keys(payload, {"observedAt", "validUntil", "beforeSha256", "selection", "update"})
        need(common.timestamp(payload["validUntil"]) - common.timestamp(payload["observedAt"]) == timedelta(seconds=300)
             and common.sha(payload["beforeSha256"]))
        selection(payload["selection"], request.native["target"])
        need(same_choice(payload["selection"], request.native["signing"]["review"]["selection"]))
    else:
        payload = _keys(payload, {"update"})
    validate_update(request, payload["update"], sequence)


def validate_result(value, request):
    value = _keys(value, {"schemaVersion", "scope", "mode", "decision", "reason", "bundleId", "profileResourceId", "profileUUID",
                          "saved", "credentialReady", "cancellationRequested", "limitations"})
    need(value["schemaVersion"] == 1 and type(value["schemaVersion"]) is int and value["scope"] == "local-ios-profile-setup"
         and value["mode"] == request.context["mode"] and value["decision"] in DECISIONS and value["reason"] in REASONS
         and value["bundleId"] == request.native["target"]["bundleId"] and value["saved"] is False and value["credentialReady"] is False
         and type(value["cancellationRequested"]) is bool and value["limitations"] == LIMITATIONS)
    if value["profileResourceId"] is not None:
        api.identifier(value["profileResourceId"])
        need(type(value["profileUUID"]) is str and api.UUID_RE.fullmatch(value["profileUUID"]) is not None)
    else:
        need(value["profileUUID"] is None)
    if value["decision"] == "download-returned":
        need(request.context["mode"] in SAVE_MODES and value["profileResourceId"] is not None)
