"""Closed certificate-only DATA on the existing Apple duplex owner.

No parsed key history, request hash, identity ACK or offline result is an
original key loan, journal reservation, native join or portable trust token.
Old Bundle/Profile/local-key grammars and frame limits remain independent.
"""
from __future__ import annotations

import base64
from dataclasses import asdict
from datetime import timedelta

from . import _desktop_apple_provisioning_protocol as common
from . import _desktop_apple_profile_protocol as profile
from . import apple_provisioning_api as api
from . import apple_provisioning_certificate_issuance as issuance
from ._desktop_preflight_protocol import _keys, integer
from .apple_provisioning import NativeKeyRef, ProvisioningTarget

MODES = frozenset({"certificate-review", "certificate-create", "certificate-reconcile"})
EVENTS, IDENTITY_LIMIT, IDENTITIES_LIMIT, OUTPUT_LIMIT = 12, 256 * 1024, 512 * 1024, 768 * 1024
CERTIFICATES, CERTIFICATE_BYTES, BATCH_DER_BYTES = 32, 64 * 1024, 128 * 1024
RAW_TOTAL_LIMIT = 1024 * 1024
ROOT_SHA256 = "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"
INTERMEDIATE_SHA256 = "dcf21878c77f4198e4b4614f03d696d89c66c66008d4244e1b99161aac91601f"
KEYS = ("certificate-key", "certificate-identities", "certificate-policy", "certificate-observed",
        "certificate-pending", "certificate-attempt")
BLOCK_REASONS = frozenset({"account-pending", "inventory-unavailable", "key-history-unavailable", "policy-unavailable",
                         "existing-certificate-needs-key", "bundle-registration-required"})
COMPARISONS = frozenset({"same-response", "different-response", "unattributed", "not-returned", "inconclusive"})

need = common.require
key_ref = profile.key_ref


def context(value):
    need(type(value) is dict and value.get("mode") in MODES)
    extra = {"keyRecordId", "keyRecordRevision"}
    need(extra <= value.keys() and common.token(value["keyRecordId"])
         and integer(value["keyRecordRevision"], 2**32 - 2, 1) and value.get("newApplication") is False)
    base = {name: item for name, item in value.items() if name not in extra}
    base.update(mode="review", reference=None)
    common.context(base)  # Does not opt the old Store access grammar into this mode.
    if value["mode"] == "certificate-review":
        need(value.get("reference") is None)
    else:
        reference = _keys(value.get("reference"), {"operationId", "ownerGeneration"})
        need(all(common.token(item) for item in reference.values()))
    return dict(value)


def target(request):
    selected = common.target(request.native["target"])
    claims = request.native["certificate"]["entitlements"]
    need(type(claims) is dict and len(api.canonical(claims)) <= 16 * 1024)
    return ProvisioningTarget(selected.bundle_id, selected.team_id, selected.app_id_prefix,
        selected.display_name, selected.existing_application, api.canonical(claims))


def choice(value, selected_target):
    value = _keys(value, {"bundle", "beforeSha256", "planSha256", "csrSha256", "publicKeySha256"})
    bundle = _keys(value["bundle"], {"resourceId", "identifier", "platform", "seedId"})
    api.identifier(bundle["resourceId"])
    need(bundle["identifier"] == selected_target["bundleId"] and bundle["platform"] in {"IOS", "UNIVERSAL"}
         and bundle["seedId"] == selected_target["appIdPrefix"]
         and all(common.sha(value[name]) for name in ("beforeSha256", "planSha256", "csrSha256", "publicKeySha256")))
    return value


def record(value, expected_context=None, expected_plan=None):
    value = _keys(value, set(common._RECORD_NAMES))
    parsed = common.core_context(value["context"])
    need((expected_context is None or parsed == expected_context) and common.sha(value["planSha256"])
         and (expected_plan is None or value["planSha256"] == expected_plan) and value["action"] == "create_certificate"
         and value["status"] in common.ATTEMPT_STATUSES and value["reason"] in common.ATTEMPT_REASONS
         and type(value["possibleSend"]) is bool and type(value["cancelRequested"]) is bool)
    for name in ("responseResourceId", "observedResourceId"):
        if value[name] is not None:
            api.identifier(value[name])
    need(value["responseResourceSha256"] is None or common.sha(value["responseResourceSha256"]))
    return value


def validate_native(selected, native):
    value = _keys(native["certificate"], {"sourceP8", "sourceKey", "entitlements", "keyPreparation", "review", "prior"})
    source, p8 = key_ref(value["sourceKey"]), key_ref(value["sourceP8"])
    need(source.record_id == selected["keyRecordId"] and source.revision_counter == selected["keyRecordRevision"]
         and p8.record_id == selected["recordId"] and p8.revision_counter == selected["recordRevision"]
         and source.vault_id == p8.vault_id and source.generation_id == p8.generation_id and source.record_id != p8.record_id
         and type(value["entitlements"]) is dict and len(api.canonical(value["entitlements"])) <= 16 * 1024
         and native["target"]["appIdPrefix"] == native["target"]["teamId"] and native["prior"] is None)
    history = value["keyPreparation"]
    if history is not None:
        history = _keys(history, {"reference", "sourceKey", "accountRef", "teamId", "csrSha256", "publicKeySha256", "updateSha256"})
        reference = _keys(history["reference"], {"operationId", "ownerGeneration"})
        need(all(common.token(item) for item in reference.values()) and history["sourceKey"] == value["sourceKey"]
             and history["accountRef"] == native["provisioning"]["accountRef"] and history["teamId"] == native["target"]["teamId"]
             and all(common.sha(history[name]) for name in ("csrSha256", "publicKeySha256", "updateSha256")))
    if selected["mode"] == "certificate-create":
        review = _keys(value["review"], {"reference", "observedAt", "validUntil", "selection"})
        need(history is not None and review["reference"] == selected["reference"] and native["reviewedAt"] == review["observedAt"]
             and common.timestamp(review["validUntil"]) - common.timestamp(review["observedAt"]) == timedelta(seconds=300))
        choice(review["selection"], native["target"])
        need(all(review["selection"][name] == history[name] for name in ("csrSha256", "publicKeySha256")))
    else:
        need(value["review"] is None and native["reviewedAt"] is None)
    if selected["mode"] == "certificate-reconcile":
        prior = _keys(value["prior"], {"reference", "sourceKey", "target", "csrSha256", "publicKeySha256", "record", "receipt"})
        need(prior["reference"] == selected["reference"] and prior["sourceKey"] == value["sourceKey"]
             and prior["target"] == {**native["target"], "entitlementsSha256": api.digest(api.canonical(value["entitlements"]))}
             and common.sha(prior["csrSha256"]) and common.sha(prior["publicKeySha256"]))
        previous = record(prior["record"])
        need(previous["context"]["operationId"] == prior["reference"]["operationId"]
             and previous["context"]["accountRef"] == native["provisioning"]["accountRef"])
        receipt(prior["receipt"], previous)
    else:
        need(value["prior"] is None)


def receipt(value, previous):
    if value is None:
        need(previous["responseResourceId"] is None and previous["responseResourceSha256"] is None)
        return None
    result = issuance.CertificateCreationReceipt.from_private_record(api.canonical(value))
    need(result.resource_id == previous["responseResourceId"] and result.sha256 == previous["responseResourceSha256"])
    return result


def key_payload(request, csr, spki):
    need(type(csr) is bytes and 0 < len(csr) <= 4096 and csr.isascii()
         and type(spki) is bytes and 0 < len(spki) <= 1024)
    value = {"sourceKey": request.native["certificate"]["sourceKey"], "csrPem": csr.decode("ascii"),
        "publicKeySpkiDer": base64.b64encode(spki).decode("ascii"), "csrSha256": api.digest(csr), "publicKeySha256": api.digest(spki)}
    validate_key(request, value)
    return value


def validate_key(request, value):
    value = _keys(value, {"sourceKey", "csrPem", "publicKeySpkiDer", "csrSha256", "publicKeySha256"})
    need(value["sourceKey"] == request.native["certificate"]["sourceKey"] and type(value["csrPem"]) is str
         and value["csrPem"].isascii() and 0 < len(value["csrPem"]) <= 4096
         and value["csrPem"].startswith("-----BEGIN CERTIFICATE REQUEST-----\n")
         and value["csrPem"].endswith("-----END CERTIFICATE REQUEST-----\n")
         and api.digest(value["csrPem"].encode("ascii")) == value["csrSha256"])
    spki = profile._base64(value["publicKeySpkiDer"], 1024)
    need(api.digest(spki) == value["publicKeySha256"])
    return spki


def candidates_payload(request, inventory, platforms, batch, public_key_sha256):
    certificates = inventory.observation.certificates
    need(len(certificates) <= CERTIFICATES and sum(len(row.content) for row in certificates) <= BATCH_DER_BYTES)
    value = {"batch": batch, "sourceKey": request.native["certificate"]["sourceKey"], "publicKeySha256": public_key_sha256,
        "certificates": [{"resourceId": row.resource_id, "certificateType": row.certificate_type,
            "platform": platforms[row.resource_id], "expiresAt": row.expires_at.isoformat(),
            "certificateDer": base64.b64encode(row.content).decode("ascii")} for row in certificates]}
    validate_candidates(request, value)
    return value


def validate_candidates(request, value):
    value = _keys(value, {"batch", "sourceKey", "publicKeySha256", "certificates"})
    need(type(value["batch"]) is int and value["batch"] in (1, 2) and (value["batch"] == 1 or request.context["mode"] == "certificate-create")
         and value["sourceKey"] == request.native["certificate"]["sourceKey"] and common.sha(value["publicKeySha256"])
         and type(value["certificates"]) is list and len(value["certificates"]) <= CERTIFICATES)
    seen, total, values = set(), 0, []
    for row in value["certificates"]:
        row = _keys(row, {"resourceId", "certificateType", "platform", "expiresAt", "certificateDer"})
        identity = api.identifier(row["resourceId"])
        need(identity not in seen and row["certificateType"] in api.CERTIFICATE_TYPES and row["platform"] in {"IOS", "UNIVERSAL"})
        seen.add(identity)
        common.timestamp(row["expiresAt"])
        der = profile._base64(row["certificateDer"], CERTIFICATE_BYTES)
        total += len(der)
        need(total <= BATCH_DER_BYTES)
        values.append((identity, der))
    need(len(api.canonical(value)) <= IDENTITY_LIMIT)
    return values


def validate_policy(value):
    value = _keys(value, {"schemaVersion", "scope", "requestBindingSha256", "identityAckSha256", "certificateSha256",
                         "publicKeySha256", "teamId", "revocationChecked", "checkedAt", "chainSha256"})
    need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["scope"] == "offline-apple-distribution-certificate" and value["revocationChecked"] is False
         and all(common.sha(value[name]) for name in ("requestBindingSha256", "identityAckSha256", "certificateSha256", "publicKeySha256"))
         and type(value["teamId"]) is str and api.TEAM_RE.fullmatch(value["teamId"]) is not None
         and value["chainSha256"] == [value["certificateSha256"], INTERMEDIATE_SHA256, ROOT_SHA256])
    common.timestamp(value["checkedAt"])
    return value


def journal_update(value, expected_context, expected_plan):
    value = _keys(value, {"sequence", "record", "receipt"})
    need(integer(value["sequence"], 3, 1))
    previous = record(value["record"], expected_context, expected_plan)
    receipt(value["receipt"], previous)
    if value["sequence"] == 1:
        need(previous["status"] == "running" and previous["reason"] == "readback_required" and previous["possibleSend"] is True
             and previous["responseResourceId"] is None and previous["observedResourceId"] is None and not previous["cancelRequested"])
    return value


def validate_event(request, kind, value, sequence):
    need(request.context["mode"] in MODES and integer(sequence, EVENTS, 1) and kind in KEYS)
    if kind == "certificate-key":
        need(sequence == 1)
        validate_key(request, value)
    elif kind == "certificate-identities":
        need(sequence >= 2)
        validate_candidates(request, value)
    elif kind == "certificate-policy":
        need(sequence >= 3)
        validate_policy(value)
        need(value["requestBindingSha256"] == request.digest and value["teamId"] == request.native["target"]["teamId"])
    elif kind == "certificate-observed":
        need(request.context["mode"] == "certificate-review")
        value = _keys(value, {"observedAt", "validUntil", "beforeSha256", "decision", "reason", "selection"})
        need(common.timestamp(value["validUntil"]) - common.timestamp(value["observedAt"]) == timedelta(seconds=300)
             and common.sha(value["beforeSha256"]))
        validate_pair("certificate-review", value["decision"], value["reason"])
        if value["decision"] == "request-review":
            choice(value["selection"], request.native["target"])
        else:
            need(value["selection"] is None)
    else:
        need(request.context["mode"] == "certificate-create")
        names = {"update"} if kind == "certificate-attempt" else {"observedAt", "validUntil", "selection", "requestBodySha256", "update"}
        value = _keys(value, names)
        previous = value["update"]["record"]
        update = journal_update(value["update"], common.core_context(request.native["provisioning"]), previous["planSha256"])
        if kind == "certificate-pending":
            need(update["sequence"] == 1 and common.sha(value["requestBodySha256"]))
            selected = choice(value["selection"], request.native["target"])
            need(selected["planSha256"] == previous["planSha256"] and
                 common.timestamp(value["validUntil"]) - common.timestamp(value["observedAt"]) == timedelta(seconds=300))
        else:
            need(update["sequence"] > 1)


def reply(raw, request, sequence, kind, payload):
    value = profile._reply_envelope(raw, request, sequence, kind + "-ack")
    result = value["payload"]
    expected = api.digest(api.canonical(payload))
    if kind == "certificate-key":
        result = _keys(result, {"keySha256", "csrSha256", "publicKeySha256", "keySavedAckSha256"})
        need(result["keySha256"] == expected and result["csrSha256"] == payload["csrSha256"]
             and result["publicKeySha256"] == payload["publicKeySha256"]
             and (result["keySavedAckSha256"] is None or common.sha(result["keySavedAckSha256"])))
    elif kind == "certificate-identities":
        result = _keys(result, {"identitySha256", "batch", "seen", "ambiguous", "selected", "checkedAt"})
        need(result["identitySha256"] == expected and result["batch"] == payload["batch"]
             and type(result["seen"]) is int and result["seen"] == len(payload["certificates"])
             and type(result["ambiguous"]) is bool and integer(result["checkedAt"], 253402300799, 1))
        selected = result["selected"]
        if selected is not None:
            selected = _keys(selected, {"resourceId", "certificateSha256", "notBefore", "notAfter"})
            matches = [row for row in payload["certificates"] if row["resourceId"] == selected["resourceId"]]
            need(not result["ambiguous"] and len(matches) == 1 and matches[0]["certificateType"] == "DISTRIBUTION"
                 and api.digest(profile._base64(matches[0]["certificateDer"], CERTIFICATE_BYTES)) == selected["certificateSha256"]
                 and all(integer(selected[name], 253402300799, 1) for name in ("notBefore", "notAfter"))
                 and selected["notBefore"] <= result["checkedAt"] < selected["notAfter"]
                 and common.timestamp(matches[0]["expiresAt"]).timestamp() == selected["notAfter"])
    elif kind == "certificate-policy":
        result = _keys(result, {"policySha256", "certificateSha256"})
        need(result["policySha256"] == expected and result["certificateSha256"] == payload["certificateSha256"])
    else:
        need(kind in {"certificate-pending", "certificate-attempt"})
        result = _keys(result, {"revision", "sequence", "recordSha256"}
                       | ({"stopped"} if kind == "certificate-attempt" else set()))
        if kind == "certificate-attempt":
            need(type(result["stopped"]) is bool)
        need(integer(result["revision"], 2**64 - 1, 1) and result["sequence"] == payload["update"]["sequence"]
             and type(result["sequence"]) is int and result["recordSha256"] == api.digest(api.canonical(payload["update"])))
    return dict(result), api.digest(api.canonical(value))


def validate_pair(mode, decision, reason):
    allowed = {"certificate-review": {"reuse", "request-review", "blocked"},
               "certificate-create": {"reuse", "blocked", "request-unconfirmed", "request-confirmed"},
               "certificate-reconcile": {"comparison-only"}}
    pairs = {"reuse": {"existing-certificate"}, "request-review": {"certificate-required"}, "blocked": BLOCK_REASONS,
             "request-unconfirmed": {"provider-outcome-unconfirmed", "provider-rejected"},
             "request-confirmed": {"certificate-confirmed"}, "comparison-only": {"comparison-only"}}
    need(mode in MODES and decision in allowed[mode] and reason in pairs[decision])


def summary(record_value):
    record(record_value)
    return {"operationId": record_value["context"]["operationId"], "action": "create_certificate", "status": record_value["status"],
            "reason": record_value["reason"], "retryAllowed": False, "credentialReady": False,
            "cancellationRequested": record_value["cancelRequested"]}


def record_wire(value):
    need(value.action == "create_certificate")
    return {**dict(zip(common._RECORD_NAMES, asdict(value).values())), "context": common.core_context_wire(value.context)}


def validate_result(value, request):
    value = _keys(value, {"schemaVersion", "scope", "mode", "decision", "reason", "certificateId", "attempt", "comparison",
                         "p12Saved", "profileSaved", "credentialReady", "revocationChecked"})
    mode = request.context["mode"]
    need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["scope"] == "local-ios-distribution-certificate"
         and value["mode"] == mode and all(value[name] is False for name in ("p12Saved", "profileSaved", "credentialReady", "revocationChecked")))
    validate_pair(mode, value["decision"], value["reason"])
    decision, comparison, identity = value["decision"], value["comparison"], value["certificateId"]
    if identity is not None:
        api.identifier(identity)
    if mode == "certificate-reconcile":
        need(comparison in COMPARISONS and (identity is not None) == (comparison in {"same-response", "different-response", "unattributed"}))
    else:
        need(comparison is None)
        if decision in {"reuse", "request-confirmed"}:
            need(identity is not None)
        elif decision in {"request-review", "blocked"} or value["reason"] == "provider-rejected":
            need(identity is None)
    attempt = value["attempt"]
    needed = decision in {"request-unconfirmed", "request-confirmed", "comparison-only"}
    need((attempt is not None) == needed)
    if attempt is not None:
        attempt = _keys(attempt, {"operationId", "action", "status", "reason", "retryAllowed", "credentialReady", "cancellationRequested"})
        need(attempt["operationId"] == (request.context["reference"]["operationId"] if mode == "certificate-reconcile" else request.operation_id)
             and attempt["action"] == "create_certificate" and attempt["status"] in common.ATTEMPT_STATUSES
             and attempt["reason"] in common.ATTEMPT_REASONS and attempt["retryAllowed"] is False and attempt["credentialReady"] is False
             and type(attempt["cancellationRequested"]) is bool)
        if decision == "request-confirmed":
            need(attempt["status"] == "succeeded" and attempt["reason"] == "provider_resource_confirmed" and not attempt["cancellationRequested"])
        elif decision == "request-unconfirmed":
            need(attempt["status"] != "succeeded")
            if value["reason"] == "provider-rejected":
                need(attempt["status"] == "failed" and attempt["reason"] == "provider_rejected_request")
    need(len(api.canonical(value)) <= 4096)
