"""Closed P12 DATA, not a key/certificate/assignment or native save permit.

The fresh certificate phase and selected-record extraction have their own
originals. Pending is a LOCAL assembly/save intent, never a provider POST.
"""
from datetime import timedelta

from . import _desktop_apple_provisioning_protocol as common
from . import _desktop_apple_profile_protocol as profile
from . import apple_provisioning_api as api
from ._desktop_preflight_protocol import _keys, integer

MODES = frozenset({"p12-review", "p12-reuse", "p12-save"})
EVENTS, COMMANDS, JSON_LIMIT = 8, 15, 768 * 1024
BLOCKED = frozenset({"account-pending", "inventory-unavailable", "certificate-required",
                    "select-existing-package", "selection-changed"})
need, key_ref = common.require, profile.key_ref


def context(value):
    need(type(value) is dict and value.get("mode") in MODES)
    extra = {"keyRecordId", "keyRecordRevision", "p12RecordId", "p12RecordRevision"}
    need(extra <= value.keys() and common.token(value["keyRecordId"])
         and integer(value["keyRecordRevision"], 2**32 - 2, 1) and value.get("newApplication") is False)
    selected = value["p12RecordId"] is not None
    need((selected and common.token(value["p12RecordId"]) and integer(value["p12RecordRevision"], 2**32 - 2, 1))
         or not selected and value["p12RecordRevision"] is None)
    need(value["mode"] != "p12-reuse" or selected)
    need(value["mode"] != "p12-save" or not selected)
    base = {name: part for name, part in value.items() if name not in extra}
    base.update(mode="review", reference=None)
    common.context(base)
    if value["mode"] == "p12-review":
        need(value["reference"] is None)
    else:
        reference = _keys(value["reference"], {"operationId", "ownerGeneration"})
        need(all(common.token(item) for item in reference.values()))
    return dict(value)


def selection(value, target):
    value = _keys(value, {"bundle", "certificate", "csrSha256", "beforeSha256"})
    bundle = _keys(value["bundle"], {"resourceId", "identifier", "platform", "seedId"})
    api.identifier(bundle["resourceId"])
    need(bundle["identifier"] == target["bundleId"] and bundle["seedId"] == target["appIdPrefix"]
         and bundle["platform"] in {"IOS", "UNIVERSAL"})
    cert = _keys(value["certificate"], {"resourceId", "certificateType", "notBefore", "expiresAt", "certificateSha256", "publicKeySha256"})
    api.identifier(cert["resourceId"])
    need(cert["certificateType"] == "DISTRIBUTION" and common.timestamp(cert["notBefore"]) < common.timestamp(cert["expiresAt"])
         and all(common.sha(part) for part in (cert["certificateSha256"], cert["publicKeySha256"], value["csrSha256"], value["beforeSha256"])))
    return value


def same_assets(left, right):
    return all(left[name] == right[name] for name in ("bundle", "certificate", "csrSha256"))


def validate_native(selected, native):
    value = _keys(native["p12"], {"sourceP8", "sourceKey", "selectedP12", "expectedCertificateSha256", "p12Sha256",
                                 "destination", "review", "previous"})
    cert = _keys(native["certificate"], {"sourceP8", "sourceKey", "entitlements", "keyPreparation", "review", "prior"})
    p8, key = key_ref(value["sourceP8"]), key_ref(value["sourceKey"])
    need(cert["sourceP8"] == value["sourceP8"] and cert["sourceKey"] == value["sourceKey"]
         and cert["keyPreparation"] is None and cert["review"] is None and cert["prior"] is None
         and type(cert["entitlements"]) is dict and len(api.canonical(cert["entitlements"])) <= 16 * 1024
         and native["target"]["teamId"] == native["target"]["appIdPrefix"]
         and key.vault_id == p8.vault_id and key.generation_id == p8.generation_id and key.record_id != p8.record_id
         and key.record_id == selected["keyRecordId"] and key.revision_counter == selected["keyRecordRevision"]
         and p8.record_id == selected["recordId"] and p8.revision_counter == selected["recordRevision"]
         and native["prior"] is None and "key" not in native and "signing" not in native)
    source = value["selectedP12"]
    if source is None:
        need(selected["p12RecordId"] is None and selected["p12RecordRevision"] is None
             and value["p12Sha256"] is None and value["expectedCertificateSha256"] is None)
    else:
        source = key_ref(source)
        need(source.vault_id == key.vault_id and source.generation_id == key.generation_id
             and source.record_id not in {key.record_id, p8.record_id}
             and source.record_id == selected["p12RecordId"] and source.revision_counter == selected["p12RecordRevision"]
             and common.sha(value["p12Sha256"]) and common.sha(value["expectedCertificateSha256"]))
    need(type(value["previous"]) is list and len(value["previous"]) <= 32)
    for hint in value["previous"]:
        hint = _keys(hint, {"destination", "certificateSha256", "publicKeySha256", "unresolved"})
        key_ref(hint["destination"])
        need(common.sha(hint["certificateSha256"]) and common.sha(hint["publicKeySha256"]) and type(hint["unresolved"]) is bool)
    if selected["mode"] == "p12-save":
        dest = key_ref(value["destination"])
        need(source is None and dest.vault_id == key.vault_id and dest.generation_id == key.generation_id
             and dest.record_id not in {p8.record_id, key.record_id} and dest.revision_counter == 1)
    else:
        need(value["destination"] is None and (selected["mode"] != "p12-reuse" or source is not None))
    if selected["mode"] == "p12-review":
        need(value["review"] is None and native["reviewedAt"] is None)
    else:
        review = _keys(value["review"], {"reference", "observedAt", "validUntil", "selection", "selectedP12"})
        need(review["reference"] == selected["reference"] and review["selectedP12"] == value["selectedP12"]
             and native["reviewedAt"] == review["observedAt"]
             and common.timestamp(review["validUntil"]) - common.timestamp(review["observedAt"]) == timedelta(seconds=300))
        selection(review["selection"], native["target"])


def output_metadata(value):
    value = _keys(value, {"frameBytes", "frameSha256", "p12Bytes", "p12Sha256", "certificateSha256", "publicKeySha256"})
    from ._desktop_apple_p12_assembly import HEADER, P12_LIMIT
    need(integer(value["p12Bytes"], P12_LIMIT, 1) and integer(value["frameBytes"], P12_LIMIT + HEADER, HEADER + 1)
         and value["frameBytes"] == HEADER + value["p12Bytes"]
         and all(common.sha(value[name]) for name in ("frameSha256", "p12Sha256", "certificateSha256", "publicKeySha256")))
    return value


def initial_update():
    return {"sequence": 1, "assembly": "armed", "output": None, "save": "not-entered",
            "savedReference": None, "disposition": "running", "cancelRequested": False}


def pair(mode, decision, reason):
    return ((mode, decision, reason) in {("p12-review", "assemble-review", "new-package-review"),
        ("p12-review", "reuse-review", "current-package-review"), ("p12-save", "assembled", "producer-returned"),
        ("p12-reuse", "reused", "existing-package")}
        or mode in MODES and decision == "blocked" and reason in BLOCKED)


def validate_event(request, kind, payload, sequence):
    mode = request.context["mode"]
    need(mode in MODES and integer(sequence, EVENTS, 2))
    if kind == "p12-observed":
        value = _keys(payload, {"observedAt", "validUntil", "decision", "reason", "selection"})
        need(mode == "p12-review" and sequence <= 4 and pair(mode, value["decision"], value["reason"])
             and common.timestamp(value["validUntil"]) - common.timestamp(value["observedAt"]) == timedelta(seconds=300))
        if value["decision"] == "blocked":
            need(value["selection"] is None)
        else:
            selection(value["selection"], request.native["target"])
    elif kind == "p12-pending":
        value = _keys(payload, {"observedAt", "validUntil", "selection", "update"})
        need(mode == "p12-save" and sequence == 4 and value["update"] == initial_update()
             and type(value["update"]["sequence"]) is int
             and value["update"]["cancelRequested"] is False
             and common.timestamp(value["validUntil"]) - common.timestamp(value["observedAt"]) == timedelta(seconds=300))
        selection(value["selection"], request.native["target"])
        need(same_assets(value["selection"], request.native["p12"]["review"]["selection"]))
    elif kind == "p12-output":
        need(mode == "p12-save" and sequence == 5)
        value = output_metadata(payload)
        expected = request.native["p12"]["review"]["selection"]["certificate"]
        need(value["certificateSha256"] == expected["certificateSha256"] and value["publicKeySha256"] == expected["publicKeySha256"])
    else:
        need(False)


def reply(raw, request, kind, sequence, payload):
    envelope = profile._reply_envelope(raw, request, sequence, kind + "-ack")
    value = envelope["payload"]
    if kind == "p12-pending":
        value = _keys(value, {"revision", "sequence", "recordSha256"})
        need(integer(value["revision"], 2**64 - 1, 1) and integer(value["sequence"], 1, 1)
             and value["recordSha256"] == api.digest(api.canonical(payload["update"])))
    elif kind == "p12-output":
        value = _keys(value, {"frameSha256", "p12Sha256", "retained"})
        need(value["retained"] is True and value["frameSha256"] == payload["frameSha256"] and value["p12Sha256"] == payload["p12Sha256"])
    else:
        need(False)
    return value, api.digest(api.canonical(envelope))


def validate_result(value, request):
    value = _keys(value, {"schemaVersion", "scope", "mode", "decision", "reason", "certificateId", "certificateSha256",
        "publicKeySha256", "output", "reused", "p12Saved", "profileSaved", "credentialReady", "revocationChecked"})
    need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
         and value["scope"] == "local-ios-p12-setup" and value["mode"] == request.context["mode"]
         and pair(value["mode"], value["decision"], value["reason"])
         and all(value[name] is False for name in ("p12Saved", "profileSaved", "credentialReady", "revocationChecked")))
    if value["decision"] == "blocked":
        need(all(value[name] is None for name in ("certificateId", "certificateSha256", "publicKeySha256", "output", "reused")))
    else:
        api.identifier(value["certificateId"])
        need(common.sha(value["certificateSha256"]) and common.sha(value["publicKeySha256"]))
    if value["decision"] == "assembled":
        output_metadata(value["output"])
        need(value["reused"] is None and all(value["output"][name] == value[name] for name in ("certificateSha256", "publicKeySha256")))
    elif value["decision"] in {"reused", "reuse-review"}:
        reuse = _keys(value["reused"], {"sourceP12", "p12Sha256", "certificateSha256", "publicKeySha256", "policyAckSha256"})
        need(value["output"] is None and reuse["sourceP12"] == request.native["p12"]["selectedP12"]
             and reuse["p12Sha256"] == request.native["p12"]["p12Sha256"]
             and reuse["certificateSha256"] == request.native["p12"]["expectedCertificateSha256"]
             and all(reuse[name] == value[name] for name in ("certificateSha256", "publicKeySha256"))
             and common.sha(reuse["policyAckSha256"]))
    else:
        need(value["output"] is None and value["reused"] is None)
        if value["decision"] == "assemble-review":
            need(request.native["p12"]["selectedP12"] is None)
    return value
