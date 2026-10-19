"""Closed Bundle-ID provisioning DATA on the original SavedCommand engine.

Journal DTO member names mirror the Service-owned native journal. This module
does not open state, grant account access, acquire native custody or turn a
restored row/ACK string into an original reservation or native join witness.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import stat

from . import apple_provisioning_api as api
from . import _desktop_store_preflight_protocol as access
from ._desktop_preflight_protocol import _keys, _pairs, _path, _TOKEN, _DECIMAL, integer, content
from ._desktop_android_build_protocol import saved_version
from .apple_provisioning import BUNDLE_ID_SCOPE, MAX_OBSERVATION_AGE, Observation, PendingMutation, ProvisioningContext, ProvisioningTarget
from .apple_provisioning_bundle_registration import prepare_bundle
from .apple_provisioning_recovery import AttemptRecord

PROTOCOL = "mrk-apple-bundle-provisioning/1"
REQUEST_LIMIT, RESPONSE_LIMIT = 64 * 1024, 128 * 1024
EVENT_LIMIT, ACK_LIMIT, MAX_EVENTS = 16 * 1024, 2048, 3
WORK_SECONDS, FINALITY_SECONDS = 1200, 1210
MODES = frozenset({"review", "register", "reconcile"})
CONSENTS = {mode: "local-ios-bundle-" + mode + "-v1" for mode in MODES}
OBSERVATIONS = frozenset({"found", "not-returned", "not-permitted", "inconclusive", "not-checked"})
DECISIONS = frozenset({"reuse", "review-required", "blocked", "registration-unconfirmed", "registration-confirmed", "comparison-only"})
ATTEMPT_STATUSES = frozenset({"running", "cancellation_requested", "succeeded", "failed", "cancelled", "recovery_required", "unknown"})
ATTEMPT_REASONS = frozenset({"readback_required", "journal_settlement_required", "authorization_changed", "cancelled_before_send",
    "provider_outcome_unknown", "original_transport_unsettled", "authorization_changed_after_send", "provider_rejected_request",
    "provider_result_requires_reconciliation", "reconciliation_read_unavailable", "reconciliation_context_changed",
    "resource_validation_required", "provider_outcome_still_unknown", "ambiguous_recovery_resources", "resource_found_review_required",
    "response_readback_disagrees", "provider_resource_confirmed", "cancelled_after_settlement"})
LIMITATIONS = ["bundle-id-only", "no-release-or-signing-readiness", "no-certificate-or-profile-changes", "no-team-verification",
              "no-global-availability-claim", "one-write-no-retry", "parent-journal-and-native-joins-required"]
REASONS = access.REASONS | {"journal-unavailable", "review-expired", "registration-blocked"}
OUTCOMES = access.OUTCOMES
_CONTEXT_NAMES = ("projectId", "clientId", "operationId", "observationRevision", "accountRef", "credentialRecordId",
                  "credentialRevision", "credentialContextRevision")
_TARGET_NAMES = ("bundleId", "teamId", "appIdPrefix", "displayName", "existingApplication")
_RECORD_NAMES = ("context", "planSha256", "action", "status", "reason", "possibleSend", "responseResourceId",
                 "responseResourceSha256", "observedResourceId", "cancelRequested")


class ProtocolError(ValueError):
    def __init__(self, *_):
        super().__init__("Invalid Bundle-ID provisioning protocol")


def require(value):
    if not value:
        raise ProtocolError()


def sha(value):
    return type(value) is str and api.HEX_RE.fullmatch(value) is not None


def token(value):
    return type(value) is str and _TOKEN.fullmatch(value) is not None


def timestamp(value):
    parsed = api.timestamp(value)
    require(parsed.isoformat() == value)
    return parsed


def _structure(value, depth=0, count=None):
    # The Service journal's native u64 revisions/device identities do not pass
    # through JavaScript. Keep its integer range, not the renderer's 53 bits.
    if count is None:
        count = [0]
    count[0] += 1
    require(depth <= 16 and count[0] <= 8192)
    if type(value) is dict:
        for key, item in value.items():
            require(type(key) is str)
            _structure(key, depth + 1, count); _structure(item, depth + 1, count)
    elif type(value) is list:
        for item in value:
            _structure(item, depth + 1, count)
    elif type(value) is str:
        require(len(value.encode("utf-8")) <= 4096)
    elif type(value) is int:
        require(0 <= value <= 2**64 - 1)
    else:
        require(value is None or type(value) is bool)


def core_context(value):
    value = _keys(value, set(_CONTEXT_NAMES))
    result = ProvisioningContext(*(value[name] for name in _CONTEXT_NAMES))
    require(sha(result.account_ref) and token(result.operation_id))
    return result


def core_context_wire(value):
    require(type(value) is ProvisioningContext)
    return dict(zip(_CONTEXT_NAMES, asdict(value).values()))


def target(value):
    value = _keys(value, set(_TARGET_NAMES))
    return ProvisioningTarget(*(value[name] for name in _TARGET_NAMES))


def attempt(value, selected, plan_sha256):
    value = _keys(value, set(_RECORD_NAMES))
    require(core_context(value["context"]) == selected and sha(plan_sha256) and value["planSha256"] == plan_sha256
            and value["action"] == "register_bundle_id" and value["status"] in ATTEMPT_STATUSES
            and value["reason"] in ATTEMPT_REASONS and type(value["possibleSend"]) is bool and type(value["cancelRequested"]) is bool)
    for name in ("responseResourceId", "observedResourceId"):
        if value[name] is not None:
            api.identifier(value[name])
    require(value["responseResourceSha256"] is None if value["responseResourceId"] is None else sha(value["responseResourceSha256"]))
    return AttemptRecord(selected, *(value[name] for name in _RECORD_NAMES[1:]))


def attempt_wire(value):
    require(type(value) is AttemptRecord)
    raw = dict(zip(_RECORD_NAMES, asdict(value).values()))
    raw["context"] = core_context_wire(value.context)
    require(attempt(raw, value.context, value.plan_sha256) == value)
    return raw


def pending(value, account):
    require(type(value) is list and len(value) <= 32)
    result = []
    seen = set()
    for row in value:
        row = _keys(row, {"accountRef", "operationId", "action", "status", "nativeSettlement"})
        require(row["accountRef"] == account and token(row["operationId"]) and row["operationId"] not in seen
                and row["action"] == "register_bundle_id" and row["status"] in ATTEMPT_STATUSES)
        seen.add(row["operationId"])
        result.append(PendingMutation(row["accountRef"], row["operationId"], row["action"], row["status"], row["nativeSettlement"]))
    return tuple(result)


def context(value):
    require(type(value) is dict and value.get("operation") == "apple-bundle-provisioning" and value.get("platform") == "ios")
    extras = {"mode", "reference", "newApplication", "displayName"}
    require(extras <= value.keys() and type(value["mode"]) is str and value["mode"] in MODES)
    base = {name: item for name, item in value.items() if name not in extras}
    base["operation"] = "local-store-preflight"
    # Validator reuse only. Domain/consent/owner remain separate; access queries
    # are intentionally not opted in and cannot enter this new grammar.
    access.context(base, apple_access=True)
    api._name(value["displayName"])
    require(type(value["newApplication"]) is bool and value["newApplication"] is (value["mode"] == "register"))
    reference = value["reference"]
    if value["mode"] == "review":
        require(reference is None)
    else:
        reference = _keys(reference, {"operationId", "ownerGeneration"})
        require(all(token(reference[name]) for name in reference))
    return dict(value)


def _identity(value):
    value = _keys(value, {"device", "inode", "mode", "uid", "gid"})
    require(all(type(value[name]) is str and _DECIMAL.fullmatch(value[name]) and int(value[name]) <= 2**64 - 1
                for name in ("device", "inode")) and value["inode"] != "0"
            and all(integer(value[name], 2**32 - 1) for name in ("mode", "uid", "gid")) and stat.S_ISDIR(value["mode"]))
    return dict(value)


def _prior(value, account, selected_target):
    """Validate Service's exact serialized row as historical comparison DATA."""
    value = _keys(value, {"intent", "sendArmed", "attempt", "nativeSettlement"})
    require(value["sendArmed"] is True and value["nativeSettlement"] in {"pending", "known", "unknown"})
    intent = _keys(value["intent"], {"context", "provenance", "target", "observedAt", "validUntil", "beforeSha256", "planSha256", "requestBodySha256"})
    selected, old_target = core_context(intent["context"]), target(intent["target"])
    require(selected.account_ref == account and old_target == selected_target and not old_target.existing_application)
    observed, until = timestamp(intent["observedAt"]), timestamp(intent["validUntil"])
    before = Observation(selected, old_target.bundle_id, observed, True, "observed", scope=BUNDLE_ID_SCOPE)
    plan = prepare_bundle(selected, old_target, before, pending=(), now=observed)
    require(plan.action == "register_bundle_id" and until == plan.valid_until and before.sha256 == intent["beforeSha256"]
            and plan.sha256 == intent["planSha256"] and api.digest(plan.request.body) == intent["requestBodySha256"])
    provenance = _keys(intent["provenance"], {"projectBinding", "operationId", "ownerGeneration", "registrationGeneration",
        "registeredRoot", "draftRevision", "baselineGeneration", "savedConfig", "savedVersion"})
    require(provenance["operationId"] == selected.operation_id and token(provenance["ownerGeneration"])
            and integer(provenance["registrationGeneration"], 2**32 - 1, 1)
            and all(integer(provenance[name], 2**32 - 2) for name in ("draftRevision", "baselineGeneration")))
    content(provenance["savedConfig"]); saved_version(provenance["savedVersion"])
    root = _keys(provenance["registeredRoot"], {"path", "device", "inode", "mode", "uid", "gid"})
    _path(root["path"])
    require(all(integer(root[name], 2**64 - 1, 1 if name == "inode" else 0) for name in ("device", "inode"))
            and all(integer(root[name], 2**32 - 1) for name in ("mode", "uid", "gid")) and stat.S_ISDIR(root["mode"]))
    binding = _keys(provenance["projectBinding"], {"projectId", "canonicalRoot", "device", "inode"})
    require(token(binding["projectId"]) and binding["canonicalRoot"] == root["path"]
            and all(integer(binding[name], 2**64 - 1, 1 if name == "inode" else 0) for name in ("device", "inode"))
            and binding["device"] == root["device"] and binding["inode"] == root["inode"])
    update = _keys(value["attempt"], {"sequence", "record"})
    require(integer(update["sequence"], 64, 1))
    attempt(update["record"], selected, plan.sha256)
    require(len(api.canonical(value)) <= EVENT_LIMIT)
    return dict(value)


@dataclass(frozen=True, repr=False)
class AppleProvisioningRequest:
    operation_id: str
    owner_generation: str
    context: dict
    native: dict
    wire_sha256: str

    @property
    def digest(self):
        # Bind the exact ORIGINAL native encoded request, including its newline.
        # Native need not duplicate Python's Unicode/ASCII reserialization.
        # Run separately pins the parsed mutable context/native contents.
        return self.wire_sha256


def parse_request(raw):
    try:
        require(type(raw) is bytes and 0 < len(raw) <= REQUEST_LIMIT and raw.endswith(b"\n") and raw.count(b"\n") == 1)
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: require(False)); _structure(value)
        value = _keys(value, {"protocol", "operationId", "ownerGeneration", "context", "native"})
        require(value["protocol"] == PROTOCOL and token(value["operationId"]) and token(value["ownerGeneration"]))
        selected = context(value["context"])
        native = _keys(value["native"], {"profile", "projectRoot", "rootIdentity", "cwd", "credentialConfig", "clock", "nonce",
            "provisioning", "target", "reviewedAt", "journalRevision", "pending", "prior"})
        require(native["profile"] in access.PROFILES and token(native["nonce"]))
        _path(native["projectRoot"]); _path(native["cwd"]); _identity(native["rootIdentity"]); content(native["credentialConfig"])
        clock = _keys(native["clock"], {"workEndNs", "hardEndNs"})
        require(all(type(clock[name]) is str and _DECIMAL.fullmatch(clock[name]) and 0 < int(clock[name]) < 2**64 for name in clock)
                and int(clock["workEndNs"]) < int(clock["hardEndNs"]) <= int(clock["workEndNs"]) + 10_000_000_000)
        owned = core_context(native["provisioning"])
        require(owned.operation_id == value["operationId"] and owned.project_id == selected["projectId"]
                and owned.credential_record_id == selected["recordId"] and owned.credential_revision == selected["recordRevision"]
                and owned.credential_context_revision == selected["credentialContextRevision"])
        chosen = target(native["target"])
        require(chosen.display_name == selected["displayName"])
        pending(native["pending"], owned.account_ref)
        require(integer(native["journalRevision"], 2**64 - 2))
        if selected["mode"] == "register":
            require(not chosen.existing_application and chosen.app_id_prefix == chosen.team_id)
            timestamp(native["reviewedAt"])
        else:
            require(native["reviewedAt"] is None)
        if selected["mode"] == "reconcile":
            prior = _prior(native["prior"], owned.account_ref, chosen)
            provenance = prior["intent"]["provenance"]
            require({name: provenance[name] for name in ("operationId", "ownerGeneration")} == selected["reference"])
        else:
            require(native["prior"] is None)
        return AppleProvisioningRequest(value["operationId"], value["ownerGeneration"], selected, dict(native), api.digest(raw))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise ProtocolError() from None


def command_count(mode):
    require(mode in MODES)
    return 9 if mode == "register" else 7


def expected_plan(request):
    """Reconstruct this original registration's fixed immutable comparison."""
    require(type(request) is AppleProvisioningRequest and request.context["mode"] == "register")
    selected, chosen = core_context(request.native["provisioning"]), target(request.native["target"])
    observed = timestamp(request.native["reviewedAt"])
    before = Observation(selected, chosen.bundle_id, observed, True, "observed", scope=BUNDLE_ID_SCOPE)
    plan = prepare_bundle(selected, chosen, before, pending=(), now=observed)
    require(plan.action == "register_bundle_id")
    return before, plan


def validate_event(request, kind, payload, sequence):
    require(type(request) is AppleProvisioningRequest and integer(sequence, MAX_EVENTS, 1))
    mode = request.context["mode"]
    if mode != "register":
        require(kind == "observed" and sequence == 1)
        payload = _keys(payload, {"observedAt", "observation", "bundle", "beforeSha256", "decision"})
        at = timestamp(payload["observedAt"])
        require(payload["observation"] in OBSERVATIONS and payload["decision"] in {"reuse", "review-required", "blocked", "comparison-only"})
        bundles = ()
        if payload["bundle"] is not None:
            row = _keys(payload["bundle"], {"resourceId", "identifier", "platform", "seedId"})
            bundles = (api.BundleId.parse({"id": row["resourceId"], "type": "bundleIds", "attributes": {
                "identifier": row["identifier"], "platform": row["platform"], "seedId": row["seedId"]}}),)
            require(bundles[0].identifier == request.native["target"]["bundleId"] and bundles[0].platform in {"IOS", "UNIVERSAL"})
        require(bool(bundles) is (payload["observation"] == "found"))
        if payload["observation"] in {"found", "not-returned"}:
            before = Observation(core_context(request.native["provisioning"]), request.native["target"]["bundleId"],
                at, True, "observed", bundles, scope=BUNDLE_ID_SCOPE)
            require(before.sha256 == payload["beforeSha256"])
        else:
            require(payload["beforeSha256"] is None)
        return
    before, plan = expected_plan(request)
    require(kind == ("pending" if sequence == 1 else "attempt"))
    if sequence == 1:
        payload = _keys(payload, {"observedAt", "validUntil", "beforeSha256", "planSha256", "requestBodySha256", "update"})
        require(payload["observedAt"] == before.observed_at.isoformat() and payload["validUntil"] == plan.valid_until.isoformat()
                and payload["beforeSha256"] == before.sha256 and payload["planSha256"] == plan.sha256
                and payload["requestBodySha256"] == api.digest(plan.request.body))
    else:
        payload = _keys(payload, {"update"})
    update = _keys(payload["update"], {"sequence", "record"})
    require(type(update["sequence"]) is int and update["sequence"] == sequence)
    record = attempt(update["record"], plan.context, plan.sha256)
    if sequence == 1:
        require(record.status == "running" and record.reason == "readback_required" and record.possible_send is True
                and record.response_resource_id is None and record.observed_resource_id is None and not record.cancel_requested)


def response(request, kind, payload, sequence):
    require(type(request) is AppleProvisioningRequest and integer(sequence, MAX_EVENTS + 1)
            and kind in {"accepted", "observed", "pending", "attempt", "terminal"})
    if kind == "accepted":
        require(sequence == 0 and payload == {"schemaVersion": 1, "context": request.context})
    elif kind == "terminal":
        require(sequence >= 1); validate_terminal(payload, request)
    else:
        validate_event(request, kind, payload, sequence)
    raw = api.canonical({"protocol": PROTOCOL, "operationId": request.operation_id, "ownerGeneration": request.owner_generation,
        "nonce": request.native["nonce"], "requestSha256": request.digest, "sequence": sequence, "kind": kind, "payload": payload}) + b"\n"
    require(len(raw) <= (EVENT_LIMIT if kind not in {"accepted", "terminal"} else 32 * 1024))
    return raw


def reply(raw, request, sequence, record_sha256):
    require(type(raw) is bytes and 0 < len(raw) <= ACK_LIMIT and raw.endswith(b"\n") and raw.count(b"\n") == 1)
    value = api.document(raw)
    value = _keys(value, {"protocol", "operationId", "ownerGeneration", "nonce", "requestSha256", "kind", "step", "payload"})
    require(value["protocol"] == PROTOCOL and value["operationId"] == request.operation_id
            and value["ownerGeneration"] == request.owner_generation and value["nonce"] == request.native["nonce"]
            and value["requestSha256"] == request.digest and value["kind"] == "journal-ack"
            and type(value["step"]) is int and value["step"] == sequence and 1 <= sequence <= MAX_EVENTS)
    payload = _keys(value["payload"], {"revision", "sequence", "recordSha256"})
    require(integer(payload["revision"], 2**64 - 1, 1) and type(payload["sequence"]) is int
            and payload["sequence"] == sequence and payload["recordSha256"] == record_sha256 and sha(record_sha256))
    return payload["revision"], api.digest(api.canonical(value))


def validate_result(value, request):
    value = _keys(value, {"schemaVersion", "scope", "mode", "observation", "decision", "attempt", "comparison", "limitations"})
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["scope"] == "local-ios-bundle-provisioning"
            and value["mode"] == request.context["mode"] and value["observation"] in OBSERVATIONS
            and value["decision"] in DECISIONS and value["limitations"] == LIMITATIONS)
    if request.context["mode"] == "reconcile":
        require(value["decision"] == "comparison-only" and value["comparison"] in {
            "same-response", "different-response", "unattributed", "not-returned", "inconclusive"})
        require(value["observation"] == "found" if value["comparison"] in {"same-response", "different-response", "unattributed"}
                else value["observation"] == "not-returned" if value["comparison"] == "not-returned"
                else value["observation"] not in {"found", "not-returned"})
    else:
        require(value["comparison"] is None)
    if value["attempt"] is not None:
        record = _keys(value["attempt"], {"operationId", "action", "status", "reason", "retryAllowed", "credentialReady", "cancellationRequested"})
        require(request.context["mode"] == "register" and record["operationId"] == request.operation_id
                and record["action"] == "register_bundle_id" and record["status"] in ATTEMPT_STATUSES and record["reason"] in ATTEMPT_REASONS
                and record["retryAllowed"] is False and record["credentialReady"] is False and type(record["cancellationRequested"]) is bool)
    if value["decision"] == "registration-confirmed":
        require(value["attempt"] is not None and value["attempt"]["status"] == "succeeded" and value["observation"] == "found")
    if request.context["mode"] != "register":
        require(value["attempt"] is None and value["decision"] not in {"registration-confirmed", "registration-unconfirmed"})


def validate_terminal(value, request):
    value = _keys(value, {"schemaVersion", "context", "outcome", "reason", "result", "lifetime"})
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and context(value["context"]) == request.context
            and value["outcome"] in OUTCOMES and value["reason"] in REASONS)
    life = _keys(value["lifetime"], {"complete", "fatal", "contained", "commandDispatched", "commands", "profileCalls", "inputClosed",
                                     "handlersRestored", "invocationClosed", "stopObserved"})
    require(all(type(life[name]) is bool for name in ("complete", "fatal", "contained", "inputClosed", "handlersRestored", "invocationClosed"))
            and (life["commandDispatched"] is None or type(life["commandDispatched"]) is bool)
            and integer(life["commands"], command_count(request.context["mode"])) and type(life["profileCalls"]) is int and life["profileCalls"] == 0
            and life["stopObserved"] in {"none", "cancelled", "timed-out"})
    settled = (life["complete"] and not life["fatal"] and life["contained"] and life["inputClosed"] and life["handlersRestored"]
               and life["invocationClosed"] and life["commandDispatched"] is not None)
    if value["outcome"] == "complete":
        require(settled and value["reason"] == "none" and life["stopObserved"] == "none"); validate_result(value["result"], request)
    else:
        require(value["result"] is None and value["reason"] != "none" and (settled or value["outcome"] == "unknown"))
        if value["outcome"] == "unknown":
            require(not settled and value["reason"] == "cleanup-unknown")
        if value["outcome"] in {"cancelled", "timed-out"}:
            require(value["reason"] == value["outcome"] == life["stopObserved"])
