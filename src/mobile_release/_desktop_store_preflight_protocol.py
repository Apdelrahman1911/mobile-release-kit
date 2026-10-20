"""Closed local Store access-check DATA; never release authority or secrets."""
from __future__ import annotations
import json
import stat
from dataclasses import dataclass
from ._desktop_preflight_protocol import (_keys, _pairs, _path, _structure, integer, content,
                                         _TOKEN, _PROJECT, _DECIMAL, STATUSES)
from ._desktop_android_build_protocol import saved_version
from . import apple_provisioning_bundle_read as bundle_read
from . import apple_provisioning_profile_read as profile_read
from . import ios_store_versions as store_versions
from . import android_store_versions as play_versions

PROTOCOL = "mrk-local-store-preflight/1"
CONSENT = "local-android-store-access-v1"
SCOPE = "local-android-store-access-no-publishing"
APPLE_SCOPE = "local-ios-store-access-no-publishing"

def command_count(platform):
    require(platform in ("android", "ios"))
    return 7 if platform == "ios" else 6
REQUEST_LIMIT, RESPONSE_LIMIT = 16 * 1024, 16 * 1024
WORK_SECONDS, FINALITY_SECONDS = 1200, 1210
PROFILES = {"macos-x86_64": ("macos", "x86_64"), "macos-arm64": ("macos", "arm64")}
CHECKS = ("credential-format", "query-prerequisites", "runtime-unavailable", "bundle-unavailable", "store-access")
REASONS = {"none", "cancelled", "timed-out", "protocol-error", "saved-source-changed", "saved-source-invalid",
           "credentials-unavailable", "query-prerequisites", "command-incomplete", "cleanup-unknown"}
OUTCOMES = {"complete", "refused", "cancelled", "timed-out", "failed", "unknown"}
LIMITATIONS = ["non-publishing", "no-project-commands", "no-build-or-signing", "no-release-readiness",
               "point-in-time-account-access", "saved-inputs-not-atomic"]

class ProtocolError(ValueError):
    pass

def require(ok):
    if not ok:
        raise ProtocolError("Invalid local Store access-check protocol")

def context(value, *, apple_access=False, bundle_query=False):
    require(type(apple_access) is bool and type(bundle_query) is bool)
    query_keys = {"query"} if type(value) is dict and "query" in value else set()
    # This explicit access-only opt-in stays false for Prepare/Execute/Reconcile.
    require(not query_keys or apple_access and bundle_query and (
        value.get("platform") == "ios" and value["query"] in (bundle_read.QUERY, profile_read.QUERY, store_versions.QUERY)
        or value.get("platform") == "android" and value["query"] == play_versions.QUERY))
    value = _keys(value, {"projectId", "draftRevision", "baselineGeneration", "savedConfig", "savedVersion",
                         "credentialContextRevision", "recordId", "recordRevision", "executionMode", "platform", "operation"} | query_keys)
    require(type(value["projectId"]) is str and _PROJECT.fullmatch(value["projectId"]) is not None
            and integer(value["draftRevision"], 2**32-2) and integer(value["baselineGeneration"], 2**32-2)
            and integer(value["credentialContextRevision"], 2**32-2, 1)
            and integer(value["recordRevision"], 2**32-2, 1)
            and type(value["recordId"]) is str and _TOKEN.fullmatch(value["recordId"]) is not None
            and value["executionMode"] == "local" and (value["platform"] == "android" or apple_access and value["platform"] == "ios")
            and value["operation"] == "local-store-preflight")
    return {**value, "savedConfig": content(value["savedConfig"]), "savedVersion": saved_version(value["savedVersion"])}

@dataclass(frozen=True)
class StorePreflightRequest:
    operation_id: str
    owner_generation: str
    context: dict
    native: dict

def parse_request(raw):
    require(type(raw) is bytes and 1 <= len(raw) <= REQUEST_LIMIT and raw.endswith(b"\n")
            and raw.count(b"\n") == 1 and not raw.startswith(b"\xef\xbb\xbf"))
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: require(False))
        _structure(value)
        value = _keys(value, {"protocol", "operationId", "ownerGeneration", "context", "native"})
        require(value["protocol"] == PROTOCOL and all(type(value[k]) is str and _TOKEN.fullmatch(value[k])
                for k in ("operationId", "ownerGeneration")))
        selected = context(value["context"], apple_access=True, bundle_query=True)
        native = _keys(value["native"], {"profile", "projectRoot", "rootIdentity", "cwd", "credentialConfig"})
        require(native["profile"] in PROFILES)
        _path(native["projectRoot"]); _path(native["cwd"])
        identity = _keys(native["rootIdentity"], {"device", "inode", "mode", "uid", "gid"})
        require(all(type(identity[k]) is str and _DECIMAL.fullmatch(identity[k]) and int(identity[k]) <= 2**64-1
                    for k in ("device", "inode")) and identity["inode"] != "0"
                and all(integer(identity[k], 2**32-1) for k in ("mode", "uid", "gid")) and stat.S_ISDIR(identity["mode"]))
        return StorePreflightRequest(value["operationId"], value["ownerGeneration"], selected,
                                      {**native, "rootIdentity": dict(identity), "credentialConfig": content(native["credentialConfig"])})
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ProtocolError("Invalid local Store access-check protocol") from None

def project_result(findings, *, platform="android"):
    from .reporting import Finding, Status
    require(type(findings) is list and len(findings) <= 16)
    names = {"credential-material.google-adc":"credential-format", "store.online.gate":"query-prerequisites",
             "store.online.tooling":"runtime-unavailable", "store.online.fastfile":"bundle-unavailable",
             "store.online.bundle":"bundle-unavailable", "store.online.android":"store-access"}
    require(platform in ("android", "ios"))
    if platform == "ios":
        del names["credential-material.google-adc"]; del names["store.online.android"]
        names.update({"credential-material.apple-p8":"credential-format", "store.online.ios":"store-access"})
    rows=[]
    for finding in findings:
        require(type(finding) is Finding and type(finding.status) is Status and finding.code in names)
        rows.append({"check":names[finding.code],"status":finding.status.value})
    result={"schemaVersion":1,"scope":APPLE_SCOPE if platform == "ios" else SCOPE,"findings":rows,"limitations":list(LIMITATIONS)}
    validate_result(result, platform=platform)
    return result

def validate_result(value, *, platform="android", query=None):
    if query is not None:
        require(platform == "android" and query == play_versions.QUERY and play_versions.valid_result(value)
                or platform == "ios" and (query == bundle_read.QUERY and bundle_read.valid_result(value)
                or query == profile_read.QUERY and profile_read.valid_result(value)
                or query == store_versions.QUERY and store_versions.valid_result(value)))
        return
    require(platform in ("android", "ios"))
    value=_keys(value,{"schemaVersion","scope","findings","limitations"})
    require(type(value["schemaVersion"]) is int and value["schemaVersion"]==1 and value["scope"]==(APPLE_SCOPE if platform == "ios" else SCOPE)
            and value["limitations"]==LIMITATIONS and type(value["findings"]) is list and len(value["findings"])<=16)
    for row in value["findings"]:
        row=_keys(row,{"check","status"})
        require(row["check"] in CHECKS and row["status"] in STATUSES)

def validate_terminal(value,request):
    value=_keys(value,{"schemaVersion","context","outcome","reason","result","lifetime"})
    require(type(value["schemaVersion"]) is int and value["schemaVersion"]==1 and context(value["context"], apple_access=True, bundle_query=True)==request.context
            and value["outcome"] in OUTCOMES and value["reason"] in REASONS)
    life=_keys(value["lifetime"],{"complete","fatal","contained","commandDispatched","commands","profileCalls",
                                "inputClosed","handlersRestored","invocationClosed","stopObserved"})
    require(all(type(life[k]) is bool for k in ("complete","fatal","contained","inputClosed","handlersRestored","invocationClosed"))
            and (life["commandDispatched"] is None or type(life["commandDispatched"]) is bool)
            and integer(life["commands"],command_count(request.context["platform"])) and type(life["profileCalls"]) is int and life["profileCalls"]==0
            and life["stopObserved"] in {"none","cancelled","timed-out"})
    settled=(life["complete"] and not life["fatal"] and life["contained"] and life["inputClosed"]
             and life["handlersRestored"] and life["invocationClosed"] and life["commandDispatched"] is not None)
    if value["outcome"]=="complete":
        require(settled and value["reason"]=="none" and life["stopObserved"]=="none")
        validate_result(value["result"], platform=request.context["platform"], query=request.context.get("query"))
    else:
        require(value["result"] is None and value["reason"]!="none" and (settled or value["outcome"]=="unknown"))
        if value["outcome"]=="unknown": require(not settled and value["reason"]=="cleanup-unknown")
        if value["outcome"] in {"cancelled","timed-out"}: require(value["reason"]==value["outcome"]==life["stopObserved"])

def response(request,kind,payload):
    require(type(request) is StorePreflightRequest and kind in {"accepted","terminal"})
    if kind=="accepted": require(payload=={"schemaVersion":1,"context":request.context})
    else: validate_terminal(payload,request)
    raw=json.dumps({"protocol":PROTOCOL,"operationId":request.operation_id,"ownerGeneration":request.owner_generation,
                    "sequence":0 if kind=="accepted" else 1,"kind":kind,"payload":payload},
                   ensure_ascii=True,sort_keys=True,separators=(",",":"),allow_nan=False).encode("ascii")+b"\n"
    require(len(raw)<=RESPONSE_LIMIT)
    return raw
