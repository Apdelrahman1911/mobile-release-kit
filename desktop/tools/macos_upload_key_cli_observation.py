"""One closed recipe for the existing installed CLI caller/Fixtures.

No process, thread, signal, native picker, credential or cleanup owner lives
here. Phase files compare actual returned originals; they authorize nothing.
"""
import hashlib
import json
import re

SCOPE = "upload-key-backup-cli"
CASES = (SCOPE,)
CALLS, ROWS = 10, 7
SUCCESS_SECONDS, APP_SECONDS = 480, 495
NATIVE_PHASES = ("export-allowed", "export-terminal", "restore-allowed", "restore-terminal",
                 "cancel-allowed", "second-entered", "cancelled-terminal")
DRIVER_PHASES = ("export-submitted", "export-checked", "restore-submitted", "restore-checked",
                 "cancel-submitted", "cancel-requested", "done")


def need(ok, reason):
    if not ok:
        raise ValueError(reason)  # Fixed reasons only, never private output.


def keys(value, *names):
    return type(value) is dict and set(value) == set(names)


def ident(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{32}", value) is not None and value != "0" * 32


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("ascii")).hexdigest()


def hash_value(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def origin(value):
    return keys(value, "projectId", "serviceInstance", "requestId") and all(ident(v) for v in value.values())


def allowed(value, phase):
    need(keys(value, "phase", "projectId", "serviceInstance", "grantId") and value["phase"] == phase
         and all(ident(value[k]) for k in ("projectId", "serviceInstance", "grantId")), "backup-cli-allowed-data")
    return value


def access(value, permission, kind):
    need(keys(value, "schemaVersion", "serviceInstance", "projectId", "grantId", "kind", "requestId",
              "enabled", "remainingMs", "consumed") and type(value["schemaVersion"]) is int
         and value["schemaVersion"] == 1 and value["enabled"] is True and value["consumed"] is False
         and value["requestId"] is None and value["kind"] == kind
         and type(value["remainingMs"]) is int and 0 < value["remainingMs"] <= 300000
         and all(value[k] == permission[k] for k in ("serviceInstance", "projectId", "grantId")),
         "backup-cli-scope-original")


def status(value, permission, kind, request=None):
    need(keys(value, "schemaVersion", "origin", "grantId", "kind", "state", "settlement", "reason",
              "assetOperationId", "key", "doNotReplay") and type(value["schemaVersion"]) is int
         and value["schemaVersion"] == 1 and value["doNotReplay"] is True and origin(value["origin"])
         and value["kind"] == kind and value["grantId"] == permission["grantId"]
         and all(value["origin"][k] == permission[k] for k in ("serviceInstance", "projectId"))
         and (request is None or value["origin"]["requestId"] == request)
         and (value["assetOperationId"] is None or type(value["assetOperationId"]) is int
              and 0 < value["assetOperationId"] < 2**32 - 1), "backup-cli-status-origin")
    return value["origin"]["requestId"]


def terminal(value, marker, permission, kind, state, request):
    status(value, permission, kind, request)
    need(keys(marker, "phase", "requestId", "assetOperationId", "statusSha256")
         and marker["requestId"] == request and hash_value(marker["statusSha256"])
         and marker["assetOperationId"] == value["assetOperationId"] and value["assetOperationId"] is not None
         and value["settlement"] == "settled" and value["state"] == state
         and value["reason"] == ("permission-revoked" if state == "cancelled" else "none")
         and digest(value) == marker["statusSha256"], "backup-cli-original-terminal")
    # Actual native Status.validate and the immutable original digest supply
    # the full public KeyReference grammar; no extra schema or key getter here.
    need((value["key"] is not None) == (state == "restored-unassigned"), "backup-cli-key-projection")


def receipt(permission, request):
    p, i = permission["projectId"], permission["serviceInstance"]
    return (f"Request {request}\nCheck: mrk upload-key-status {p} {i} {request} --json\n"
            f"Stop: mrk upload-key-cancel {p} {i} {request} --json\n").encode("ascii")


def phase(channel, calls, name, index):
    while True:
        calls.check()
        rows = channel.read()
        if rows is not None:
            need(len(rows) <= index + 1 and all(r.get("phase") == NATIVE_PHASES[n] for n, r in enumerate(rows)),
                 "backup-cli-native-order")
            if len(rows) == index + 1:
                need(rows[index]["phase"] == name, "backup-cli-native-phase")
                return rows[index]
        calls.wait()


def journey(c, calls, call):
    """Only three submits. The actual caller supplies its existing call body."""
    instance, project, grants, requests = None, None, [], []
    for index, (label, kind, wanted) in enumerate((
            ("export", "backup-encrypted", "backup-delivered"),
            ("restore", "restore-encrypted", "restored-unassigned"),
            ("cancel", "restore-encrypted", "cancelled"))):
        marker_index, number = index * 2, index * 3
        permission = allowed(phase(c.native, calls, label + "-allowed", marker_index), label + "-allowed")
        need(permission["grantId"] not in grants, "backup-cli-consent-reused")
        if instance is None:
            instance, project = permission["serviceInstance"], permission["projectId"]
        need((permission["serviceInstance"], permission["projectId"]) == (instance, project),
             "backup-cli-project-instance-changed")
        grants.append(permission["grantId"])
        same, scope = call(number, ["upload-key-scope", project], "upload-key-access")
        need(same == instance, "backup-cli-scope-instance")
        access(scope, permission, kind)
        same, row = call(number + 1, ["upload-key-submit", project, instance, permission["grantId"], "--reviewed"],
                         "upload-key-request", receipt=True)
        need(same == instance, "backup-cli-submit-instance")
        request = status(row, permission, kind)
        need(request not in requests and row["state"] in ("queued", "running")
             and row["settlement"] == "pending" and row["reason"] == "none" and row["key"] is None
             and calls.results[number + 1].stderr == receipt(permission, request), "backup-cli-submit-return")
        requests.append(request)
        c.driver.append({"phase": label + "-submitted", "requestId": request})
        query = [project, instance, request]
        if index == 2:
            entered = phase(c.native, calls, "second-entered", 5)
            need(keys(entered, "phase", "requestId", "assetOperationId") and entered["requestId"] == request
                 and type(entered["assetOperationId"]) is int and entered["assetOperationId"] == 13,
                 "backup-cli-second-original-data")
            same, stopped = call(8, ["upload-key-cancel", *query], "upload-key-request")
            need(same == instance, "backup-cli-cancel-instance")
            status(stopped, permission, kind, request)
            need(stopped["key"] is None and stopped["assetOperationId"] == 13
                 and ((stopped["state"], stopped["settlement"], calls.results[8].returncode)
                      in (("stop-requested", "pending", 0), ("cancelled", "settled", 5)))
                 and stopped["reason"] == "permission-revoked", "backup-cli-cancel-return")
            c.driver.append({"phase": "cancel-requested", "requestId": request})
            marker_index, number = 6, 7  # Last status is call 9, not another submit.
        else:
            marker_index += 1
        marker_name = "cancelled-terminal" if index == 2 else label + "-terminal"
        done = phase(c.native, calls, marker_name, marker_index)
        same, row = call(number + 2, ["upload-key-status", *query], "upload-key-request")
        need(same == instance and calls.results[number + 2].returncode == (5 if index == 2 else 0),
             "backup-cli-terminal-return")
        terminal(row, done, permission, kind, wanted, request)
        c.driver.append({"phase": "done" if index == 2 else label + "-checked", "requestId": request,
                         "statusSha256": done["statusSha256"]})
    calls.returned = True


def report(value):
    need(keys(value, "schemaVersion", "scope", "requests", "statusSha256", "originalCount", "openActions",
              "pickerCalls", "cancelledBeforeIo", "explicitBind", "allOriginalsSettled", "hostWorkersJoined",
              "sourceLockedBeforeRestore", "shippingEnabled", "rendererInteractionTested", "restartTested")
         and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["scope"] == SCOPE
         and type(value["requests"]) is list and len(value["requests"]) == 3
         and all(ident(x) for x in value["requests"]) and len(set(value["requests"])) == 3
         and type(value["statusSha256"]) is list and len(value["statusSha256"]) == 3
         and all(hash_value(x) for x in value["statusSha256"])
         and all(type(value[k]) is int and value[k] == v for k, v in
                 (("originalCount", 14), ("openActions", 5), ("pickerCalls", 6), ("hostWorkersJoined", 10)))
         and all(value[k] is True for k in ("cancelledBeforeIo", "explicitBind", "allOriginalsSettled", "sourceLockedBeforeRestore"))
         and all(value[k] is False for k in ("shippingEnabled", "rendererInteractionTested", "restartTested")),
         "backup-cli-native-report")
    return value


def readback(f, value):
    v = report(value)
    c = f.cli
    need(not f.inflight and f.last_returned and c is not None and c.joined and c.calls.returned
         and not c.calls.failed and c.calls.next == CALLS and c.calls.inflight is None
         and len(c.calls.results) == CALLS, "backup-cli-originals-not-returned")
    c.current_cli()
    native, driver = c.native.read(), c.driver.read()
    need(native is not None and driver is not None and len(native) == len(driver) == ROWS
         and [x.get("phase") for x in native] == list(NATIVE_PHASES)
         and [x.get("phase") for x in driver] == list(DRIVER_PHASES)
         and [driver[i]["requestId"] for i in (1, 3, 6)] == v["requests"]
         and [driver[i]["statusSha256"] for i in (1, 3, 6)] == v["statusSha256"]
         and [native[i]["statusSha256"] for i in (1, 3, 6)] == v["statusSha256"],
         "backup-cli-returned-comparison")
    return {"cliProcessesReturned": CALLS, "ipcWorkersActuallyJoined": CALLS, "submissions": 3,
            "sameRequestsReconnected": True, "originalThreadJoined": True,
            "secondChooserStopped": True, "privateEndpointCopied": False}
