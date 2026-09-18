"""Finite no-network G1 framing fixture, NOT the live GitHub transport.

The original fixed bootstrap imports this module from the admitted fixture
package. Case supplies the same fixed mode/control/nonce and readiness/release
files as passive_core. Facts and their timestamp are synthetic constants, not
authenticated observations. No token or raw request is emitted or persisted.
There is no subprocess, fork, shell, network, project-code or clock override.
"""

import json
import math
import os
from pathlib import Path
import re
import time


PROTOCOL = "mrk-github-readonly/1"
MAX_REQUEST_BYTES = 8 * 1024
SYNTHETIC_TOKEN = "INERT_NOT_A_CREDENTIAL"
MODES = frozenset({
    "correct", "wrong_id", "wrong_protocol", "passive_envelope", "truncated",
    "extra_frames", "nonzero_exit", "delay_exit", "stdout_limit",
    "stderr_limit", "stalled_input", "wait_release",
})


def write_all(fd, data):
    remaining = memoryview(data)
    while remaining:
        length = os.write(fd, remaining)
        if length <= 0:
            raise OSError("fixture write failed")
        remaining = remaining[length:]


def unique_object(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError("fixture duplicate field")
        value[key] = item
    return value


def request():
    raw = bytearray()
    while True:
        block = os.read(0, min(8192, MAX_REQUEST_BYTES + 1 - len(raw)))
        if not block:
            break
        raw.extend(block)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError("fixture request too large")
    if (not 1 < len(raw) <= MAX_REQUEST_BYTES or not raw.startswith(b"{")
            or not raw.endswith(b"}\n") or raw.count(b"\n") != 1 or b"\r" in raw):
        raise ValueError("fixture request frame")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    if (type(value) is not dict or set(value) != {"protocol", "id", "params"}
            or value["protocol"] != PROTOCOL):
        raise ValueError("fixture request shape")
    if (type(value["id"]) is not str
            or re.fullmatch(r"github-read-[0-9]{1,20}", value["id"]) is None):
        raise ValueError("fixture identity")
    params = value["params"]
    if (type(params) is not dict
            or set(params) != {"repository", "expectedAccountId", "expectedRepositoryId", "token"}
            or params["repository"] != "owner/app" or params["token"] != SYNTHETIC_TOKEN
            or (params["expectedAccountId"], params["expectedRepositoryId"])
            not in ((None, None), ("11", "22"))):
        raise ValueError("fixture request fields")
    return value["id"]  # Never return or serialize the private request/token.


def observed(value):
    return {"state": "observed", "value": value,
            "observedAt": "2026-09-17T12:00:01Z", "reason": "none"}


def frame(identity, mode):
    value = {
        "protocol": PROTOCOL,
        "id": identity,
        "facts": {
            "schemaVersion": 1,
            "account": observed({"id": "11", "login": "owner"}),
            "repository": observed({
                "id": "22", "fullName": "owner/app", "defaultBranch": "main",
                "visibility": "private", "archived": False,
                "permissions": {"pull": "reported-allowed", "push": "unknown", "admin": "unknown"},
            }),
            "automation": observed({
                "coverage": "complete",
                "workflows": [
                    {"id": workflow, "remoteId": None, "presence": "not-listed", "state": "unknown"}
                    for workflow in ("preflight", "candidate", "external-testing", "production-submit")
                ],
            }),
        },
        "control": {"reason": "none", "credentialExpiresAt": None,
                    "cooldownSeconds": None, "cooldownBlocked": False},
    }
    if mode == "wrong_id":
        value["id"] = "wrong-id"
    elif mode == "wrong_protocol":
        value["protocol"] = "mrk-github-readonly/0"
    elif mode == "passive_envelope":
        value = {"protocol": 1, "id": identity, "ok": True,
                 "result": {"case": "passive_envelope"}}
    return json.dumps(value, separators=(",", ":")).encode("ascii") + b"\n"


def ready(config, identity, phase):
    root = Path(config["control"])
    content = json.dumps({"nonce": config["nonce"], "id": identity, "phase": phase},
                         separators=(",", ":")).encode("ascii")
    temporary = root / ("ready-" + identity + ".tmp")
    target = root / ("ready-" + identity + ".json")
    with temporary.open("xb") as stream:
        stream.write(content)
    # Distinct G1/passive prefixes share the original numeric allocator.
    if target.exists():
        raise ValueError("fixture duplicate readiness")
    temporary.rename(target)


def await_release(config, identity):
    target = Path(config["control"]) / ("release-" + identity + ".json")
    end = time.monotonic() + 30.0
    while time.monotonic() < end:
        try:
            with target.open("rb") as stream:
                raw = stream.read(513)
        except FileNotFoundError:
            time.sleep(0.01)  # Poll interval, never a readiness/finality claim.
            continue
        if len(raw) > 512 or json.loads(raw) != {"nonce": config["nonce"], "id": identity, "release": True}:
            raise ValueError("fixture release contract")
        return
    raise ValueError("fixture release deadline")


def main(*, started: float, runtime_dir: str) -> int:
    try:
        # Required bootstrap interface only. Do not open runtime_dir or replace
        # the original owner's operation/cleanup clocks with fixture timing.
        if (type(started) not in (float, int) or not math.isfinite(started)
                or type(runtime_dir) is not str or not Path(runtime_dir).is_absolute()):
            return 71
        with Path(__file__).with_name("case.json").open("rb") as stream:
            raw = stream.read(16 * 1024 + 1)
        if len(raw) > 16 * 1024:
            return 71
        config = json.loads(raw, object_pairs_hook=unique_object)
        if (type(config) is not dict or set(config) != {"mode", "control", "nonce"}
                or type(config["mode"]) is not str or config["mode"] not in MODES
                or type(config["control"]) is not str or not Path(config["control"]).is_absolute()
                or type(config["nonce"]) is not str or re.fullmatch(r"[0-9a-f]{64}", config["nonce"]) is None):
            return 71
        mode = config["mode"]
        if mode == "stalled_input":
            # This case is the fresh supervisor's first admitted original, a G1
            # github-read-1. An unread <=8KiB request may fit the OS pipe;
            # readiness here does NOT prove that the parent's writer blocked.
            ready(config, "github-read-1", "input-unread")
            await_release(config, "github-read-1")
            return 72
        identity = request()
        response = frame(identity, mode)
        if mode == "truncated":
            write_all(1, response[:-1])
        elif mode == "extra_frames":
            write_all(1, response + response)
        elif mode in {"stdout_limit", "stderr_limit"}:
            # Both G1 stdout and retained stderr have the actual 64KiB cap.
            fd = 1 if mode == "stdout_limit" else 2
            for _ in range((64 * 1024 + 8192) // 8192):
                write_all(fd, b"x" * 8192)
        elif mode == "wait_release":
            ready(config, identity, "request-eof")
            await_release(config, identity)
            write_all(1, response)
        elif mode == "delay_exit":
            write_all(1, response)
            os.close(1)
            os.close(2)
            ready(config, identity, "pipes-closed-child-held")
            await_release(config, identity)
            os._exit(0)  # Original child only; no inherited/wrapper flush route.
        else:
            write_all(1, response)
        return 9 if mode == "nonzero_exit" else 0
    except Exception:
        return 71  # No input, token, path, exception repr or traceback output.
