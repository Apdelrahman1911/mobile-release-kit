"""Diagnostic only: real macOS trust evaluation with a fixed public staging chain."""
from __future__ import annotations

import base64
import hashlib
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import time

DIRECTORY = Path(__file__).resolve().parent
ISSUER_HOST = "stg-yr2.i.lencr.org"
VERIFY_DATE = 1795651200.0 - 978307200.0  # 2026-11-26T00:00:00Z, inside the leaf validity period.
DIGESTS = {
    "leaf": "2fccbacff0ee33562357e211e08ad8ab48dfca22c5fc115a697c27ae3c90fcc0",
    "issuer": "b3afc3f8095ccd232ecb07ad04147409aff2ef47e7b0c45d061c559cd739f6ea",
    "root": "ef115fb59e040ff39d15fd8f3ef54063c704321d83cb081213272f77d3091672",
}
MODES = ("leaf-offline-before", "leaf-online", "complete-offline")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def certificates():
    raw = (DIRECTORY / "aia-staging-certificates.json").read_bytes()
    require(0 < len(raw) < 8192, "public certificate capsule size differs")
    records = json.loads(raw)
    require(type(records) is dict and records.keys() == DIGESTS.keys(), "public certificate roster differs")
    certs = {role: base64.b64decode(records[role], validate=True) for role in DIGESTS}
    require(all(hashlib.sha256(certs[role]).hexdigest() == DIGESTS[role] for role in DIGESTS),
            "public certificate digest differs")
    return certs


def evaluate(mode, certs):
    full = mode == "complete-offline"
    online = mode == "leaf-online"
    helper = runpy.run_path(str(DIRECTORY / "ci_native_authority.py"))
    owner = helper["_Trust"](certs["leaf"], certs["root"], issuer=certs["issuer"] if full else None)
    try:
        C = owner.C
        create = owner.foundation.CFDateCreate
        create.argtypes, create.restype = [C.c_void_p, C.c_double], C.c_void_p
        date = owner._own(create(None, VERIFY_DATE))
        set_date = owner.security.SecTrustSetVerifyDate
        set_date.argtypes, set_date.restype = [C.c_void_p, C.c_void_p], C.c_int32
        require(set_date(owner.trust, date) == 0, "fixed verify date refused")
        owner.set_keychains(not full)
        owner.set_network(online)
        require(owner.get_network() is online and owner.get_keychains() is (not full), "native settings differ")
        result = owner.evaluate()
        return {
            "mode": mode, "network": online, "keychains": not full, "accepted": result["accepted"],
            "chain": [next((name for name, digest in DIGESTS.items() if sha == digest), "other")
                      for sha in result["chain"]],
            "trust_error": owner.error_observation,
        }
    finally:
        owner.close()


def same_issuer_from_http(certs):
    connection = HTTPConnection(ISSUER_HOST, 80, timeout=5)
    try:
        connection.request("GET", "/", headers={"Accept": "application/pkix-cert"})
        response = connection.getresponse()
        require(response.status == 200 and response.read(len(certs["issuer"]) + 1) == certs["issuer"],
                "HTTP did not return the exact pinned staging issuer")
    finally:
        connection.close()


def run():
    require(sys.platform == "darwin" and os.uname().machine == "arm64" and os.getuid() != 0,
            "requires a fixed nonroot Apple Silicon host")
    certs = certificates()
    if len(sys.argv) == 2 and sys.argv[1] in MODES:
        print(json.dumps(evaluate(sys.argv[1], certs), sort_keys=True))
        return
    require(len(sys.argv) == 1, "unexpected staging diagnostic invocation")
    same_issuer_from_http(certs)
    notes = []
    with tempfile.TemporaryFile(dir=os.environ["RUNNER_TEMP"]) as stream:
        collector = subprocess.Popen([
            "/usr/bin/sudo", "-n", "/usr/bin/log", "stream", "--style", "ndjson", "--level", "debug",
            "--timeout", "20", "--predicate",
            f'process == "trustd" AND eventMessage CONTAINS "{ISSUER_HOST}"',
        ], stdout=stream, stderr=subprocess.DEVNULL)
        try:
            time.sleep(1.5)
            for mode in MODES:
                start = time.monotonic()
                child = subprocess.run([
                    "/usr/bin/sandbox-exec", "-p", "(version 1) (allow default) (deny network*)",
                    sys.executable, "-I", "-B", str(Path(__file__).resolve()), mode,
                ], timeout=5, capture_output=True, check=False)
                require(child.returncode == 0 and not child.stderr and len(child.stdout) <= 2048,
                        "staging evaluation child did not cleanly finish")
                note = json.loads(child.stdout)
                require(note["mode"] == mode, "child role differs")
                notes.append({**note, "seconds": round(time.monotonic() - start, 3)})
        finally:
            collector_code = collector.wait(timeout=23)
        stream.seek(0)
        raw = stream.read(131073)
    require(len(raw) <= 131072, "bounded trust event capture exceeded")
    events = []
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        message = event.get("eventMessage", "") if isinstance(event, dict) else ""
        if isinstance(message, str) and ISSUER_HOST in message:
            events.append(message.lower())
    print("MRK_AIA_STAGING=" + json.dumps({
        "certificateSha256": DIGESTS, "hostedHttpReturnedPinnedIssuer": True,
        "trustCollectorExit": collector_code,
        "issuerRequestMarkers": sum("request for uri:" in event for event in events),
        "issuerDownloadErrorMarkers": sum("failed to download issuer" in event for event in events),
        "modes": notes,
    }, sort_keys=True))


if __name__ == "__main__":
    run()
