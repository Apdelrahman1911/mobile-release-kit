"""Diagnostic only: isolate fixture inputs with a single clock, host and trust API."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile
import time

DIRECTORY = Path(__file__).resolve().parent
STAGING = runpy.run_path(str(DIRECTORY / "aia-staging-probe.py"))
SYNTHETIC = runpy.run_path(str(DIRECTORY / "aia-crl-probe.py"))
BASE = SYNTHETIC["BASE"]
MODES = (
    ("synthetic", "leaf-offline"),
    ("synthetic", "leaf-online"),
    ("synthetic", "complete-offline"),
    ("staging", "leaf-offline"),
    ("staging", "leaf-online"),
    ("staging", "complete-offline"),
)
require = STAGING["require"]


def chain_for(kind, work):
    if kind == "staging":
        return STAGING["certificates"]()
    module = SYNTHETIC["authority"]()
    result = module._fixtures(work, SYNTHETIC["MANIFEST_PORT"], time.monotonic() + 3)[0]
    return {role: result[role] for role in ("leaf", "issuer", "root")}


def evaluate(work, kind, mode, timestamp):
    chain = chain_for(kind, work)
    full = mode == "complete-offline"
    online = mode == "leaf-online"
    helper = runpy.run_path(str(DIRECTORY / "ci_native_authority.py"))
    owner = helper["_Trust"](chain["leaf"], chain["root"], issuer=chain["issuer"] if full else None)
    try:
        C = owner.C
        create = owner.foundation.CFDateCreate
        create.argtypes, create.restype = [C.c_void_p, C.c_double], C.c_void_p
        date = owner._own(create(None, timestamp - 978307200.0))
        set_date = owner.security.SecTrustSetVerifyDate
        set_date.argtypes, set_date.restype = [C.c_void_p, C.c_void_p], C.c_int32
        require(set_date(owner.trust, date) == 0, "shared verify date refused")
        owner.set_keychains(not full)
        owner.set_network(online)
        require(owner.get_network() is online and owner.get_keychains() is (not full),
                "trust settings differ")
        result = owner.evaluate()
        digests = {role: hashlib.sha256(der).hexdigest() for role, der in chain.items()}
        return {
            "fixture": kind, "mode": mode, "network": online, "accepted": result["accepted"],
            "chain": [next((name for name, digest in digests.items() if sha == digest), "other")
                      for sha in result["chain"]],
            "error": owner.error_observation, "sha256": digests,
        }
    finally:
        owner.close()


def observe(work, timestamp):
    issuer_host = STAGING["ISSUER_HOST"]
    STAGING["same_issuer_from_http"](STAGING["certificates"]())
    note = f'process == "trustd" AND (eventMessage CONTAINS "{issuer_host}" OR category == "caissuer" OR category == "trust")'
    observations = []
    with tempfile.TemporaryFile(dir=BASE) as stream:
        collector = subprocess.Popen([
            "/usr/bin/sudo", "-n", "/usr/bin/log", "stream", "--style", "ndjson", "--level",
            "debug", "--timeout", "24", "--predicate", note,
        ], stdout=stream, stderr=subprocess.DEVNULL)
        try:
            time.sleep(1.5)
            for kind, mode in MODES:
                start = datetime.now(timezone.utc)
                result = subprocess.run([
                    "/usr/bin/sandbox-exec", "-p", "(version 1) (allow default) (deny network*)",
                    sys.executable, "-I", "-B", str(Path(__file__).resolve()), kind, mode, str(timestamp),
                ], cwd=work, timeout=4, capture_output=True, check=False)
                end = datetime.now(timezone.utc)
                require(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) <= 2048,
                        "comparison child did not cleanly complete")
                row = json.loads(result.stdout)
                require(row["fixture"] == kind and row["mode"] == mode, "wrong comparison result")
                observations.append((start, end, row))
                time.sleep(0.2)
        finally:
            code = collector.wait(timeout=27)
        stream.seek(0)
        raw = stream.read(1048577)
    require(code == 0 and len(raw) <= 1048576, "collector failed or exceeded capture bound")
    events = []
    for line in raw.splitlines():
        try:
            item = json.loads(line)
            stamp = datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
            message = item["eventMessage"]
        except (KeyError, TypeError, ValueError, UnicodeError):
            continue
        events.append((stamp, message))
    rows = []
    for start, end, row in observations:
        own = [message for stamp, message in events if start <= stamp <= end + timedelta(milliseconds=100)]
        counts = Counter()
        for line in own:
            if issuer_host in line and "request for uri:" in line.lower():
                counts["issuerRequestMarkers"] += 1
            if "network access disabled by policy" in line:
                counts["networkDisabledMarkers"] += 1
            if "MissingIntermediate" in line:
                counts["missingIntermediateMarkers"] += 1
            match = re.search(r"searching (?:anchor|parent) source \d+/\d+", line)
            if match:
                counts[match.group()] += 1
        rows.append({**row, "seconds": round((end - start).total_seconds(), 3),
                     "issuerRequestMarkers": counts.pop("issuerRequestMarkers", 0),
                     "trustEventCounts": dict(counts)})
    print("MRK_AIA_PAIRED=" + json.dumps({
        "sharedVerifyTime": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
        "issuerUrl": SYNTHETIC["PUBLIC_URI"], "capturedEvents": len(events), "modes": rows,
    }, sort_keys=True))


def run():
    require(sys.platform == "darwin" and os.uname().machine == "arm64" and os.getuid() != 0,
            "requires the nonroot hosted Apple Silicon account")
    if len(sys.argv) == 4 and tuple(sys.argv[1:3]) in MODES:
        print(json.dumps(evaluate(SYNTHETIC["scratch"](Path.cwd()), *sys.argv[1:3], float(sys.argv[3]))))
        return
    require(len(sys.argv) == 1, "unexpected paired comparison invocation")
    with tempfile.TemporaryDirectory(prefix="mrk-aia-uri-", dir=BASE) as directory:
        work = SYNTHETIC["scratch"](Path(directory))
        previous = Path.cwd()
        try:
            os.chdir(work)
            generator = SYNTHETIC["authority"]()
            generator.prepare_aia(SYNTHETIC["MANIFEST_PORT"], time.monotonic() + 30)
            kind_chain = chain_for("synthetic", work)
            require(kind_chain["leaf"].count(SYNTHETIC["PUBLIC_URI"].encode("ascii")) == 1,
                    "synthetic certificate did not carry the matching AIA URI")
            observe(work, time.time())
        finally:
            os.chdir(previous)


if __name__ == "__main__":
    run()
