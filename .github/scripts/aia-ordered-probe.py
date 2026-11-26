"""Diagnostic only: vary a cold offline evaluation and an explicit clock independently."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tempfile
import time

SCRIPT = Path(__file__).resolve()
BASE = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
AUTHORITY = runpy.run_path(str(SCRIPT.with_name("ci_native_authority.py")))
CONDITIONS = (
    (False, False),
    (False, True),
    (True, False),
    (True, True),
)
MODES = ("offline", "online", "complete")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def scratch(path):
    state = path.lstat()
    require(path == path.resolve(strict=True) and path.parent == BASE
            and path.name.startswith("mrk-aia-ordered-") and stat.S_ISDIR(state.st_mode)
            and stat.S_IMODE(state.st_mode) == 0o700 and state.st_uid == os.getuid(),
            "unexpected synthetic scratch")
    return path


def fixture_set(work, port, deadline):
    fixtures = AUTHORITY["_fixtures"](work, port, deadline)
    for fixture in fixtures:
        url = f"http://127.0.0.1:{port}" + fixture["route"]
        require(fixture["leaf"].count(url.encode("ascii")) == 1, "original loopback URI differs")
    return fixtures


def evaluate(fixture, mode, timestamp):
    full = mode == "complete"
    online = mode == "online"
    trust = AUTHORITY["_Trust"](fixture["leaf"], fixture["root"], issuer=fixture["issuer"] if full else None)
    try:
        if timestamp is not None:
            C = trust.C
            create = trust.foundation.CFDateCreate
            create.argtypes, create.restype = [C.c_void_p, C.c_double], C.c_void_p
            date = trust._own(create(None, timestamp - 978307200.0))
            set_date = trust.security.SecTrustSetVerifyDate
            set_date.argtypes, set_date.restype = [C.c_void_p, C.c_void_p], C.c_int32
            require(set_date(trust.trust, date) == 0, "explicit verification date refused")
        trust.set_keychains(not full)
        trust.set_network(online)
        require(trust.get_network() is online and trust.get_keychains() is (not full),
                "native getters differ")
        result = trust.evaluate()
        normalized = {hashlib.sha256(fixture[role]).hexdigest(): role for role in ("leaf", "issuer", "root")}
        return {"mode": mode, "accepted": result["accepted"],
                "chain": [normalized.get(digest, "other") for digest in result["chain"]],
                "error": trust.error_observation}
    finally:
        trust.close()


def capture(work, responder, fixtures):
    results = []
    timestamp = time.time()
    for index, (prime, fixed_date) in enumerate(CONDITIONS):
        rows = []
        for mode in MODES if prime else MODES[1:]:
            start = time.monotonic()
            child = subprocess.run([
                "/usr/bin/sandbox-exec", "-p", "(version 1) (allow default) (deny network*)",
                sys.executable, "-I", "-B", str(SCRIPT), mode, str(index), str(responder.port),
                str(timestamp) if fixed_date else "-",
            ], cwd=work, timeout=4, capture_output=True, check=False)
            require(child.returncode == 0 and not child.stderr and 0 < len(child.stdout) <= 2048,
                    "comparison child did not cleanly complete")
            row = json.loads(child.stdout)
            require(row["mode"] == mode, "unexpected evaluation comparison")
            rows.append({**row, "seconds": round(time.monotonic() - start, 3)})
        results.append((fixtures[index], {"offlineFirst": prime, "explicitDate": fixed_date, "modes": rows}))
    return results


def run():
    require(sys.platform == "darwin" and os.uname().machine == "arm64" and os.getuid() != 0,
            "requires the nonroot hosted Apple Silicon account")
    for name in ("prepare_aia", "_fixtures"):
        AUTHORITY[name].__globals__["_scratch"] = scratch
    if len(sys.argv) == 5 and sys.argv[1] in MODES:
        mode, index, port, timestamp = sys.argv[1:]
        fixtures = fixture_set(scratch(Path.cwd()), int(port), time.monotonic() + 3)
        print(json.dumps(evaluate(fixtures[int(index)], mode, None if timestamp == "-" else float(timestamp))))
        return
    require(len(sys.argv) == 1, "unexpected ordering probe invocation")
    with tempfile.TemporaryDirectory(prefix="mrk-aia-ordered-", dir=BASE) as directory:
        work = scratch(Path(directory))
        deadline = time.monotonic() + 60
        responder = AUTHORITY["_Responder"](deadline)
        previous = Path.cwd()
        try:
            os.chdir(work)
            AUTHORITY["prepare_aia"](responder.port, deadline)
            fixtures = fixture_set(work, responder.port, deadline)
            responder.start({row["route"]: row["issuer"] for row in fixtures})
            results = capture(work, responder, fixtures)
        finally:
            os.chdir(previous)
            responder.close()
    rows = []
    for fixture, row in results:
        hashes = [digest for route, digest in responder.requests if route == fixture["route"]]
        matching = hashlib.sha256(fixture["issuer"]).hexdigest()
        require(all(digest == matching for digest in hashes), "responder sent wrong exact DER")
        rows.append({**row, "exactIssuerRequests": len(hashes)})
    print("MRK_AIA_ORDERED=" + json.dumps(rows, sort_keys=True))


if __name__ == "__main__":
    run()
