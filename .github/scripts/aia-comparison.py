"""Diagnostic-only comparison for a disposable, unsigned hosted macOS run."""
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request

HELPER = Path(".github/scripts/ci_native_authority.py").resolve()
BASE = Path(os.environ["RUNNER_TEMP"]).resolve()
spec = importlib.util.spec_from_file_location("original_native_aia", HELPER)
authority = importlib.util.module_from_spec(spec)
spec.loader.exec_module(authority)


def diagnostic_scratch(work):
    info = work.lstat()
    if (work != work.resolve(strict=True) or work.parent != BASE or not work.name.startswith("mrk-aia-")
            or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != os.getuid() or os.getuid() == 0):
        raise RuntimeError("diagnostic scratch custody differs")
    return work


def evaluate(work, port, deadline):
    diagnostic_scratch(work)
    os.chdir(work)
    authority._scratch = diagnostic_scratch
    print(authority.AIA_PREFIX.decode("ascii") + json.dumps(authority.evaluate_aia(port, deadline), separators=(",", ":")))


def exercise(name, isolated):
    deadline = time.monotonic() + 85
    former = Path.cwd()
    script = Path(__file__).resolve()
    with tempfile.TemporaryDirectory(prefix="mrk-aia-", dir=BASE) as path:
        work = diagnostic_scratch(Path(path))
        responder = authority._Responder(deadline)
        closed = False
        try:
            authority._scratch = diagnostic_scratch
            os.chdir(work)
            authority.prepare_aia(responder.port, deadline)
            fixtures = authority._fixtures(work, responder.port, deadline)
            responder.start({row["route"]: row["issuer"] for row in fixtures})
            offline = next(row for row in fixtures if row["case"] == "product-offline")
            request = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with request.open(f"http://127.0.0.1:{responder.port}" + offline["route"], timeout=3) as reply:
                if reply.read(len(offline["issuer"]) + 1) != offline["issuer"]:
                    raise RuntimeError("original loopback responder returned different fixture bytes")
            reachability_deadline = min(deadline, time.monotonic() + 3)
            while len(responder.requests) != 1 and time.monotonic() < reachability_deadline:
                time.sleep(0.01)
            if len(responder.requests) != 1:
                raise RuntimeError("original loopback responder did not account for the reachability control")
            responder.requests.clear()
            command = [sys.executable, "-I", "-B", str(script), "evaluate", str(work),
                       str(responder.port), repr(deadline)]
            if isolated:
                command = ["/usr/bin/sandbox-exec", "-p", "(version 1) (allow default) (deny network*)", *command]
            # Fresh synthetic anchors and a loopback URL, with no job token or signing inputs.
            child = subprocess.run(command, cwd=former, env={"PATH": "/usr/bin:/bin",
                "RUNNER_TEMP": str(BASE), "HOME": str(work), "LC_ALL": "C"}, capture_output=True,
                timeout=max(1, deadline - time.monotonic()), check=False)
            if child.returncode != 0 or child.stderr or not 0 < len(child.stdout) <= 8192:
                return {"case": name, "controllerReachedResponder": True, "childReturn": child.returncode,
                        "boundedOutput": 0 < len(child.stdout) <= 8192, "stderrBytes": len(child.stderr),
                        "result": "unavailable"}
            closed = True
            responder.close()
            observation = authority._aia_comparison_note(child.stdout, fixtures, responder.requests)
            return {"case": name, "controllerReachedResponder": True, "childReturn": child.returncode,
                    "result": observation,
                    "elapsedSeconds": round(time.monotonic() - (deadline - 85), 3)}
        finally:
            os.chdir(former)
            if not closed:
                responder.close()


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "evaluate":
        evaluate(Path(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4]))
    elif len(sys.argv) == 1:
        if sys.platform != "darwin" or os.uname().machine != "arm64" or os.getuid() == 0:
            raise RuntimeError("requires the fixed nonroot hosted Apple Silicon account")
        report = {"scope": "test-only runner diagnostic", "os": subprocess.check_output(
            ["/usr/bin/sw_vers", "-productVersion"], text=True).strip(),
            "runs": [exercise("direct-network-denied", True), exercise("runner-network-policy", False)]}
        print(json.dumps(report, sort_keys=True))
    else:
        raise RuntimeError("unexpected diagnostic route")
