"""Diagnostic-only comparison for a disposable, unsigned hosted macOS run."""
import contextlib
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


@contextlib.contextmanager
def live_trust_events(routes):
    predicate = ('(process == "trustd" OR process == "trustd.agent") '
                 'AND (category == "http" OR category == "caissuer")')
    notes = {"available": False}
    # No raw system messages enter the report or an uploaded file.
    with tempfile.TemporaryFile(dir=BASE) as capture:
        with subprocess.Popen(["/usr/bin/log", "stream", "--timeout", "7", "--level", "debug",
                               "--style", "compact", "--predicate", predicate],
                              stdin=subprocess.DEVNULL, stdout=capture, stderr=subprocess.DEVNULL) as stream:
            try:
                time.sleep(0.5)
                yield notes
            finally:
                try:
                    result = stream.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    stream.kill()
                    stream.wait(timeout=2)
                    result = -1
                capture.seek(0)
                raw = capture.read(256 * 1024 + 1)
                if result == 0 and len(raw) <= 256 * 1024:
                    lines = raw.decode("utf-8", "replace").splitlines()
                    matching = [line for line in lines if any(route in line for route in routes)]
                    markers = {"request": "request for uri:", "downloadFailure": "Failed to download issuer",
                               "parentsFound": "found parents for", "timedOut": "evaluation timeout",
                               "networkPolicyRefusal": "network access not allowed in this environment",
                               "networkDisabled": "network access disabled by policy",
                               "noRequest": "no request issued"}
                    notes.update(available=True,
                                 fixtureScoped={key: sum(marker in line for line in matching)
                                                for key, marker in markers.items()},
                                 allTrustEvents={key: sum(marker in line for line in lines)
                                                 for key, marker in markers.items()},
                                 fixtureUrlErrors=sorted({int(code) for line in matching for code in
                                    re.findall(r"NSURLErrorDomain Code=(-1[0-9]{3})", line)}))


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
            with live_trust_events([row["route"] for row in fixtures]) as system:
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
                    "result": observation, "system": system,
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
            "runs": [exercise("default-process", False), exercise("direct-network-denied", True)]}
        print(json.dumps(report, sort_keys=True))
    else:
        raise RuntimeError("unexpected diagnostic route")
