"""Test the staging leaf's CRL distribution point as the sole added synthetic extension."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import types

DIRECTORY = Path(__file__).resolve().parent
BASE = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
PUBLIC_URI = "http://stg-yr2.i.lencr.org/"
CRL_URI = "http://stg-yr2.c.lencr.org/44.crl"
MANIFEST_PORT = 39077
MODES = ("leaf-online", "complete-offline")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def scratch(path):
    info = path.lstat()
    require(path == path.resolve(strict=True) and path.parent == BASE
            and path.name.startswith("mrk-aia-uri-") and stat.S_ISDIR(info.st_mode)
            and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid(),
            "unexpected synthetic scratch")
    return path


def authority():
    helper = DIRECTORY / "ci_native_authority.py"
    original = helper.read_text(encoding="utf-8")
    line = 'url = f"http://127.0.0.1:{port}" + _route(nonce, case)'
    require(original.count(line) == 1, "reviewed fixture generation seam changed")
    module = types.ModuleType("_mrk_aia_uri")
    module.__file__ = str(helper)
    extensions = PUBLIC_URI + chr(10) + "crlDistributionPoints=URI:" + CRL_URI
    exec(compile(original.replace(line, f"url = {extensions!r}", 1), str(helper), "exec"), vars(module))
    module._scratch = scratch
    return module


def evaluate(module, mode, fixture):
    full = mode == "complete-offline"
    owner = module._Trust(fixture["leaf"], fixture["root"], issuer=fixture["issuer"] if full else None)
    try:
        owner.set_keychains(not full)
        owner.set_network(not full)
        require(owner.get_network() is (not full) and owner.get_keychains() is (not full), "native settings differ")
        result = owner.evaluate()
        original = {hashlib.sha256(fixture[role]).hexdigest(): role for role in ("leaf", "issuer", "root")}
        return {
            "mode": mode, "network": not full, "accepted": result["accepted"],
            "chain": [original.get(sha, "other") for sha in result["chain"]],
            "trust_error": owner.error_observation,
        }
    finally:
        owner.close()


def compare(module, work):
    module.prepare_aia(MANIFEST_PORT, time.monotonic() + 30)
    fixtures = module._fixtures(work, MANIFEST_PORT, time.monotonic() + 3)
    leaf = fixtures[0]["leaf"]
    require(all(leaf.count(uri.encode("ascii")) == 1 for uri in (PUBLIC_URI, CRL_URI)),
            "both public staging URLs must occur once in the synthetic leaf")
    notes = []
    notice = f'process == "trustd" AND (eventMessage CONTAINS "{PUBLIC_URI}" OR eventMessage CONTAINS "{CRL_URI}")'
    with tempfile.TemporaryFile(dir=BASE) as stream:
        collector = subprocess.Popen([
            "/usr/bin/sudo", "-n", "/usr/bin/log", "stream", "--style", "ndjson", "--level", "debug",
            "--timeout", "15", "--predicate", notice,
        ], stdout=stream, stderr=subprocess.DEVNULL)
        try:
            time.sleep(1.5)
            for mode in MODES:
                start = time.monotonic()
                child = subprocess.run([
                    "/usr/bin/sandbox-exec", "-p", "(version 1) (allow default) (deny network*)",
                    sys.executable, "-I", "-B", str(Path(__file__).resolve()), mode,
                ], timeout=5, capture_output=True, check=False)
                require(child.returncode == 0 and not child.stderr and 0 < len(child.stdout) <= 2048,
                        "synthetic evaluation child did not cleanly finish")
                note = json.loads(child.stdout)
                require(note["mode"] == mode, "child role differs")
                notes.append({**note, "seconds": round(time.monotonic() - start, 3)})
        finally:
            collector_code = collector.wait(timeout=18)
        stream.seek(0)
        raw = stream.read(131073)
    require(len(raw) <= 131072, "bounded trust event capture exceeded")
    marker_count = sum(b"request for uri:" in line.lower() and PUBLIC_URI.encode("ascii") in line
                       for line in raw.splitlines())
    print("MRK_AIA_SYNTHETIC_CRL=" + json.dumps({
        "certificateSha256": {role: hashlib.sha256(fixtures[0][role]).hexdigest() for role in ("leaf", "issuer", "root")},
        "trustCollectorExit": collector_code, "issuerRequestMarkers": marker_count, "modes": notes,
        "crlLogMarkers": sum(CRL_URI.encode("ascii") in line for line in raw.splitlines()),
    }, sort_keys=True))


def run():
    require(sys.platform == "darwin" and os.uname().machine == "arm64" and os.getuid() != 0,
            "requires the fixed nonroot hosted Apple Silicon host")
    module = authority()
    if len(sys.argv) == 2 and sys.argv[1] in MODES:
        fixture = module._fixtures(scratch(Path.cwd()), MANIFEST_PORT, time.monotonic() + 3)[0]
        print(json.dumps(evaluate(module, sys.argv[1], fixture), sort_keys=True))
        return
    require(len(sys.argv) == 1, "unexpected URI diagnostic invocation")
    previous = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="mrk-aia-uri-", dir=BASE) as scratch_dir:
        work = scratch(Path(scratch_dir))
        try:
            os.chdir(work)
            compare(module, work)
        finally:
            os.chdir(previous)


if __name__ == "__main__":
    run()
