"""Compare Apple trust policies using fresh synthetic loopback issuer fixtures."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import types
from urllib.request import ProxyHandler, build_opener

BASE = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
HELPER = Path(__file__).with_name("ci_native_authority.py")
MODES = ("basic-x509", "basic-revocation", "ssl-client-revocation", "ssl-client-reevaluate")


def scratch(path):
    state = path.lstat()
    if (path != path.resolve(strict=True) or path.parent != BASE
            or not path.name.startswith("mrk-aia-policy-") or not stat.S_ISDIR(state.st_mode)
            or stat.S_IMODE(state.st_mode) != 0o700 or state.st_uid != os.getuid()):
        raise RuntimeError("unexpected synthetic scratch")
    return path


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError("reviewed diagnostic seam changed")
    return text.replace(old, new, 1)


def authority_for(mode):
    if mode not in MODES:
        raise RuntimeError("unknown diagnostic mode")
    text = HELPER.read_text(encoding="utf-8")
    if mode != "basic-x509":
        policy_binding = '        policy_create = bind(security, "SecPolicyCreateBasicX509", P, [])'
        revocation_binding = '        revocation_create = bind(security, "SecPolicyCreateRevocation", P, [C.c_ulong])'
        original_policy = '            policy = self._own(policy_create())'
        if mode.startswith("ssl-client"):
            trust_binding = '        policy_create = bind(security, "SecPolicyCreateSSL", P, [C.c_ubyte, P])'
            trust_policy = '            policy = self._own(policy_create(0, None))'
        else:
            trust_binding = policy_binding
            trust_policy = original_policy
        text = replace_once(text, policy_binding, trust_binding + "\n" + revocation_binding)
        text = replace_once(text, original_policy, trust_policy + """
            # SecPolicy.h defines UseAnyAvailableMethod as OCSP (1) | CRL (2).
            revocation = self._own(revocation_create(1 | 2))
            policy = self._array([policy, revocation])""")
    if mode == "ssl-client-reevaluate":
        location = '        result = trust.evaluate()\n        _remaining(deadline)\n        row = {"case": case,'
        text = replace_once(text, location, """        if network:
            trust.set_network(False)
            _require(trust.get_network() is False, "offline reevaluation baseline setting differs")
            offline = trust.evaluate()
            _require(offline["accepted"] is False and offline["result"] == 5 and len(offline["chain"]) == 1,
                     "offline reevaluation baseline unexpectedly found the synthetic issuer")
            trust.set_network(True)
            _require(trust.get_network() is True, "online reevaluation setting differs")
            _remaining(deadline)
""" + location)
    authority = types.ModuleType("_mrk_aia_policy")
    authority.__file__ = str(HELPER)
    exec(compile(text, str(HELPER), "exec"), vars(authority))
    authority._scratch = scratch
    return authority


def probe(authority, mode):
    start = time.monotonic()
    deadline = start + 35.0
    previous = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="mrk-aia-policy-", dir=BASE) as directory:
        work = scratch(Path(directory))
        responder = authority._Responder(deadline)
        try:
            os.chdir(work)
            authority.prepare_aia(responder.port, deadline)
            fixtures = authority._fixtures(work, responder.port, deadline)
            fixture_sha = hashlib.sha256(authority._read_public(work / "aia.json")).hexdigest()
            responder.start({row["route"]: row["issuer"] for row in fixtures})
            # Check the listener using a separate path. This does not involve trustd or its cache.
            control = fixtures[-1]
            opener = build_opener(ProxyHandler({}))
            with opener.open(f"http://127.0.0.1:{responder.port}" + control["route"], timeout=3) as reply:
                if reply.read(len(control["issuer"]) + 1) != control["issuer"]:
                    raise RuntimeError("listener returned unexpected bytes")
            until = time.monotonic() + 2
            while not responder.requests and time.monotonic() < until:
                time.sleep(0.01)
            if len(responder.requests) != 1:
                raise RuntimeError("listener lacked a direct positive capture")
            responder.requests.clear()
            child = subprocess.run([
                "/usr/bin/sandbox-exec", "-p", "(version 1) (allow default) (deny network*)",
                sys.executable, "-I", "-B", str(Path(__file__).resolve()), "evaluate", mode,
                str(responder.port), repr(deadline),
            ], cwd=work, env={"PATH": "/usr/bin:/bin", "RUNNER_TEMP": str(BASE), "HOME": str(work), "LC_ALL": "C"},
                capture_output=True, timeout=authority._remaining(deadline), check=False)
        finally:
            os.chdir(previous)
            responder.close()
    note = {"mode": mode, "manifestSha256": fixture_sha, "childReturn": child.returncode,
            "stdoutBytes": len(child.stdout), "stderrBytes": len(child.stderr),
            "controllerReachedResponder": True, "seconds": round(time.monotonic() - start, 3)}
    if child.returncode == 0 and not child.stderr and 0 < len(child.stdout) < 8192:
        result = authority._aia_comparison_note(child.stdout, fixtures, responder.requests)
        note["observation"] = result
        try:
            authority.require_aia_controls(child.stdout, fixtures, responder.requests)
        except authority.NativeControlError:
            note["strictOutcome"] = False
        else:
            note["strictOutcome"] = True
    else:
        note["observation"] = {"available": False}
    print("MRK_AIA_POLICY=" + json.dumps(note, sort_keys=True), flush=True)
    return note["observation"].get("available") is True


def main():
    if sys.platform != "darwin" or os.uname().machine != "arm64" or os.getuid() == 0:
        raise RuntimeError("requires the fixed hosted nonroot Apple Silicon account")
    if len(sys.argv) == 5 and sys.argv[1] == "evaluate":
        _, _, mode, port, deadline = sys.argv
        scratch(Path.cwd())
        authority = authority_for(mode)
        record = authority.evaluate_aia(int(port), float(deadline))
        print(authority.AIA_PREFIX.decode("ascii") + json.dumps(record, separators=(",", ":")))
        return 0
    if sys.argv[1:]:
        raise RuntimeError("unexpected diagnostic invocation")
    authority = authority_for("basic-x509")
    results = [probe(authority, mode) for mode in MODES]
    return int(not all(results))


if __name__ == "__main__":
    raise SystemExit(main())
