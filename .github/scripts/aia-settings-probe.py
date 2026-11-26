"""Disposable macOS experiment with fresh, private, public-key-only fixtures per case."""
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
MODES = ("original", "explicit-verify-date", "network-last", "system-parent-sources")


def scratch(path):
    state = path.lstat()
    if (path != path.resolve(strict=True) or path.parent != BASE
            or not path.name.startswith("mrk-aia-settings-") or not stat.S_ISDIR(state.st_mode)
            or stat.S_IMODE(state.st_mode) != 0o700 or state.st_uid != os.getuid()):
        raise RuntimeError("unexpected synthetic scratch")
    return path


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError("reviewed diagnostic seam changed")
    return text.replace(old, new, 1)


def authority_for(mode):
    text = HELPER.read_text(encoding="utf-8")
    if mode == "explicit-verify-date":
        location = '        result = trust.evaluate()\n        _remaining(deadline)\n        row = {"case": case,'
        text = replace_once(text, location, """        C = trust.C
        now = trust.foundation.CFAbsoluteTimeGetCurrent
        now.argtypes, now.restype = [], C.c_double
        create = trust.foundation.CFDateCreate
        create.argtypes, create.restype = [C.c_void_p, C.c_double], C.c_void_p
        set_date = trust.security.SecTrustSetVerifyDate
        set_date.argtypes, set_date.restype = [C.c_void_p, C.c_void_p], C.c_int32
        date = trust._own(create(None, now()))
        _require(set_date(trust.trust, date) == 0, "explicit verification date refused")
""" + location)
    elif mode == "network-last":
        text = replace_once(text, '''        trust.set_network(True)
        _require(trust.get_network() is True, "native AIA enabled baseline failed")
        keys = case != "product-offline"
        trust.set_keychains(keys)
        if case in ("offline", "product-offline"):
            trust.set_network(False)''', '''        keys = case != "product-offline"
        trust.set_keychains(keys)
        trust.set_network(True)
        _require(trust.get_network() is True, "native AIA enabled baseline failed")
        if case in ("offline", "product-offline"):
            trust.set_network(False)''')
    elif mode == "system-parent-sources":
        text = replace_once(text, "and anchors_only(self.trust, 1) == 0", "and anchors_only(self.trust, 0) == 0")
    elif mode != "original":
        raise RuntimeError("unknown diagnostic mode")
    authority = types.ModuleType("_mrk_aia_settings")
    authority.__file__ = str(HELPER)
    exec(compile(text, str(HELPER), "exec"), vars(authority))
    authority._scratch = scratch
    return authority


def probe(authority, mode):
    start = time.monotonic()
    deadline = start + 35.0
    previous = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="mrk-aia-settings-", dir=BASE) as directory:
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
    print("MRK_AIA_SETTINGS=" + json.dumps(note, sort_keys=True), flush=True)
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
    authority = authority_for("original")
    results = [probe(authority, mode) for mode in MODES]
    return int(not all(results))


if __name__ == "__main__":
    raise SystemExit(main())
