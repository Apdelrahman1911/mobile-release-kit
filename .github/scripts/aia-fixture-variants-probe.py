"""Compare certificate inputs while keeping the loopback AIA evaluation fixed."""
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
MODES = ("random-serial", "tls-extensions", "backdated-leaf", "combined")


def scratch(path):
    state = path.lstat()
    if (path != path.resolve(strict=True) or path.parent != BASE
            or not path.name.startswith("mrk-aia-fixture-variant-") or not stat.S_ISDIR(state.st_mode)
            or stat.S_IMODE(state.st_mode) != 0o700 or state.st_uid != os.getuid()):
        raise RuntimeError("unexpected synthetic scratch")
    return path


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError("reviewed diagnostic seam changed")
    return text.replace(old, new, 1)


def sign_backdated_leaf(command, config, csr, parent, pem, serial, deadline):
    # Only the leaf gets a controlled start date. The signing key and CA
    # database are disposable, and the surrounding fixture verifies the chain.
    with tempfile.TemporaryDirectory(prefix="ca-", dir=config.parent) as directory:
        work = Path(directory)
        settings = work / "ca.cnf"
        settings.write_text(config.read_text() + """
[ca]
default_ca=issuer_ca
[issuer_ca]
database=""" + str(work / "index") + """
new_certs_dir=""" + str(work) + """
serial=""" + str(work / "serial") + """
default_md=sha256
default_days=1
policy=dn_policy
[dn_policy]
commonName=supplied
""", encoding="ascii")
        (work / "index").touch()
        (work / "serial").write_text(f"{int(serial, 0):036x}\n", encoding="ascii")
        before = time.strftime("%y%m%d%H%M%SZ", time.gmtime(time.time() - 3600))
        command(["/usr/bin/openssl", "ca", "-batch", "-notext", "-config", str(settings),
                 "-extensions", "leaf", "-cert", str(parent) + ".pem", "-keyfile", str(parent) + ".key",
                 "-startdate", before, "-days", "1", "-in", str(csr), "-out", str(pem)], deadline)


def authority_for(mode):
    if mode not in MODES:
        raise RuntimeError("unknown diagnostic mode")
    text = HELPER.read_text(encoding="utf-8")
    serial = "str(index + 1)"
    if mode in ("random-serial", "combined"):
        serial = 'f"0x{nonce}{index + 1:02x}"'
        text = replace_once(text, '"-set_serial", "1", "-extensions"', '"-set_serial", ' + serial + ', "-extensions"')
        text = replace_once(text, '"-set_serial", str(index + 1), "-days"', '"-set_serial", ' + serial + ', "-days"')
    if mode in ("tls-extensions", "combined"):
        text = replace_once(text, 'f"authorityInfoAccess=caIssuers;URI:{url}',
                            'f"extendedKeyUsage=serverAuth\\nsubjectAltName=DNS:{nonce}.example.test\\n'
                            'certificatePolicies=2.23.140.1.2.1\\nauthorityInfoAccess=caIssuers;URI:{url}')
    if mode in ("backdated-leaf", "combined"):
        begin = '                _command(["/usr/bin/openssl", "x509", "-req",'
        start = text.index(begin)
        end = text.index("\n            _command(", start)
        original = text[start:end]
        text = replace_once(text, original,
            "                if role == 'leaf':\n"
            "                    _sign_backdated_leaf(_command, config, csr, parent, pem, " + serial + ", deadline)\n"
            "                else:\n" + "\n".join("    " + line for line in original.splitlines()))
    module = types.ModuleType("_mrk_aia_fixture_variant")
    module.__file__ = str(HELPER)
    exec(compile(text, str(HELPER), "exec"), vars(module))
    module._scratch = scratch
    module._sign_backdated_leaf = sign_backdated_leaf
    return module


def probe(authority, mode):
    start = time.monotonic()
    deadline = start + 35.0
    previous = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="mrk-aia-fixture-variant-", dir=BASE) as directory:
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
    print("MRK_AIA_FIXTURE_VARIANT=" + json.dumps(note, sort_keys=True), flush=True)
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
    results = [probe(authority_for(mode), mode) for mode in MODES]
    return int(not all(results))


if __name__ == "__main__":
    raise SystemExit(main())
