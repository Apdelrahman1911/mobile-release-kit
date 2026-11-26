"""Compare two addresses on one disposable macOS VM using synthetic issuer fixtures."""
from __future__ import annotations

import hashlib
import ipaddress
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
MODES = ("loopback", "vm-private-interface")


def scratch(path):
    state = path.lstat()
    if (path != path.resolve(strict=True) or path.parent != BASE
            or not path.name.startswith("mrk-aia-address-") or not stat.S_ISDIR(state.st_mode)
            or stat.S_IMODE(state.st_mode) != 0o700 or state.st_uid != os.getuid()):
        raise RuntimeError("unexpected synthetic scratch")
    return path


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError("reviewed diagnostic seam changed")
    return text.replace(old, new, 1)


def vm_private_address():
    route = subprocess.check_output(
        ["/sbin/route", "-n", "get", "default"], stderr=subprocess.DEVNULL, text=True, timeout=3
    )
    interfaces = re.findall(r"(?m)^\s*interface: ([a-z][a-z0-9]{0,15})\s*$", route)
    if len(interfaces) != 1:
        raise RuntimeError("private runner interface is unavailable")
    address = ipaddress.IPv4Address(subprocess.check_output(
        ["/usr/sbin/ipconfig", "getifaddr", interfaces[0]],
        stderr=subprocess.DEVNULL, text=True, timeout=3
    ).strip())
    private = (ipaddress.IPv4Network(prefix) for prefix in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    if not any(address in network for network in private):
        raise RuntimeError("runner interface lacks an RFC1918 address")
    return str(address)


def authority_for(host):
    if str(ipaddress.IPv4Address(host)) != host:
        raise RuntimeError("invalid synthetic issuer address")
    text = HELPER.read_text(encoding="utf-8")
    text = replace_once(text, 'listener.bind(("127.0.0.1", 0))', f'listener.bind(({host!r}, 0))')
    text = replace_once(text, 'address[0] == "127.0.0.1"', f'address[0] == {host!r}')
    text = replace_once(text, 'url = f"http://127.0.0.1:{port}"', 'url = f"http://' + host + ':{port}"')
    authority = types.ModuleType("_mrk_aia_addresses")
    authority.__file__ = str(HELPER)
    exec(compile(text, str(HELPER), "exec"), vars(authority))
    authority._scratch = scratch
    return authority


def probe(mode, host):
    authority = authority_for(host)
    start = time.monotonic()
    deadline = start + 35.0
    previous = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="mrk-aia-address-", dir=BASE) as directory:
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
            with opener.open(f"http://{host}:{responder.port}" + control["route"], timeout=3) as reply:
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
                sys.executable, "-I", "-B", str(Path(__file__).resolve()), "evaluate",
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
    print("MRK_AIA_ADDRESS=" + json.dumps(note, sort_keys=True), flush=True)
    return note["observation"].get("available") is True


def main():
    if sys.platform != "darwin" or os.uname().machine != "arm64" or os.getuid() == 0:
        raise RuntimeError("requires the fixed hosted nonroot Apple Silicon account")
    if len(sys.argv) == 4 and sys.argv[1] == "evaluate":
        _, _, port, deadline = sys.argv
        scratch(Path.cwd())
        authority = authority_for("127.0.0.1")
        record = authority.evaluate_aia(int(port), float(deadline))
        print(authority.AIA_PREFIX.decode("ascii") + json.dumps(record, separators=(",", ":")))
        return 0
    if sys.argv[1:]:
        raise RuntimeError("unexpected diagnostic invocation")
    hosts = ("127.0.0.1", vm_private_address())
    results = [probe(mode, host) for mode, host in zip(MODES, hosts)]
    return int(not all(results))


if __name__ == "__main__":
    raise SystemExit(main())
