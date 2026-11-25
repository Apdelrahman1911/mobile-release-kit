"""Compare synthetic loopback transports on disposable hosted macOS."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import types
import urllib.request


HELPER = Path(__file__).resolve().with_name("ci_native_authority.py")
BASE = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
HOSTS = {"ipv4": "127.0.0.1", "ipv6": "[::1]", "localhost": "localhost"}


def scratch(path):
    state = path.lstat()
    if (path != path.resolve(strict=True) or path.parent != BASE or not path.name.startswith("mrk-aia-route-")
            or not stat.S_ISDIR(state.st_mode) or stat.S_IMODE(state.st_mode) != 0o700
            or state.st_uid != os.getuid()):
        raise RuntimeError("diagnostic scratch custody differs")
    return path


def authority_for(route):
    text = HELPER.read_text(encoding="utf-8")
    if route == "ipv6":
        pairs = (
            ("http://127.0.0.1:{port}", "http://[::1]:{port}"),
            ("socket.socket(socket.AF_INET, socket.SOCK_STREAM)", "socket.socket(socket.AF_INET6, socket.SOCK_STREAM)"),
            ('listener.bind(("127.0.0.1", 0))', 'listener.bind(("::1", 0))'),
            ('address[0] == "127.0.0.1"', 'address[0] == "::1"'),
        )
        for original, replacement in pairs:
            if text.count(original) != 1:
                raise RuntimeError("original responder shape differs")
            text = text.replace(original, replacement)
    elif route == "localhost":
        before = "http://127.0.0.1:{port}"
        if text.count(before) != 1:
            raise RuntimeError("original fixture URL differs")
        text = text.replace(before, "http://localhost:{port}")
    elif route != "ipv4":
        raise RuntimeError("unexpected loopback selector")
    authority = types.ModuleType("_mrk_aia_transport_diagnostic")
    authority.__file__ = str(HELPER)
    exec(compile(text, str(HELPER), "exec"), vars(authority))
    authority._scratch = scratch
    return authority


def evaluate(route, port, deadline):
    scratch(Path.cwd())
    module = authority_for(route)
    record = module.evaluate_aia(port, deadline)
    print(module.AIA_PREFIX.decode("ascii") + json.dumps(record, separators=(",", ":")))


def issuer_extension(authority, fixture, expected_uri):
    """Read only the synthetic leaf's AIA property using Security.framework."""
    import ctypes as C
    import plistlib

    def contains(value):
        if isinstance(value, dict):
            return any(contains(item) for item in value.values())
        if isinstance(value, list):
            return any(contains(item) for item in value)
        return type(value) is str and value == expected_uri

    owner = authority._Trust(fixture["leaf"], fixture["root"])
    ptr = C.c_void_p
    try:
        copy_values = owner.security.SecCertificateCopyValues
        copy_values.restype, copy_values.argtypes = ptr, [ptr, ptr, C.POINTER(ptr)]
        oid_aia = ptr.in_dll(owner.security, "kSecOIDAuthorityInfoAccess").value
        error = ptr()
        values = copy_values(owner._certificate(fixture["leaf"]), owner._array([oid_aia]), C.byref(error))
        if error.value:
            owner._own(error.value)
        if not values:
            return {"propertyAvailable": False, "uriMatches": False}
        owner._own(values)
        serialize = owner.foundation.CFPropertyListCreateData
        serialize.restype, serialize.argtypes = ptr, [ptr, ptr, C.c_long, C.c_ulong, C.POINTER(ptr)]
        error = ptr()
        data = serialize(None, values, 200, 0, C.byref(error))  # Binary plist, read-only public properties.
        if error.value:
            owner._own(error.value)
        if not data:
            return {"propertyAvailable": False, "uriMatches": False}
        raw = owner._own(data)
        size, address = owner.data_length(raw), owner.data_bytes(raw)
        if not address or not 0 < size < 16384:
            return {"propertyAvailable": False, "uriMatches": False}
        document = plistlib.loads(C.string_at(address, size))
        return {"propertyAvailable": bool(document), "uriMatches": contains(document)}
    finally:
        owner.close()


def observe(route, deny_direct_network):
    start = time.monotonic()
    deadline = start + 70.0
    authority = authority_for(route)
    previous = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="mrk-aia-route-", dir=BASE) as directory:
        work = scratch(Path(directory))
        responder = authority._Responder(deadline)
        try:
            os.chdir(work)
            authority.prepare_aia(responder.port, deadline)
            fixtures = authority._fixtures(work, responder.port, deadline)
            decoder = [
                {"case": row["case"], **issuer_extension(
                    authority, row, f"http://{HOSTS[route]}:{responder.port}" + row["route"])}
                for row in fixtures
            ]
            responder.start({row["route"]: row["issuer"] for row in fixtures})
            control = fixtures[-1]
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(f"http://{HOSTS[route]}:{responder.port}" + control["route"], timeout=3) as reply:
                if reply.read(len(control["issuer"]) + 1) != control["issuer"]:
                    raise RuntimeError("direct reachability returned different issuer bytes")
            until = time.monotonic() + 2
            while not responder.requests and time.monotonic() < until:
                time.sleep(0.01)
            if len(responder.requests) != 1:
                raise RuntimeError("direct reachability lacks its original capture")
            responder.requests.clear()
            argv = [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "evaluate", route,
                    str(responder.port), repr(deadline)]
            if deny_direct_network:
                argv = ["/usr/bin/sandbox-exec", "-p", "(version 1) (allow default) (deny network*)", *argv]
            evaluation_start = time.time_ns()
            child = subprocess.run(argv, cwd=work, env={"PATH": "/usr/bin:/bin", "RUNNER_TEMP": str(BASE),
                    "HOME": str(work), "LC_ALL": "C"}, capture_output=True, check=False,
                    timeout=authority._remaining(deadline))
            evaluation_end = time.time_ns()
        finally:
            os.chdir(previous)
            responder.close()
        note = {"route": route, "directNetworkDenied": deny_direct_network, "controllerReachedResponder": True,
                "childReturn": child.returncode, "elapsedSeconds": round(time.monotonic() - start, 3),
                "nativeIssuerProperty": decoder,
                "evaluationStartUnixNs": evaluation_start, "evaluationEndUnixNs": evaluation_end}
        if child.returncode or child.stderr or not 0 < len(child.stdout) <= 8192:
            return {**note, "result": "unavailable", "stderrBytes": len(child.stderr)}
        return {**note, "result": authority._aia_comparison_note(child.stdout, fixtures, responder.requests)}


if __name__ == "__main__":
    if sys.platform != "darwin" or os.uname().machine != "arm64" or os.getuid() == 0:
        raise RuntimeError("requires the fixed nonroot hosted Apple Silicon account")
    if len(sys.argv) == 5 and sys.argv[1] == "evaluate":
        evaluate(sys.argv[2], int(sys.argv[3]), float(sys.argv[4]))
    elif len(sys.argv) == 1:
        os_version = subprocess.check_output(["/usr/bin/sw_vers", "-productVersion"], text=True).strip()
        observations = [observe(route, denied) for route in ("ipv4",) for denied in (False, True)]
        print(json.dumps({"scope": "diagnostic only", "os": os_version, "observations": observations}, sort_keys=True))
        raise SystemExit(int(any(row["result"] == "unavailable" or not row["result"].get("available")
                                 for row in observations)))
    else:
        raise RuntimeError("unexpected diagnostic invocation")
