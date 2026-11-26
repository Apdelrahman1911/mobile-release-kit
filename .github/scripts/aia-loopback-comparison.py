"""Compare synthetic loopback transports on disposable hosted macOS."""
import base64
import hashlib
import json
import re
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
FIXTURE_PORT = 38771
CAPSULE_NAMES = ("aia.json", *(f"{case}-{role}.der"
    for case in ("online", "offline", "mutant", "product-offline")
    for role in ("root", "issuer", "leaf")))


def scratch(path):
    state = path.lstat()
    if (path != path.resolve(strict=True) or path.parent != BASE or not path.name.startswith("mrk-aia-route-")
            or not stat.S_ISDIR(state.st_mode) or stat.S_IMODE(state.st_mode) != 0o700
            or state.st_uid != os.getuid()):
        raise RuntimeError("diagnostic scratch custody differs")
    return path


def authority_for(route):
    text = HELPER.read_text(encoding="utf-8")
    listener = 'listener.bind(("127.0.0.1", 0))'
    if route != "ipv4" or text.count(listener) != 1:
        raise RuntimeError("fixed loopback responder differs")
    text = text.replace(listener, f'listener.bind(("127.0.0.1", {FIXTURE_PORT}))')
    authority = types.ModuleType("_mrk_aia_transport_diagnostic")
    authority.__file__ = str(HELPER)
    exec(compile(text, str(HELPER), "exec"), vars(authority))
    authority._scratch = scratch
    return authority


def evaluate(route, port, deadline):
    scratch(Path.cwd())
    module = authority_for(route)
    windows = []
    original = module._evaluate_case

    def timed_case(fixture, deadline, observations):
        start = time.time_ns()
        result = original(fixture, deadline, observations)
        windows.append({"case": fixture["case"], "start": start, "end": time.time_ns()})
        return result

    module._evaluate_case = timed_case
    record = module.evaluate_aia(port, deadline)
    print("MRK_TRUST_CASE_WINDOWS=" + json.dumps(windows, separators=(",", ":")), file=sys.stderr)
    print(module.AIA_PREFIX.decode("ascii") + json.dumps(record, separators=(",", ":")))


def issuer_extension(authority, fixture, expected_uri):
    """Observe the same borrowed issuer-URL array used by trustd's fetch path."""
    import ctypes as C

    owner = authority._Trust(fixture["leaf"], fixture["root"])
    ptr = C.c_void_p
    try:
        get_issuers = getattr(owner.security, "SecCertificateGetCAIssuers", None)
        if get_issuers is None:
            return {"accessorAvailable": False, "uriCount": None, "uriMatches": False}
        get_issuers.restype, get_issuers.argtypes = ptr, [ptr]
        leaf = owner._certificate(fixture["leaf"])
        urls = get_issuers(leaf)  # The certificate owns this Get-rule result.
        if not urls:
            return {"accessorAvailable": True, "uriCount": 0, "uriMatches": False}
        count = owner.array_count(urls)
        if not 0 <= count <= 8:
            return {"accessorAvailable": True, "uriCount": None, "uriMatches": False}
        url_text = owner.foundation.CFURLGetString
        url_text.restype, url_text.argtypes = ptr, [ptr]
        string_to_bytes = owner.foundation.CFStringGetCString
        string_to_bytes.restype = C.c_ubyte
        string_to_bytes.argtypes = [ptr, ptr, C.c_long, C.c_uint32]
        for index in range(count):
            item = owner.array_item(urls, index)
            text = url_text(item) if item else None
            result = C.create_string_buffer(1024)
            if (text and string_to_bytes(text, result, len(result), 0x08000100)
                    and result.value == expected_uri.encode("ascii")):
                return {"accessorAvailable": True, "uriCount": count, "uriMatches": True}
        return {"accessorAvailable": True, "uriCount": count, "uriMatches": False}
    finally:
        owner.close()


def case_windows(data, start, end):
    prefix = b"MRK_TRUST_CASE_WINDOWS="
    if len(data) > 1024 or not data.startswith(prefix) or data.count(b"\n") != 1 or not data.endswith(b"\n"):
        return None
    try:
        rows = json.loads(data[len(prefix):])
    except (ValueError, UnicodeError):
        return None
    cases = ("online", "offline", "mutant", "product-offline")
    if type(rows) is not list or len(rows) != len(cases):
        return None
    for case, row in zip(cases, rows):
        if (type(row) is not dict or set(row) != {"case", "start", "end"} or row["case"] != case
                or type(row["start"]) is not int or type(row["end"]) is not int
                or not start <= row["start"] <= row["end"] <= end):
            return None
        start = row["end"]
    return rows


def export_fixture():
    authority = authority_for("ipv4")
    deadline = time.monotonic() + 70.0
    previous = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="mrk-aia-route-", dir=BASE) as directory:
        work = scratch(Path(directory))
        try:
            os.chdir(work)
            authority.prepare_aia(FIXTURE_PORT, deadline)
            authority._fixtures(work, FIXTURE_PORT, deadline)
            if {path.name for path in work.iterdir()} != set(CAPSULE_NAMES):
                raise RuntimeError("synthetic public fixture inventory differs")
            public = {name: base64.b64encode(authority._read_public(work / name)).decode("ascii")
                      for name in CAPSULE_NAMES}
        finally:
            os.chdir(previous)
    print(json.dumps(public, sort_keys=True, separators=(",", ":")))


def import_fixture(authority, work):
    expected = os.environ["MRK_FIXTURE_SHA256"]
    wire = authority._read_public(BASE / "mrk-aia-fixture" / "capsule.json", 65536)
    if not re.fullmatch(r"[a-f0-9]{64}", expected) or hashlib.sha256(wire).hexdigest() != expected:
        raise RuntimeError("shared fixture digest differs")
    public = json.loads(wire)
    if type(public) is not dict or set(public) != set(CAPSULE_NAMES):
        raise RuntimeError("shared public fixture inventory differs")
    for name in CAPSULE_NAMES:
        original = base64.b64decode(public[name], validate=True)
        if not 0 < len(original) <= 4096:
            raise RuntimeError("shared fixture member size differs")
        authority._write_new(work / name, original)
    return expected


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
            fixture_sha = import_fixture(authority, work)
            fixtures = authority._fixtures(work, responder.port, deadline)
            decoder = [
                {"case": row["case"], **issuer_extension(
                    authority, row, f"http://127.0.0.1:{responder.port}" + row["route"])}
                for row in fixtures
            ]
            responder.start({row["route"]: row["issuer"] for row in fixtures})
            control = fixtures[-1]
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(f"http://127.0.0.1:{responder.port}" + control["route"], timeout=3) as reply:
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
                "nativeIssuerProperty": decoder, "fixtureSha256": fixture_sha,
                "evaluationStartUnixNs": evaluation_start, "evaluationEndUnixNs": evaluation_end}
        windows = case_windows(child.stderr, evaluation_start, evaluation_end)
        if child.returncode or windows is None or not 0 < len(child.stdout) <= 8192:
            return {**note, "result": "unavailable", "stderrBytes": len(child.stderr)}
        return {**note, "casesTimed": windows,
                "result": authority._aia_comparison_note(child.stdout, fixtures, responder.requests)}


if __name__ == "__main__":
    if sys.platform != "darwin" or os.uname().machine != "arm64" or os.getuid() == 0:
        raise RuntimeError("requires the fixed nonroot hosted Apple Silicon account")
    if len(sys.argv) == 5 and sys.argv[1] == "evaluate":
        evaluate(sys.argv[2], int(sys.argv[3]), float(sys.argv[4]))
    elif sys.argv[1:] == ["generate"]:
        export_fixture()
    elif sys.argv[1:] == ["replay"]:
        os_version = subprocess.check_output(["/usr/bin/sw_vers", "-productVersion"], text=True).strip()
        observation = observe("ipv4", True)
        print(json.dumps({"scope": "diagnostic only", "os": os_version, "observation": observation}, sort_keys=True))
        result = observation["result"]
        raise SystemExit(int(result == "unavailable" or not result.get("available")))
    else:
        raise RuntimeError("unexpected diagnostic invocation")
