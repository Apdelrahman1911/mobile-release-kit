"""Identify separate effects from the AIA hostname and HTTP port."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
import hashlib
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import time
import types

SCRIPT = Path(__file__).resolve()
BASE = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
HELPER = SCRIPT.with_name("ci_native_authority.py")
HOSTS = {"online": "127.0.0.1", "offline": "localhost", "mutant": "localhost", "product-offline": "localhost"}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def scratch(path):
    state = path.lstat()
    require(path == path.resolve(strict=True) and path.parent == BASE
            and path.name.startswith("mrk-aia-endpoint-") and stat.S_ISDIR(state.st_mode)
            and stat.S_IMODE(state.st_mode) == 0o700 and state.st_uid == os.getuid(), "invalid probe scratch")
    return path


def module_for(port):
    source = HELPER.read_text(encoding="utf-8")
    overrides = {
        'http://127.0.0.1:{port}': 'http://{_probe_hosts[case]}:{port}',
        'listener.bind(("127.0.0.1", 0))': f'listener.bind(("127.0.0.1", {port}))',
    }
    for original, replacement in overrides.items():
        require(source.count(original) == 1, "reviewed AIA seam changed")
        source = source.replace(original, replacement, 1)
    module = types.ModuleType("_mrk_aia_port_policy")
    module.__file__ = str(HELPER)
    exec(compile(source, str(HELPER), "exec"), vars(module))
    module._scratch = scratch
    module._probe_hosts = HOSTS
    return module


def fixture_set(module, work, port, cutoff):
    fixtures = module._fixtures(work, port, cutoff)
    for item in fixtures:
        url = f"http://{HOSTS[item['case']]}:{port}" + item["route"]
        require(item["leaf"].count(url.encode("ascii")) == 1, "AIA URL disagrees with verified fixture")
    return fixtures


def observe(module, port, cutoff):
    work = scratch(Path.cwd())
    fixtures = fixture_set(module, work, port, cutoff)
    observations = []
    for fixture in fixtures:
        start = time.time()
        result = module._evaluate_case(fixture, cutoff)
        observations.append({"start": start, "end": time.time(), "result": result})
    original = fixtures[0]
    contrast, _ = module._evaluate_offline_contrast(original, cutoff)
    print(json.dumps({"rows": observations, "fullPresentedOffline": contrast}))


def exec_child(work, port, cutoff):
    command = [
        "/usr/bin/sandbox-exec", "-p", "(version 1) (allow default) (deny network*)",
        sys.executable, "-I", "-B", str(SCRIPT), "evaluate", str(port), repr(cutoff),
    ]
    child = subprocess.run(command, cwd=work, timeout=10, capture_output=True, check=False)
    require(child.returncode == 0 and not child.stderr and 0 < len(child.stdout) <= 8192,
            "sandboxed issuer cases did not complete")
    return json.loads(child.stdout)


def measure(requested_port):
    module = module_for(requested_port)
    cutoff = time.monotonic() + 45
    with tempfile.TemporaryDirectory(prefix="mrk-aia-endpoint-", dir=BASE) as directory:
        work = scratch(Path(directory))
        previous = Path.cwd()
        responder = module._Responder(cutoff)
        try:
            os.chdir(work)
            port = responder.port
            require(port == requested_port if requested_port else port not in (80, 8080), "unexpected test port")
            module.prepare_aia(port, cutoff)
            fixtures = fixture_set(module, work, port, cutoff)
            responder.start({fixture["route"]: fixture["issuer"] for fixture in fixtures})
            result = exec_child(work, port, cutoff)
            direct = fixtures[-1]
            before_control = len(responder.requests)
            conn = HTTPConnection("localhost", port, timeout=2)
            try:
                conn.request("GET", direct["route"])
                reply = conn.getresponse()
                require(reply.status == 200 and reply.read(len(direct["issuer"]) + 1) == direct["issuer"],
                        "direct positive control did not return exact DER")
            finally:
                conn.close()
        finally:
            os.chdir(previous)
            responder.close()
    seen = responder.requests[:before_control]
    require(responder.requests[before_control:] == [
        (direct["route"], hashlib.sha256(direct["issuer"]).hexdigest())
    ], "direct control request was not captured exactly once")
    for item, row in zip(fixtures, result["rows"], strict=True):
        native = row["result"]
        require(item["case"] == native["case"], "fixture/evaluation order differs")
        digest = [hashlib.sha256(item[role]).hexdigest() for role in ("leaf", "issuer", "root")]
        expected = digest if native["accepted"] else digest[:1]
        require(native["chain"] == expected, "native chain does not match the fixture")
        row["host"] = HOSTS[item["case"]]
        row["url"] = f"http://{row['host']}:{port}" + item["route"]
        row["exactRequests"] = sum(route == item["route"] and sha == digest[1] for route, sha in seen)
        native.pop("chain")
    require(result["fullPresentedOffline"]["accepted"] is True, "complete chain failed its offline control")
    return {"port": port, **result}


def logs(stream):
    stream.seek(0)
    raw = stream.read(1048577)
    require(len(raw) <= 1048576, "log collector exceeded output bound")
    for line in raw.splitlines():
        try:
            row = json.loads(line)
            stamp = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00")).timestamp()
            yield stamp, row["eventMessage"].lower()
        except (ValueError, KeyError, TypeError, AttributeError):
            continue


def annotate(result, events):
    for row in result["rows"]:
        messages = [message for stamp, message in events if row["start"] <= stamp <= row["end"] + 0.05]
        uri = row.pop("url")
        row["exactSchedules"] = sum(uri in message and "request for uri:" in message for message in messages)
        tokens = {
            "ssrf": "ssrf",
            "blockedPort": "disallowed port",
            "literal": "ip literal",
            "noRequest": "no request issued",
            "missingIntermediate": "missingintermediate",
            "networkDisabled": "network access disabled by policy",
            "networkUnavailable": "network access not allowed in this environment",
            "failedDownload": "failed to download issuer",
        }
        row["logMarkers"] = dict(Counter(key for msg in messages for key, needle in tokens.items() if needle in msg))
        row["seconds"] = round(row.pop("end") - row.pop("start"), 3)
    return result


def run():
    require(sys.platform == "darwin" and os.uname().machine == "arm64" and os.getuid() != 0,
            "requires a disposable nonroot Apple Silicon runner")
    if len(sys.argv) == 4 and sys.argv[1] == "evaluate":
        observe(module_for(0), int(sys.argv[2]), float(sys.argv[3]))
        return
    require(len(sys.argv) == 1, "unexpected port policy diagnostic arguments")
    addresses = {row[4][0] for row in socket.getaddrinfo("localhost", 8080, type=socket.SOCK_STREAM)}
    require("127.0.0.1" in addresses and addresses <= {"127.0.0.1", "::1"}, "localhost escaped loopback")
    predicate = (
        'process == "trustd" AND (category == "caissuer" OR category == "http" OR category == "trust" '
        'OR eventMessage CONTAINS[c] "SSRF" OR eventMessage CONTAINS[c] "/mrk-aia/")'
    )
    with tempfile.TemporaryFile(dir=BASE) as stream:
        collector = subprocess.Popen([
            "/usr/bin/sudo", "-n", "/usr/bin/log", "stream", "--style", "ndjson", "--level",
            "debug", "--timeout", "25", "--predicate", predicate,
        ], stdout=stream, stderr=subprocess.DEVNULL)
        try:
            time.sleep(1.0)
            probes = [measure(port) for port in (0, 8080)]
        finally:
            code = collector.wait(timeout=28)
        require(code == 0, "trustd log collector failed")
        events = list(logs(stream))
    result = {"localhostAddresses": sorted(addresses), "capturedLogEvents": len(events),
              "probes": [annotate(probe, events) for probe in probes]}
    print("MRK_AIA_PORT_POLICY=" + json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    run()
