"""Observe the original issuer cases alongside a verified transport and logging control."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ORDERED = runpy.run_path(str(HERE / "aia-ordered-probe.py"))
STAGING = runpy.run_path(str(HERE / "aia-staging-probe.py"))
BASE = ORDERED["BASE"]
AUTHORITY = ORDERED["AUTHORITY"]
require = ORDERED["require"]
TIME_LIMIT = 22
REQUEST = "request for uri:"
CATEGORIES = {
    "didNotIssue": "no request issued",
    "networkDisabled": "network access disabled by policy",
    "networkUnavailable": "network access not allowed in this environment",
    "issuerDownloadFailed": "failed to download issuer",
    "issuerUrlMissing": "certificate has no caissuer urls",
    "issuerExpired": "skipping caissuer fetch for expired",
    "localNetworkDenied": "local network prohibited",
    "missingIntermediate": "missingintermediate",
    "appTransportSecurity": "app transport security",
}


def text(stream, limit):
    stream.seek(0)
    raw = stream.read(limit + 1)
    require(len(raw) <= limit, "bounded collector output exceeded")
    return raw.decode("utf-8", errors="replace")


def capture(predicate, port, action):
    with (tempfile.TemporaryFile(dir=BASE) as logs,
          tempfile.TemporaryFile(dir=BASE) as packets,
          tempfile.TemporaryFile(dir=BASE) as packet_status):
        unified = subprocess.Popen([
            "/usr/bin/sudo", "-n", "/usr/bin/log", "stream", "--style", "ndjson",
            "--level", "debug", "--timeout", str(TIME_LIMIT), "--predicate", predicate,
        ], stdout=logs, stderr=subprocess.DEVNULL)
        try:
            packet = subprocess.Popen([
                "/usr/bin/sudo", "-n", "/usr/bin/perl", "-e", "alarm shift; exec @ARGV",
                str(TIME_LIMIT), "/usr/sbin/tcpdump", "-ni", "lo0", "-l", "-tt", "-s", "96",
                "-c", "96", f"tcp and host 127.0.0.1 and port {port}",
            ], stdout=packets, stderr=packet_status)
            try:
                for _ in range(30):
                    status = text(packet_status, 16384)
                    if "listening on lo0" in status:
                        break
                    time.sleep(0.1)
                require("listening on lo0" in status and packet.poll() is None and unified.poll() is None,
                        "packet or unified log collector did not start")
                time.sleep(0.5)
                windows = action()
            finally:
                packet_exit = packet.wait(timeout=TIME_LIMIT + 3)
        finally:
            log_exit = unified.wait(timeout=TIME_LIMIT + 3)
        require(log_exit == 0 and packet_exit in (0, -14, 142), "diagnostic collector failed")
        messages = []
        for line in text(logs, 1048576).splitlines():
            try:
                event = json.loads(line)
                stamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                message = event["eventMessage"]
                require(stamp.tzinfo is not None and type(message) is str, "invalid event fields")
            except (KeyError, ValueError, TypeError, RuntimeError):
                continue
            messages.append((stamp.timestamp(), message.lower()))
        times = [float(match[1]) for line in text(packets, 65536).splitlines()
                 if (match := re.match(r"(\d+\.\d+)\s+IP\s", line))]
    return windows, messages, times


def child(script, work, *arguments):
    command = ["/usr/bin/sandbox-exec", "-p", "(version 1) (allow default) (deny network*)",
               sys.executable, "-I", "-B", str(HERE / script), *arguments]
    done = subprocess.run(command, cwd=work, timeout=4, capture_output=True, check=False)
    require(done.returncode == 0 and not done.stderr and 0 < len(done.stdout) <= 4096,
            "sandboxed observation did not complete cleanly")
    return json.loads(done.stdout)


def window(rows, name, url, action):
    start = time.time()
    details = action()
    rows.append((name, url, start, time.time(), details))
    time.sleep(0.15)


def probe(work, responder, fixtures):
    def sanity_check():
        # The fourth fixture has its own URL. Run after every trust case.
        fixture = fixtures[-1]
        conn = HTTPConnection("127.0.0.1", responder.port, timeout=2)
        try:
            conn.request("GET", fixture["route"])
            reply = conn.getresponse()
            require(reply.status == 200 and reply.read(len(fixture["issuer"]) + 1) == fixture["issuer"],
                    "direct loopback control received wrong bytes")
        finally:
            conn.close()
        return {"exactDigest": hashlib.sha256(fixture["issuer"]).hexdigest()}

    def actions():
        rows = []
        # Every leaf/URL here starts cold. The public control runs after local cases.
        for index, label, mode in ((0, "loopback-online", "online"), (1, "loopback-offline", "offline"),
                                   (2, "loopback-mutant", "online"), (0, "loopback-complete-offline", "complete")):
            url = f"http://127.0.0.1:{responder.port}" + fixtures[index]["route"]
            window(rows, label, url, lambda: child(
                "aia-ordered-probe.py", work, mode, str(index), str(responder.port), "-",
            ))
        window(rows, "direct-loopback-control", "", sanity_check)
        window(rows, "public-leaf-offline", f"http://{STAGING['ISSUER_HOST']}/",
               lambda: child("aia-staging-probe.py", work, "leaf-offline-before"))
        window(rows, "public-leaf-online", f"http://{STAGING['ISSUER_HOST']}/",
               lambda: child("aia-staging-probe.py", work, "leaf-online"))
        return rows

    host = STAGING["ISSUER_HOST"]
    needle = f"127.0.0.1:{responder.port}"
    predicate = (
        f'process == "trustd" AND (eventMessage CONTAINS "{host}" OR '
        f'eventMessage CONTAINS "{needle}" OR category == "caissuer" OR category == "http" '
        'OR category == "trust" OR subsystem == "com.apple.CFNetwork")'
    )
    return capture(predicate, responder.port, actions)


def report(responder, evidence):
    windows, events, packets = evidence
    output = []
    for label, url, start, end, details in windows:
        within = [message for stamp, message in events if start <= stamp <= end + 0.08]
        counts = Counter(key for line in within for key, marker in CATEGORIES.items() if marker in line)
        route = "/" + url.split("/", 3)[-1] if label.startswith("loopback-") else None
        if label == "loopback-complete-offline":
            route = None  # Same leaf as online. Listener hits belong to its cold evaluation.
        output.append({
            "test": label, "result": details, "elapsedSeconds": round(end - start, 3),
            "exactUrlSchedules": sum(bool(url) and url in line and REQUEST in line for line in within),
            "anyScheduleMarkers": sum(REQUEST in line for line in within),
            "exactUrlLogEvents": sum(bool(url) and url in line for line in within),
            "portPacketCount": sum(start <= stamp <= end + 0.08 for stamp in packets),
            "listenerRequestsForRoute": sum(route == observed for observed, _ in responder.requests),
            "markers": dict(counts),
        })
    positive = {row["test"]: row for row in output}
    require(positive["direct-loopback-control"]["portPacketCount"] > 0,
            "packet capture missed its known loopback positive")
    require(positive["public-leaf-offline"]["result"]["accepted"] is False
            and positive["public-leaf-online"]["result"]["chain"] == ["leaf", "issuer", "root"]
            and positive["public-leaf-online"]["result"]["accepted"] is True
            and positive["public-leaf-online"]["exactUrlSchedules"] == 1,
            "unified log capture missed its known exact issuer positive")
    print("MRK_AIA_CORRELATED=" + json.dumps({
        "logEvents": len(events), "portPackets": len(packets), "listenerRequests": len(responder.requests),
        "observations": output,
    }, sort_keys=True))


def run():
    require(sys.platform == "darwin" and os.uname().machine == "arm64" and os.getuid() != 0,
            "requires a disposable nonroot Apple Silicon runner")
    STAGING["same_issuer_from_http"](STAGING["certificates"]())
    previous = Path.cwd()
    for key in ("prepare_aia", "_fixtures"):
        AUTHORITY[key].__globals__["_scratch"] = ORDERED["scratch"]
    with tempfile.TemporaryDirectory(prefix="mrk-aia-ordered-", dir=BASE) as directory:
        work = ORDERED["scratch"](Path(directory))
        deadline = time.monotonic() + 70
        responder = AUTHORITY["_Responder"](deadline)
        try:
            os.chdir(work)
            AUTHORITY["prepare_aia"](responder.port, deadline)
            fixtures = ORDERED["fixture_set"](work, responder.port, deadline)
            responder.start({row["route"]: row["issuer"] for row in fixtures})
            evidence = probe(work, responder, fixtures)
        finally:
            os.chdir(previous)
            responder.close()
        report(responder, evidence)


if __name__ == "__main__":
    run()
