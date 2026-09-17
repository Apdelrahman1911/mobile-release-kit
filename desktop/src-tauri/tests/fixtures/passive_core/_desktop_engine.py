"""Finite, single-process IPC faults, NOT the real core or a process controller.

The hosted Rust test copies these reviewed bytes into a fresh trusted fixture
package and writes one fixed case.json. There is no subprocess, fork, shell,
network, arbitrary command, descendant or project-code execution route.
"""

import json
import os
from pathlib import Path
import re
import time


MODES = frozenset({
    "echo", "malformed", "truncated", "extra_frames", "wrong_id",
    "nonzero_exit", "delay_exit", "pipe_pressure", "stdout_limit",
    "stderr_limit", "wait_release", "stalled_input",
})


def write_all(fd, data):
    remaining = memoryview(data)
    while remaining:
        length = os.write(fd, remaining)
        if length <= 0:
            raise OSError("fixture write failed")
        remaining = remaining[length:]


def frame(identity, result):
    return json.dumps({"protocol": 1, "id": identity, "ok": True, "result": result},
                      separators=(",", ":")).encode("utf-8") + b"\n"


def request():
    raw = bytearray()
    while True:
        block = os.read(0, min(8192, 1024 * 1024 + 1 - len(raw)))
        if not block:
            break
        raw.extend(block)
        if len(raw) > 1024 * 1024:
            raise ValueError("fixture request too large")
    value = json.loads(raw)
    if set(value) != {"protocol", "id", "method", "params"} or value["protocol"] != 1:
        raise ValueError("fixture request shape")
    if re.fullmatch(r"query-[0-9]{1,20}", value["id"]) is None:
        raise ValueError("fixture identity")
    return value


def ready(config, identity, phase):
    root = Path(config["control"])
    content = json.dumps({"nonce": config["nonce"], "id": identity, "phase": phase},
                         separators=(",", ":")).encode("ascii")
    temporary = root / ("ready-" + identity + ".tmp")
    target = root / ("ready-" + identity + ".json")
    with temporary.open("xb") as stream:
        stream.write(content)
    # Each original query has one distinct, previously absent marker name.
    if target.exists():
        raise ValueError("fixture duplicate readiness")
    temporary.rename(target)


def await_release(config, identity):
    target = Path(config["control"]) / ("release-" + identity + ".json")
    end = time.monotonic() + 30.0
    while time.monotonic() < end:
        try:
            with target.open("rb") as stream:
                raw = stream.read(513)
        except FileNotFoundError:
            time.sleep(0.01)  # Poll interval, never a readiness/finality claim.
            continue
        if len(raw) > 512 or json.loads(raw) != {"nonce": config["nonce"], "id": identity, "release": True}:
            raise ValueError("fixture release contract")
        return
    raise ValueError("fixture release deadline")


def main():
    try:
        if os.name == "nt":
            import msvcrt

            for descriptor in (0, 1, 2):
                msvcrt.setmode(descriptor, os.O_BINARY)
        raw = Path(__file__).with_name("case.json").read_bytes()
        if len(raw) > 16 * 1024:
            return 71
        config = json.loads(raw)
        if (set(config) != {"mode", "control", "nonce"} or config["mode"] not in MODES
                or not Path(config["control"]).is_absolute()
                or re.fullmatch(r"[0-9a-f]{64}", config["nonce"]) is None):
            return 71
        mode = config["mode"]
        if mode == "stalled_input":
            ready(config, "query-1", "input-unread")
            await_release(config, "query-1")
            return 72
        if mode == "pipe_pressure":
            # Fresh supervisor's first identity is fixed by the reviewed test.
            # Write more than normal pipe capacity before reading its large
            # request: a serial write-then-read parent would deadlock here.
            write_all(1, frame("query-1", {"pressure": "p" * (256 * 1024)}))
            write_all(2, b"d" * (32 * 1024))
            return 0 if request()["id"] == "query-1" else 73
        identity = request()["id"]
        response = frame(identity, {"case": mode})
        if mode == "malformed":
            write_all(1, b"not-json\n")
        elif mode == "truncated":
            write_all(1, response[:-1])
        elif mode == "extra_frames":
            write_all(1, response + response)
        elif mode == "wrong_id":
            write_all(1, frame("wrong-id", {}))
        elif mode in {"stdout_limit", "stderr_limit"}:
            fd, length = (1, 4 * 1024 * 1024 + 8192) if mode == "stdout_limit" else (2, 64 * 1024 + 8192)
            for _ in range(length // 8192):
                write_all(fd, b"x" * 8192)
        elif mode == "wait_release":
            ready(config, identity, "request-eof")
            await_release(config, identity)
            write_all(1, response)
        elif mode == "delay_exit":
            write_all(1, response)
            os.close(1)
            os.close(2)
            ready(config, identity, "pipes-closed-child-held")
            await_release(config, identity)
            os._exit(0)  # Original child exits; no inherited/wrapper flush route.
        else:
            write_all(1, response)
        return 9 if mode == "nonzero_exit" else 0
    except Exception:
        return 71  # No input, path, exception repr or traceback in diagnostics.
