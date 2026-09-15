"""One fixed fictional native command inside genuine production command custody."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    if len(sys.argv) != 7:
        raise AssertionError("fixed model target arguments required")
    package, namespace, binding, root, deadline, token = sys.argv[1:]
    sys.path[:0] = [package, str(ROOT / "tests")]
    from workflow.local_signing_bridge import Channel, Namespace, RemoteTrace, VERSION, decode, require, result_policy
    from unit.local_signing_persistent import PersistentSigningModel
    owned = Namespace(Path(namespace), decode(binding.encode("ascii")))
    try:
        cutoff = float(deadline)
        ack = Channel(owned.open("acks.fifo", os.O_RDONLY, cutoff), cutoff)
        events = Channel(owned.open("events.fifo", os.O_WRONLY, cutoff), cutoff)
        events.send({"version": VERSION, "kind": "HELLO", "token": token})
        config = ack.receive()
        require(type(config) is dict and set(config) == {"version", "kind", "token", "argv", "recovery", "auto_add", "trace", "result_policy"}
                and type(config["version"]) is int and config["version"] == VERSION
                and config["kind"] == "HELLO-ACK" and config["token"] == token
                and type(config["argv"]) is list and 0 < len(config["argv"]) <= 64
                and all(type(item) is str and len(item) <= 8192 for item in config["argv"])
                and sum(len(item.encode("utf-8")) for item in config["argv"]) <= 32768
                and type(config["recovery"]) is bool and type(config["auto_add"]) is bool
                and type(config["trace"]) is bool, "invalid model request")
        ack.established = events.established = True
        trace = RemoteTrace(events, ack)
        policy = result_policy(config["result_policy"])
        model = PersistentSigningModel(Path(root), trace=trace if config["trace"] else None,
                                       recovery=config["recovery"], auto_add=config["auto_add"])
        output = model.execute_model(config["argv"]) if policy["perform_effect"] else ""
        if policy["stdout"] is not None:
            output = policy["stdout"]
        trace.request("DONE", None)
        owned.close_node("events.fifo")
        ack.require_eof()
        require(owned.close(), "target original descriptor close failed")
        sys.stdout.write(output)
        sys.stdout.flush()
        sys.stderr.write(policy["stderr"])
        sys.stderr.flush()
        return policy["returncode"]
    finally:
        if not owned.close():
            raise AssertionError("target namespace cleanup unresolved")


if __name__ == "__main__":
    raise SystemExit(main())
