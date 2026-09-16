"""Explicit inert Store transport model for caller/filesystem unit fixtures.

The original private _Outer publisher and checked file reader are exercised,
but the engine's process facts are MODELED. No Ruby, child or Store is invoked.
This helper is not native/platform/process-finality evidence or an executable
production seam. A reviewed real-process fixture remains separately required.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

from mobile_release import _command_process as command
from mobile_release import _store_lane_files as lane_files
from mobile_release.owned_process import PRIVATE_OUTPUT_LIMIT


def identity(value):
    return {"device": value.st_dev, "inode": value.st_ino, "uid": value.st_uid,
            "gid": value.st_gid, "mode": stat.S_IMODE(value.st_mode)}


def write_exclusive(path, data):
    number = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(data)
        while view:
            count = os.write(number, view)
            if type(count) is not int or not 0 < count <= len(view):
                raise OSError("synthetic fixture write made no progress")
            view = view[count:]
        os.fsync(number)
        return identity(os.fstat(number))
    finally:
        os.close(number)


class StoreLaneModel:
    """producer(argv, environment) returns (document|None, normal exit code)."""

    def __init__(self, producer, *, terminal=True, confirmed=True, after=None):
        self.producer, self.terminal, self.confirmed, self.after = producer, terminal, confirmed, after
        self.records, self.engines, self.calls = [], [], []

    def __call__(self, argv, *, cwd, environ, capture, timeout, cancellation, _evidence):
        assert type(_evidence) is command.CommandCallEvidence and _evidence._lane_reservation is not None
        assert timeout == 3600 and capture is False
        record = _evidence._lane_reservation[0]
        self.records.append(record)
        self.calls.append((tuple(argv), cwd, dict(environ), cancellation))
        _evidence._attempt(cancellation, timeout=timeout, ordinary=True)
        engine = command._Outer(cancellation, False, timeout, None, None,
                                suppress_cancel=False, evidence=_evidence)
        self.engines.append(engine)
        _evidence._bind(engine); engine.evidence = _evidence
        engine.frozen = command._freeze_command(argv, environ=environ, cwd=cwd, capture=capture,
            output_limit=PRIVATE_OUTPUT_LIMIT, nonce=engine.nonce)
        _evidence._match(engine)
        document, code = self.producer(argv, environ)
        # Deliberately modeled fields; no syscall, native receipt or child exists.
        engine.handlers_complete, engine.local_cleanup_complete = True, self.confirmed
        engine.create_route.attempted = engine.run_route.attempted = True
        engine.create_route.retired = engine.run_route.retired = True
        engine.wait = command.native.WaitReceipt(1001, "exit", command.HELPER_OK, 0)
        engine.child = SimpleNamespace(receipt=engine.wait)
        engine.sealed, engine.wire = True, SimpleNamespace(eof=True, poisoned=False)
        engine.readers, engine.output_eof = [object(), object()], [True, True]
        engine.terminal = {"producer": True, "no_target": None, "stdout": 0, "stderr": 0,
                           "result": True, "wait": {"kind": "exit", "code": code}}
        engine.publish()
        files, receipt = record._files_owner(), None
        if document is not None:
            data = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
            receipt = {**write_exclusive(Path(record._output), data), "size": len(data),
                       "sha256": hashlib.sha256(data).hexdigest()}
        if self.terminal:
            part = files.root_path / "terminal.part"
            number = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                value = {"version": 1, "nonce": record._nonce.hex(), "lane": record._lane,
                    "mode": files.mode, "output": record._output, "clock": files.timing.clock,
                    "run_deadline_ns": files.timing.run, "hard_deadline_ns": files.timing.hard,
                    "outcome": "success" if code == 0 else "failed", "launches_closed": True,
                    "adapter_settled": True, "nested_settled": True,
                    "terminal_identity": identity(os.fstat(number)), "receipt": receipt,
                    "inventory": []}
                data = (json.dumps(value, separators=(",", ":")) + "\n").encode("utf-8")
                view = memoryview(data)
                while view:
                    count = os.write(number, view)
                    if type(count) is not int or not 0 < count <= len(view):
                        raise OSError("synthetic terminal write made no progress")
                    view = view[count:]
                os.fsync(number)
            finally:
                os.close(number)
            os.link(part, part.with_name("terminal.json"))
        if self.after is not None:
            self.after(record)
        return subprocess.CompletedProcess(argv, code)

    def close(self):
        # No process work was started. Close only this fixture's positively
        # owned original file handles; never invoke modeled engine cleanup.
        owners = []
        for record in self.records:
            binding = record._resources.get("terminal")
            owners.extend(owner for owner in (None if binding is None else binding._owner,
                                               record._pending_attempt) if owner is not None)
        for owner in reversed(owners):
            owner.close_handles()
        lane_files._RETAINED[:] = [value for value in lane_files._RETAINED
            if not any(value is owner for owner in owners)]
        command._RETAINED[:] = [value for value in command._RETAINED
            if not any(value is engine for engine in self.engines)]
