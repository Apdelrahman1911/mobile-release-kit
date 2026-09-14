"""Seven complementary bare-home cuts, inside the fixed original case owner.

The full persistent matrix owns the all-operation/all-edge replay. This fixture
adds only real profile-parent creation and empty-native cleanup-prefix coverage;
it is not a shared-host-safe entrypoint despite using fictional signing effects.
"""
from __future__ import annotations

import json
import os
import sys
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

if __name__ == "__main__":
    raise SystemExit("Use the fixed verification owner; raw crash-fixture execution is not admitted.")

from mobile_release import local_signing as signing
from mobile_release.credentials import _temporary_profile_installation
from unit.local_signing_helpers import NativeSigningModel


TOKEN = "a" * 32
UUID = "12345678-1234-1234-1234-1234567890AB"
DIRECTORY_SLOTS = ("home/Library", "home/Library/MobileDevice",
                   "home/Library/MobileDevice/Provisioning Profiles")
DIRECTORY_ORIGIN = "mobile_release.credentials:_open_profile_directory"
DIRECTORY_PHASE = "mobile_release.credentials:_temporary_profile_installation"
STATE_SLOT = f"home/{signing.LEASE_DIRECTORY}/session-<TOKEN>/state.pending"
STATE_ORIGIN = "mobile_release.local_signing:_write"
STATE_PHASE = "mobile_release.local_signing:cleanup_native"
IDENTITY_FIELDS = ("operation", "origin", "slot", "phase", "occurrence", "context")


def event_identity(event):
    return {key: event[key] for key in IDENTITY_FIELDS}


def select_cuts(events):
    """Select actual successful semantic events, never historical IO indices."""
    directories = [event for event in events if event["operation"] == "mkdir"]
    assert len(directories) == 3, "expected exactly three bare-home directory creations"
    selected = []
    for slot in DIRECTORY_SLOTS:
        matches = [event for event in directories if event["origin"] == DIRECTORY_ORIGIN
                   and event["phase"] == DIRECTORY_PHASE and event["slot"] == slot
                   and event["occurrence"] == 0 and event["context"] == {}]
        assert len(matches) == 1 and matches[0]["succeeded"] is True, {"missingSuccessfulMkdir": slot}
        selected.extend({"event": event_identity(matches[0]), "edge": edge} for edge in ("before", "after"))
    first = [event for event in events if event["operation"] == "write" and event["origin"] == STATE_ORIGIN
             and event["phase"] == STATE_PHASE and event["slot"] == STATE_SLOT and event["occurrence"] == 0]
    assert len(first) == 1 and first[0]["succeeded"] is True, "first successful cleanup state write is missing"
    context = first[0]["context"]
    assert set(context) == {"profilePhase", "native", "searchAttempted", "defaultAttempted", "cleanupStarted"}
    assert context["profilePhase"] == "resolved" and type(context["native"]) is dict and context["native"] == {}
    assert context["searchAttempted"] is False and context["defaultAttempted"] is False
    assert context["cleanupStarted"] is True, "cleanup prefix is not the intended empty-native state"
    selected.append({"event": event_identity(first[0]), "edge": "partial"})
    assert len(selected) == 7
    return selected


def _semantic_event(root, operation, args, kwargs, frame):
    origin = frame.f_globals.get("__name__", "") + ":" + frame.f_code.co_name
    if operation == "mkdir" and origin == DIRECTORY_ORIGIN:
        phase, context = DIRECTORY_PHASE, {}
        assert kwargs["dir_fd"] == frame.f_locals["descriptor"]
        path = frame.f_locals["current"] / args[0]
    elif operation == "write" and origin == STATE_ORIGIN and frame.f_locals["name"] == "state.json":
        phase = STATE_PHASE
        session = frame.f_locals["self"]
        assert args[0] == frame.f_locals["descriptor"] and frame.f_locals["value"] is session.state
        assert frame.f_locals["stage"] == "state.pending" and session.token == TOKEN
        path = session.path / frame.f_locals["stage"]
        state = session.state
        context = {"profilePhase": state["profile"]["phase"], "native": dict(state["native"]),
                   "searchAttempted": state["searchAttempted"], "defaultAttempted": state["defaultAttempted"],
                   "cleanupStarted": state["cleanupStarted"]}
    else:
        return None
    # The phase comes from the actual production call chain, not a test label.
    caller = frame.f_back
    while caller is not None:
        if caller.f_globals.get("__name__", "") + ":" + caller.f_code.co_name == phase:
            if operation == "write":
                assert caller.f_locals["self"] is session
            break
        caller = caller.f_back
    if caller is None:
        return None
    slot = path.relative_to(root).as_posix().replace("session-" + TOKEN, "session-<TOKEN>")
    return {"operation": operation, "origin": origin, "slot": slot, "phase": phase, "context": context}


def main(root: Path, target=None) -> dict:
    home = root / "home"
    home.mkdir(mode=0o700)  # Every inventory/replay starts from a genuinely bare home.
    model = NativeSigningModel(home)
    events, occurrences = [], {}
    real_write = os.write
    log = os.open(root / "cuts.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)

    def boundary(event, edge, **details):
        identity = event_identity(event)
        record = {"event": identity, "edge": edge, **details}
        remaining = (json.dumps(record, sort_keys=True) + "\n").encode()
        while remaining:
            count = real_write(log, remaining)
            assert 0 < count <= len(remaining), "cut trace was not completely written"
            remaining = remaining[count:]
        if target == {"event": identity, "edge": edge}:
            assert edge == "before" or details["succeeded"] is True, "selected effect did not succeed"
            os._exit(73)

    def wrapper(operation, original):
        def invoke(*args, **kwargs):
            event = _semantic_event(root, operation, args, kwargs, sys._getframe(1))
            if event is None:
                return original(*args, **kwargs)
            key = tuple(event[field] for field in ("operation", "origin", "slot", "phase"))
            event["occurrence"] = occurrences.get(key, 0)
            occurrences[key] = event["occurrence"] + 1
            event["succeeded"] = None
            events.append(event)
            boundary(event, "before", succeeded=None)
            if target == {"event": event_identity(event), "edge": "partial"}:
                assert operation == "write" and len(args[1]) > 1
                count = original(args[0], args[1][:len(args[1]) // 2])
                assert 0 < count < len(args[1]), "selected prefix was not genuinely written"
                boundary(event, "partial", succeeded=True, partialBytes=count, requestedBytes=len(args[1]))
            try:
                result = original(*args, **kwargs)
            except BaseException as error:
                event["succeeded"] = False
                boundary(event, "after", succeeded=False, error=type(error).__name__)
                raise
            event["succeeded"] = True
            boundary(event, "after", succeeded=True)
            return result
        return invoke

    try:
        with ExitStack() as patches:
            for name in ("write", "mkdir"):
                patches.enter_context(patch.object(os, name, new=wrapper(name, getattr(os, name))))
            with signing.local_signing_lease(home=home) as lease:
                session = lease.session(token=TOKEN)
                session.bind_runner(model)
                session.open(create=True)
                content = b"fictional-authenticated-profile"
                session.prepare(content, UUID)
                with _temporary_profile_installation(content, UUID, home, cancellation=lease.cancellation,
                                                     observer=session.profile_event,
                                                     reserved_stage=session.intent["profile"]["stage"]):
                    pass
                session.cleanup_native()
                session.cleanup_profile()
                session.finish()
        assert target is None, {"selectedCutNotReached": target}
        return {"events": events, "completed": True}
    finally:
        os.close(log)
