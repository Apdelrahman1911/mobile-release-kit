"""Fixed enrollment arm of the EXISTING private GitHub Setup bootstrap.

The bootstrap retains/closes the original descriptors; this module borrows
them and uses its existing READY/GO/EOF framing helpers, not another executor.
No local state is opened here. Native enrollment follows actual worker finality.
"""
from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass

from . import version_enrollment as policy
from . import version_allocation as allocation
from . import version_policy
from ._desktop_github_engine import _ID, _check_control, _read_request, _write_response, ProtocolError
from .github_setup_remote import _frame

INITIAL_LIMIT = 8192
READY_LIMIT = 512
GO_LIMIT = 8192
RESULT_LIMIT = 8192
SECONDS = 60.0


@dataclass(frozen=True, slots=True)
class Initial:
    id: str
    kind: str
    target: policy.Target
    review: policy.Offer | None
    previous: allocation.Checkpoint | None
    digest: str


def parse_initial(raw: bytes) -> Initial:
    row = version_policy._object(_frame(raw, INITIAL_LIMIT, nodes=256, depth=8), {"protocol", "id", "action"})
    policy.need(row["protocol"] == policy.PROTOCOL)
    action = version_policy._object(row["action"], {"kind", "target", "review", "previous"})
    policy.need(type(action["kind"]) is str and action["kind"] in {"review", "confirm"})
    target = policy.Target.parse(action["target"])
    review = None if action["review"] is None else policy.Offer.parse(action["review"])
    previous = None if action["previous"] is None else allocation.Checkpoint.parse(action["previous"])
    policy.need((review is not None) == (action["kind"] == "confirm")
                and (previous is None or review is not None))
    if review is not None:
        policy.need(review.authority.repository == target.repository
                    and review.authority.repository_id == target.repository_id)
    return Initial(version_policy._match(row["id"], _ID), action["kind"], target, review, previous,
                   hashlib.sha256(raw).hexdigest())


def ready_frame(request: Initial) -> bytes:
    return version_policy.canonical({"protocol": policy.PROTOCOL, "id": request.id,
        "ready": {"requestSha256": request.digest}}) + b"\n"


def parse_go(raw: bytes, request: Initial) -> str:
    row = version_policy._object(_frame(raw, GO_LIMIT, nodes=32, depth=4), {"protocol", "id", "go"})
    go = version_policy._object(row["go"], {"requestSha256", "token"})
    token = go["token"]
    policy.need(row["protocol"] == policy.PROTOCOL and row["id"] == request.id
                and go["requestSha256"] == request.digest and type(token) is str and 1 <= len(token) <= 4096
                and all(0x21 <= ord(char) <= 0x7e for char in token))
    return token


def encode_result(request: Initial, result: dict) -> bytes:
    version_policy._object(result, {"schemaVersion", "reason", "offer", "control"})
    policy.need(type(result["schemaVersion"]) is int and result["schemaVersion"] == 1
                and type(result["reason"]) is str and result["reason"] in policy.REASONS)
    control = _check_control(result["control"])
    policy.need((result["offer"] is not None) == (result["reason"] == "none")
                and (result["offer"] is None or control["reason"] == "none"))
    if result["offer"] is not None:
        offer = policy.Offer.parse(result["offer"])
        policy.need(offer.authority.repository == request.target.repository
                    and offer.authority.repository_id == request.target.repository_id
                    and (request.review is None or offer == request.review))
    raw = version_policy.canonical({"protocol": policy.PROTOCOL, "id": request.id, "result": result}) + b"\n"
    policy.need(len(raw) <= RESULT_LIMIT)
    return raw


def run_owned(control: int, output: int, initial: bytes, *, started: float, runtime_dir: str) -> None:
    end = started + SECONDS
    def check():
        now = time.monotonic()
        if not math.isfinite(now) or not math.isfinite(started) or not math.isfinite(end) or now < started or now >= end:
            raise ProtocolError("Original shared counter read deadline elapsed")
    check()
    request = parse_initial(initial)
    _write_response(output, ready_frame(request))
    check()
    # Original native writer sends this exact GO and closes its original stdin.
    # The existing helper waits for actual EOF; no new pipe/cancel owner exists.
    token = parse_go(_read_request(control, end), request)
    check()
    reader = policy.make_reader(request.target, token, previous=request.previous,
                                started=started, runtime_dir=runtime_dir)
    try:
        result = policy.execute(request.target, reader, review=request.review, previous=request.previous)
    finally:
        reader = token = None  # Best-effort reference release, not universal erasure.
    check()
    _write_response(output, encode_result(request, result))
    check()
