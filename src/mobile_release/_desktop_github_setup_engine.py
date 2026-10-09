"""Private fixed Setup helper; no public method/URL/credential interface.

The existing native Supervisor owns the original child, final GO and retirement.
A READY or JSON result is not consent, sent-byte proof or local finality.
"""
from __future__ import annotations

import math
import os
import time

from ._desktop_github_engine import READ_SECONDS, ProtocolError, _read_request, _write_response
from . import github_setup_remote as policy


def _read_initial(fd: int, end: float) -> bytes:
    # Same existing preflight initial-frame cursor, with Setup's smaller cap.
    # Unlike final GO, initial input cannot await EOF before sending READY.
    value = bytearray()
    while b"\n" not in value:
        if time.monotonic() >= end:
            raise ProtocolError("Fixed Setup initial deadline elapsed")
        part = os.read(fd, min(4096, policy.MAX_INITIAL_BYTES + 1 - len(value)))
        if not part:
            raise ProtocolError("Fixed Setup initial frame was incomplete")
        value.extend(part)
        if len(value) > policy.MAX_INITIAL_BYTES:
            raise ProtocolError("Fixed Setup initial frame exceeded its bound")
    # Whole admitted read is checked: coalesced initial+GO never truncates.
    policy._frame(bytes(value), policy.MAX_INITIAL_BYTES, nodes=256, depth=8)
    return bytes(value)


def main(*, started: float, runtime_dir: str) -> int:
    owned: list[int] = []
    status = 0
    token = None
    try:
        if (type(started) not in (int, float) or not math.isfinite(started)
                or not math.isfinite(started + READ_SECONDS)
                or type(runtime_dir) is not str or not os.path.isabs(runtime_dir)):
            return 78
        end = started + READ_SECONDS
        def check() -> None:
            now = time.monotonic()
            if not math.isfinite(now) or now < started or now >= end:
                raise ProtocolError("Fixed Setup original deadline elapsed")

        check()
        control = os.dup(0); owned.append(control); os.set_inheritable(control, False)
        output = os.dup(1); owned.append(output); os.set_inheritable(output, False)
        null = os.open(os.devnull, os.O_RDONLY); owned.append(null)
        os.dup2(null, 0, inheritable=False)
        os.dup2(2, 1, inheritable=False)
        request = policy.parse_initial(_read_initial(control, end))
        check()
        _write_response(output, policy.ready_frame(request))
        check()
        # EOF belongs to the original native GO writer's checked close.
        token = policy.parse_go(_read_request(control, end), request)
        check()
        from datetime import datetime, timezone

        reader = policy._make_live_reader(request.action, token, started=started, runtime_dir=runtime_dir)
        observed = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        if type(request.action) is policy.EnvironmentAction:
            result = policy.execute_environment(request.action, reader, observed_at=observed)
        elif type(request.action) is policy.Action:
            result = policy.execute(request.action, reader, observed_at=observed)
        else:
            raise ProtocolError("Unknown fixed Setup action")
        reader = None
        token = None
        check()
        _write_response(output, policy.encode_result(request, result))
        check()
    except (KeyboardInterrupt, SystemExit):
        status = 130
    except Exception:
        status = 70
        # No raw token/upstream/error body and no extra blocking stderr write.
    finally:
        token = None  # Best-effort reference release, not universal erasure.
        while owned:
            fd = owned.pop()
            try:
                os.close(fd)
            except BaseException:
                # A failed consuming close never retries that descriptor or
                # skips retirement attempts for the remaining originals.
                status = status or 74
    return status
