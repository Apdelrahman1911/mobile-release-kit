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


def _read_secret_apply_go(fd: int, end: float) -> bytes:
    # Selected only from an already validated secret-Apply Initial. The ordinary
    # request cursor remains 8KiB; no body can promote its own input authority.
    buffer = bytearray(policy.SECRET_APPLY_GO_BYTES + 1)
    size = 0
    while True:
        if time.monotonic() >= end: raise ProtocolError("Fixed secret GO deadline elapsed")
        block = os.read(fd, min(4096, len(buffer) - size))
        if time.monotonic() >= end: raise ProtocolError("Fixed secret GO deadline elapsed")
        if not block: return bytes(memoryview(buffer)[:size])
        if len(block) > policy.SECRET_APPLY_GO_BYTES - size:
            raise ProtocolError("Fixed secret GO exceeded its bound")
        buffer[size:size + len(block)] = block
        size += len(block)


def main(*, started: float, runtime_dir: str) -> int:
    owned: list[int] = []
    status = 0
    token = None
    sealed = None
    variable_value = variable_binding = None
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
        from .github_setup_variable_runtime import VariableRuntimeAction, parse_variable_go, execute_runtime
        variable = type(request.action) is VariableRuntimeAction
        applying_secret = type(request.action) is policy.SecretAction and request.action.kind == "apply"
        if variable:
            token, variable_value = parse_variable_go(_read_request(control, end), request)
        elif applying_secret:
            token, sealed = policy.parse_secret_apply_go(_read_secret_apply_go(control, end), request)
        else:
            token = policy.parse_go(_read_request(control, end), request)
        check()
        from datetime import datetime, timezone

        observed = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        if variable:
            from ._github_connection_transport import _Budget, _ExchangeProfile
            budget = _Budget(started, _profile=_ExchangeProfile.SETUP)
            result, variable_binding = execute_runtime(request.action, token, variable_value,
                started=started, runtime_dir=runtime_dir, budget=budget, observed_at=observed)
        elif type(request.action) is policy.SecretAction:
            from ._github_connection_transport import _Budget, _ExchangeProfile, _control
            from .github_setup_secret_inputs import observe_secret_configuration, SecretConfigurationError

            budget = _Budget(started, _profile=_ExchangeProfile.SETUP)
            reader = None
            result = None
            progress = policy.SecretApplyProgress() if applying_secret else None
            try:
                with observe_secret_configuration(request.action.source, request.action.target["selection"], budget=budget) as configuration:
                    value = configuration.value()
                    policy._object(value, {"savedConfig", "canonicalConfig", "requirement"})
                    expected = {"name": request.action.target["selection"]["requirement"], "kind": "secret",
                                "stage": request.action.target["selection"]["stage"], "platform": request.action.source["platform"]}
                    policy._require(value["requirement"] == expected)
                    reader = policy._make_secret_reader(request.action, token, started=started, runtime_dir=runtime_dir,
                                                        budget=budget, configuration=configuration, sealed=sealed, progress=progress)
                    binding = {"savedConfig": value["savedConfig"], "canonicalConfig": value["canonicalConfig"]}
                    result = (policy.execute_secret_apply(request.action, reader, binding, key=sealed["key"], progress=progress)
                              if applying_secret else policy.execute_secret_read(request.action, reader, binding, observed_at=observed))
                    configuration.checkpoint()
                # Exiting the SAME context includes actual held/named POST,
                # every consuming close and one final original deadline check.
            except SecretConfigurationError as error:
                if error.cleanup_unknown:
                    raise  # No finite result can attest a failed close.
                retained_control = reader.control if reader is not None else (result["control"] if result is not None else _control())
                result = policy.secret_configuration_failure(error.reason, retained_control, result, progress=progress)
            finally:
                reader = None
        else:
            reader = policy._make_live_reader(request.action, token, started=started, runtime_dir=runtime_dir)
            if type(request.action) is policy.EnvironmentAction:
                result = policy.execute_environment(request.action, reader, observed_at=observed)
            elif type(request.action) is policy.Action:
                result = policy.execute(request.action, reader, observed_at=observed)
            else:
                raise ProtocolError("Unknown fixed Setup action")
        reader = None
        token = None
        check()
        encoded = policy.encode_result(request, result, variable_value=variable_value,
                                       variable_configuration=variable_binding)
        variable_value = variable_binding = None
        _write_response(output, encoded)
        encoded = None
        check()
    except (KeyboardInterrupt, SystemExit):
        status = 130
    except Exception:
        status = 70
        # No raw token/upstream/error body and no extra blocking stderr write.
    finally:
        sealed = None
        variable_value = variable_binding = None
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
