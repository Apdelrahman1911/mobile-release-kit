"""Fixed runtime adapter for the existing Setup original; not a process owner.

Imported lazily by that original's closed variable discriminator. Configuration,
transport and native material custody remain their genuine existing providers.
No secret ciphertext, sealing helper, unbounded field access or token output.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from . import github_setup_remote as setup
from . import github_setup_variables as data
from ._desktop_github_engine import _check_control, _check_values
from ._github_connection_transport import ReadResult, _control
from .github_preflight import _object, _require, _match, _DIGEST

WIRE_WORK_BYTES = 663554
RUNTIME_REASONS = data.REASONS | frozenset({"runtime-unavailable"})


def _source(value: object, selected: data.VariableSelection) -> dict:
    row = _object(value, {"root", "rootIdentity", "draft", "platform", "purpose", "material"})
    identity = _object(row["rootIdentity"], {"device", "inode", "mode", "uid", "gid"})
    _require(type(row["root"]) is str and row["root"].startswith("/")
             and 1 <= len(row["root"].encode("utf-8", "strict")) <= 4096
             and not any(ord(c) < 32 or ord(c) == 127 for c in row["root"])
             and row["platform"] == selected.mapping[2] and row["purpose"] in {"full", "signing", "store"})
    for key in ("device", "inode"):
        part = identity[key]
        _require(type(part) is str and part.isascii() and part.isdecimal() and len(part) <= 20
                 and int(part) <= 2**64-1 and str(int(part)) == part)
    _require(all(type(identity[k]) is int and 0 <= identity[k] <= 2**32-1 for k in ("mode", "uid", "gid"))
             and identity["mode"] & 0o170000 == 0o040000)
    draft = setup._secret_digest(row["draft"])  # Exact shared size/digest DATA, not a secret source.
    material = _object(row["material"], {"bytes", "sha256"})
    _require(type(material["bytes"]) is int and 1 <= material["bytes"] <= data.MAX_VALUE_BYTES)
    digest = _match(material["sha256"], _DIGEST)
    return {"root": row["root"], "rootIdentity": dict(identity), "draft": draft,
            "platform": row["platform"], "purpose": row["purpose"],
            "material": {"bytes": material["bytes"], "sha256": digest}}


@dataclass(frozen=True, slots=True, repr=False)
class VariableRuntimeAction:
    action: data.VariableAction
    source: dict

    @classmethod
    def parse(cls, value: object) -> VariableRuntimeAction:
        row = _object(value, {"kind", "target", "prepared", "source"})
        action = data.VariableAction.parse({key: row[key] for key in ("kind", "target", "prepared")})
        source = _source(row["source"], action.target.selection)
        if action.prepared is not None:
            _require(source["draft"] == action.prepared.value()["configuration"]["canonicalConfig"])
            _require(source["material"] == _fingerprint(action.prepared.text))
        return cls(action, source)

    def value(self) -> dict:
        return {**self.action.value(), "source": self.source}


def _fingerprint(value: str) -> dict:
    raw = value.encode("utf-8", "strict")
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def parse_variable_go(raw: bytes, request) -> tuple[str, str]:
    _require(type(request) is setup.Initial and type(request.action) is VariableRuntimeAction)
    frame = setup._frame(raw, setup.MAX_GO_BYTES, nodes=32, depth=5)
    row = _object(frame, {"protocol", "id", "go"})
    go = _object(row["go"], {"requestSha256", "token", "value"})
    _require(row["protocol"] == setup.PROTOCOL and row["id"] == request.id
             and go["requestSha256"] == request.digest)
    token = go["token"]
    _require(type(token) is str and 0 < len(token) <= 4096
             and all(0x21 <= ord(c) <= 0x7e for c in token))
    value = data._desired(request.action.action.target.selection.requirement, go["value"])
    _require(_fingerprint(value) == request.action.source["material"])
    if request.action.action.prepared is not None:
        _require(value == request.action.action.prepared.text)
    return token, value


def _make_variable_reader(action: data.VariableAction, token: str, *, started: float,
                          runtime_dir: str, budget, configuration):
    from ._github_connection_transport import _Budget, _ExchangeProfile, _ResponseRole, _make_live_exchange
    _require(type(action) is data.VariableAction and type(budget) is _Budget
             and budget.profile is _ExchangeProfile.SETUP and budget.started == started)
    schedule = data.VariableSchedule(action)
    exchange = _make_live_exchange(token, started=started, runtime_dir=runtime_dir, api_version=data.API_VERSION,
                                  _profile=_ExchangeProfile.SETUP, _setup_budget=budget)

    class FixedVariableReader:
        def __init__(self):
            self.control = _control()
            self.write_claimed = self.write_acknowledged = False

        def read(self, step: str, reference: str | None = None) -> ReadResult:
            configuration.checkpoint()
            request = schedule.claim(step, reference)
            role = _ResponseRole.STANDARD
            if step in {"environment-before", "environment-after"}:
                role = _ResponseRole.SETUP_ENVIRONMENT_READ
            elif step in {"variable-before", "variable-after"}:
                role = _ResponseRole.SETUP_VARIABLE_READ
            elif step == "write":
                role = (_ResponseRole.SETUP_VARIABLE_CREATE if action.target.selection.mode == "create"
                        else _ResponseRole.SETUP_VARIABLE_REPLACE)
                self.write_claimed = True  # Before the first possible send, never undone.
            reply = exchange(request.method, request.path, request.body, _role=role)
            _require(type(reply) is ReadResult)
            # Retain the actual response before a following original-source
            # POST can fail; neither custody failure nor control is reset.
            self.control = dict(_check_control(reply.control))
            if step == "write":
                row = _object(reply.observation, {"status", "body", "failure"})
                expected = 201 if action.target.selection.mode == "create" else 204
                if type(row["status"]) is int and row["status"] == expected and row["failure"] == "none":
                    _require((row["body"] is None or type(row["body"]) is dict and not row["body"])
                             if expected == 201 else row["body"] is None)
                    self.write_acknowledged = True
            configuration.checkpoint()
            return reply

    return FixedVariableReader()


def _configuration_failure(action, error, control, *, reader, prior):
    from .github_setup_secret_inputs import SecretConfigurationError
    _require(type(error) is SecretConfigurationError)
    if error.cleanup_unknown:
        raise error  # Finite text never upgrades a lost/failed original close.
    control = dict(_check_control(control))
    reason = error.reason
    _require(type(reason) is str and reason in RUNTIME_REASONS - {"none", "no-change"})
    if type(prior) is dict and prior.get("reason") in RUNTIME_REASONS - {"none", "no-change"}:
        reason = prior["reason"]
    elif control["reason"] != "none":
        reason = control["reason"]
    _require(control["reason"] in {"none", reason})
    claimed = (reader.write_claimed if reader is not None else False) or (prior.get("writeClaimed", False) if prior else False)
    acknowledged = (reader.write_acknowledged if reader is not None else False) or (prior.get("writeAcknowledged", False) if prior else False)
    _require(type(claimed) is bool and type(acknowledged) is bool and (not acknowledged or claimed))
    return {"schemaVersion": 1, "action": action.kind, "reason": reason,
            "effect": "unknown" if claimed else "not-started", "writeClaimed": claimed,
            "writeAcknowledged": acknowledged, "prepared": None, "observed": None, "control": control}


def execute_runtime(action: VariableRuntimeAction, token: str, value: str, *, started: float,
                    runtime_dir: str, budget, observed_at: str) -> tuple[dict, dict | None]:
    from .github_setup_secret_inputs import observe_variable_configuration, SecretConfigurationError
    from ._github_connection_transport import _Budget, _ExchangeProfile
    _require(type(action) is VariableRuntimeAction and type(budget) is _Budget
             and budget.profile is _ExchangeProfile.SETUP and budget.started == started)
    action = VariableRuntimeAction.parse(action.value())
    value = data._desired(action.action.target.selection.requirement, value)
    _require(_fingerprint(value) == action.source["material"])
    reader = result = binding = None
    try:
        with observe_variable_configuration(action.source, action.action.target.selection.value(), budget=budget) as configuration:
            actual = _object(configuration.value(), {"savedConfig", "canonicalConfig", "requirement"})
            selected = action.action.target.selection
            _require(actual["requirement"] == {"name": selected.requirement, "kind": "variable",
                     "stage": selected.stage, "platform": selected.mapping[2]})
            binding = {"savedConfig": actual["savedConfig"], "canonicalConfig": actual["canonicalConfig"]}
            _require(binding["canonicalConfig"] == action.source["draft"])
            reader = _make_variable_reader(action.action, token, started=started, runtime_dir=runtime_dir,
                                          budget=budget, configuration=configuration)
            result = data.execute_variable(action.action, reader, value=value, configuration=binding, observed_at=observed_at)
            configuration.checkpoint()
        # Same context actual POST and consuming closes precede every return.
    except data.VariableRefused as error:
        # Genuine source/config binding may refuse prospectively before the
        # pure DATA sequence enters its catch block. The same context has
        # already POSTed/closed here; no reader write can have been entered.
        _require(reader is None or not reader.write_claimed)
        result = {"schemaVersion": 1, "action": action.action.kind, "reason": error.reason,
                  "effect": "not-started", "writeClaimed": False, "writeAcknowledged": False,
                  "prepared": None, "observed": None, "control": _control()}
    except SecretConfigurationError as error:
        control = reader.control if reader is not None else (result["control"] if result is not None else _control())
        result = _configuration_failure(action.action, error, control, reader=reader, prior=result)
    finally:
        reader = None
    return result, binding


def encode_runtime_result(request, result: object, *, desired_value: str, configuration: dict | None) -> bytes:
    _require(type(request) is setup.Initial and type(request.action) is VariableRuntimeAction)
    action = request.action.action
    row = _object(result, {"schemaVersion", "action", "reason", "effect", "writeClaimed",
                           "writeAcknowledged", "prepared", "observed", "control"})
    if row["reason"] in {"none", "no-change"}:
        _require(configuration is not None)
        # Use the sole existing complete variable result parser, including
        # actual desired/config/target/readback correlation, not a second pass.
        data.encode_variable_result(action, row, desired_value=desired_value, configuration=configuration)
    else:
        # A failed source/config observation has no saved-config grant to
        # invent. This closed failure branch admits NO prepared/observed data.
        control = _check_control(row["control"])
        _require(type(row["schemaVersion"]) is int and row["schemaVersion"] == 1 and row["action"] == action.kind
                 and type(row["reason"]) is str and row["reason"] in RUNTIME_REASONS - {"none", "no-change"}
                 and row["prepared"] is None and row["observed"] is None
                 and type(row["writeClaimed"]) is bool and type(row["writeAcknowledged"]) is bool
                 and (not row["writeAcknowledged"] or row["writeClaimed"])
                 and row["effect"] == ("unknown" if row["writeClaimed"] else "not-started")
                 and (action.kind != "prepare" or not row["writeClaimed"])
                 and control["reason"] in {"none", row["reason"]})
    envelope = {"protocol": setup.PROTOCOL, "id": request.id, "result": row}
    _check_values(envelope, nodes=1024, depth=12)
    raw = setup._canonical(envelope) + b"\n"
    _require(len(raw) <= data.MAX_RESULT_BYTES)
    return raw
