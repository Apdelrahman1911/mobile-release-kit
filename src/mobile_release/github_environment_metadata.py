"""One canonical GitHub environment/field metadata observation; read-only.

Local saved requirements are displayed by the existing snapshot API. This
network profile receives no project path/configuration and cannot establish
applicability, workflow equivalence, effective permissions or release readiness.
"""
from __future__ import annotations

import json
from typing import Any

from .credential_requirements import ENVIRONMENT_NAMES, ENVIRONMENT_INPUT_TYPES
from ._desktop_github_engine import (MetadataRequest, ProtocolError, REASONS, _ID, _check_control,
                                    _check_values)
from ._github_connection_transport import (ReadResult, ReadFailure, _control,
                                           _refuse, _make_live_exchange, MAX_BODY_BYTES,
                                           MAX_BODY_TOTAL)
from .api._github_connection import (_account, _fact, _id, _object, _projection, _read,
                                     _repository, _require, _utc)
from .api._json import bounded_json_text
from .errors import ConfigurationError

PROTOCOL = "mrk-github-input-metadata/1"
API_VERSION = "2026-03-10"
STEPS = ("account", "repository-before", "environment", "field", "repository-after")
_FATAL = {"unauthorized", "rate-limited", "target-changed", "response-invalid", "expired", "cancelled"}


def target(stage: object, name: object) -> tuple[str, str]:
    # This map also supplies every secret/variable type emitted by core
    # requirements. A renderer never chooses the URL or secret/variable route.
    _require(type(stage) is str and stage in ENVIRONMENT_NAMES
             and type(name) is str and name in ENVIRONMENT_INPUT_TYPES)
    return ENVIRONMENT_NAMES[stage], ENVIRONMENT_INPUT_TYPES[name]


def _make_live_reader(request: MetadataRequest, *, started: float, runtime_dir: str):
    environment, kind = target(request.stage, request.name)
    _require(request.expected_account_id is not None and request.expected_repository_id is not None)
    prefix = "/repos/" + request.repository
    paths = { "account": "/user", "repository-before": prefix, "repository-after": prefix,
              "environment": prefix + "/environments/" + environment,
              "field": prefix + "/environments/" + environment + "/" +
                       ("secrets/" if kind == "secret" else "variables/") + request.name }
    exchange = _make_live_exchange(request.token, started=started, runtime_dir=runtime_dir,
                                   api_version=API_VERSION)

    class FixedReader:
        def __init__(self) -> None:
            self.steps: list[str] = []

        def read(self, step: str) -> ReadResult:
            expected = STEPS[len(self.steps)] if len(self.steps) < len(STEPS) else None
            skip_field = self.steps == list(STEPS[:3]) and step == "repository-after"
            if step != expected and not skip_field or len(self.steps) >= 5:
                raise ValueError("Invalid fixed environment metadata schedule")
            # Closing with repository-after is terminal, including a skipped field.
            if self.steps and self.steps[-1] == "repository-after":
                raise ValueError("The original environment metadata read already settled")
            self.steps.append(step)
            return exchange("GET", paths[step], None)

    return FixedReader()


def observe(request: MetadataRequest, reader, *, observed_at: str) -> dict[str, Any]:
    environment, kind = target(request.stage, request.name)
    _utc(observed_at)
    _require(request.expected_account_id is not None and request.expected_repository_id is not None)
    empty = lambda reason="cancelled": _fact(None, None, reason)
    facts = {"schemaVersion": 1, "account": empty(), "repository": empty(), "automation": empty()}
    metadata = {"selection": {"stage": request.stage, "name": request.name},
                "environment": empty(), "field": empty()}
    control = _control()
    total = 0
    initial = None

    def take(step: str) -> tuple[dict[str, Any] | None, str, int | None]:
        nonlocal control, total
        admitted = None
        result = None
        try:
            result = reader.read(step)
            _require(type(result) is ReadResult)
            admitted = _check_control(result.control)
            # Five replies * at most 4,000 nodes preserves the original 20,000
            # aggregate ceiling. Body-byte accounting includes discarded values.
            raw = bounded_json_text(result.observation, max_bytes=MAX_BODY_BYTES + 128,
                                    max_nodes=4000, max_depth=24)
            total += len(raw.encode("utf-8"))
            if total > MAX_BODY_TOTAL:
                raise ReadFailure("response-limit")
            body, reason = _read(result.observation)
            control = admitted
            return body, reason, result.observation["status"]
        except ReadFailure as error:
            control = _refuse(admitted or control, error.reason)
        except ConfigurationError:
            control = _refuse(admitted or control, "response-limit")
        except (ValueError, TypeError, UnicodeError, OverflowError):
            control = _refuse(admitted or control, "response-invalid")
        if type(result) is ReadResult and type(result.observation) is dict:
            discarded = result.observation.get("body")
            if type(discarded) is dict:
                discarded.clear()
        return None, control["reason"], None

    def finish() -> dict[str, Any]:
        nonlocal control
        # Metadata is meaningful only after the original repository-ID bracket.
        if facts["repository"]["state"] != "observed":
            reason = facts["repository"]["reason"]
            metadata["environment"] = empty(reason)
            metadata["field"] = empty(reason)
        if control["reason"] == "none":
            for fact in (facts["account"], facts["repository"], metadata["environment"], metadata["field"]):
                if fact["state"] != "observed":
                    control = _refuse(control, fact["reason"])
                    break
        return {"facts": facts, "metadata": metadata, "control": control}

    body, reason, _ = take("account")
    if body is None:
        facts["account"] = empty(reason)
        return finish()
    try:
        account = _account(body)
    except (ValueError, TypeError, UnicodeError, OverflowError):
        facts["account"] = empty("response-invalid")
        control = _refuse(control, "response-invalid")
        return finish()
    if account["id"] != request.expected_account_id:
        facts["account"] = empty("target-changed")
        control = _refuse(control, "target-changed")
        return finish()
    facts["account"] = _fact(account, observed_at)
    if control["reason"] != "none":
        return finish()
    body, reason, _ = take("repository-before")
    if body is None:
        facts["repository"] = empty(reason)
        return finish()
    try:
        initial = _repository(body)
    except (ValueError, TypeError, UnicodeError, OverflowError):
        control = _refuse(control, "response-invalid")
        facts["repository"] = empty("response-invalid")
        return finish()
    if initial["id"] != request.expected_repository_id or initial["fullName"].lower() != request.repository.lower():
        control = _refuse(control, "target-changed")
        facts["repository"] = empty("target-changed")
        return finish()
    if control["reason"] != "none":
        return finish()

    for step in ("environment", "field"):
        body, reason, code = take(step)
        if body is None:
            metadata[step] = empty(reason)
            # A 404 is not proof of absence. Ordinary refusals may still bracket
            # identity; transport/finality/rate failures never start another GET.
            if control["reason"] in _FATAL or code not in {403, 404} and not (type(code) is int and 500 <= code <= 599):
                return finish()
            break
        try:
            if step == "environment":
                _require(body.get("name") == environment)
                projected = {"name": environment, "id": _id(body.get("id"), upstream=True)}
            else:
                _require(body.get("name") == request.name)
                projected = {"name": request.name, "kind": kind,
                             "createdAt": _utc(body.get("created_at")), "updatedAt": _utc(body.get("updated_at"))}
            metadata[step] = _fact(projected, observed_at)
        except (ValueError, TypeError, UnicodeError, OverflowError):
            control = _refuse(control, "response-invalid")
            metadata[step] = empty("response-invalid")
            return finish()
        finally:
            # GitHub variable responses contain a value; it is not input to a
            # view, log, journal, workflow, artifact or retained result.
            body.clear()
        if control["reason"] != "none":
            return finish()

    prior = control
    body, reason, _ = take("repository-after")
    if control["reason"] == "none":
        control = prior
    if body is None:
        facts["repository"] = empty(reason)
        return finish()
    try:
        ending = _repository(body)
        if ending["id"] != initial["id"] or ending["fullName"].lower() != request.repository.lower():
            control = _refuse(control, "target-changed")
            facts["repository"] = empty("target-changed")
        else:
            facts["repository"] = _fact(initial, observed_at)
    except (ValueError, TypeError, UnicodeError, OverflowError):
        control = _refuse(control, "response-invalid")
        facts["repository"] = empty("response-invalid")
    return finish()


def encode_response(request: MetadataRequest, result: dict[str, Any]) -> bytes:
    _require(_ID.fullmatch(request.id) is not None)
    value = _object(result, {"facts", "metadata", "control"})
    facts, control = _projection(value["facts"]), _check_control(value["control"])
    metadata = _object(value["metadata"], {"selection", "environment", "field"})
    _require(metadata["selection"] == {"stage": request.stage, "name": request.name})
    environment, kind = target(request.stage, request.name)
    _require(facts["automation"] == _fact(None, None, "cancelled"))
    for role in ("account", "repository", "automation"):
        _require(facts[role]["state"] in {"observed", "unavailable"} and facts[role]["reason"] in REASONS)
    for role in ("environment", "field"):
        fact = _object(metadata[role], {"state", "value", "observedAt", "reason"})
        item = fact["value"]
        if fact["state"] == "observed":
            _require(fact["reason"] == "none" and facts["repository"]["state"] == "observed")
            _utc(fact["observedAt"])
            if role == "environment":
                item = _object(item, {"name", "id"})
                _require(item["name"] == environment)
                _id(item["id"])
            else:
                item = _object(item, {"name", "kind", "createdAt", "updatedAt"})
                _require(item["name"] == request.name and item["kind"] == kind
                         and metadata["environment"]["state"] == "observed")
                _utc(item["createdAt"]); _utc(item["updatedAt"])
        else:
            _require(fact["state"] == "unavailable" and item is None and fact["observedAt"] is None
                     and fact["reason"] in {"cancelled", "unauthorized", "forbidden", "not-found-or-inaccessible",
                     "target-changed", "rate-limited", "network-unavailable", "tls-failed", "response-invalid",
                     "response-limit", "expired"})
    observed = (facts["account"], facts["repository"], metadata["environment"], metadata["field"])
    _require(control["reason"] != "none" or all(f["state"] == "observed" for f in observed))
    for fact in observed:
        if fact["reason"] in {"unauthorized", "target-changed", "expired", "response-invalid", "rate-limited"}:
            _require(control["reason"] in {fact["reason"], "response-invalid"})
    envelope = {"protocol": PROTOCOL, "id": request.id, "facts": facts, "metadata": metadata, "control": control}
    _check_values(envelope, nodes=2000, depth=12)
    raw = json.dumps(envelope, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode() + b"\n"
    if len(raw) > 64 * 1024:
        raise ProtocolError("Environment metadata response exceeded the existing bound")
    return raw
