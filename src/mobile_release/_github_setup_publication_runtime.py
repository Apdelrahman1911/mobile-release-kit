"""Private fixed publication frames and operation; no public API registration.

The installed Setup bootstrap and original native Supervisor own its clock,
private pipes, final connection/consent GO and child retirement. Parsed frames
are DATA and cannot grant authority without that original caller.
"""
from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, replace

from . import github_setup_publication as policy
from . import version_counter_setup as counter
from ._desktop_github_engine import _ID, _check_control, _write_response, ProtocolError
from ._github_connection_transport import _Budget, _ExchangeProfile, _control, ReadFailure
from ._github_setup_publication_journal import Journal, summary, MAX_RECORDS
from ._github_setup_publication_transport import make_exchange
from .github_setup_remote import _frame
from .github_setup_secret_inputs import (observe_publication_configuration, publication_source,
                                         SecretConfigurationError)

SECONDS = 60.0
MAX_INITIAL_BYTES = 8192
MAX_GO_BYTES = policy.MAX_REVIEW_BYTES + 8192
MAX_RESULT_BYTES = 512 * 1024
KINDS = {"prepare", "publish", "pending", "reconcile"}
REASONS = policy.REASONS | counter.REASONS | {"none", "configuration-changed", "resources-unavailable", "runtime-unavailable"}


@dataclass(frozen=True, slots=True, repr=False)
class Initial:
    id: str
    kind: str
    target: policy.Target | counter.Target
    source: dict | None
    home: str | None
    prepared_sha256: str | None
    digest: str


def parse_initial(raw: bytes) -> Initial:
    row = policy._object(_frame(raw, MAX_INITIAL_BYTES, nodes=256, depth=8), {"protocol", "id", "action"})
    policy._require(row["protocol"] == policy.PROTOCOL)
    action = policy._object(row["action"], {"kind", "target", "source", "home", "preparedSha256"})
    kind = action["kind"]
    policy._require(type(kind) is str and kind in KINDS)
    source = action["source"]
    policy._require((source is not None) == (kind in {"prepare", "publish"}))
    if source is not None:
        publication_source(source)
    target = counter.target(action["target"], unresolved=kind == "prepare")
    policy._require(kind != "pending" or type(target) is policy.Target)
    home = action["home"]
    policy._require((home is not None) == (kind != "prepare" or type(target) is counter.Target))
    if home is not None:
        Journal(home, end=0)  # Closed home grammar only, never opens here.
    digest = action["preparedSha256"]
    policy._require((digest is not None) == (kind == "publish"))
    if digest is not None:
        policy._match(digest, policy._DIGEST)
    return Initial(policy._match(row["id"], _ID), kind, target,
                   source, home, digest, hashlib.sha256(raw).hexdigest())


def ready_frame(request: Initial) -> bytes:
    return policy._canonical({"protocol": policy.PROTOCOL, "id": request.id,
        "ready": {"requestSha256": request.digest}}) + b"\n"


def parse_go(raw: bytes, request: Initial) -> tuple[str | None, policy.Prepared | counter.NativeGo | None]:
    maximum = MAX_GO_BYTES if request.kind == "publish" else 8192
    row = policy._object(_frame(raw, maximum, nodes=1024, depth=12), {"protocol", "id", "go"})
    policy._require(row["protocol"] == policy.PROTOCOL and row["id"] == request.id)
    is_counter = type(request.target) is counter.Target
    go = policy._object(row["go"], {"requestSha256", "token", "prepared"} | ({"projectId"} if is_counter else set()))
    policy._require(go["requestSha256"] == request.digest)
    token = go["token"]
    if request.kind == "pending":
        policy._require(token is None)
    else:
        policy._require(type(token) is str and 1 <= len(token) <= 4096
                        and all(0x21 <= ord(char) <= 0x7e for char in token))
    prepared = go["prepared"]
    policy._require((prepared is not None) == (request.kind == "publish"))
    if prepared is not None:
        policy._require(hashlib.sha256(policy._canonical(prepared)).hexdigest() == request.prepared_sha256)
        prepared = counter.prepared(prepared)
        policy._require(prepared.target == request.target)
    return token, counter.resolve_go(request.target, go["projectId"], prepared) if is_counter else prepared


def _scope(target: policy.Target) -> dict:
    return {key: target.value()[key] for key in ("projectBinding", "accountId", "repositoryId", "repository")}


def execute(request: Initial, token: str | None, retained: policy.Prepared | None, *,
            started: float, runtime_dir: str) -> dict:
    """Only invoked after original native GO. No journal result before close."""
    if type(request.target) is counter.Target:
        policy._require(type(retained) is counter.NativeGo and counter.resolved_matches(request.target, retained.target))
        request = replace(request, target=retained.target)
        retained = retained.review
    budget = _Budget(started, _profile=_ExchangeProfile.PUBLICATION)
    budget.remaining()
    result = {"schemaVersion": 1, "kind": request.kind, "reason": "none", "prepared": None,
              "publication": None, "pending": None, "configuration": None, "control": _control()}
    journal = None
    exchange = None
    try:
        if request.home is not None:
            journal = Journal(request.home, end=budget.end)
            journal.open()
        if request.kind == "pending":
            # Like existing preflight pending, fixed local identities only;
            # no token, HTTP, config body or regained mutation authority.
            policy._require(token is None and retained is None and journal is not None)
            result["pending"] = journal.pending(_scope(request.target))
        elif request.kind == "reconcile":
            policy._require(retained is None and journal is not None)
            matches = [row for row in journal.pending(_scope(request.target))
                       if row["summary"]["target"] == request.target.value()]
            policy._need(len(matches) == 1, "journal-unavailable")
            original = matches[0]
            exchange = make_exchange(request.target, token, started=started, runtime_dir=runtime_dir,
                                     budget=budget, checkpoint=journal._post)
            facet = counter if type(request.target) is counter.Target else policy
            result["publication"] = facet.reconcile(summary(original["summary"]), original["confirmed"],
                                                     tuple(original["claimed"]), exchange)
            result["reason"] = result["publication"]["reason"]
        else:
            is_counter = type(request.target) is counter.Target
            with observe_publication_configuration(request.source, budget=budget, counter=is_counter) as captured:
                def checkpoint():
                    try:
                        captured.checkpoint()
                    except SecretConfigurationError:
                        raise
                    except Exception as error:
                        if not is_counter:
                            raise
                        # The retained reader may raise its private _ReadProblem.
                        # Normalize only this checkpoint, not arbitrary policy or
                        # HTTP failures; the enclosing owner still performs POST
                        # and all consuming closes before any usable frame.
                        raise SecretConfigurationError("configuration-changed") from error
                    if journal is not None:
                        journal._post()
                try:
                    if is_counter:
                        counter.source_matches(captured.saved_bytes(), captured.version_bytes(), request.target)
                        source = None
                    else:
                        source = policy.Source.from_saved(captured.saved_bytes(), request.target)
                    result["configuration"] = captured.value()
                    exchange = make_exchange(request.target, token, started=started, runtime_dir=runtime_dir,
                                             budget=budget, checkpoint=checkpoint)
                    if request.kind == "prepare":
                        policy._require(retained is None)
                        result["prepared"] = (counter.prepare(request.target, exchange, journal) if is_counter
                            else policy.prepare(request.target, source, exchange)).view()
                    else:
                        policy._require(request.kind == "publish" and retained is not None and journal is not None
                                        and retained.target == request.target)
                        result["publication"] = (counter.publish(retained, exchange, journal) if is_counter
                            else policy.publish(retained, source, exchange, journal))
                        result["reason"] = result["publication"]["reason"]
                except SecretConfigurationError:
                    raise
                except (policy.Refused, ReadFailure) as error:
                    # A network refusal is not a changed file. Settle the
                    # original config normally and retain its actual control.
                    result["reason"] = error.reason
                except (ValueError, TypeError, KeyError, UnicodeError, OverflowError):
                    result["reason"] = "response-invalid"
                captured.checkpoint()
            # Includes the SAME held/named POST and every consuming config close.
    except SecretConfigurationError as error:
        if error.cleanup_unknown:
            raise  # Native child finality must refuse: no success frame.
        result["reason"] = error.reason
        result["prepared"] = None
        if result["publication"] is not None:
            result["publication"]["reason"] = error.reason
            if result["publication"].get("claimed"):
                result["publication"]["effect"] = "potentially-applied"
                result["publication"]["counter" if type(request.target) is counter.Target else "pull"] = None
    except (policy.Refused, ReadFailure) as error:
        result["reason"] = error.reason
    finally:
        if exchange is not None:
            result["control"] = dict(_check_control(exchange.control))
            if result["publication"] is not None:
                result["publication"]["control"] = dict(result["control"])
        if journal is not None:
            journal.close()  # Also retires partially acquired originals on open failure.
    budget.remaining()  # Close time belongs to the same endpoint.
    return result


def encode_result(request: Initial, result: dict) -> bytes:
    policy._object(result, {"schemaVersion", "kind", "reason", "prepared", "publication", "pending",
                            "configuration", "control"})
    policy._require(type(result["schemaVersion"]) is int and result["schemaVersion"] == 1
                    and result["kind"] == request.kind and result["reason"] in REASONS)
    _check_control(result["control"])
    if result["prepared"] is not None:
        policy._require(request.kind == "prepare" and result["reason"] == "none"
                        and counter.resolved_matches(request.target, counter.prepared(result["prepared"]).target))
    if result["pending"] is not None:
        policy._require(request.kind == "pending" and len(result["pending"]) <= MAX_RECORDS)
        for row in result["pending"]:
            policy._object(row, {"summary", "claimed", "confirmed"})
            summary(row["summary"])
    raw = policy._canonical({"protocol": policy.PROTOCOL, "id": request.id, "result": result}) + b"\n"
    policy._require(len(raw) <= MAX_RESULT_BYTES)
    return raw


def run_owned(control: int, output: int, initial: bytes, *, started: float, runtime_dir: str) -> None:
    """Borrow the Setup entry's original FDs, never duplicate ownership/clock."""
    end = started + SECONDS
    def check():
        now = time.monotonic()
        if now < started or now >= end:
            raise ProtocolError("Original publication deadline elapsed")
    check()
    request = parse_initial(initial)
    _write_response(output, ready_frame(request))
    maximum = MAX_GO_BYTES if request.kind == "publish" else 8192
    raw = bytearray()
    while True:
        check()
        block = os.read(control, min(4096, maximum + 1 - len(raw)))
        check()
        if not block:
            break
        raw.extend(block)
        if len(raw) > maximum:
            raise ProtocolError("Private publication GO exceeded its bound")
    token, retained = parse_go(bytes(raw), request)
    raw.clear()
    result = execute(request, token, retained, started=started, runtime_dir=runtime_dir)
    token = retained = None
    check()
    _write_response(output, encode_result(request, result))
    check()
