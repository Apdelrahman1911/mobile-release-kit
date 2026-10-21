"""Fixed version-ledger requests delegated to the existing GitHub HTTP owner.

No new socket/TLS/credential implementation or public route exists here. The
private factory requires the original native actor's credential/custody and the
shared VERSION_ALLOCATION profile; missing hooks refuse rather than fall back
to a generic profile. Native authorization, cooldown, connection settlement and
job finality remain with that original owner. Controller journal acknowledgements
must precede its write; this transport's shape checks cannot prove durability.
"""
from __future__ import annotations

import base64
import re
from typing import Callable

from . import version_allocation as allocation
from . import version_policy as policy
from ._desktop_github_engine import _check_control, _decode_json
from ._github_connection_transport import ReadResult
from .api._github_connection import _coordinate
from .api._json import bounded_json_text
from .github_preflight import HttpRequest

ROLE_REPOSITORY = "version-allocation-repository"
ROLE_REF = "version-allocation-ref"
ROLE_COMPARE = "version-allocation-compare"
ROLE_LEDGER_READ = "version-allocation-ledger-read"
ROLE_LEDGER_WRITE = "version-allocation-ledger-write"
ROLE_TAG = "version-allocation-tag"
_ROLE_NAMES = {ROLE_REPOSITORY: "VERSION_ALLOCATION_REPOSITORY", ROLE_REF: "VERSION_ALLOCATION_REF",
               ROLE_COMPARE: "VERSION_ALLOCATION_COMPARE", ROLE_LEDGER_READ: "VERSION_ALLOCATION_LEDGER_READ",
               ROLE_LEDGER_WRITE: "VERSION_ALLOCATION_LEDGER_WRITE", ROLE_TAG: "VERSION_ALLOCATION_TAG"}
_STEP_ROLES = {"repository-before": ROLE_REPOSITORY, "repository-after": ROLE_REPOSITORY,
               "ref-before": ROLE_REF, "ref-after": ROLE_REF,
               "compare-before": ROLE_COMPARE, "compare-after": ROLE_COMPARE,
               "ledger-before": ROLE_LEDGER_READ, "ledger-after": ROLE_LEDGER_READ, "write": ROLE_LEDGER_WRITE,
               "tag-before": ROLE_TAG}
_SHA = r"[0-9a-f]{40}"


def _need(condition: bool) -> None:
    if not condition:
        raise ValueError("Invalid fixed version allocation request")


def _path(path: str) -> tuple[str, str]:
    _need(type(path) is str and 0 < len(path) <= 1024)
    parts = path.split("/")
    _need(len(parts) >= 4 and parts[:2] == ["", "repos"])
    repository = _coordinate(parts[2] + "/" + parts[3])
    return repository, "/".join(parts[4:])


def validate_endpoint(role: str, method: str, path: str) -> None:
    """Shared transport calls this only AFTER admitting its enum profile/role.

    These fixed role.value strings are validator inputs, not transport authority.
    No alternate host, branch, path, query, pagination or mutable ref is accepted.
    """
    _need(type(role) is str and role in _ROLE_NAMES and type(method) is str)
    _, tail = _path(path)
    if role == ROLE_REPOSITORY:
        valid = method == "GET" and tail == "" and not path.endswith("/")
    elif role == ROLE_REF:
        valid = method == "GET" and tail == "git/ref/heads/" + allocation.LEDGER_BRANCH
    elif role == ROLE_COMPARE:
        valid = method == "GET" and re.fullmatch(r"compare/" + _SHA + r"\.\.\." + _SHA
                                                + r"\?per_page=1&page=1", tail, re.ASCII) is not None
    elif role == ROLE_LEDGER_READ:
        valid = method == "GET" and re.fullmatch("contents/" + re.escape(allocation.LEDGER_PATH)
                                                + r"\?ref=" + _SHA, tail, re.ASCII) is not None
    elif role == ROLE_TAG:
        valid = method == "GET" and tail.startswith("git/ref/tags/")
        if valid:
            allocation.future_tag.reference("refs/" + tail.removeprefix("git/ref/"))
    else:
        valid = method == "PUT" and tail == "contents/" + allocation.LEDGER_PATH
    _need(valid)


def _write_ledger(body: bytes, *, path: str) -> allocation.Ledger:
    validate_endpoint(ROLE_LEDGER_WRITE, "PUT", path)
    _need(type(body) is bytes and 0 < len(body) <= allocation.MAX_HTTP_BYTES)
    row = policy._object(_decode_json(body, limit=allocation.MAX_HTTP_BYTES, nodes=16, depth=2, exact=True),
                         {"message", "branch", "sha", "content"})
    _need(row["message"] == "Reserve Mobile Release Kit candidate version"
          and row["branch"] == allocation.LEDGER_BRANCH and policy.canonical(row) == body)
    policy._match(row["sha"], policy._SHA)
    encoded = row["content"]
    _need(type(encoded) is str and 0 < len(encoded) <= 4 * ((allocation.MAX_LEDGER_BYTES + 2) // 3))
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, UnicodeError):
        raise ValueError("Invalid fixed version allocation request") from None
    _need(base64.b64encode(raw).decode("ascii") == encoded)
    # Derive structural bindings solely to validate the body. This does not
    # enroll/trust an authority; the private wrapper checks its retained one.
    value = _decode_json(raw, limit=allocation.MAX_LEDGER_BYTES, nodes=20_000, depth=16)
    _need(type(value) is dict)
    policy._object(value, {"schemaVersion", "protocol", "genesis", "reservations"} |
                   ({"tagBindings"} if value.get("schemaVersion") == 5 else set()))
    genesis = allocation.Genesis.parse(value["genesis"])
    repository, _ = _path(path)
    structural = allocation.AuthorityRegistration(genesis.project_id, repository, genesis.repository_id,
                                                   genesis.ledger_id, genesis.sha256, True)
    after = allocation.Ledger.parse(raw, structural)
    _need(bool(after.reservations))  # No genesis creation/reset/delete role.
    before = allocation.Ledger(after.genesis, after.reservations[:-1], after.tag_bindings)
    _need(row["sha"] == allocation.blob_sha(before.to_bytes()))
    return after


def validate_body(role: str, body: object, *, path: str) -> None:
    """No full-ledger replacement other than one structurally valid append."""
    _need(type(role) is str and role in _ROLE_NAMES)
    if role == ROLE_LEDGER_WRITE:
        _write_ledger(body, path=path)
    else:
        validate_endpoint(role, "GET", path)
        _need(body is None)


class _FixedAllocationTransport:
    """One retained candidate/authority/checkpoint and finite exchange schedule."""
    def __init__(self, selected: allocation.AllocationRequest,
                 authority: allocation.AuthorityRegistration, checkpoint: allocation.Checkpoint,
                 send: Callable[[str, HttpRequest], ReadResult], *, reconcile: bool = False) -> None:
        _need(type(selected) is allocation.AllocationRequest and selected.project_id == authority.project_id
              and selected.version_policy.mode == "automatic" and authority.protected_branch and callable(send))
        self._schedule = allocation.Schedule(authority, checkpoint, reconcile=reconcile, future_tag=selected.future_tag)
        self._selected = selected
        self._send = send
        self._before_commit: str | None = None
        self._after_commit: str | None = None
        self._before: allocation.LedgerSnapshot | None = None
        self._after: allocation.Ledger | None = None
        self._stopped = False

    def exchange(self, step: str, request: HttpRequest) -> ReadResult:
        _need(not self._stopped)
        try:
            _need(type(request) is HttpRequest and type(step) is str and step in _STEP_ROLES)
            reference = (self._before_commit if step in {"compare-before", "ledger-before"} else
                         self._after_commit if step in {"compare-after", "ledger-after"} else None)
            expected = self._schedule.claim(step, reference, body=request.body if step == "write" else None)
            _need(request == expected)  # Includes exact selected coordinate and pinned commit.
            role = _STEP_ROLES[step]
            validate_endpoint(role, request.method, request.path)
            if step == "write":
                after = _write_ledger(request.body, path=request.path)
                _need(self._before is not None and after.genesis == self._before.ledger.genesis
                      and len(after.reservations) == len(self._before.ledger.reservations) + 1
                      and after.reservations[:-1] == self._before.ledger.reservations
                      and after.tag_bindings == self._before.ledger.tag_bindings
                      and after.reservations[-1].request == self._selected)
                pending = allocation.PendingAllocation(self._schedule.authority, self._before.checkpoint,
                                                        self._before.blob, after.reservations[-1])
                _need(allocation.conditional_write_body(pending, after) == request.body)
                self._after = after
            else:
                validate_body(role, request.body, path=request.path)
            result = self._send(role, request)  # Claimed even if the original send fails.
            _need(type(result) is ReadResult)
            control = _check_control(result.control)
            bounded_json_text(result.observation, max_bytes=allocation.MAX_HTTP_BYTES,
                              max_nodes=20_000, max_depth=24)
            row = policy._object(result.observation, {"status", "body", "failure"})
            if step == "tag-before" and control["reason"] == "none" and row["failure"] == "none":
                if row["status"] == 404:
                    _need(row["body"] is None)
                    return result
                _need(row["status"] == 200 and type(row["body"]) is dict)
                self._stopped = True  # A positive match is a collision, never adopted.
                return result
            if control["reason"] != "none" or row["failure"] != "none" or row["status"] != 200:
                self._stopped = True
                return result  # Preserve original reason/cooldown; never retry/erase pending.
            _need(type(row["status"]) is int and type(row["body"]) is dict)
            self._retain(step, row["body"])
            if step == "repository-after":
                self._stopped = True
            return result
        except Exception:
            self._stopped = True
            raise

    def _retain(self, step: str, body: dict) -> None:
        authority, checkpoint = self._schedule.authority, self._schedule.checkpoint
        if step in {"repository-before", "repository-after"}:
            allocation._repository_identity(body, authority)
        elif step == "ref-before":
            self._before_commit = allocation._ref_commit(body)
        elif step == "ref-after":
            self._after_commit = allocation._ref_commit(body)
        elif step == "compare-before":
            allocation._ancestry(body, checkpoint.commit, self._before_commit)
        elif step == "compare-after":
            allocation._ancestry(body, self._before_commit, self._after_commit)
        elif step == "ledger-before":
            self._before = allocation._snapshot(body, self._before_commit, authority, checkpoint)
            self._before.ledger.find(self._selected)
        elif step == "ledger-after":
            _need(self._before is not None)
            final = allocation._snapshot(body, self._after_commit, authority, self._before.checkpoint)
            _need(self._after is not None and allocation.future_tag.preserves(self._after, final.ledger))
        else:
            _need(step == "write" and self._after is not None
                  and type(body.get("content")) is dict and type(body.get("commit")) is dict
                  and body["content"].get("path") == allocation.LEDGER_PATH
                  and body["content"].get("sha") == allocation.blob_sha(self._after.to_bytes()))
            policy._match(body["commit"].get("sha"), policy._SHA)


def _make_allocation_transport(token: str, *, started: float, runtime_dir: str,
                               selected: allocation.AllocationRequest,
                               authority: allocation.AuthorityRegistration,
                               checkpoint: allocation.Checkpoint, reconcile: bool = False) -> _FixedAllocationTransport:
    """Only the original authorized native actor may call this private factory.

    Token discovery, consent and actor identity do not move here. The runtime
    directory is its existing retained custody, never a new Python file owner.
    No automatic enrollment, branch protection bypass or generic fallback.
    """
    from . import _github_connection_transport as native

    # Resolve the closed hooks before the original factory loads network/TLS.
    try:
        profile = native._ExchangeProfile.VERSION_ALLOCATION
        roles = {value: native._ResponseRole[name] for value, name in _ROLE_NAMES.items()}
    except (AttributeError, KeyError):
        raise allocation.VersionAllocationError("authority-unavailable") from None
    _need(type(selected) is allocation.AllocationRequest and type(authority) is allocation.AuthorityRegistration
          and selected.project_id == authority.project_id and selected.version_policy.mode == "automatic"
          and authority.protected_branch
          and type(checkpoint) is allocation.Checkpoint and type(reconcile) is bool)
    exchange = native._make_live_exchange(token, started=started, runtime_dir=runtime_dir,
                                         api_version="2026-03-10", _profile=profile)

    def send(role: str, request: HttpRequest) -> ReadResult:
        return exchange(request.method, request.path, request.body, _role=roles[role])

    return _FixedAllocationTransport(selected, authority, checkpoint, send, reconcile=reconcile)
