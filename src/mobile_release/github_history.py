"""Bounded read-only history DATA, not a provider, verifier or operation owner.

A parsed context is not authenticated. Only the future actual original adapter
may supply independently admitted context and project a fully verified result.
No filesystem, process, credential, network, Store or native entry is here.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .errors import ValidationError
from .provenance import _authority_for_stage, _reject_duplicate_pairs
from .workflow import ReadOnlyEvidenceContext, artifact_name

MIB = 1024 * 1024
GIB = 1024 * MIB
TOOLING_REPOSITORY = "Apdelrahman1911/mobile-release-kit"
ASSURANCE = "authenticated-retained-workflow-evidence-not-current-store-state"
STAGES = ("candidate", "external-testing", "production-submit")
PLATFORMS = ("android", "ios")
UNAVAILABLE = frozenset(("unqualified", "publisher-unconfigured", "unsupported-tooling",
    "provider-unavailable", "runtime-unavailable", "resources-unavailable", "unauthorized",
    "forbidden", "not-found-or-inaccessible", "rate-limited", "network-unavailable",
    "tls-failed", "artifact-missing", "artifact-expired", "producer-pending"))
REFUSED = frozenset(("invalid-input", "target-changed", "config-invalid", "platform-disabled",
    "provider-mismatch", "response-invalid", "response-limit", "evidence-invalid",
    "attestation-not-confirmed"))
OUTCOMES = frozenset(("mutated", "reconciled", "already-present",
    "operator-authorized-reconciliation", "operator-authorized-retry",
    "operator-authorized-create-retry"))


def _require(condition: bool, message: str = "history data is invalid") -> None:
    if not condition:
        raise ValidationError(message)


def _keys(value: object, names: tuple[str, ...]) -> dict[str, Any]:
    _require(type(value) is dict and len(value) == len(names) and set(value) == set(names))
    return value  # type: ignore[return-value]


def _text(value: object, maximum: int) -> str:
    _require(type(value) is str and 1 <= len(value) <= maximum)
    _require(all(not (ord(c) < 32 or 127 <= ord(c) <= 159 or 0xD800 <= ord(c) <= 0xDFFF) for c in value))
    return value  # type: ignore[return-value]


def _integer(value: object, minimum: int, maximum: int) -> int:
    _require(type(value) is int and minimum <= value <= maximum)
    return value  # type: ignore[return-value]


def _decimal(value: object) -> str:
    text = _text(value, 20)
    _require(re.fullmatch(r"[1-9][0-9]*", text) is not None and int(text) <= (1 << 64) - 1)
    return text


def _hex(value: object, size: int) -> str:
    text = _text(value, size)
    _require(re.fullmatch(r"[0-9a-f]{" + str(size) + "}", text) is not None)
    return text


def _coordinate(value: object) -> str:
    text = _text(value, 255)
    _require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", text) is not None)
    return text


@dataclass(frozen=True)
class Selection:
    run_id: str
    attempt: int
    stage: str
    platform: str

    def __post_init__(self) -> None:
        _decimal(self.run_id)
        _integer(self.attempt, 1, 100)
        _require(type(self.stage) is str and self.stage in STAGES)
        _require(type(self.platform) is str and self.platform in PLATFORMS)

    @classmethod
    def parse(cls, value: object) -> Selection:
        row = _keys(value, ("runId", "attempt", "stage", "platform"))
        return cls(row["runId"], row["attempt"], row["stage"], row["platform"])

    def value(self) -> dict[str, Any]:
        return {"runId": self.run_id, "attempt": self.attempt, "stage": self.stage, "platform": self.platform}


@dataclass(frozen=True)
class HistoryContext:
    project_binding: str
    config_sha256: str
    repository: str
    repository_id: str
    account_id: str
    tooling_sha: str
    selection: Selection

    def __post_init__(self) -> None:
        _hex(self.project_binding, 64)
        _hex(self.config_sha256, 64)
        _coordinate(self.repository)
        _decimal(self.repository_id)
        _decimal(self.account_id)
        _hex(self.tooling_sha, 40)
        _require(type(self.selection) is Selection)

    @classmethod
    def parse(cls, value: object) -> HistoryContext:
        row = _keys(value, ("schemaVersion", "projectBinding", "configSha256", "repository",
            "repositoryId", "accountId", "toolingRepository", "toolingSha", "selection"))
        _integer(row["schemaVersion"], 1, 1)
        _require(row["toolingRepository"] == TOOLING_REPOSITORY and type(row["toolingRepository"]) is str)
        return cls(row["projectBinding"], row["configSha256"], row["repository"], row["repositoryId"],
            row["accountId"], row["toolingSha"], Selection.parse(row["selection"]))

    def value(self) -> dict[str, Any]:
        return {"schemaVersion": 1, "projectBinding": self.project_binding,
            "configSha256": self.config_sha256, "repository": self.repository,
            "repositoryId": self.repository_id, "accountId": self.account_id,
            "toolingRepository": TOOLING_REPOSITORY, "toolingSha": self.tooling_sha,
            "selection": self.selection.value()}

    def verifier_context(self) -> ReadOnlyEvidenceContext:
        return ReadOnlyEvidenceContext({"id": self.repository_id, "fullName": self.repository},
            self.selection.platform, TOOLING_REPOSITORY, self.tooling_sha)


class HistoryBudget:
    """One request's prospective scalar quote, never an IO or memory permit.

    Failed claims are absorbing. A caller cannot spend other remaining counters
    after any refused claim. Actual adapters/owners still must account and close
    every original; this DATA class performs no resource reservation itself.
    """
    __slots__ = ("_calls", "_auth", "_downloads", "_download_raw", "_decodes", "_decode_raw",
                 "_capture_raw", "_maximum_capture", "_originals", "_verifiers", "_pending_decode", "_verifiers_reserved", "_failed")

    def __init__(self) -> None:
        self._calls = self._auth = self._downloads = self._download_raw = 0
        self._decodes = self._decode_raw = self._capture_raw = self._maximum_capture = self._originals = 0
        self._verifiers = 0
        self._pending_decode = None
        self._verifiers_reserved = False
        self._failed = False

    def _check(self, condition: bool) -> None:
        if self._failed or not condition:
            self._failed = True
            raise ValidationError("history prospective resource limit exceeded")

    def _size(self, value: object, maximum: int) -> int:
        self._check(type(value) is int and 0 <= value <= maximum)
        return value  # type: ignore[return-value]

    def _memory(self, calls: int, raw: int, capture: int, maximum: int) -> None:
        self._check(512 * MIB + 256 * 4096 * calls + 16 * raw + 5 * capture + 4 * maximum <= GIB)

    def claim_call(self) -> None:
        self._check(self._calls < 128)
        self._calls += 1

    def reserve_verifiers(self) -> None:
        self._check(not self._verifiers_reserved and self._verifiers == 0 and self._calls == 0)
        self._verifiers_reserved = True

    def reserve_decode(self, raw_bytes: int) -> None:
        self._check(self._pending_decode is None)
        self.claim_decode(raw_bytes)
        self._pending_decode = raw_bytes

    def consume_decode(self, raw_bytes: int) -> None:
        if self._pending_decode is None:
            self.claim_decode(raw_bytes)
        else:
            self._check(type(raw_bytes) is int and raw_bytes == self._pending_decode)
            self._pending_decode = None

    def decode_reserved(self, raw: bytes):
        self._check(self._pending_decode is not None and type(raw) is bytes
                    and len(raw) == self._pending_decode)
        return _decode_json(raw, self)

    def claim_verifier(self) -> None:
        # Separate subbudget of the SAME global128 calls, not another owner.
        # Parent preflight reserves the full supported3/8/19 stage allowance.
        # Atomically reserve this attempted command in both counters. A failed
        # global claim must not leave verifierCalls greater than commands.
        self._check(self._verifiers_reserved and self._verifiers < 19 and self._calls < 128)
        self._calls += 1
        self._verifiers += 1

    def claim_auth_read(self) -> None:
        self._check(self._auth < 4)
        self._auth += 1

    def claim_download(self, raw_bytes: int) -> None:
        size = self._size(raw_bytes, GIB)
        self._check(self._downloads < 4 and self._download_raw + size <= 4 * GIB)
        self._downloads += 1
        self._download_raw += size

    def claim_decode(self, raw_bytes: int) -> None:
        size = self._size(raw_bytes, MIB)
        calls, raw = self._decodes + 1, self._decode_raw + size
        self._check(calls <= 128 and raw <= 8 * MIB)
        self._memory(calls, raw, self._capture_raw, self._maximum_capture)
        self._decodes, self._decode_raw = calls, raw

    def claim_capture(self, raw_bytes: int, maximum: int) -> None:
        cap = self._size(maximum, MIB)
        size = self._size(raw_bytes, cap)
        total, largest = self._capture_raw + size, max(self._maximum_capture, cap)
        self._check(total <= 32 * MIB)
        self._memory(self._decodes, self._decode_raw, total, largest)
        self._capture_raw, self._maximum_capture = total, largest

    def claim_originals(self, count: int) -> None:
        amount = self._size(count, 32768)
        self._check(self._originals + amount <= 32768)
        self._originals += amount

    def check_descriptors(self, native_parent: int, python_live: int, next_count: int) -> None:
        parent = self._size(native_parent, 192)
        live, extra = self._size(python_live, 128), self._size(next_count, 128)
        self._check(live + extra <= 128 and parent + 8 + live + extra <= 192)


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("nonfinite history JSON number")
    return value


def _decode_json(raw: bytes, budget: HistoryBudget) -> Any:
    """Private fixed preflight BEFORE decoding; stdlib owns actual JSON grammar.

    Counts keys too (conservative). Stack is a depth counter, not an allocated
    syntax tree. Delimiter mismatches and malformed literals remain the decoder's
    error, never positive validity inferred from this preflight.
    """
    _require(type(raw) is bytes and type(budget) is HistoryBudget)
    budget.consume_decode(len(raw))
    depth = nodes = 0
    quoted = escaped = primitive = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
            continue
        if byte == 34:
            quoted, primitive = True, False
            nodes += 1
        elif byte in (91, 123):
            depth += 1
            nodes += 1
            primitive = False
        elif byte in (93, 125):
            depth -= 1
            primitive = False
        elif byte in (9, 10, 13, 32, 44, 58):
            primitive = False
        elif not primitive:
            nodes += 1
            primitive = True
        budget._check(0 <= depth <= 32 and nodes <= 4096)
    budget._check(not quoted and not escaped and depth == 0)
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs,
            parse_float=_finite_float, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError, ValidationError):
        budget._failed = True
        raise ValidationError("history JSON is invalid") from None


def _authority(value: object, stage: str) -> dict[str, Any]:
    row = _keys(value, ("workflow", "callerPath", "reusableRepository", "reusablePath",
        "reusableCommit", "runId", "attempt", "headSha", "ref", "event"))
    for key, maximum in (("workflow", 255), ("callerPath", 512), ("reusableRepository", 255),
                         ("reusablePath", 512), ("ref", 512), ("event", 32)):
        _text(row[key], maximum)
    _decimal(row["runId"])
    _integer(row["attempt"], 1, 100)
    _hex(row["reusableCommit"], 40)
    _hex(row["headSha"], 40)
    return dict(_authority_for_stage(row, stage, "history workflow authority"))


def _evidence(value: object, context: HistoryContext) -> dict[str, Any]:
    row = _keys(value, ("artifactId", "artifactSha256", "artifactName", "producerJobId",
        "producedBy", "authorizedBy", "candidateSource", "operationSource", "version",
        "applicationId", "outcome", "candidateManifestSha256", "operationIntentSha256",
        "receiptSha256", "provenanceSha256"))
    selected = context.selection
    result: dict[str, Any] = {"artifactId": _decimal(row["artifactId"]),
        "producerJobId": _decimal(row["producerJobId"]), "artifactName": _text(row["artifactName"], 255),
        "applicationId": _text(row["applicationId"], 255)}
    _require(result["artifactName"] == artifact_name(selected.stage, selected.platform, "evidence"))
    for key in ("artifactSha256", "candidateManifestSha256", "operationIntentSha256", "receiptSha256", "provenanceSha256"):
        result[key] = _hex(row[key], 64)
    for key in ("producedBy", "authorizedBy"):
        result[key] = _authority(row[key], selected.stage)
        _require(result[key]["reusableRepository"] == TOOLING_REPOSITORY
                 and result[key]["reusableCommit"] == context.tooling_sha)
    _require(result["producedBy"]["runId"] == selected.run_id and result["producedBy"]["attempt"] == selected.attempt)
    for key in ("candidateSource", "operationSource"):
        source = _keys(row[key], ("commit", "tree"))
        result[key] = {part: _hex(source[part], 40) for part in ("commit", "tree")}
    version = _keys(row["version"], ("name", "build"))
    name = _text(version["name"], 64)
    _require(re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?", name) is not None)
    if selected.platform == "ios":
        _require(re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", name) is not None)
    result["version"] = {"name": name, "build": _integer(version["build"], 1, 2_100_000_000)}
    outcome = _text(row["outcome"], 64)
    _require(outcome in OUTCOMES)
    result["outcome"] = outcome
    return result


def parse_result(value: object, expected_context: HistoryContext) -> dict[str, Any]:
    """Validate bounded correlated projection, not its authentication or custody."""
    _require(type(expected_context) is HistoryContext)
    row = _keys(value, ("schemaVersion", "context", "observedAt", "verification", "reason", "evidence", "assurance"))
    _integer(row["schemaVersion"], 1, 1)
    context = HistoryContext.parse(row["context"])
    _require(context == expected_context and row["assurance"] == ASSURANCE)
    stamp = _text(row["observedAt"], 32)
    _require(re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z", stamp) is not None)
    try:
        datetime.fromisoformat(stamp[:-1] + "+00:00")
    except ValueError:
        raise ValidationError("history observation timestamp is invalid") from None
    verification, reason = _text(row["verification"], 16), _text(row["reason"], 64)
    if verification == "verified":
        _require(reason == "none" and row["evidence"] is not None)
        evidence = _evidence(row["evidence"], context)
    else:
        _require((verification == "unavailable" and reason in UNAVAILABLE)
                 or (verification == "refused" and reason in REFUSED))
        _require(row["evidence"] is None)
        evidence = None
    result = {"schemaVersion": 1, "context": context.value(), "observedAt": stamp,
        "verification": verification, "reason": reason, "evidence": evidence, "assurance": ASSURANCE}
    _require(len(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) <= 16 * 1024)
    return result
