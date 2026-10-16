"""Publication's fixed create-only leaves under the existing journal custodian.

Intent, each pre-send claim and each acknowledged identity are separate durable
files. No overwrite/delete/resume-write API exists. An interrupted write remains
unknown; reconciliation reads facts and never repairs or retries the mutation.
"""
from __future__ import annotations

import hashlib
import re

from ._desktop_github_engine import _decode_json
from ._github_preflight_journal import Journal as _Custodian, JournalError, canonical
from .github_setup_publication import (CONFIG_PATH, MAX_CONFIG_BYTES, MAX_CALLER_BYTES, PATHS, PHASES,
    PROTOCOL, Target, _DIGEST, _SHA, _id, _match, _object, _require)

MAX_RECORDS = 64
MAX_INTENT_BYTES = 8192
MAX_PHASE_BYTES = 512


def summary(value: object) -> dict:
    row = _object(value, {"protocol", "target", "baseCommit", "baseTree", "desiredTree", "files"})
    _require(row["protocol"] == PROTOCOL)
    target = Target.parse(row["target"])
    for name in ("baseCommit", "baseTree", "desiredTree"):
        _match(row[name], _SHA)
    _require(row["baseTree"] != row["desiredTree"])
    files = row["files"]
    _require(type(files) is list and len(files) == len(PATHS))
    for file, path in zip(files, PATHS, strict=True):
        entry = _object(file, {"path", "before", "after"})
        _require(entry["path"] == path)
        maximum = MAX_CONFIG_BYTES if path == CONFIG_PATH else MAX_CALLER_BYTES
        for name in ("before", "after"):
            if name == "before" and entry[name] is None:
                continue
            fingerprint = _object(entry[name], {"bytes", "sha256"})
            _require(type(fingerprint["bytes"]) is int and 0 < fingerprint["bytes"] <= maximum)
            _match(fingerprint["sha256"], _DIGEST)
    _require(len(canonical(row)) <= MAX_INTENT_BYTES)
    # Detached strict parsed DATA. No caller retains a mutable authority alias.
    return {**row, "target": target.value(), "files": [dict(file,
        before=None if file["before"] is None else dict(file["before"]), after=dict(file["after"])) for file in files]}


class Journal(_Custodian):
    _leaf_pattern = re.compile(r"([0-9a-f]{32})\.(intent|(?:tree|commit|branch|pull)\.(?:claim|result))\.json\Z", re.ASCII)
    _max_entries = MAX_RECORDS * 9
    _max_total_bytes = MAX_RECORDS * (MAX_INTENT_BYTES + 8 * MAX_PHASE_BYTES)

    def __init__(self, home: str, *, end: float):
        super().__init__(home, end=end)
        self.suffix = (".local", "share", "mobile-release-kit", "github-setup-publication")
        self.publications: dict[str, dict] = {}
        self.selected: str | None = None

    def _leaf_limit(self, name: str) -> int:
        return MAX_INTENT_BYTES if name.endswith(".intent.json") else MAX_PHASE_BYTES

    def _decode(self, raw: bytes, limit: int) -> dict:
        _require(raw.endswith(b"\n") and raw.count(b"\n") == 1)
        value = _decode_json(raw[:-1], limit=limit, nodes=512, depth=10, exact=True)
        _require(type(value) is dict and canonical(value) + b"\n" == raw)
        return value

    def _load(self) -> None:
        names = self._names()
        markers = {name.split(".")[0] for name in names}
        if len(markers) > MAX_RECORDS:
            raise JournalError("Private publication capacity exceeded")
        total = 0
        for marker in sorted(markers):
            intent_name = marker + ".intent.json"
            if intent_name not in names:
                raise JournalError("Private publication intent is missing")
            raw = self._read(intent_name); total += len(raw)
            original = summary(self._decode(raw, MAX_INTENT_BYTES))
            _require(original["target"]["marker"] == marker)
            digest = hashlib.sha256(raw).hexdigest()
            record = {"summary": original, "digest": digest, "claimed": [], "confirmed": {}}
            seen = {intent_name}
            for phase in PHASES:
                claim, result = marker + "." + phase + ".claim.json", marker + "." + phase + ".result.json"
                if claim not in names:
                    break
                claim_raw = self._read(claim); total += len(claim_raw)
                _require(self._decode(claim_raw, MAX_PHASE_BYTES) == self._claim_value(digest, phase))
                seen.add(claim); record["claimed"].append(phase)
                if result not in names:
                    break
                result_raw = self._read(result); total += len(result_raw)
                row = _object(self._decode(result_raw, MAX_PHASE_BYTES), {"intentSha256", "phase", "identity"})
                _require(row["intentSha256"] == digest and row["phase"] == phase)
                identity = self._identity(phase, row["identity"], original, record["confirmed"])
                seen.add(result); record["confirmed"][phase] = identity
            _require(seen == {name for name in names if name.startswith(marker + ".")})
            self.publications[marker] = record
        _require(total <= self._max_total_bytes and names == self._names())

    @staticmethod
    def _claim_value(digest: str, phase: str) -> dict:
        return {"intentSha256": digest, "phase": phase}

    @staticmethod
    def _identity(phase: str, identity: object, original: dict, confirmed: dict) -> str:
        _require(phase in PHASES)
        value = _id(identity) if phase == "pull" else _match(identity, _SHA)
        if phase == "tree":
            _require(value == original["desiredTree"])
        if phase == "branch":
            _require(value == confirmed.get("commit"))
        return value

    def create_intent(self, value: dict) -> None:
        original = summary(value)
        marker = original["target"]["marker"]
        _require(self.selected is None and marker not in self.publications and len(self.publications) < MAX_RECORDS)
        raw = canonical(original) + b"\n"
        self._create(marker + ".intent.json", raw)
        self.publications[marker] = {"summary": original, "digest": hashlib.sha256(raw).hexdigest(),
                                     "claimed": [], "confirmed": {}}
        self.selected = marker  # Only a NEW original can obtain write authority.

    def claim_write(self, phase: str) -> None:
        _require(self.selected is not None)
        record = self.publications[self.selected]
        count = len(record["claimed"])
        _require(count < len(PHASES) and phase == PHASES[count]
                 and len(record["confirmed"]) == count)
        self._create(self.selected + "." + phase + ".claim.json",
                     canonical(self._claim_value(record["digest"], phase)) + b"\n")
        record["claimed"].append(phase)

    def record(self, phase: str, identity: str) -> None:
        _require(self.selected is not None)
        record = self.publications[self.selected]
        _require(phase in PHASES and record["claimed"] and phase == record["claimed"][-1]
                 and phase not in record["confirmed"])
        identity = self._identity(phase, identity, record["summary"], record["confirmed"])
        self._create(self.selected + "." + phase + ".result.json", canonical({
            "intentSha256": record["digest"], "phase": phase, "identity": identity}) + b"\n")
        record["confirmed"][phase] = identity

    def pending(self, scope: dict) -> list[dict]:
        _object(scope, {"projectBinding", "accountId", "repositoryId", "repository"})
        self._post()
        return [{"summary": summary(record["summary"]), "claimed": list(record["claimed"]),
                 "confirmed": dict(record["confirmed"])} for record in self.publications.values()
                if all(record["summary"]["target"][key] == value for key, value in scope.items())]
