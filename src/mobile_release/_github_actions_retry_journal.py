"""Fixed create-only retry records on the existing held-directory custodian.

No repair/eviction/replay: a newer explicitly reviewed attempt is allowed only
after older records for this immutable run have a durable 201 receipt. Pending
records survive restart and account/project aliases cannot bypass the fence.
"""
from __future__ import annotations

import hashlib
import re

from . import github_actions_retry as p
from ._desktop_github_engine import _decode_json
from ._github_preflight_journal import Journal as Custodian, JournalError


class Journal(Custodian):
    _leaf_pattern = re.compile(r"([0-9a-f]{32})\.(intent|claim|receipt)\.json\Z", re.ASCII)
    _max_entries = p.MAX_RECORDS * 3
    _max_total_bytes = p.MAX_RECORDS * (p.MAX_RECORD_BYTES + 2048)

    def __init__(self, home: str, *, end: float):
        super().__init__(home, end=end)
        self.suffix = (".local", "share", "mobile-release-kit", "github-actions-retry")
        self.attempts: dict[str, dict] = {}
        self.selected: str | None = None

    def _leaf_limit(self, name: str) -> int:
        return p.MAX_RECORD_BYTES if name.endswith(".intent.json") else 1024

    @staticmethod
    def decode(raw: bytes, limit: int) -> dict:
        p.require(type(raw) is bytes and raw.endswith(b"\n") and raw.count(b"\n") == 1)
        value = _decode_json(raw[:-1], limit=limit, nodes=512, depth=9, exact=True)
        p.require(type(value) is dict and p.canonical(value) + b"\n" == raw)
        return value

    def _load(self) -> None:
        names = self._names()
        markers = {name.split(".")[0] for name in names}
        p.require(len(markers) <= p.MAX_RECORDS)
        seen: set[str] = set(); keys: set[tuple] = set()
        for marker in sorted(markers):
            intent = marker + ".intent.json"
            p.require(intent in names)
            raw = self._read(intent)
            row = p.obj(self.decode(raw, p.MAX_RECORD_BYTES), {"protocol", "prepared"})
            p.require(row["protocol"] == p.PROTOCOL)
            prepared = p.Prepared.parse(row["prepared"])
            p.require(prepared.target.selection["marker"] == marker)
            key = (prepared.target.scope["repositoryId"], prepared.run["id"], prepared.run["attempt"])
            p.require(key not in keys); keys.add(key)
            digest = hashlib.sha256(raw).hexdigest()
            entry = {"prepared": prepared.value(), "claimed": False, "acknowledged": False}
            seen.add(intent)
            claim, receipt = marker + ".claim.json", marker + ".receipt.json"
            if claim in names:
                p.require(self.decode(self._read(claim), 1024) == {"intentSha256": digest, "phase": "retry"})
                seen.add(claim); entry["claimed"] = True
                if receipt in names:
                    p.require(self.decode(self._read(receipt), 1024) == {"intentSha256": digest, "accepted": True, "status": 201})
                    seen.add(receipt); entry["acknowledged"] = True
            self.attempts[marker] = {"data": p.pending_record(entry), "digest": digest}
        p.require(seen == names and names == self._names())

    def create_intent(self, value: dict) -> None:
        prepared = p.Prepared.parse(value)
        p.need(self.selected is None, "previous-attempt")
        p.need(len(self.attempts) < p.MAX_RECORDS, "journal-full")
        for record in self.attempts.values():
            previous = p.pending_record(record["data"])
            old = p.Prepared.parse(previous["prepared"])
            if old.target.scope["repositoryId"] != prepared.target.scope["repositoryId"] or old.run["id"] != prepared.run["id"]:
                continue
            # Do not copy PR's permanent branch-pair exclusion: an accepted
            # older attempt permits a genuinely NEW user-approved retry. A
            # missing/uncertain receipt never does, even across account aliases.
            p.need(previous["acknowledged"] and old.run["attempt"] < prepared.run["attempt"], "previous-attempt")
        marker = prepared.target.selection["marker"]
        p.need(marker not in self.attempts, "previous-attempt")
        raw = p.canonical({"protocol": p.PROTOCOL, "prepared": prepared.value()}) + b"\n"
        p.require(len(raw) <= p.MAX_RECORD_BYTES)
        try:
            self._create(marker + ".intent.json", raw)
        except (JournalError, OSError):
            raise p.Refused("journal-unavailable") from None
        self.attempts[marker] = {"data": {"prepared": prepared.value(), "claimed": False, "acknowledged": False},
                                 "digest": hashlib.sha256(raw).hexdigest()}
        self.selected = marker

    def claim(self) -> None:
        p.need(self.selected is not None, "journal-unavailable")
        record = self.attempts[self.selected]
        p.need(record["data"]["claimed"] is False, "previous-attempt")
        try:
            self._create(self.selected + ".claim.json", p.canonical({"intentSha256": record["digest"], "phase": "retry"}) + b"\n")
        except (JournalError, OSError):
            raise p.Refused("journal-unavailable") from None
        record["data"]["claimed"] = True

    def record_accepted(self) -> None:
        p.need(self.selected is not None, "journal-unavailable")
        record = self.attempts[self.selected]
        p.need(record["data"]["claimed"] and record["data"]["acknowledged"] is False, "previous-attempt")
        try:
            self._create(self.selected + ".receipt.json", p.canonical({"intentSha256": record["digest"], "accepted": True, "status": 201}) + b"\n")
        except (JournalError, OSError):
            raise p.Refused("journal-unavailable") from None
        record["data"]["acknowledged"] = True

    def pending(self, target: p.Target) -> list[dict]:
        self._post()
        return [p.pending_record(entry["data"]) for entry in self.attempts.values()
                if p.Target.parse(entry["data"]["prepared"]["target"]).same_scope(target)]
