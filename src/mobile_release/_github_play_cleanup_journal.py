"""Fixed immutable dispatch records on the existing directory custodian.

This is not the protected hosted cleanup claim or a counter store. Even an
acknowledged dispatch permanently excludes its exact candidate/attempt here.
No account/project alias, absence in a later read or restart permits resending.
"""
from __future__ import annotations

import hashlib
import re

from . import github_play_cleanup as p
from ._desktop_github_engine import _decode_json
from ._github_preflight_journal import Journal as Custodian, JournalError


class Journal(Custodian):
    _leaf_pattern = re.compile(r"([0-9a-f]{32})\.(intent|claim|receipt)\.json\Z", re.ASCII)
    _max_entries = p.MAX_RECORDS * 3
    _max_total_bytes = p.MAX_RECORDS * (p.MAX_RECORD_BYTES + 2048)

    def __init__(self, home: str, *, end: float):
        super().__init__(home, end=end)
        self.suffix = (".local", "share", "mobile-release-kit", "github-play-cleanup")
        self.attempts: dict[str, dict] = {}
        self.selected: str | None = None
        self.used = self.claim_entered = self.receipt_entered = False

    def _leaf_limit(self, name: str) -> int:
        return p.MAX_RECORD_BYTES if name.endswith(".intent.json") else 1024

    @staticmethod
    def decode(raw: bytes, limit: int) -> dict:
        p.require(type(raw) is bytes and raw.endswith(b"\n") and raw.count(b"\n") == 1)
        row = _decode_json(raw[:-1], limit=limit - 1, nodes=1024, depth=12, exact=True)
        p.require(type(row) is dict and p.canonical(row) + b"\n" == raw)
        return row

    def _load(self) -> None:
        names = self._names()
        markers = {name.split(".")[0] for name in names}
        p.require(len(markers) <= p.MAX_RECORDS)
        seen: set[str] = set()
        keys: set[tuple] = set()
        for marker in sorted(markers):
            intent = marker + ".intent.json"
            p.require(intent in names)
            raw = self._read(intent)
            row = p.obj(self.decode(raw, p.MAX_RECORD_BYTES), {"protocol", "prepared"})
            p.require(row["protocol"] == p.PROTOCOL)
            prepared = p.Prepared.parse(row["prepared"])
            p.require(prepared.target.marker == marker)
            key = p.once_key(prepared)
            p.require(key not in keys); keys.add(key)
            digest = hashlib.sha256(raw).hexdigest()
            data = {"prepared": prepared.value(), "claimed": False, "acknowledged": False}
            seen.add(intent)
            claim, receipt = marker + ".claim.json", marker + ".receipt.json"
            if claim in names:
                p.require(self.decode(self._read(claim), 1024) == {"intentSha256": digest, "phase": "dispatch"})
                seen.add(claim); data["claimed"] = True
                if receipt in names:
                    p.require(self.decode(self._read(receipt), 1024) == {"intentSha256": digest,
                        "acknowledged": True, "status": 204})
                    seen.add(receipt); data["acknowledged"] = True
            self.attempts[marker] = {"data": p.pending_record(data), "digest": digest}
        p.require(seen == names and names == self._names())

    def create_intent(self, value: dict) -> None:
        prepared = p.Prepared.parse(value)
        p.need(not self.used and self.selected is None, "previous-attempt")
        p.need(len(self.attempts) < p.MAX_RECORDS, "journal-full")
        key = p.once_key(prepared)
        p.need(all(p.once_key(p.Prepared.parse(record["data"]["prepared"])) != key
            for record in self.attempts.values()), "previous-attempt")
        marker = prepared.target.marker
        p.need(marker not in self.attempts, "previous-attempt")
        raw = p.canonical({"protocol": p.PROTOCOL, "prepared": prepared.value()}) + b"\n"
        p.require(len(raw) <= p.MAX_RECORD_BYTES)
        self.used = True  # Before possible create; no replacement after an unknown return.
        try:
            self._create(marker + ".intent.json", raw)
        except (JournalError, OSError):
            raise p.Refused("journal-unavailable") from None
        self.attempts[marker] = {"data": {"prepared": prepared.value(), "claimed": False, "acknowledged": False},
                                 "digest": hashlib.sha256(raw).hexdigest()}
        self.selected = marker

    def claim(self) -> None:
        p.need(self.selected is not None and self.used and not self.claim_entered, "previous-attempt")
        record = self.attempts[self.selected]
        p.need(record["data"]["claimed"] is False, "previous-attempt")
        self.claim_entered = True
        try:
            self._create(self.selected + ".claim.json", p.canonical({"intentSha256": record["digest"], "phase": "dispatch"}) + b"\n")
        except (JournalError, OSError):
            raise p.Refused("journal-unavailable") from None
        record["data"]["claimed"] = True

    def record_accepted(self) -> None:
        p.need(self.selected is not None and self.claim_entered and not self.receipt_entered, "previous-attempt")
        record = self.attempts[self.selected]
        p.need(record["data"]["claimed"] and not record["data"]["acknowledged"], "previous-attempt")
        self.receipt_entered = True
        try:
            self._create(self.selected + ".receipt.json", p.canonical({"intentSha256": record["digest"],
                "acknowledged": True, "status": 204}) + b"\n")
        except (JournalError, OSError):
            raise p.Refused("journal-unavailable") from None
        record["data"]["acknowledged"] = True

    def pending(self, target: p.Target) -> list[dict]:
        self._post()
        return [p.pending_record(entry["data"]) for entry in self.attempts.values()
                if p.Target.parse(entry["data"]["prepared"]["target"]).same_scope(target)]
