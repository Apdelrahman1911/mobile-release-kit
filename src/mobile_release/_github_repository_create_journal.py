"""Create-only repository intents on the existing private journal custodian.

No replacement, deletion or resume-write method. Loaded records are comparison
data only. A new marker cannot bypass an earlier intent for the same owner/name.
"""
from __future__ import annotations

import hashlib
import re

from ._desktop_github_engine import _decode_json
from ._github_preflight_journal import Journal as Custodian, JournalError
from . import github_repository_create as p


class Journal(Custodian):
    _leaf_pattern = re.compile(r"([0-9a-f]{32})\.(intent|claim|receipt)\.json\Z", re.ASCII)
    _max_entries = p.MAX_RECORDS * 3
    _max_total_bytes = p.MAX_RECORDS * (p.MAX_RECORD_BYTES + 2048)

    def __init__(self, home: str, *, end: float):
        super().__init__(home, end=end)
        self.suffix = (".local", "share", "mobile-release-kit", "github-repository-create")
        self.creations: dict[str, dict] = {}
        self.selected: str | None = None

    def _leaf_limit(self, name: str) -> int:
        return p.MAX_RECORD_BYTES if name.endswith(".intent.json") else 1024

    @staticmethod
    def decode(raw: bytes, limit: int) -> dict:
        p.require(type(raw) is bytes and raw.endswith(b"\n") and raw.count(b"\n") == 1)
        value = _decode_json(raw[:-1], limit=limit, nodes=128, depth=6, exact=True)
        p.require(type(value) is dict and p.canonical(value) + b"\n" == raw)
        return value

    def _load(self) -> None:
        names = self._names()
        markers = {name.split(".")[0] for name in names}
        p.require(len(markers) <= p.MAX_RECORDS)
        seen: set[str] = set()
        for marker in sorted(markers):
            intent = marker + ".intent.json"
            p.require(intent in names)
            raw = self._read(intent)
            row = p.obj(self.decode(raw, p.MAX_RECORD_BYTES), {"protocol", "prepared"})
            p.require(row["protocol"] == p.PROTOCOL)
            prepared = p.Prepared.parse(row["prepared"])
            p.require(prepared.target.marker == marker)
            digest = hashlib.sha256(raw).hexdigest()
            entry = {"prepared": prepared.value(), "claimed": False, "acknowledged": None}
            seen.add(intent)
            claim, receipt = marker + ".claim.json", marker + ".receipt.json"
            if claim in names:
                p.require(self.decode(self._read(claim), 1024) == {"intentSha256": digest, "phase": "create"})
                seen.add(claim); entry["claimed"] = True
                if receipt in names:
                    acknowledged = p.obj(self.decode(self._read(receipt), 1024), {"intentSha256", "repository"})
                    p.require(acknowledged["intentSha256"] == digest)
                    entry["acknowledged"] = p.observation(acknowledged["repository"], prepared)
                    seen.add(receipt)
            self.creations[marker] = {"data": p.pending_record(entry), "digest": digest}
        p.require(seen == names and names == self._names())

    def create_intent(self, value: dict) -> None:
        prepared = p.Prepared.parse(value)
        p.need(self.selected is None and len(self.creations) < p.MAX_RECORDS, "previous-attempt")
        # This check deliberately crosses marker/project/account aliases. The
        # same server owner ID + name cannot gain another send through a nonce.
        for record in self.creations.values():
            previous = p.Prepared.parse(record["data"]["prepared"])
            p.need(previous.owner_id != prepared.owner_id
                   or previous.target.name.lower() != prepared.target.name.lower(), "previous-attempt")
        marker = prepared.target.marker
        p.need(marker not in self.creations, "previous-attempt")
        raw = p.canonical({"protocol": p.PROTOCOL, "prepared": prepared.value()}) + b"\n"
        try:
            self._create(marker + ".intent.json", raw)
        except (JournalError, OSError):
            raise p.Refused("journal-unavailable") from None
        self.creations[marker] = {"data": {"prepared": prepared.value(), "claimed": False, "acknowledged": None},
                                  "digest": hashlib.sha256(raw).hexdigest()}
        self.selected = marker  # Only this new original may ever claim POST.

    def claim(self) -> None:
        p.need(self.selected is not None, "journal-unavailable")
        record = self.creations[self.selected]
        p.need(record["data"]["claimed"] is False, "previous-attempt")
        try:
            self._create(self.selected + ".claim.json", p.canonical({"intentSha256": record["digest"], "phase": "create"}) + b"\n")
        except (JournalError, OSError):
            raise p.Refused("journal-unavailable") from None
        record["data"]["claimed"] = True

    def record(self, repository: dict) -> None:
        p.need(self.selected is not None, "journal-unavailable")
        record = self.creations[self.selected]
        p.need(record["data"]["claimed"] and record["data"]["acknowledged"] is None, "previous-attempt")
        safe = p.observation(repository, p.Prepared.parse(record["data"]["prepared"]))
        try:
            self._create(self.selected + ".receipt.json", p.canonical({"intentSha256": record["digest"], "repository": safe}) + b"\n")
        except (JournalError, OSError):
            raise p.Refused("journal-unavailable") from None
        record["data"]["acknowledged"] = safe

    def pending(self, target: p.Target) -> list[dict]:
        self._post()
        return [p.pending_record(entry["data"]) for entry in self.creations.values()
                if (old := p.Target.parse(entry["data"]["prepared"]["target"])).project_binding == target.project_binding
                and old.account_id == target.account_id and old.repository.lower() == target.repository.lower()]
