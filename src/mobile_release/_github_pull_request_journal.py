"""Create-only draft-PR intents on the existing private journal custodian.

No replacement, deletion or resume-write method. Loaded records are comparison
data only. A new marker cannot bypass an earlier intent for the same repository ID/branch pair.
"""
from __future__ import annotations

import hashlib
import re

from ._desktop_github_engine import _decode_json
from ._github_preflight_journal import Journal as Custodian, JournalError
from . import github_pull_request as p


class Journal(Custodian):
    _leaf_pattern = re.compile(r"([0-9a-f]{32})\.(intent|claim|receipt)\.json\Z", re.ASCII)
    _max_entries = p.MAX_RECORDS * 3
    _max_total_bytes = p.MAX_RECORDS * (p.MAX_RECORD_BYTES + 2048)

    def __init__(self, home: str, *, end: float):
        super().__init__(home, end=end)
        self.suffix = (".local", "share", "mobile-release-kit", "github-pull-request")
        self.creations: dict[str, dict] = {}
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
        seen: set[str] = set()
        for marker in sorted(markers):
            intent = marker + ".intent.json"
            p.require(intent in names)
            raw = self._read(intent)
            row = p.obj(self.decode(raw, p.MAX_RECORD_BYTES), {"protocol", "prepared"})
            p.require(row["protocol"] == p.PROTOCOL)
            prepared = p.Prepared.parse(row["prepared"])
            p.require(prepared.target.intent["marker"] == marker)
            digest = hashlib.sha256(raw).hexdigest()
            entry = {"prepared": prepared.value(), "claimed": False, "acknowledged": None}
            seen.add(intent)
            claim, receipt = marker + ".claim.json", marker + ".receipt.json"
            if claim in names:
                p.require(self.decode(self._read(claim), 1024) == {"intentSha256": digest, "phase": "create"})
                seen.add(claim); entry["claimed"] = True
                if receipt in names:
                    acknowledged = p.obj(self.decode(self._read(receipt), 1024), {"intentSha256", "pullRequest"})
                    p.require(acknowledged["intentSha256"] == digest)
                    entry["acknowledged"] = p.acknowledgement(acknowledged["pullRequest"], prepared)
                    seen.add(receipt)
            self.creations[marker] = {"data": p.pending_record(entry), "digest": digest}
        p.require(seen == names and names == self._names())

    def create_intent(self, value: dict) -> None:
        prepared = p.Prepared.parse(value)
        p.need(self.selected is None and len(self.creations) < p.MAX_RECORDS, "previous-attempt")
        # Cross marker/project/account aliases: no new nonce can grant a second
        # attempt for this exact remote repository ID and base/head pair.
        for record in self.creations.values():
            previous = p.Prepared.parse(record["data"]["prepared"]).target
            p.need(previous.scope["repositoryId"] != prepared.target.scope["repositoryId"]
                   or (previous.intent["base"], previous.intent["head"]) !=
                   (prepared.target.intent["base"], prepared.target.intent["head"]), "previous-attempt")
        marker = prepared.target.intent["marker"]
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
        safe = p.acknowledgement(repository, p.Prepared.parse(record["data"]["prepared"]))
        try:
            self._create(self.selected + ".receipt.json", p.canonical({"intentSha256": record["digest"], "pullRequest": safe}) + b"\n")
        except (JournalError, OSError):
            raise p.Refused("journal-unavailable") from None
        record["data"]["acknowledged"] = safe

    def pending(self, target: p.Target) -> list[dict]:
        self._post()
        return [p.pending_record(entry["data"]) for entry in self.creations.values()
                if p.Target.parse(entry["data"]["prepared"]["target"]).same_scope(target)]
