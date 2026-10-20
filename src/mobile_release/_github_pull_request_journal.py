"""Create-only draft-PR intents on the existing private journal custodian.

No replacement, deletion or resume-write method. Loaded records are comparison
data only. Every earlier same-pair intent must have its exact durable 201 receipt
and an immutable historical closure; new creation still checks open PRs afresh.
"""
from __future__ import annotations

import hashlib
import re

from ._desktop_github_engine import _decode_json
from ._github_preflight_journal import Journal as Custodian, JournalError
from . import github_pull_request as p
from .github_pull_request_management import closure_leaf, closed_observation


class Journal(Custodian):
    _leaf_pattern = re.compile(r"([0-9a-f]{32})\.(intent|claim|receipt|closed)\.json\Z", re.ASCII)
    _max_entries = p.MAX_RECORDS * 4
    _max_total_bytes = p.MAX_RECORDS * (p.MAX_RECORD_BYTES + 3072)

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
            receipt_digest = None
            claim, receipt = marker + ".claim.json", marker + ".receipt.json"
            if claim in names:
                p.require(self.decode(self._read(claim), 1024) == {"intentSha256": digest, "phase": "create"})
                seen.add(claim); entry["claimed"] = True
                if receipt in names:
                    receipt_raw = self._read(receipt)
                    acknowledged = p.obj(self.decode(receipt_raw, 1024), {"intentSha256", "pullRequest"})
                    receipt_digest = hashlib.sha256(receipt_raw).hexdigest()
                    p.require(acknowledged["intentSha256"] == digest)
                    entry["acknowledged"] = p.acknowledgement(acknowledged["pullRequest"], prepared)
                    seen.add(receipt)
                    closed = marker + ".closed.json"
                    if closed in names:
                        entry["closed"] = closure_leaf(self.decode(self._read(closed), 1024), prepared,
                                                       digest, receipt_digest, entry["acknowledged"])
                        seen.add(closed)
            self.creations[marker] = {"data": p.pending_record(entry), "digest": digest, "receiptDigest": receipt_digest}
        p.require(seen == names and names == self._names())

    def create_intent(self, value: dict) -> None:
        prepared = p.Prepared.parse(value)
        p.need(self.selected is None and len(self.creations) < p.MAX_RECORDS, "previous-attempt")
        # Every prior same-pair attempt, across project/account aliases, stays
        # fenced unless its actual 201 receipt has an exact historical closure.
        # Never replay that old claim. The new original already repeated the
        # fresh open-PR query, so a reopened PR still blocks a replacement.
        for record in self.creations.values():
            previous = p.Prepared.parse(record["data"]["prepared"]).target
            p.need(previous.scope["repositoryId"] != prepared.target.scope["repositoryId"]
                   or (previous.intent["base"], previous.intent["head"]) !=
                   (prepared.target.intent["base"], prepared.target.intent["head"])
                   or record["data"].get("closed") is not None, "previous-attempt")
        marker = prepared.target.intent["marker"]
        p.need(marker not in self.creations, "previous-attempt")
        raw = p.canonical({"protocol": p.PROTOCOL, "prepared": prepared.value()}) + b"\n"
        try:
            self._create(marker + ".intent.json", raw)
        except (JournalError, OSError):
            raise p.Refused("journal-unavailable") from None
        self.creations[marker] = {"data": {"prepared": prepared.value(), "claimed": False, "acknowledged": None},
                                  "digest": hashlib.sha256(raw).hexdigest(), "receiptDigest": None}
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
        raw = p.canonical({"intentSha256": record["digest"], "pullRequest": safe}) + b"\n"
        try:
            self._create(self.selected + ".receipt.json", raw)
        except (JournalError, OSError):
            raise p.Refused("journal-unavailable") from None
        record["data"]["acknowledged"] = safe
        record["receiptDigest"] = hashlib.sha256(raw).hexdigest()

    def record_closed(self, value: dict, closed: dict) -> None:
        self._post()
        prepared = p.Prepared.parse(value)
        marker = prepared.target.intent["marker"]
        record = self.creations.get(marker)
        p.need(self.selected is None and record is not None
               and record["data"]["prepared"] == prepared.value()
               and record["data"]["claimed"] is True
               and record["data"]["acknowledged"] is not None
               and record["receiptDigest"] is not None, "journal-unavailable")
        safe = closed_observation(closed, record["data"]["acknowledged"])
        if record["data"].get("closed") is not None:
            # Retain the first actual closure, even if a PR later reopens and
            # closes again. It is explicitly historical, never current absence.
            return
        raw = p.canonical({"protocol": p.PROTOCOL, "intentSha256": record["digest"],
                           "receiptSha256": record["receiptDigest"], "closed": safe}) + b"\n"
        try:
            self._create(marker + ".closed.json", raw)
        except (JournalError, OSError):
            raise p.Refused("journal-unavailable") from None
        record["data"]["closed"] = safe

    def pending(self, target: p.Target) -> list[dict]:
        self._post()
        return [p.pending_record(entry["data"]) for entry in self.creations.values()
                if p.Target.parse(entry["data"]["prepared"]["target"]).same_scope(target)]
