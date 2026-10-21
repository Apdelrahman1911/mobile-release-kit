"""Closed future-tag DATA on the existing version ledger, never write authority.

The source remains an actual branch and pre-edit commit. This optional selector
does not reinterpret an old tag, derive a numeric version from its name, or
authorize creating/moving a ref. Only the separate original binding action can
claim a final commit and issue the single create-only request.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from . import version_policy as p

WIRE_VERSION = 5
PROTOCOL = "mrk-version-allocation/5"
_RUN = re.compile(r"[1-9][0-9]{0,19}\Z", re.ASCII)


def need(condition, reason="ledger-invalid"):
    from .version_allocation import VersionAllocationError
    if not condition:
        raise VersionAllocationError(reason)


def reference(value):
    p.source_ref(value)
    need(value.startswith("refs/tags/"), "invalid-allocation")
    return value


def hosted_selector(operation, platform, confirmation):
    """Closed use of the existing confirmation input, no free JSON/ref override."""
    need(platform in {"ios", "android", "both"}, "invalid-allocation")
    if operation == "reserve-version":
        need(confirmation == "reserve-version:" + platform +
             (":temporary-play-edit" if platform != "ios" else ""), "invalid-allocation")
        return None
    prefix = "reserve-future-tag:" + platform + (":temporary-play-edit" if platform != "ios" else "") + ":"
    need(operation == "reserve-future-tag" and type(confirmation) is str
         and confirmation.startswith(prefix) and len(confirmation) <= len(prefix) + 220,
         "invalid-allocation")
    return reference(confirmation[len(prefix):])


def request_version(request):
    return WIRE_VERSION if request.future_tag is not None else request.version_policy.schema_version


def policy_reference(request):
    return request.source.ref if request.future_tag is None else request.future_tag


def validate_request(request):
    if request.future_tag is None:
        return
    reference(request.future_tag)
    need(request.version_policy.schema_version in (2, 3, 4)
         and request.version_policy.mode == "automatic"
         and request.source.ref.startswith("refs/heads/"), "invalid-allocation")
    request.version_policy.increment_for(request.future_tag)


@dataclass(frozen=True, slots=True)
class Binding:
    """Immutable intent DATA, not an original HTTP/native completion receipt."""
    candidate_id: str
    reservation_sha256: str
    final_commit: str
    final_tree: str
    attempt_id: str
    run_id: str
    run_attempt: int

    def __post_init__(self):
        from . import version_allocation as a
        a._uuid(self.candidate_id)
        p._match(self.reservation_sha256, p._DIGEST)
        p._match(self.final_commit, p._SHA)
        p._match(self.final_tree, p._SHA)
        a._uuid(self.attempt_id)
        need(type(self.run_id) is str and _RUN.fullmatch(self.run_id) is not None
             and int(self.run_id) <= (1 << 64) - 1)
        p._integer(self.run_attempt, 999, 1)

    def value(self):
        return {"candidateId": self.candidate_id, "reservationSha256": self.reservation_sha256,
                "finalCommit": self.final_commit, "finalTree": self.final_tree,
                "attemptId": self.attempt_id, "runId": self.run_id, "runAttempt": self.run_attempt}

    @classmethod
    def parse(cls, value):
        row = p._object(value, {"candidateId", "reservationSha256", "finalCommit", "finalTree",
                                "attemptId", "runId", "runAttempt"})
        return cls(*(row[key] for key in ("candidateId", "reservationSha256", "finalCommit",
                                         "finalTree", "attemptId", "runId", "runAttempt")))


def validate_ledger(reservations, bindings):
    from . import version_allocation as a
    need(type(bindings) is tuple and len(bindings) <= len(reservations) <= a.MAX_RESERVATIONS)
    tags, selected = {}, {}
    for row in reservations:
        request = row.request
        selected[request.candidate_id] = row
        # Historical source tags are not new intents, but cannot alias one.
        tag = request.future_tag or (request.source.ref if request.source.ref.startswith("refs/tags/") else None)
        if tag is not None:
            # Legacy repeated tags keep their historical interpretation. A
            # collision involving any new future-tag intent is always refused.
            previous = tags.get(tag)
            need(previous is None or request.future_tag is None and previous.future_tag is None,
                 "candidate-binding-conflict")
            tags[tag] = request
    candidates, attempts = set(), set()
    for binding in bindings:
        need(type(binding) is Binding)
        row = selected.get(binding.candidate_id)
        need(row is not None and row.request.future_tag is not None
             and row.sha256 == binding.reservation_sha256
             and binding.final_commit != row.request.source.commit
             and binding.candidate_id not in candidates and binding.attempt_id not in attempts)
        candidates.add(binding.candidate_id)
        attempts.add(binding.attempt_id)


def append_binding(ledger, binding):
    """Pure exact successor; neither this result nor a loaded Binding arms IO."""
    from . import version_allocation as a
    need(type(ledger) is a.Ledger and type(binding) is Binding)
    need(all(old.candidate_id != binding.candidate_id for old in ledger.tag_bindings),
         "candidate-binding-conflict")
    after = a.Ledger(ledger.genesis, ledger.reservations, (*ledger.tag_bindings, binding))
    after.to_bytes()  # Same original prospective byte cap, before any CAS.
    return after


def preserves(before, after):
    """Full prefix comparison, not a checkpoint/sequence-only preservation test."""
    from . import version_allocation as a
    return (type(before) is a.Ledger and type(after) is a.Ledger
            and before.genesis == after.genesis
            and after.reservations[:len(before.reservations)] == before.reservations
            and after.tag_bindings[:len(before.tag_bindings)] == before.tag_bindings)


def check_bound(ledger, row, final, tree):
    need(row in ledger.reservations and row.request.future_tag is not None, "candidate-binding-conflict")
    matches = [item for item in ledger.tag_bindings if item.candidate_id == row.request.candidate_id]
    need(len(matches) == 1 and matches[0].reservation_sha256 == row.sha256
         and matches[0].final_commit == final and matches[0].final_tree == tree,
         "candidate-binding-conflict")
    return matches[0]


def check_ref(body, target, final):
    reference(target)
    need(type(body) is dict and body.get("ref") == target and type(body.get("object")) is dict
         and body["object"].get("type") == "commit" and body["object"].get("sha") == final,
         "candidate-binding-conflict")
