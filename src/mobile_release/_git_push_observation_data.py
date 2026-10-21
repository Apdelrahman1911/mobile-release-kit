"""Fixed PUBLIC transcript data for the nonshipping installed Push cases.

These identities are not credentials, a Connected session, a send receipt or
native authority. Only the fixed observer entry imports this supplier; the
ordinary Push/Connection entries and shipping CLT nomination are unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re

CASES = ("git-push-pack", "git-push-stale", "git-push-held-refusal")
SCOPE = "git-push-native"
ACCOUNT, ACCOUNT_ID, REPOSITORY_ID = "mrk-push-fixture", "831", "842"
REFERENCE = "refs/heads/main"
DATA_NAME = "mrk-push-observation.json"
DATA_LIMIT = 4096  # No PACK copy: just three local, setup-produced commit OIDs.
WINDOW_MARKER = b"MRK_PUSH_OBSERVER=refused-with-original-open\n"
_OID = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)


class Refused(ValueError):
    def __init__(self):
        super().__init__("The fixed Push observation input was refused.")


def need(value):
    if not value:
        raise Refused()


def coordinate(case):
    need(type(case) is str and case in CASES)
    return ACCOUNT + "/" + case


def token(case):
    need(type(case) is str and case in CASES)
    return "MRK-NON-CREDENTIAL-PUSH-OBSERVER-" + case


def token_case(value):
    need(type(value) is str)
    matches = [case for case in CASES if value == token(case)]
    need(len(matches) == 1)
    return matches[0]


def oid(value):
    return type(value) is str and _OID.fullmatch(value) is not None and value != "0" * 40


def _pairs(rows):
    result = {}
    for key, value in rows:
        need(key not in result)
        result[key] = value
    return result


@dataclass(frozen=True, slots=True, repr=False)
class Transcript:
    case: str
    base: str
    target: str
    other: str

    def __post_init__(self):
        need(type(self.case) is str and self.case in CASES
             and all(oid(v) for v in (self.base, self.target, self.other))
             and len({self.base, self.target, self.other}) == 3)

    def raw(self):
        raw = json.dumps({"schemaVersion": 1, "case": self.case, "base": self.base,
            "target": self.target, "other": self.other}, sort_keys=True,
            separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
        need(len(raw) <= DATA_LIMIT)
        return raw


def decode(raw, case):
    need(type(raw) is bytes and 0 < len(raw) <= DATA_LIMIT and type(case) is str and case in CASES)
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs)
        need(type(value) is dict and set(value) == {"schemaVersion", "case", "base", "target", "other"}
             and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["case"] == case)
        result = Transcript(case, value["base"], value["target"], value["other"])
        need(result.raw() == raw)
        return result
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise Refused() from None


def packet(body):
    need(type(body) is bytes and 0 < len(body) <= 4092)
    return f"{len(body) + 4:04x}".encode("ascii") + body


def advertisement(value, mode, *, after=False):
    need(type(value) is Transcript and mode in ("review", "apply") and type(after) is bool
         and (not after or mode == "apply" and value.case == CASES[0]))
    tip = value.target if after else value.other if mode == "apply" and value.case == CASES[1] else value.base
    # Native stock Git negotiates its own command. No Fetch v2, push-options,
    # certificate, extra ref, sideband or report-status-v2 fixture ambiguity.
    row = (tip + " " + REFERENCE).encode("ascii") + b"\0report-status ofs-delta object-format=sha1\n"
    return packet(b"# service=git-receive-pack\n") + b"0000" + packet(row) + b"0000"


def receive_status(value):
    need(type(value) is Transcript and value.case in (CASES[0], CASES[2]))
    first = packet(b"unpack ok\n")
    second = packet(("ok " + REFERENCE + "\n").encode("ascii"))
    if value.case == CASES[2]:
        # HTTP Content-Length and EOF are COMPLETE. The declared pkt-line
        # payload alone is truncated: the REAL Push status parser must refuse.
        return first + second[:-1]
    return first + second + b"0000"


def account():
    return {"id": int(ACCOUNT_ID), "login": ACCOUNT}


def repository(case):
    return {"id": int(REPOSITORY_ID), "full_name": coordinate(case), "default_branch": "main",
            "visibility": "private", "archived": False, "permissions": {"pull": True, "push": True},
            "clone_url": "https://github.com/" + coordinate(case) + ".git"}
