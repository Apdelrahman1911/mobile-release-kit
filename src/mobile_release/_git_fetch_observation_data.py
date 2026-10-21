"""Closed PUBLIC DATA for the nonshipping installed Fetch observer.

Nothing imports this from a shipping entry. These synthetic identities are not
credentials or a Connected/GO/native proof. A held observer bootstrap uses the
ordinary Connection/remote parsers; the actual native owners still own every
child, descriptor, deadline, candidate and close.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import re

CASES = ("git-fetch-pack", "git-fetch-corrupt", "git-fetch-limit", "git-fetch-held-helper")
SCOPE = "git-fetch-native"
ACCOUNT = "mrk-fetch-fixture"
ACCOUNT_ID = "811"
REPOSITORY_ID = "822"
REFERENCE = "refs/heads/main"
DATA_NAME = "mrk-fetch-observation.json"
LIMIT_NAME = "mrk-fetch-observation.limit"
DATA_LIMIT = 64 * 1024
PACK_LIMIT = 40 * 1024
WINDOW_MARKER = b"MRK_FETCH_OBSERVER=returned-with-original-open\n"
_OID = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)


class Refused(ValueError):
    def __init__(self):
        super().__init__("The fixed Fetch observation input was refused.")


def need(value):
    if not value:
        raise Refused()


def coordinate(case):
    need(type(case) is str and case in CASES)
    return ACCOUNT + "/" + case


def token(case):
    # Public literal, accepted only by the separate finite transcript supplier.
    # A real HTTP transport must NEVER receive it.
    need(type(case) is str and case in CASES)
    return "MRK-NON-CREDENTIAL-FETCH-OBSERVER-" + case


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
    pack: bytes

    def __post_init__(self):
        need(type(self.case) is str and self.case in CASES and oid(self.base) and oid(self.target)
             and self.base != self.target and type(self.pack) is bytes and 32 <= len(self.pack) <= PACK_LIMIT)
        need(self.pack[:8] == b"PACK\0\0\0\2" and 1 <= int.from_bytes(self.pack[8:12], "big") <= 24
             and hashlib.sha1(self.pack[:-20], usedforsecurity=False).digest() == self.pack[-20:])

    def raw(self):
        raw = json.dumps({"schemaVersion": 1, "case": self.case, "base": self.base,
            "target": self.target, "pack": base64.b64encode(self.pack).decode("ascii")},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
        need(len(raw) <= DATA_LIMIT)
        return raw


def decode(raw, case):
    need(type(raw) is bytes and 0 < len(raw) <= DATA_LIMIT and type(case) is str and case in CASES)
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs)
        need(type(value) is dict and set(value) == {"schemaVersion", "case", "base", "target", "pack"}
             and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1 and value["case"] == case
             and type(value["pack"]) is str and len(value["pack"]) <= 4 * ((PACK_LIMIT + 2) // 3))
        result = Transcript(case, value["base"], value["target"], base64.b64decode(value["pack"], validate=True))
        need(result.raw() == raw)
        return result
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise Refused() from None


def packet(body):
    need(type(body) is bytes and 0 < len(body) <= 65516)
    return f"{len(body) + 4:04x}".encode("ascii") + body


def advertisement():
    # No URI, shallow, filter, bundle, packfile-URI or sideband-all capability.
    return b"".join(packet(row) for row in (
        b"version 2\n", b"agent=git/mrk-inert-observer\n", b"ls-refs\n",
        b"fetch\n", b"object-format=sha1\n")) + b"0000"


def refs(value):
    need(type(value) is Transcript)
    return packet((value.target + " " + REFERENCE + "\n").encode("ascii")) + b"0000"


def fetch(value):
    need(type(value) is Transcript)
    pack = value.pack
    if value.case == CASES[1]:
        # Still a bounded PACK-shaped body. Actual stock index-pack/fsck must
        # reject the changed object/checksum; the fixture never repairs it.
        pack = pack[:-1] + bytes([pack[-1] ^ 1])
    return packet(b"packfile\n") + b"".join(packet(b"\1" + pack[i:i + 32768])
        for i in range(0, len(pack), 32768)) + b"0000"


def account():
    return {"id": int(ACCOUNT_ID), "login": ACCOUNT}


def repository(case):
    return {"id": int(REPOSITORY_ID), "full_name": coordinate(case), "default_branch": "main",
            "visibility": "private", "archived": False, "permissions": {"pull": True, "push": False},
            "clone_url": "https://github.com/" + coordinate(case) + ".git"}
