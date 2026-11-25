"""Fixed signed-support nomination DATA, not signing or producer authority.

The owner supplies source-authenticated nomination bytes and retains originals.
These reducers open no path and execute nothing. A successful capsule match
joins bytes and a closed receipt envelope to that nomination and the current
public signer profiles: it does not establish producer outer-zero, native
signing, notarization or a shipping enrollment. No
shipping caller is connected until real supplier evidence is enrolled/reviewed.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

DOCUMENT_LIMIT = 16 * 1024
ARCHIVES_LIMIT = 48 * 1024 * 1024
MEMBER_LIMIT = 16 * 1024 * 1024
UPSTREAM_BYTES = 3023
UPSTREAM_SHA256 = "3450a83882cecdc9d8e402380ccf21e6dc5cec65382cbc7c18b4e6ff6a9aeb8f"
REPOSITORY = "Apdelrahman1911/mobile-release-kit"
WORKFLOW = ".github/workflows/desktop-macos-android-support-signing.yml"
ARTIFACT_NAME = "mrk-macos-android-signed-support"
RECEIPT_NAME = "android-support-signed-receipt.json"
KIND = "mrk-macos-signed-android-support-v1"
PRODUCER_PROFILE_BYTES = 488
PRODUCER_PROFILE_SHA256 = "2f42e8e333ceb5dd96089c3dd7c38fbe4aaa1c79b6ae7369157c06179f0c08f2"
SERVICE_PROFILE_BYTES = 219
SERVICE_PROFILE_SHA256 = "7f1a96c30d75d915e84f1a45095170ba6e4b2870203efda199515c7260e98663"
SIGNER_TEAM = "7CGZ2343AA"
SIGNER_SHA1 = "5effa7d19bbe005b19c1617833cbe22186c2af96"
_LAYOUT = (
    ("bundletool", "bundletool-all-1.18.3.jar"),
    ("aapt2", "aapt2-8.9.2-12782657-osx.jar"),
)
_AAPT_SLICES = ((16777223, -2147483645), (16777228, 0))
_MEMBERS = (
    ("bundletool-aapt2", "bundletool", "macos/aapt2", 11186368,
     "995cf1a04fb55045dd22ae3d6248f32d649bac9dfa7bf9357507499794051c6b", _AAPT_SLICES),
    ("bundletool-jna", "bundletool", "com/sun/jna/darwin/libjnidispatch.jnilib", 180932,
     "e8ad39879b107ed955388d29555ddbcff3ada41598780eef579246752dd96c75", ((7, 3), (16777223, 3))),
    ("agp-aapt2", "aapt2", "aapt2", 11143368,
     "213e3d049e2c85daa930ed777bbd5627c1c5479a8d6698029b8f9c0161ad0a7e", _AAPT_SLICES),
)


class Refused(ValueError):
    """Finite DATA-contract error, never an authorization to repair inputs."""


def _need(ok, reason):
    if not ok:
        raise Refused(reason)


def _hash(body):
    return hashlib.sha256(body).hexdigest()


def _keys(value, expected):
    _need(type(value) is dict and set(value) == set(expected), "object-shape")
    return value


def _hex(value, digits=64):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{" + str(digits) + r"}", value) is not None


def _pairs(items):
    result = {}
    for key, value in items:
        _need(key not in result, "duplicate-json-key")
        result[key] = value
    return result


def _not_number(_):
    raise Refused("json-number")


def _number(value):
    _need(len(value.lstrip("-")) <= 20, "json-number")
    return int(value)


def _decode(raw):
    _need(type(raw) is bytes and 0 < len(raw) <= DOCUMENT_LIMIT and not raw.startswith(b"\xef\xbb\xbf"), "document-bound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_int=_number,
                           parse_float=_not_number, parse_constant=_not_number)
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, Refused):
            raise
        raise Refused("json-input") from None
    # The byte cap is preparse. These are postparse semantic bounds, not a
    # claim that the stdlib parser's allocations were prospectively counted.
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        _need(count <= 1024 and depth <= 12, "json-shape-bound")
        if type(item) is dict:
            for key, child in item.items():
                _need(type(key) is str and len(key) <= 2048, "json-string-bound")
                pending.append((child, depth + 1))
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            _need(len(item) <= 2048, "json-string-bound")
        else:
            _need(type(item) in (int, bool, type(None)), "json-value")
    return value


@dataclass(frozen=True)
class Pin:
    size: int
    sha256: str


@dataclass(frozen=True)
class Archive:
    identity: str
    file_name: str
    resource_path: str
    upstream_url: str
    upstream: Pin
    derived: Pin
    inventory_sha256: str


@dataclass(frozen=True)
class Member:
    role: str
    archive_id: str
    path: str
    upstream: Pin
    derived: Pin
    slices: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class Nomination:
    sha256: str
    producer: tuple[tuple[str, str], ...]
    receipt: Pin
    archives: tuple[Archive, ...]
    members: tuple[Member, ...]


def _pin(value, maximum):
    _keys(value, ("size", "sha256"))
    _need(type(value["size"]) is int and 0 < value["size"] <= maximum and _hex(value["sha256"]), "pin")
    return Pin(value["size"], value["sha256"])


def nomination(raw: bytes, upstream_raw: bytes) -> Nomination:
    """Parse the fixed recipe only; raw must ALSO be source-pinned by its owner."""
    _need(type(upstream_raw) is bytes and len(upstream_raw) == UPSTREAM_BYTES
          and _hash(upstream_raw) == UPSTREAM_SHA256, "fixed-upstream-original")
    upstream = _decode(upstream_raw)  # Exact complete bytes authenticated first.
    value = _keys(_decode(raw), ("schemaVersion", "kind", "upstreamManifestSha256", "producer", "receipt", "archives", "members"))
    _need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
          and value["kind"] == KIND and value["upstreamManifestSha256"] == UPSTREAM_SHA256, "nomination-kind")
    producer = _keys(value["producer"], ("repository", "sourceCommit", "sourceTree", "workflow", "runId", "runAttempt",
                                         "artifactId", "artifactName", "artifactSha256"))
    _need(producer["repository"] == REPOSITORY and producer["workflow"] == WORKFLOW
          and producer["artifactName"] == ARTIFACT_NAME and _hex(producer["sourceCommit"], 40)
          and _hex(producer["sourceTree"], 40) and _hex(producer["artifactSha256"]), "producer-source")
    _need(all(type(producer[k]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", producer[k]) is not None
              for k in ("runId", "runAttempt", "artifactId")), "producer-identity")
    receipt = _keys(value["receipt"], ("fileName", "size", "sha256"))
    _need(receipt["fileName"] == RECEIPT_NAME, "receipt-name")
    receipt_pin = _pin({k: receipt[k] for k in ("size", "sha256")}, DOCUMENT_LIMIT)
    rows = value["archives"]
    _need(type(rows) is list and len(rows) == 2, "archive-roster")
    archives = []
    for row, official, (identity, filename) in zip(rows, upstream["archives"], _LAYOUT):
        _keys(row, ("id", "fileName", "resourcePath", "upstream", "derived", "inventorySha256"))
        _need(row["id"] == official["id"] == identity and row["fileName"] == official["fileName"] == filename
              and row["resourcePath"] == official["resourcePath"], "archive-layout")
        _keys(row["upstream"], ("url", "size", "sha256"))
        _need(row["upstream"] == {k: official[k] for k in ("url", "size", "sha256")}, "archive-upstream")
        old = _pin({k: row["upstream"][k] for k in ("size", "sha256")}, ARCHIVES_LIMIT)
        derived = _pin(row["derived"], ARCHIVES_LIMIT)
        _need(derived.sha256 != old.sha256 and _hex(row["inventorySha256"]), "archive-derivation")
        archives.append(Archive(identity, filename, row["resourcePath"], official["url"], old, derived, row["inventorySha256"]))
    _need(sum(row.derived.size for row in archives) <= ARCHIVES_LIMIT, "archive-aggregate")
    rows = value["members"]
    _need(type(rows) is list and len(rows) == 3, "member-roster")
    members = []
    for row, (role, archive, path, size, digest, slices) in zip(rows, _MEMBERS):
        _keys(row, ("role", "archiveId", "path", "upstream", "derived", "slices"))
        _need((row["role"], row["archiveId"], row["path"]) == (role, archive, path), "member-role")
        old, derived = _pin(row["upstream"], MEMBER_LIMIT), _pin(row["derived"], MEMBER_LIMIT)
        _need(old == Pin(size, digest) and derived.sha256 != digest, "member-derivation")
        actual = row["slices"]
        _need(type(actual) is list and len(actual) == len(slices), "member-slices")
        for item, (cpu, subtype) in zip(actual, slices):
            _keys(item, ("cpuType", "cpuSubtype"))
            _need(type(item["cpuType"]) is int and type(item["cpuSubtype"]) is int
                  and (item["cpuType"], item["cpuSubtype"]) == (cpu, subtype), "member-slices")
        members.append(Member(role, archive, path, old, derived, slices))
    return Nomination(_hash(raw), tuple(sorted(producer.items())), receipt_pin, tuple(archives), tuple(members))


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _receipt_envelope(relation, raw, producer_profile_raw, service_profile_raw):
    for body, size, digest in (
        (producer_profile_raw, PRODUCER_PROFILE_BYTES, PRODUCER_PROFILE_SHA256),
        (service_profile_raw, SERVICE_PROFILE_BYTES, SERVICE_PROFILE_SHA256),
    ):
        _need(type(body) is bytes and len(body) == size and _hash(body) == digest, "fixed-signer-profile")
    value = _keys(_decode(raw), (
        "schemaVersion", "kind", "source", "sourceTree", "workflow", "runId", "runAttempt",
        "sourceNominationSha256", "signer", "archives", "nativeMembers", "notarizationQualified",
        "productReady", "outerExitRequired", "sourcePost", "inputPost", "nonDeliveryScratchRetired",
        "originalsClosed", "nativeOriginals", "credentialOriginalsSha256", "credentialOriginalCount", "credentialContexts",
    ))
    producer = dict(relation.producer)
    _need(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
          and value["kind"] == "macos-android-support-signed-v1"
          and value["source"] == producer["sourceCommit"] and value["sourceTree"] == producer["sourceTree"]
          and value["runId"] == producer["runId"] and value["runAttempt"] == producer["runAttempt"]
          and value["workflow"] == REPOSITORY + "/" + WORKFLOW + "@refs/heads/verify/desktop-macos-android-support-signing"
          and value["sourceNominationSha256"] == UPSTREAM_SHA256, "receipt-source")
    signer = _keys(value["signer"], ("teamIdentifier", "certificateSha1", "producerProfileSha256", "serviceProfileSha256"))
    _need(signer == {"teamIdentifier": SIGNER_TEAM, "certificateSha1": SIGNER_SHA1,
                     "producerProfileSha256": PRODUCER_PROFILE_SHA256, "serviceProfileSha256": SERVICE_PROFILE_SHA256},
          "receipt-signer")
    _need(all(value[key] is True for key in ("outerExitRequired", "sourcePost", "inputPost", "nonDeliveryScratchRetired", "originalsClosed"))
          and value["notarizationQualified"] is False and value["productReady"] is False, "receipt-finality")
    rows = value["archives"]
    _need(type(rows) is list and len(rows) == 2, "receipt-archives")
    for row, expected in zip(rows, relation.archives):
        _keys(row, ("name", "upstreamUrl", "originalBytes", "originalSha256", "originalInventorySha256",
                    "derivedBytes", "derivedSha256", "derivedInventorySha256", "nonNativeUnchanged"))
        _need(row["name"] == expected.file_name and row["upstreamUrl"] == expected.upstream_url
              and _integer(row["originalBytes"], 1, ARCHIVES_LIMIT) and row["originalBytes"] == expected.upstream.size
              and row["originalSha256"] == expected.upstream.sha256 and _hex(row["originalInventorySha256"])
              and _integer(row["derivedBytes"], 1, ARCHIVES_LIMIT) and row["derivedBytes"] == expected.derived.size
              and row["derivedSha256"] == expected.derived.sha256
              and row["derivedInventorySha256"] == expected.inventory_sha256 and row["nonNativeUnchanged"] is True,
              "receipt-archive-correspondence")
    rows = value["nativeMembers"]
    _need(type(rows) is list and len(rows) == 3, "receipt-members")
    for row, expected in zip(rows, relation.members):
        _keys(row, ("role", "member", "originalBytes", "originalSha256", "signedBytes", "signedSha256",
                    "slices", "identifier", "runtimeRequired", "timestampRequested"))
        runtime = expected.role != "bundletool-jna"
        _need(row["role"] == expected.role and row["member"] == expected.path
              and _integer(row["originalBytes"], 1, MEMBER_LIMIT) and row["originalBytes"] == expected.upstream.size
              and row["originalSha256"] == expected.upstream.sha256
              and _integer(row["signedBytes"], 1, MEMBER_LIMIT) and row["signedBytes"] == expected.derived.size
              and row["signedSha256"] == expected.derived.sha256
              and row["identifier"] == "dev.mobile-release-kit.desktop.android-support." + expected.role
              and row["runtimeRequired"] is runtime and row["timestampRequested"] is True, "receipt-member-correspondence")
        slices = row["slices"]
        _need(type(slices) is list and len(slices) == len(expected.slices), "receipt-slices")
        total = 0
        for item, (cpu, subtype) in zip(slices, expected.slices):
            _keys(item, ("cpuType", "cpuSubtype", "size", "sha256", "codeDirectoryFlags", "cmsPresent"))
            _need(type(item["cpuType"]) is int and type(item["cpuSubtype"]) is int
                  and (item["cpuType"], item["cpuSubtype"]) == (cpu, subtype)
                  and _integer(item["size"], 1, expected.derived.size) and _hex(item["sha256"])
                  and item["cmsPresent"] is True, "receipt-slice-correspondence")
            flags = item["codeDirectoryFlags"]
            _need(type(flags) is list and 1 <= len(flags) <= 6
                  and all(_integer(flag, 0, 0xffffffff) and not flag & 2
                          and (not runtime or flag & 0x10000) for flag in flags)
                  and len(set(flags)) == 1, "receipt-signature-flags")
            total += item["size"]
        _need(total <= expected.derived.size, "receipt-slice-aggregate")
    roles = tuple(member.role + suffix for member in relation.members for suffix in ("-sign", "-verify")) + tuple(
        member.role + "-final-verify" for member in relation.members)
    rows = value["nativeOriginals"]
    _need(type(rows) is list and len(rows) == len(roles), "receipt-originals")
    for row, role in zip(rows, roles):
        _keys(row, ("role", "entered", "returned", "capturesSettled", "returncode", "stdoutSha256", "stderrSha256"))
        _need(row["role"] == role and all(row[key] is True for key in ("entered", "returned", "capturesSettled"))
              and type(row["returncode"]) is int and row["returncode"] == 0
              and _hex(row["stdoutSha256"]) and _hex(row["stderrSha256"]), "receipt-native-original")
    _need(type(value["credentialOriginalCount"]) is int and value["credentialOriginalCount"] == 57
          and _hex(value["credentialOriginalsSha256"]), "receipt-credential-originals")
    contexts = value["credentialContexts"]
    _need(type(contexts) is list and len(contexts) == 3, "receipt-credential-contexts")
    for row, member in zip(contexts, relation.members):
        _keys(row, ("purpose", "searchRestored", "defaultUnchanged", "retired", "closed"))
        _need(row["purpose"] == member.role
              and all(row[key] is True for key in ("searchRestored", "defaultUnchanged", "retired", "closed")), "receipt-credential-finality")


def admit_capsule(relation: Nomination, receipt_raw: bytes, archives: dict[str, bytes], *,
                  producer_profile_raw: bytes, service_profile_raw: bytes) -> dict:
    """Match original bytes and the closed DATA envelope, not native authority.

    relation must be the result of nomination() over the owner's pinned SOURCE.
    The owner must separately prove transport roster/custody/finality and the
    successful producer before enrollment. This is deliberately not shipping.
    """
    _need(type(relation) is Nomination, "nomination-type")
    _need(type(receipt_raw) is bytes and 0 < len(receipt_raw) <= DOCUMENT_LIMIT
          and len(receipt_raw) == relation.receipt.size and _hash(receipt_raw) == relation.receipt.sha256, "receipt-original")
    _need(type(archives) is dict and set(archives) == {a.file_name for a in relation.archives}, "capsule-roster")
    _need(all(type(body) is bytes for body in archives.values())
          and sum(map(len, archives.values())) <= ARCHIVES_LIMIT, "capsule-bound")
    for row in relation.archives:
        body = archives[row.file_name]
        _need(len(body) == row.derived.size and _hash(body) == row.derived.sha256, "capsule-original")
    _receipt_envelope(relation, receipt_raw, producer_profile_raw, service_profile_raw)
    return {"schemaVersion": 1, "kind": "mrk-macos-signed-support-data-correspondence-v1",
            "nominationSha256": relation.sha256, "upstreamManifestSha256": UPSTREAM_SHA256,
            "receiptSha256": relation.receipt.sha256,
            "archives": [{"fileName": a.file_name, "size": a.derived.size, "sha256": a.derived.sha256} for a in relation.archives],
            "dataOnly": True, "receiptEnvelopeValidated": True, "originalProducerValidated": False,
            "signedNativeQualified": False, "shippingEnrollment": False}
