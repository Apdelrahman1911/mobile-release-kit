"""One compiled-in Windows snapshot fixture bootstrap, not a test controller.

SOURCE ONLY until separately reviewed and admitted on the fixed disposable job.
The original passive Rust owner starts this exact copy with -I -S -B and ONE
genuine core argument. No fixture child, shell command, native-result substitute,
public qualification opt-in, PID discovery, or production bootstrap edit.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import threading
import time
import zipfile

SCOPE = "windows-static-snapshot-native-v1"
SDK_VERSION = "10.0.26100.0"
GROUPS = (
    ("W1", ("ordinary-source", "ordinary-zip", "closed-gate")),
    ("W2", ("link-children", "reparse-root", "reparse-ancestor", "short-alias", "case-alias",
            "case-collision", "subst-drive", "unc", "device", "ads")),
    ("W3", ("root-reparse-race", "config-reparse-race", "walk-reparse-race", "case-mode-race")),
    ("W4", ("acl-type", "read-eof-size", "entry-limit", "candidate-limit", "aggregate-limit", "depth-path-limit")),
    ("W5", ("replace", "disappear", "config-disappear", "ending-metadata-case", "drive-map-change")),
    ("W6", ("oplock-release", "oplock-withhold", "pending-failstop")),
)
READER_APIS = ("GetCurrentProcess", "IsWow64Process2", "QueryDosDeviceW", "NtCreateFile",
               "GetHandleInformation", "GetFileType", "GetFileInformationByHandleEx",
               "GetVolumeInformationByHandleW", "GetFinalPathNameByHandleW", "ReadFile",
               "CloseHandle", "DeviceIoControl")
READER_COUNTS = ("acquired", "closeAttempts", "closeSucceeded", "closeFailed", "live", "maxLive",
                 "maxBufferBytes", "rootOpens", "relativeOpens", "metadataChecks", "identitiesMatched",
                 "readCalls", "readBytes", "readEof", "directoryCalls", "directoryRecords", "directoryEof",
                 "outsideAcquired", "outsideReads", "outsideDescent", "aliasMetadataAcquired", "violations", "eventCount")
CHECKS = {
    "ordinary-source": ("genuineCore", "configExact", "androidExact", "iosExact", "versionNotDisclosed", "unicodeOpens", "spelling"),
    "ordinary-zip": ("genuineCore", "configExact", "androidExact", "iosExact", "versionNotDisclosed", "unicodeOpens", "spelling"),
    "closed-gate": (),
    "link-children": ("fileSymlinkTag", "directorySymlinkTag", "junctionTag", "hardlinkCount", "hardlinkIdMatch", "excludedReparses", "hardlinkReadBytes", "restoredLinks"),
    "reparse-root": ("junctionTag", "unsafeControlMatched", "rootRefused", "reparseRestored"),
    "reparse-ancestor": ("junctionTag", "unsafeControlMatched", "rootRefused", "reparseRestored"),
    "short-alias": ("aliasObserved", "spellingDiffers", "sameObject", "aliasAcquired", "aliasReadBytes"),
    "case-alias": ("aliasObserved", "spellingDiffers", "sameObject", "aliasAcquired", "aliasReadBytes"),
    "case-collision": ("enabledFlags", "distinctIds", "collisionFiles", "collisionDirectoryBatches", "caseRestored"),
    "subst-drive": ("aliasInitiallyAbsent", "localNonSystemToken", "subtreeMappingObserved", "rootOpens", "mappingRemoved"),
    "unc": ("readerFfiEntries", "readerInstances", "unsafePathRefused"),
    "device": ("readerFfiEntries", "readerInstances", "unsafePathRefused"),
    "ads": ("readerFfiEntries", "readerInstances", "unsafePathRefused"),
    "case-mode-race": ("parentIdSame", "mutationAccess", "enabledFlags", "originalRelativeEntry", "entryBeforeDeadline", "missingNotTrusted", "caseRestored"),
    "acl-type": ("fileAccessDenied", "directoryAccessDenied", "accessibleSiblingRead", "configDirectoryRefused",
                 "denialPoliciesConfirmed", "createdObjectsRemoved", "initialAbsenceRestored"),
    "read-eof-size": ("emptyEof", "invalidUtf8Refused", "shortFinalRead", "multichunkEof", "exactLimitEof", "oversizeReadBytes", "largestRequest", "largestReturn"),
    "entry-limit": ("returnedRecords", "chargedEntries", "overBudgetChildOpens", "entryLimitIssue"),
    "candidate-limit": ("chargedCandidates", "refusedExtraCandidate", "sourceFileLimitIssue"),
    "aggregate-limit": ("chargedBytes", "extraByteRead", "capNotEof", "byteLimitIssue"),
    "depth-path-limit": ("deepestAdmitted", "depth13Opens", "oversizedPathOpens", "depthIssue", "pathIssue", "siblingRead"),
    "replace": ("entryObserved", "originalIdDiffers", "replacementReadBytes", "changedIssue"),
    "disappear": ("entryObserved", "actualMissingReturn", "changedIssue", "missingNotTrusted"),
    "config-disappear": ("entryObserved", "actualMissingReturn", "changedIssue", "missingNotTrusted"),
    "ending-metadata-case": ("genuineFileEof", "writeMetadataChanged", "fileChangeVeto", "genuineDirectoryEof", "caseFlagsChanged", "directoryCaseVeto", "attributesRestored"),
    "drive-map-change": ("aliasInitiallyAbsent", "localNonSystemToken", "initialVolumeMapping", "endingSubtreeMapping", "changedIssue", "laterProjectOpens", "mappingRemoved"),
    "oplock-release": ("grantPending", "originalReaderEntered", "breakSignalled", "completionKnown", "blockedBeforeRelease", "holderCloseReturned", "observerJoined", "eventCloseReturned", "originalReaderReturned"),
    "oplock-withhold": ("grantPending", "originalReaderEntered", "breakSignalled", "completionKnown", "readerReturnedBeforeStop", "holderReleasedBeforeStop", "originalProcessStopped"),
    "pending-failstop": ("originalParentHeld", "realFsctlEntry", "afterCallMarker", "originalExitCode"),
}
for _case in ("root-reparse-race", "config-reparse-race", "walk-reparse-race"):
    CHECKS[_case] = ("parentIdSame", "mutationAccess", "mutationTag", "mutationSucceeded", "originalRelativeEntry",
                     "entryBeforeDeadline", "unsafeControlMatched", "outsideAcquired", "outsideReadBytes",
                     "sharingWriteDenied", "sharingDeleteDenied", "preparatoryDeletes", "reparseRestored")

INVALID = (1 << 64) - 1
READ_ATTRIBUTES, WRITE_ATTRIBUTES, DELETE = 0x80, 0x100, 0x10000
BACKUP, NOFOLLOW, OVERLAPPED_FLAG = 0x02000000, 0x00200000, 0x40000000
MOUNT_TAG, SYMLINK_TAG = 0xA0000003, 0xA000000C
SET_REPARSE, GET_REPARSE, DELETE_REPARSE = 0x900A4, 0x900A8, 0x900AC
BATCH_OPLOCK = 0x90008
MAX_PAYLOAD, MAX_FILE = 32 * 1024 * 1024, 8 * 1024 * 1024


class FixtureFailure(RuntimeError):
    """A fixed fixture failure is never an acceptable reader refusal."""


class NativeFailure(FixtureFailure):
    def __init__(self, api: str, code: int):
        self.api, self.code = api, code
        super().__init__("fixture_native_unavailable")


def require(value: bool, code: str) -> None:
    if not value:
        raise FixtureFailure(code)


def _short_alias_selection(exact_name, observed_name):
    """Classify one actual getter result, never synthesize a native observation."""
    if (type(exact_name) is not str or exact_name != "LongSnapshotDirectory"
            or type(observed_name) is not str):
        return None
    if observed_name == exact_name:
        return "absent"
    if not 1 <= len(observed_name) <= 12:
        return None
    parts = observed_name.split(".")
    if not 1 <= len(parts) <= 2 or not 1 <= len(parts[0]) <= 8:
        return None
    if len(parts) == 2 and not 1 <= len(parts[1]) <= 3:
        return None
    for part in parts:
        for character in part:
            if character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_~":
                return None
    return "existing"


def _short_alias_error_reason(api, code):
    """Fixed labels for already returned setup/restore calls, not policy probes."""
    if type(api) is not str or type(code) is not int or not 0 <= code < 1 << 32 or code == 997:
        return None
    if api not in ("CreateFileW", "GetHandleInformation", "GetFileInformationByHandleEx",
                   "GetShortPathNameW", "SetFileShortNameW"):
        return "fixture_native_unavailable"
    reasons = {5: "short_alias_access_denied", 32: "short_alias_sharing_violation",
               50: "short_alias_not_supported", 87: "short_alias_invalid_parameter",
               183: "short_alias_name_collision", 305: "short_alias_volume_disabled",
               1314: "short_alias_privilege_unavailable"}
    return reasons.get(code, "short_alias_other_refused")


def _installed_deny_data_dacl(data):
    """Validate installed policy bytes, not the caller's effective access."""
    if type(data) is not bytes or not 20 <= len(data) <= 16 * 1024 or data[0] != 1:
        return False
    control = int.from_bytes(data[2:4], "little")
    if control & 0x9004 != 0x9004:  # SELF_RELATIVE, DACL_PROTECTED, DACL_PRESENT.
        return False
    offset = int.from_bytes(data[16:20], "little")
    if offset < 20 or offset % 4 or offset > len(data) - 8:
        return False
    size = int.from_bytes(data[offset + 2:offset + 4], "little")
    count = int.from_bytes(data[offset + 4:offset + 6], "little")
    if data[offset] != 2 or size < 8 or size % 4 or size > len(data) - offset or count != 2:
        return False
    cursor, end = offset + 8, offset + size
    world = b"\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00"
    for ace_type, mask in ((1, 1), (0, 0x1F01FF)):
        if (cursor + 20 > end or data[cursor] != ace_type or data[cursor + 1] != 0
                or int.from_bytes(data[cursor + 2:cursor + 4], "little") != 20
                or int.from_bytes(data[cursor + 4:cursor + 8], "little") != mask
                or data[cursor + 8:cursor + 20] != world):
            return False
        cursor += 20
    # The original ACL allocation may contain spare capacity. Only AceCount
    # records are ACEs; unused bounded bytes are not another access rule.
    return True


def _dacl_policy(data):
    """DACL-only relative SD; ACL2/4, ordinary allow/deny ACEs, SID1 (1..15).

    Owner/group/SACL/RM, other ACEs (including object/condition payloads),
    reserved fields and in-ACE surplus are unsupported, never opaque policy.
    Only outer placement/gaps and ACL capacity after AceCount are excluded.
    """
    if (type(data) is not bytes or not 20 <= len(data) <= 16384
            or data[0] != 1 or data[1] or any(data[4:16])):
        return None
    control = int.from_bytes(data[2:4], "little")
    offset = int.from_bytes(data[16:20], "little")
    if not control & 0x8000 or control & ~0x950C:
        return None
    present = bool(control & 4)
    if not present and (offset or control != 0x8000):
        return None
    if not offset:
        return (control, present, present, None, ())  # Absent != present-null.
    if offset < 20 or offset % 4 or offset > len(data) - 8:
        return None
    revision = data[offset]
    size = int.from_bytes(data[offset + 2:offset + 4], "little")
    count = int.from_bytes(data[offset + 4:offset + 6], "little")
    if (revision not in (2, 4) or data[offset + 1] or any(data[offset + 6:offset + 8])
            or size < 8 or size % 4 or size > len(data) - offset):
        return None
    cursor, end, aces = offset + 8, offset + size, []
    for _ in range(count):
        if cursor + 16 > end:
            return None
        length = int.from_bytes(data[cursor + 2:cursor + 4], "little")
        subcount = data[cursor + 9]
        if (data[cursor] not in (0, 1) or data[cursor + 1] & ~0x1F
                or data[cursor + 8] != 1 or not 1 <= subcount <= 15
                or length != 16 + 4 * subcount or length > end - cursor):
            return None
        aces.append(data[cursor:cursor + length])  # Entire ordered ACE, no projection.
        cursor += length
    return (control, True, False, revision, tuple(aces))


def _dacl_comparison(saved, observed, role):
    a, b = _dacl_policy(saved), _dacl_policy(observed)
    complete = (type(saved) is bytes and len(saved) <= 16384
                and type(observed) is bytes and len(observed) <= 16384)
    valid = a is not None and b is not None
    facts = {"role": role, "savedShapeValid": a is not None, "observedShapeValid": b is not None,
             "lengthEqual": len(saved) == len(observed) if complete else None,
             "bytesEqual": saved == observed if complete else None}
    for key, index in (("presenceEqual", 1), ("nullEqual", 2), ("controlEqual", 0),
                       ("aclRevisionEqual", 3), ("orderedAcesEqual", 4)):
        facts[key] = a[index] == b[index] if valid else None
    for key, mask in (("protectedEqual", 0x1000), ("defaultedEqual", 8), ("autoInheritanceEqual", 0x500)):
        facts[key] = a[0] & mask == b[0] & mask if valid else None
    return facts, valid and a == b


def _dacl_comparison_valid(value):
    policy = ("presenceEqual", "nullEqual", "controlEqual", "protectedEqual", "defaultedEqual",
              "autoInheritanceEqual", "aclRevisionEqual", "orderedAcesEqual")
    fields = ("role", "savedShapeValid", "observedShapeValid", "lengthEqual", "bytesEqual") + policy
    if type(value) is not dict or len(value) != len(fields):
        return False
    for key in value:
        if type(key) is not str or key not in fields:
            return False
    if (type(value["role"]) is not str or value["role"] not in ("denied-file", "denied-directory")
            or type(value["savedShapeValid"]) is not bool or type(value["observedShapeValid"]) is not bool):
        return False
    valid = value["savedShapeValid"] and value["observedShapeValid"]
    for key in ("lengthEqual", "bytesEqual") + policy:
        if value[key] is not None and type(value[key]) is not bool:
            return False
    if ((value["lengthEqual"] is None) != (value["bytesEqual"] is None)
            or (valid and value["lengthEqual"] is None)):
        return False
    for key in policy:
        if (valid and type(value[key]) is not bool) or (not valid and value[key] is not None):
            return False
    if value["bytesEqual"] is True:
        if value["lengthEqual"] is not True or value["savedShapeValid"] != value["observedShapeValid"]:
            return False
        if valid:
            for key in policy:
                if value[key] is not True:
                    return False
    if valid and value["controlEqual"] != (value["presenceEqual"] and value["protectedEqual"]
                                           and value["defaultedEqual"] and value["autoInheritanceEqual"]):
        return False
    return True


def _failure_diagnostic(case, nonce, stage, reason, fixture_state, reader_state, output_state, comparison=None):
    """Closed scalar reduction only; no exception rendering, IO or custody probe."""
    cases = ("ordinary-source", "ordinary-zip", "closed-gate", "link-children", "reparse-root",
             "reparse-ancestor", "short-alias", "case-alias", "case-collision", "subst-drive", "unc", "device", "ads",
             "root-reparse-race", "config-reparse-race", "walk-reparse-race", "case-mode-race", "acl-type",
             "read-eof-size", "entry-limit", "candidate-limit", "aggregate-limit", "depth-path-limit",
             "replace", "disappear", "config-disappear", "ending-metadata-case", "drive-map-change",
             "oplock-release", "oplock-withhold", "pending-failstop")
    if (type(case) is not str or case not in cases or type(nonce) is not str or len(nonce) != 64
            or type(stage) is not str or stage not in ("setup", "reader", "reduction", "restoration")):
        return None
    for character in nonce:
        if character not in "0123456789abcdef":
            return None
    # Ready; entered/wait/pinned clear; pending absent/completed; observer absent/joined.
    if type(fixture_state) is not tuple or len(fixture_state) != 8:
        return None
    for flag in fixture_state:
        if type(flag) is not bool:
            return None
    if (fixture_state[:4] != (True, True, True, True)
            or fixture_state[4:6] not in ((True, False), (False, True))
            or fixture_state[6:8] not in ((True, False), (False, True))):
        return None
    # An incremented instance count with no attached object is NOT clear custody.
    if (type(reader_state) is not tuple or len(reader_state) != 5
            or type(reader_state[0]) is not int or type(reader_state[1]) is not bool):
        return None
    if reader_state[1] is False:
        if (reader_state[0] != 0 or reader_state[2] is not None
                or reader_state[3] is not None or reader_state[4] is not None):
            return None
    elif (reader_state[0] != 1 or reader_state[2] is not True
            or reader_state[3] is not False or reader_state[4] is not True):
        return None
    if (type(output_state) is not tuple or len(output_state) != 3 or output_state[0] is not False
            or type(output_state[1]) is not int or not 0 <= output_state[1] < 4
            or type(output_state[2]) is not int or not 0 <= output_state[2] <= 64 * 1024):
        return None
    if type(reason) is not str or reason not in (
            "short_alias_bound", "real_short_alias_unavailable", "real_alias_required",
            "normalized_alias_veto_required", "fixture_native_unavailable",
            "short_alias_access_denied", "short_alias_sharing_violation", "short_alias_not_supported",
            "short_alias_invalid_parameter", "short_alias_name_collision", "short_alias_volume_disabled",
            "short_alias_privilege_unavailable", "short_alias_other_refused",
            "saved_dacl_bound", "saved_dacl_unsupported", "world_sid_bound", "fixture_dacl_denial_required", "fixture_dacl_not_effective",
            "dacl_restore_original_object", "saved_dacl_present", "dacl_restoration_not_confirmed",
            "fixture_restoration_bound", "fixture_retained_arena_bound", "fixture_arena_bound",
            "fixture_path_bound", "fixture_inherited_handle", "fixture_zero_file_id"):
        reason = "fixture_failure"
    detail = ""
    if comparison is not None:
        if ((case, stage, reason) != ("acl-type", "restoration", "dacl_restoration_not_confirmed")
                or not _dacl_comparison_valid(comparison)):
            return None
        detail = ',"comparison":{"role":"' + comparison["role"] + '"'
        for key in ("savedShapeValid", "observedShapeValid", "lengthEqual", "bytesEqual", "presenceEqual", "nullEqual",
                    "controlEqual", "protectedEqual", "defaultedEqual", "autoInheritanceEqual", "aclRevisionEqual", "orderedAcesEqual"):
            value = comparison[key]
            detail += ',"' + key + '":' + ("true" if value is True else "false" if value is False else "null")
        detail += "}"
    # Only fixed literals, hex nonce and already-computed closed scalar facts.
    raw = ('MRK_WINDOWS_SNAPSHOT_FAILURE_V1 {"schemaVersion":1,"scope":"windows-static-snapshot-native-v1","id":"'
           + case + '","nonce":"' + nonce + '","stage":"' + stage + '","code":"' + reason + '"' + detail + '}\n').encode("ascii")
    # A dispatch failure is followed by this unchanged genuine-engine line.
    # Reserve it even for setup failures, rather than creating an output overflow.
    engine_error = b"Mobile Release Kit desktop engine rejected the request or transport.\n"
    if len(raw) > 1024 or output_state[2] + len(raw) + len(engine_error) > 64 * 1024:
        return None
    return raw


def _reparse_witness_state(expected):
    """Three setup identities, initially with no exclusion evidence; no IO."""
    roles = {"linked-file/build.gradle": (False, 0xA000000C),
             "linked-dir": (True, 0xA000000C), "junction-dir": (True, 0xA0000003)}
    if type(expected) is not dict or set(expected) != set(roles):
        raise ValueError("reparse_setup_roster")
    identities = set()
    for role, value in expected.items():
        if type(value) is not tuple or len(value) != 3:
            raise ValueError("reparse_setup_shape")
        identity, directory, tag = value
        if (type(identity) is not tuple or len(identity) != 2
                or type(identity[0]) is not int or not 0 < identity[0] < 1 << 64
                or type(identity[1]) is not bytes or len(identity[1]) != 16 or not any(identity[1])
                or type(directory) is not bool or type(tag) is not int
                or (directory, tag) != roles[role] or identity in identities):
            raise ValueError("reparse_setup_identity_kind_tag")
        identities.add(identity)
    return {"expected": dict(expected), "entries": {}, "credited": set(), "invalid": set()}


def _reparse_witness_entry(state, relative, parent, name, file_id, directory, attributes, tag):
    """Reduce one decoded entry from its original parent, not a pathname probe."""
    expected = state["expected"].get(relative)
    if expected is None:
        return False
    identity, expected_directory, expected_tag = expected
    parent_valid = (type(parent) is tuple and len(parent) == 3
        and type(parent[0]) is int and 0 < parent[0] < (1 << 64) - 1
        and type(parent[1]) is int and parent[1] > 0
        and type(parent[2]) is tuple and len(parent[2]) == 2
        and type(parent[2][0]) is int and parent[2][0] == identity[0]
        and type(parent[2][1]) is bytes and len(parent[2][1]) == 16 and any(parent[2][1]))
    fields_valid = (name == relative.rsplit("/", 1)[-1]
        and type(file_id) is bytes and file_id == identity[1]
        and type(directory) is bool and directory is expected_directory
        and type(attributes) is int and 0 <= attributes < 1 << 32)
    advertised = fields_valid and bool(attributes & 0x400)
    tag_valid = (type(tag) is int and tag == expected_tag) if advertised else tag is None
    entry = (parent, name, file_id, directory, advertised, tag)
    previous = state["entries"].get(relative)
    if (relative in state["invalid"] or not parent_valid or not fields_valid or not tag_valid
            or (previous is not None and previous != entry)):
        # A later conflict cannot leave the older identity or credit usable.
        state["entries"].pop(relative, None)
        state["credited"].discard(relative)
        state["invalid"].add(relative)
        raise ValueError("reparse_entry_conflict")
    state["entries"][relative] = entry
    if advertised:
        state["credited"].add(relative)
    return advertised


def _reparse_witness_refusal(state, relative, name, directory, entered_parent, completed_parent,
                             owned, classified, status, category):
    """Credit only that unflagged candidate's classified original relative refusal.

    The failed open supplies no child handle/current tag. This is not a new
    identity observation or a continuous namespace/mutation guarantee.
    """
    if relative not in state["expected"]:
        return False
    entry = state["entries"].get(relative)
    if (relative in state["invalid"] or entry is None or entry[4] is not False
            or name != entry[1] or type(directory) is not bool or directory is not entry[3]
            or entered_parent != entry[0] or completed_parent != entered_parent
            or owned is not True or classified is not True
            or type(status) is not int or status != 0xC000050B or category != "unsafe"):
        state["entries"].pop(relative, None)
        state["credited"].discard(relative)
        state["invalid"].add(relative)
        raise ValueError("reparse_refusal_not_original")
    state["credited"].add(relative)
    return True


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in items:
        require(key not in result, "duplicate_json_field")
        result[key] = value
    return result


def strict(data: bytes, limit: int) -> dict | list:
    require(0 < len(data) <= limit, "json_bound")
    def nonfinite(_value: str):
        raise FixtureFailure("nonfinite_json")
    value = json.loads(data, object_pairs_hook=pairs, parse_constant=nonfinite)
    def visit(item: object, depth: int) -> None:
        require(depth <= 16, "json_depth")
        if isinstance(item, dict):
            for key, child in item.items():
                require(type(key) is str, "json_key")
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
        else:
            require(type(item) in (str, int, bool, type(None)), "json_scalar")
    visit(value, 0)
    require(type(value) in (dict, list), "json_container")
    return value


def ordinary_bytes(path: Path, limit: int, *, single_link: bool = True) -> bytes:
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and not getattr(before, "st_file_attributes", 0) & 0x400
            and (not single_link or before.st_nlink == 1) and 0 <= before.st_size <= limit, "ordinary_data_required")
    with path.open("rb") as stream:
        data = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    require(len(data) == before.st_size == after.st_size and before.st_ino == after.st_ino
            and before.st_mtime_ns == after.st_mtime_ns, "data_input_changed")
    return data


def ordinary_directory(path: Path) -> None:
    details = path.lstat()
    require(stat.S_ISDIR(details.st_mode) and not getattr(details, "st_file_attributes", 0) & 0x400,
            "ordinary_directory_required")


def payload_inventory(root: Path) -> tuple[list[dict], dict]:
    """Actual bounded, nonfollowing preparation inventory, including empty dirs."""
    files, count, total, maximum = [], 0, 0, 0
    pending = [root / name for name in ("project", "outside", "scratch")]
    while pending:
        path = pending.pop()
        relative = path.relative_to(root).as_posix()
        count += 1
        depth = len(relative.split("/")) - 1
        maximum = max(maximum, depth)
        require(count <= 12000 and maximum <= 14, "fixture_tree_bound")
        details = path.lstat()
        require(not stat.S_ISLNK(details.st_mode) and not getattr(details, "st_file_attributes", 0) & 0x400,
                "fixture_tree_not_ordinary")
        if stat.S_ISDIR(details.st_mode):
            with os.scandir(path) as entries:
                for entry in entries:
                    require(len(pending) + count < 12000, "fixture_tree_bound")
                    pending.append(Path(entry.path))
        else:
            data = ordinary_bytes(path, MAX_FILE)
            total += len(data)
            require(total <= MAX_PAYLOAD, "fixture_payload_bound")
            files.append({"path": relative, "sha256": digest(data), "size": len(data)})
    return sorted(files, key=lambda item: item["path"]), {"entries": count, "bytes": total, "maxDepth": maximum}


def source_inventory(core: Path) -> list[dict]:
    result, total, entries = [], 0, 0
    stack = [(core / "mobile_release", 0)]
    while stack:
        directory, depth = stack.pop()
        ordinary_directory(directory)
        require(depth <= 32, "core_depth")
        with os.scandir(directory) as scan:
            children = sorted(scan, key=lambda item: item.name)
        for item in children:
            entries += 1
            require(entries <= 8192, "core_entries")
            path = Path(item.path)
            details = item.stat(follow_symlinks=False)
            require(not item.is_symlink() and not getattr(details, "st_file_attributes", 0) & 0x400, "core_link")
            if stat.S_ISDIR(details.st_mode):
                stack.append((path, depth + 1))
            else:
                require(path.suffix in (".py", ".json", ".pem") and len(result) < 2048, "core_file_shape")
                data = ordinary_bytes(path, MAX_FILE)
                total += len(data)
                require(total <= MAX_PAYLOAD, "core_payload")
                result.append({"path": path.relative_to(core).as_posix(), "size": len(data), "sha256": digest(data)})
    return sorted(result, key=lambda item: item["path"])


def admit() -> tuple[dict, dict, Path, Path, dict]:
    require(sys.platform == "win32" and os.name == "nt" and len(sys.argv) == 2
            and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and sys.version.split()[0] == "3.14.7", "bootstrap_admission")
    bootstrap = Path(__file__)
    require(bootstrap.is_absolute() and bootstrap.name == "engine-bootstrap.py"
            and bootstrap.parent.name == "control", "bootstrap_layout")
    case_root = bootstrap.parent.parent
    group, case_id = case_root.parent.name, case_root.name
    require((group, case_id) in {(g, c) for g, cases in GROUPS for c in cases}
            and case_id != "closed-gate", "fixed_case_required")
    task = case_root.parent.parent.parent
    require(case_root.parent.parent.name == "windows-snapshot" and task.name.startswith("mrk-desktop-foundation-"), "task_layout")
    for path in (task, task / "windows-snapshot", case_root.parent, case_root, bootstrap.parent,
                 case_root / "project", case_root / "outside", case_root / "scratch"):
        ordinary_directory(path)
    descriptor = strict(ordinary_bytes(bootstrap.parent / "case.json", 4096), 4096)
    require(set(descriptor) == {"schemaVersion", "scope", "id", "group", "nonce", "coreMode", "bindingSha256", "dataManifestSha256"}
            and type(descriptor["schemaVersion"]) is int and descriptor["schemaVersion"] == 1 and descriptor["scope"] == SCOPE
            and descriptor["id"] == case_id and descriptor["group"] == group
            and descriptor["coreMode"] == ("zip" if case_id == "ordinary-zip" else "source")
            and type(descriptor["nonce"]) is str and re.fullmatch(r"[0-9a-f]{64}", descriptor["nonce"]) is not None, "descriptor_shape")
    inputs = strict(ordinary_bytes(task / "windows-snapshot-inputs.json", 1024 * 1024), 1024 * 1024)
    require(set(inputs) == {"schemaVersion", "scope", "bindings", "coreFiles", "sdkRoot"}
            and type(inputs["schemaVersion"]) is int and inputs["schemaVersion"] == 1 and inputs["scope"] == SCOPE, "input_shape")
    bindings = inputs["bindings"]
    require(type(bindings) is dict and set(bindings) == {"sourceSha", "sourceTree", "target", "pythonVersion", "rustVersion",
            "runId", "attempt", "job", "image", "architecture", "coreZipSha256", "coreInventorySha256", "sources",
            "pythonSha256", "compiledTestSha256", "compileInvocationSha256", "sdk"}
            and digest(canonical(bindings)) == descriptor["bindingSha256"]
            and bindings["target"] == "x86_64-pc-windows-msvc" and bindings["architecture"] == "X64"
            and bindings["pythonVersion"] == "3.14.7" and bindings["rustVersion"] == "1.98.0"
            and bindings["sdk"]["version"] == SDK_VERSION, "binding_shape")
    own = [item for item in bindings["sources"] if item["path"] == "tests/native_desktop_snapshot_windows.py"]
    copied = ordinary_bytes(bootstrap, 256 * 1024)
    require(len(own) == 1 and own[0]["size"] == len(copied) and own[0]["sha256"] == digest(copied), "compiled_bootstrap_changed")
    require(digest(ordinary_bytes(Path(sys.executable), 128 * 1024 * 1024, single_link=False)) == bindings["pythonSha256"], "python_changed")
    core = Path(sys.argv[1])
    require(core.is_absolute() and not core.is_relative_to(case_root), "core_layout")
    inventory = inputs["coreFiles"]
    require(type(inventory) is list and 0 < len(inventory) <= 2048
            and digest(canonical(inventory)) == bindings["coreInventorySha256"], "core_inventory_binding")
    require(all(type(item) is dict and set(item) == {"path", "sha256", "size"} for item in inventory), "core_inventory_shape")
    if descriptor["coreMode"] == "source":
        require(core.name == "src" and source_inventory(core) == inventory, "source_core_changed")
    else:
        require(core == task / "core.zip" and digest(ordinary_bytes(core, MAX_PAYLOAD)) == bindings["coreZipSha256"], "zip_binding")
        with zipfile.ZipFile(core) as archive:
            members = archive.infolist()
            require(len(members) == len(inventory) and len({member.filename for member in members}) == len(members), "zip_members")
            actual = []
            total = 0
            for member in members:
                require(not member.is_dir() and member.file_size <= MAX_FILE and not member.flag_bits & 1
                        and stat.S_ISREG(member.external_attr >> 16), "zip_member_shape")
                total += member.file_size
                require(total <= MAX_PAYLOAD, "zip_payload")
                data = archive.read(member)
                actual.append({"path": member.filename, "sha256": digest(data), "size": len(data)})
            require(sorted(actual, key=lambda item: item["path"]) == inventory, "zip_member_changed")
    data_bytes = ordinary_bytes(bootstrap.parent / "data.json", 2 * 1024 * 1024)
    require(digest(data_bytes) == descriptor["dataManifestSha256"], "fixture_manifest_binding")
    data_inventory = strict(data_bytes, 2 * 1024 * 1024)
    require(type(data_inventory) is list and len(data_inventory) <= 12000, "fixture_manifest_shape")
    previous = ""
    for item in data_inventory:
        require(type(item) is dict and set(item) == {"path", "sha256", "size"}, "fixture_entry_shape")
        relative = item["path"]
        require(type(relative) is str and relative > previous and relative.split("/")[0] in ("project", "outside", "scratch")
                and all(part not in ("", ".", "..") and ":" not in part and "\\" not in part for part in relative.split("/")), "fixture_entry_path")
        require(type(item["size"]) is int and 0 <= item["size"] <= MAX_FILE and type(item["sha256"]) is str
                and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None, "fixture_entry_shape")
        previous = relative
    actual, facts = payload_inventory(case_root)
    require(actual == data_inventory, "fixture_input_changed")
    facts["manifestSha256"] = digest(data_bytes)
    facts["after"] = None  # Filled only by the Rust owner after original settlement.
    return descriptor, inputs, case_root, core, facts


class FixtureNative:
    """Finite in-child fixture handles/arenas. Never an original-child owner."""
    def __init__(self, inputs: dict):
        import ctypes as c
        self.c = c
        self.lock = threading.RLock()
        self.entered = None
        self.wait_entered = None
        self.pinned = None
        self.pending_arena = None
        self.pending_complete = False
        self.retained_arenas = {}
        self.held = {}
        self.sequence = 0
        self.counts = {key: 0 for key in ("acquired", "closeAttempts", "closeSucceeded", "closeFailed", "live", "maxLive", "maxArenaBytes")}
        self.k = c.WinDLL("kernel32.dll", winmode=0x800, use_last_error=True)
        self.a = c.WinDLL("advapi32.dll", winmode=0x800, use_last_error=True)
        self.nt = c.WinDLL("ntdll.dll", winmode=0x800, use_last_error=True)
        U32, U16, HANDLE, BOOL, VOID, WCHAR = c.c_uint32, c.c_uint16, c.c_void_p, c.c_int32, c.c_void_p, c.c_wchar_p
        self.U32, self.U16, self.HANDLE = U32, U16, HANDLE
        require(tuple(c.sizeof(t) for t in (HANDLE, c.c_wchar, BOOL, U32, U16)) == (8, 2, 4, 4, 2), "fixture_scalar_abi")
        class Overlapped(c.Structure):
            _fields_ = [("Internal", c.c_uint64), ("InternalHigh", c.c_uint64),
                        ("Offset", U32), ("OffsetHigh", U32), ("hEvent", HANDLE)]
        class Id(c.Structure):
            _fields_ = [("VolumeSerialNumber", c.c_uint64), ("FileId", c.c_ubyte * 16)]
        class Tag(c.Structure):
            _fields_ = [("FileAttributes", U32), ("ReparseTag", U32)]
        class Basic(c.Structure):
            _fields_ = [("CreationTime", c.c_int64), ("LastAccessTime", c.c_int64),
                        ("LastWriteTime", c.c_int64), ("ChangeTime", c.c_int64), ("FileAttributes", U32)]
        class Standard(c.Structure):
            _fields_ = [("AllocationSize", c.c_int64), ("EndOfFile", c.c_int64), ("NumberOfLinks", U32),
                        ("DeletePending", c.c_ubyte), ("Directory", c.c_ubyte)]
        class Security(c.Structure):
            _fields_ = [("nLength", U32), ("lpSecurityDescriptor", VOID), ("bInheritHandle", BOOL)]
        self.Overlapped, self.Id, self.Tag, self.Basic, self.Standard = Overlapped, Id, Tag, Basic, Standard
        self.Security = Security
        layout = {"Overlapped": [c.sizeof(Overlapped), c.alignment(Overlapped), [getattr(Overlapped, x).offset for x, _ in Overlapped._fields_]],
                  "Id": [c.sizeof(Id), Id.FileId.offset], "Tag": [c.sizeof(Tag), Tag.ReparseTag.offset],
                  "Basic": [c.sizeof(Basic), Basic.LastWriteTime.offset, Basic.FileAttributes.offset],
                  "Standard": [c.sizeof(Standard), Standard.NumberOfLinks.offset, Standard.Directory.offset],
                  "Security": [c.sizeof(Security), c.alignment(Security),
                               [getattr(Security, x).offset for x, _ in Security._fields_]]}
        require(layout == {"Overlapped": [32, 8, [0, 8, 16, 20, 24]], "Id": [24, 8], "Tag": [8, 4],
                           "Basic": [40, 16, 32], "Standard": [24, 16, 21],
                           "Security": [24, 8, [0, 8, 16]]}, "fixture_structure_abi")
        kernel = {
            "GetCurrentProcess": ([], HANDLE), "IsWow64Process2": ([HANDLE, c.POINTER(U16), c.POINTER(U16)], BOOL),
            "CreateFileW": ([WCHAR, U32, U32, VOID, U32, U32, HANDLE], HANDLE),
            "CreateDirectoryW": ([WCHAR, VOID], BOOL),
            "CreateEventW": ([VOID, BOOL, BOOL, WCHAR], HANDLE), "CloseHandle": ([HANDLE], BOOL),
            "GetHandleInformation": ([HANDLE, c.POINTER(U32)], BOOL),
            "GetFileInformationByHandleEx": ([HANDLE, c.c_int32, VOID, U32], BOOL),
            "SetFileInformationByHandle": ([HANDLE, c.c_int32, VOID, U32], BOOL),
            "ReadFile": ([HANDLE, VOID, U32, c.POINTER(U32), VOID], BOOL),
            "WriteFile": ([HANDLE, VOID, U32, c.POINTER(U32), VOID], BOOL),
            "DeviceIoControl": ([HANDLE, U32, VOID, U32, VOID, U32, c.POINTER(U32), c.POINTER(Overlapped)], BOOL),
            "WaitForSingleObject": ([HANDLE, U32], U32),
            "GetOverlappedResult": ([HANDLE, c.POINTER(Overlapped), c.POINTER(U32), BOOL], BOOL),
            "CreateSymbolicLinkW": ([WCHAR, WCHAR, U32], c.c_ubyte),
            "CreateHardLinkW": ([WCHAR, WCHAR, VOID], BOOL),
            "GetShortPathNameW": ([WCHAR, c.POINTER(c.c_wchar), U32], U32),
            "SetFileShortNameW": ([HANDLE, WCHAR], BOOL),
            "QueryDosDeviceW": ([WCHAR, c.POINTER(c.c_wchar), U32], U32),
            "DefineDosDeviceW": ([U32, WCHAR, WCHAR], BOOL),
            "GetVolumeInformationByHandleW": ([HANDLE, c.POINTER(c.c_wchar), U32, c.POINTER(U32), c.POINTER(U32), c.POINTER(U32), c.POINTER(c.c_wchar), U32], BOOL),
            "GetSystemDirectoryW": ([c.POINTER(c.c_wchar), U32], U32),
            "GetModuleFileNameW": ([HANDLE, c.POINTER(c.c_wchar), U32], U32),
        }
        advapi = {
            "OpenProcessToken": ([HANDLE, U32, c.POINTER(HANDLE)], BOOL),
            "GetTokenInformation": ([HANDLE, U32, VOID, U32, c.POINTER(U32)], BOOL),
            "IsWellKnownSid": ([VOID, U32], BOOL),
            "GetKernelObjectSecurity": ([HANDLE, U32, VOID, U32, c.POINTER(U32)], BOOL),
        }
        for dll, signatures in ((self.k, kernel), (self.a, advapi)):
            for name, (args, result) in signatures.items():
                function = getattr(dll, name)
                function.argtypes, function.restype = args, result
        machine, native = U16(0xFFFF), U16(0xFFFF)
        process = self.k.GetCurrentProcess()
        self.call(self.k.IsWow64Process2, (process, c.byref(machine), c.byref(native)), (machine, native))
        require(machine.value == 0 and native.value == 0x8664, "fixture_native_amd64")
        system_buffer = c.create_unicode_buffer(8192)
        count = self.call(self.k.GetSystemDirectoryW, (system_buffer, 8192), (system_buffer,), kind="count")
        require(0 < count < 8192, "system_directory_bound")
        system_directory = Path(system_buffer.value)
        dlls = []
        for name, dll in (("kernel32.dll", self.k), ("ntdll.dll", self.nt), ("advapi32.dll", self.a)):
            buffer = c.create_unicode_buffer(8192)
            count = self.call(self.k.GetModuleFileNameW, (dll._handle, buffer, 8192), (buffer,), kind="count")
            require(0 < count < 8192 and Path(buffer.value).parent == system_directory
                    and Path(buffer.value).name.casefold() == name, "selected_system_dll")
            data = ordinary_bytes(Path(buffer.value), 64 * 1024 * 1024, single_link=False)
            dlls.append({"name": name, "sha256": digest(data), "size": len(data)})
        sdk = inputs["bindings"]["sdk"]
        sdk_root = Path(inputs["sdkRoot"])
        require(sdk_root.is_absolute() and sdk_root.name == SDK_VERSION and sdk_root.parent.name == "Include"
                and sdk_root.parent.parent.name == "10" and sdk_root.parent.parent.parent.name == "Windows Kits", "installed_sdk_layout")
        required_headers = {"shared/ntdef.h", "shared/ntstatus.h", "shared/winerror.h", "um/winternl.h", "um/winnt.h",
                            "um/minwinbase.h", "um/WinBase.h", "um/winioctl.h", "um/ioapiset.h", "um/fileapi.h",
                            "um/securitybaseapi.h", "um/aclapi.h"}
        require(set(sdk) == {"version", "headers"} and {item["path"] for item in sdk["headers"]} == required_headers
                and len(sdk["headers"]) == len(required_headers), "installed_sdk_header_roster")
        for item in sdk["headers"]:
            require(set(item) == {"path", "size", "sha256"}, "sdk_header_shape")
            data = ordinary_bytes(sdk_root / item["path"], MAX_FILE, single_link=False)
            require(len(data) == item["size"] and digest(data) == item["sha256"], "installed_sdk_changed")
        import _ctypes
        self.profile = {"pointerBytes": 8, "processMachine": machine.value, "nativeMachine": native.value,
                        "filesystem": None, "pythonSha256": inputs["bindings"]["pythonSha256"],
                        "ctypesSha256": digest(ordinary_bytes(Path(_ctypes.__file__), 64 * 1024 * 1024, single_link=False)),
                        "dlls": dlls, "layoutSha256": digest(canonical(layout)), "sdkSha256": digest(canonical(sdk))}

    def abort(self, arena: object) -> None:
        self.pinned = (self, arena, self.entered, self.wait_entered, self.pending_arena)
        os._exit(70)  # Never unwind unknown buffers, retry a handle, or spawn cleanup.

    def register(self, handle: int) -> None:
        require(type(handle) is int and 0 < handle < INVALID and handle not in self.held
                and len(self.held) < 32, "fixture_handle_registration")
        self.sequence += 1
        self.held[handle] = self.sequence
        self.counts["acquired"] += 1
        self.counts["live"] = len(self.held)
        self.counts["maxLive"] = max(self.counts["maxLive"], len(self.held))

    def arena_bytes(self, extra: tuple = ()) -> None:
        buffers = {}
        for items in (*self.retained_arenas.values(), extra):
            for item in items:
                try:
                    buffers[id(item)] = self.c.sizeof(item)
                except (TypeError, ValueError):
                    pass
        amount = sum(buffers.values())
        require(amount <= 128 * 1024, "fixture_arena_bound")
        self.counts["maxArenaBytes"] = max(self.counts["maxArenaBytes"], amount)

    def retain(self, label: str, items: tuple) -> None:
        require(label not in self.retained_arenas and len(self.retained_arenas) < 16, "fixture_retained_arena_bound")
        self.retained_arenas[label] = items
        self.arena_bytes()

    def call(self, function, arguments: tuple, keep: tuple = (), *, kind: str = "boolean", output_handle=None):
        with self.lock:
            if self.entered is not None:
                self.abort(self.entered)
            self.arena_bytes(keep)
            arena = (self, function, arguments, keep, tuple(self.held), output_handle)
            self.entered = arena
            try:
                value = function(*arguments)
                error = self.c.get_last_error()
                require(type(value) in (int, type(None)), "fixture_native_return_type")
                bad = ((not value) if kind in ("boolean", "count") else
                       value in (None, 0, INVALID) if kind == "handle" else value != 0 if kind == "zero" else False)
                if bad:
                    code = value if kind == "zero" else error
                    if code == 997:
                        self.abort(arena)
                    self.entered = None
                    raise NativeFailure(function.__name__, code)
                if kind == "handle":
                    self.register(value)
                if output_handle is not None:
                    self.register(output_handle.value)
                self.entered = None
                return value
            except BaseException:
                if self.entered is not None:
                    self.abort(arena)
                raise

    def open(self, path: Path | str, access: int = READ_ATTRIBUTES, *, flags: int = BACKUP | NOFOLLOW,
             creation: int = 3, sharing: int = 7, security=None) -> int:
        require(len(str(path).encode("utf-16-le")) <= 8192 * 2, "fixture_path_bound")
        attributes = self.c.byref(security) if security is not None else None
        handle = self.call(self.k.CreateFileW, (str(path), access, sharing, attributes, creation, flags, None),
                           (security,), kind="handle")
        flags_value = self.U32(0xFFFFFFFF)
        self.call(self.k.GetHandleInformation, (handle, self.c.byref(flags_value)), (flags_value,))
        require(not flags_value.value & 1, "fixture_inherited_handle")
        return handle

    def absent(self, path: Path) -> None:
        ordinary_directory(path.parent)  # A missing parent is not leaf absence.
        try:
            self.open(path)
        except NativeFailure as error:
            require(error.api == "CreateFileW" and error.code == 2, "fixture_leaf_absence_required")
        else:
            raise FixtureFailure("fixture_leaf_absence_required")  # Retain any unexpected occupant handle.

    def close(self, handle: int) -> None:
        with self.lock:
            require(handle in self.held, "fixture_close_not_owned")
            self.held.pop(handle)  # Retire BEFORE the sole actual close attempt.
            self.counts["live"] = len(self.held)
            self.counts["closeAttempts"] += 1
            try:
                self.call(self.k.CloseHandle, (handle,))
            except BaseException:
                self.counts["closeFailed"] += 1
                self.abort((self, handle))
            self.counts["closeSucceeded"] += 1

    def info(self, handle: int, information_class: int, cls):
        value = cls()
        self.call(self.k.GetFileInformationByHandleEx,
                  (handle, information_class, self.c.byref(value), self.c.sizeof(value)), (value,))
        return value

    def identity(self, handle: int) -> tuple[int, bytes]:
        # May borrow an ALREADY REGISTERED original reader handle; never reopen.
        value = self.info(handle, 18, self.Id)
        require(any(value.FileId), "fixture_zero_file_id")
        return value.VolumeSerialNumber, bytes(value.FileId)

    def path_identity(self, path: Path, *, follow: bool = False) -> tuple[int, bytes]:
        handle = self.open(path, flags=BACKUP | (0 if follow else NOFOLLOW))
        result = self.identity(handle)
        self.close(handle)
        return result

    def short_name(self, path: Path) -> str:
        buffer = self.c.create_unicode_buffer(8192)
        count = self.call(self.k.GetShortPathNameW, (str(path), buffer, 8192), (buffer,), kind="count")
        require(0 < count < 8192, "short_alias_bound")
        return Path(buffer.value).name

    def read_control(self, path: Path, expected: bytes, *, follow: bool = False) -> tuple[int, bytes]:
        handle = self.open(path, 0x100081, flags=BACKUP | (0 if follow else NOFOLLOW))
        identity = self.identity(handle)
        buffer, consumed = self.c.create_string_buffer(len(expected) + 1), self.U32(0xFFFFFFFF)
        self.call(self.k.ReadFile, (handle, buffer, len(expected) + 1, self.c.byref(consumed), None), (buffer, consumed))
        require(consumed.value == len(expected) and bytes(buffer.raw[:consumed.value]) == expected, "fixture_control_bytes")
        final, zero = self.c.create_string_buffer(1), self.U32(0xFFFFFFFF)
        self.call(self.k.ReadFile, (handle, final, 1, self.c.byref(zero), None), (final, zero))
        require(zero.value == 0, "fixture_control_eof")
        self.close(handle)
        return identity

    def file_write(self, path: Path, data: bytes, *, case_sensitive: bool = False) -> tuple[int, bytes]:
        require(len(data) <= 64 * 1024, "fixture_write_bound")
        handle = self.open(path, 0x82, creation=1, flags=NOFOLLOW | (0x01000000 if case_sensitive else 0))
        buffer, written = self.c.create_string_buffer(data), self.U32(0xFFFFFFFF)
        self.call(self.k.WriteFile, (handle, buffer, len(data), self.c.byref(written), None), (buffer, written))
        require(written.value == len(data), "fixture_write_short")
        result = self.identity(handle)
        self.close(handle)
        return result

    def delete(self, path: Path, expected_id: tuple[int, bytes] | None = None, *, case_sensitive: bool = False) -> None:
        handle = self.open(path, DELETE | READ_ATTRIBUTES, flags=BACKUP | NOFOLLOW | (0x01000000 if case_sensitive else 0))
        if expected_id is not None:
            require(self.identity(handle) == expected_id, "fixture_delete_identity")
        flag = self.c.c_int32(1)
        self.call(self.k.SetFileInformationByHandle, (handle, 4, self.c.byref(flag), self.c.sizeof(flag)), (flag,))
        self.close(handle)

    def device(self, handle: int, code: int, data: bytes) -> None:
        require(len(data) <= 16 * 1024, "fixture_reparse_buffer")
        buffer, returned = self.c.create_string_buffer(data, len(data)), self.U32(0xFFFFFFFF)
        self.call(self.k.DeviceIoControl, (handle, code, buffer, len(data), None, 0, self.c.byref(returned), None), (buffer, returned))

    def set_junction(self, handle: int, target: Path) -> None:
        spelling = str(target)
        if spelling.startswith("\\\\?\\"):
            spelling = spelling[4:]
        require(re.match(r"^[A-Za-z]:\\", spelling) is not None, "junction_target")
        substitute, display = ("\\??\\" + spelling).encode("utf-16-le"), spelling.encode("utf-16-le")
        names = substitute + b"\0\0" + display + b"\0\0"
        body = struct.pack("<HHHH", 0, len(substitute), len(substitute) + 2, len(display)) + names
        self.device(handle, SET_REPARSE, struct.pack("<IHH", MOUNT_TAG, len(body), 0) + body)

    def clear_junction(self, handle: int) -> None:
        self.device(handle, DELETE_REPARSE, struct.pack("<IHH", MOUNT_TAG, 0, 0))

    def set_case(self, handle: int, flags: int) -> None:
        value = self.U32(flags)
        self.call(self.k.SetFileInformationByHandle, (handle, 23, self.c.byref(value), self.c.sizeof(value)), (value,))

    def query_mapping(self, letter: str) -> str | None:
        buffer = self.c.create_unicode_buffer(4096)
        try:
            count = self.call(self.k.QueryDosDeviceW, (letter, buffer, 4096), (buffer,), kind="count")
        except NativeFailure as error:
            if error.code == 2:
                return None
            raise
        require(2 <= count <= 4096, "fixture_mapping_bound")
        raw = self.c.string_at(self.c.addressof(buffer), count * 2).decode("utf-16-le")
        require(raw.endswith("\0\0"), "fixture_mapping_shape")
        return raw.split("\0")[0]

    def local_non_system(self) -> None:
        token = self.HANDLE()
        self.call(self.a.OpenProcessToken, (self.k.GetCurrentProcess(), 8, self.c.byref(token)), (token,), output_handle=token)
        buffer, needed = self.c.create_string_buffer(1024), self.U32()
        self.call(self.a.GetTokenInformation, (token.value, 1, buffer, 1024, self.c.byref(needed)), (buffer, needed))
        require(8 < needed.value <= 1024, "fixture_token_bound")
        sid = self.c.c_void_p.from_buffer(buffer).value
        require(sid is not None and self.c.addressof(buffer) <= sid < self.c.addressof(buffer) + needed.value, "fixture_token_sid")
        # IsWellKnownSid returns a classification, not BOOL IO completion.
        local_system = self.call(self.a.IsWellKnownSid, (sid, 22), (buffer,), kind="scalar")
        require(local_system == 0, "local_dos_mapping_scope_required")
        self.close(token.value)

    def grant_oplock(self, holder: int, event: int, overlapped, returned) -> None:
        require(self.pending_arena is None and holder in self.held and event in self.held, "one_pending_fixture_request")
        arena = (self, holder, event, overlapped, returned, self.k.DeviceIoControl)
        self.pending_arena = arena  # Before genuine kernel entry, retained until completion/exit.
        self.entered = arena
        try:
            value = self.k.DeviceIoControl(holder, BATCH_OPLOCK, None, 0, None, 0, self.c.byref(returned), self.c.byref(overlapped))
            error = self.c.get_last_error()
            if value == 0 and error == 997:
                self.entered = None
                return
            self.pending_complete = True  # A known nonpending return; not a granted oplock.
            self.entered = None
            raise FixtureFailure("batch_oplock_not_pending")
        except BaseException:
            if self.entered is not None:
                self.abort(arena)
            raise

    def wait_oplock_event(self, event: int) -> None:
        # This one fixed scalar wait must NOT hold the native-call lock: the
        # original reader needs independent metadata observations before it can
        # reach the held file. The event and pending arena remain original and
        # cannot be closed until completion plus this thread's actual join.
        require(event in self.held and self.wait_entered is None and self.pending_arena is not None,
                "fixture_event_wait_ownership")
        arena = (self, event, self.k.WaitForSingleObject, self.pending_arena)
        self.wait_entered = arena
        try:
            outcome = self.k.WaitForSingleObject(event, 3000)
            if type(outcome) is not int or outcome not in (0, 258):
                self.abort(arena)
            self.wait_entered = None
            if outcome != 0:
                self.abort(arena)  # Pending IO remains; a timeout cannot unwind it.
        except BaseException:
            self.abort(arena)

    def close_all(self) -> None:
        if self.entered is not None or self.wait_entered is not None or (self.pending_arena is not None and not self.pending_complete):
            self.abort(self.entered or self.wait_entered or self.pending_arena)
        for handle in tuple(reversed(self.held)):
            self.close(handle)


class ReaderTrace:
    """Bounded observations of genuine classified calls, never replacement IO."""
    def __init__(self, fixture):
        self.fixture = fixture
        self.counts = dict.fromkeys(READER_COUNTS, 0)
        self.calls = {name: {"api": name, "entered": 0, "returned": 0, "completed": 0, "errors": 0} for name in READER_APIS}
        self.handles = {}
        self.generation = 0
        self.hash = hashlib.sha256()
        self.lock = threading.RLock()
        self.instances = 0
        self.inventory = None
        self.native = None
        self.entries = {}
        self.entry_kinds = {}
        self.reads = {}
        self.config_opened = False
        self.opened_candidates = 0
        self.outside_bytes = 0
        self.over_budget_batch = False
        self.after_over_budget_opens = 0
        self.largest_request = self.largest_return = 0

    def event(self, event: str, *facts) -> None:
        with self.lock:
            self.counts["eventCount"] += 1
            require(self.counts["eventCount"] <= 1000000, "reader_trace_bound")
            self.hash.update(canonical([event, *facts]))
            self.hash.update(b"\n")

    def role(self, path: str) -> str:
        prefix = self.fixture.project_nt + "\\"
        return path[len(prefix):].replace("\\", "/") if path.startswith(prefix) else "@ancestor"

    def selected_read(self, path: str) -> str:
        relative = self.role(path)
        if self.fixture.case == "read-eof-size":
            first = relative.split("/", 1)[0]
            if first in ("empty", "invalid", "multi", "exact", "oversize"):
                return first
        if self.fixture.case == "aggregate-limit" and re.fullmatch(r"budget[0-9]{2}/build.gradle", relative):
            return relative
        if relative in ("android/app/build.gradle", "release/mobile-release.json", "oplock/build.gradle",
                        "hardlinked/build.gradle", "sibling/build.gradle", "extra/build.gradle"):
            return relative
        return "other"

    def snapshot(self, state: str = "complete") -> dict:
        with self.lock:
            return {"state": state, "calls": [dict(self.calls[name]) for name in READER_APIS], **self.counts,
                    "eventSha256": self.hash.hexdigest(),
                    "closeDisposition": "returned-once" if state == "complete" else "not-observed-after-abnormal-exit"}

    def attach(self, windows, native_api, inventory):
        require(self.instances == 0, "one_real_reader_required")
        self.instances += 1
        self.inventory = inventory
        trace, fixture = self, self.fixture
        Base = native_api.Native

        class ObservedNative(Base):
            def _invoke(self, function, arguments, keep=(), *, completion="scalar"):
                api = function.__name__
                require(api in trace.calls, "reader_api_roster")
                observed = trace.calls[api]
                raw = []
                spec = keep[0] if completion == "open" else None
                entered_parent, entered_relative = None, "@root"
                def entered(*actual):
                    nonlocal entered_parent, entered_relative
                    # The original _invoke already owns self/_b/arguments/keep
                    # and original parents here. No pre-open metadata veto.
                    require(time.monotonic() < inventory.deadline, "real_entry_after_reader_deadline")
                    observed["entered"] += 1
                    if completion == "directory":
                        record = trace.handles[actual[0]]
                        trace.counts["directoryCalls"] += 1
                        if record["id"] in fixture.outside_ids:
                            trace.counts["outsideDescent"] += 1
                        if trace.role(record["path"]) == "collision":
                            fixture.collision_batches += 1
                    if api == "ReadFile":
                        record = trace.handles[actual[0]]
                        stats = trace.reads[trace.selected_read(record["path"])]
                        stats["calls"] += 1
                        trace.counts["readCalls"] += 1
                        trace.largest_request = max(trace.largest_request, actual[2])
                        if record["id"] in fixture.outside_ids:
                            trace.counts["outsideReads"] += 1
                        if fixture.case in ("short-alias", "case-alias") and record["id"] == fixture.alias_object_id:
                            fixture.alias_read_calls += 1
                    if spec is not None:
                        require(spec.attributes == 0x1000 and spec.sharing == 1 and spec.disposition == 1
                                and spec.access == (0x1000A1 if spec.directory else 0x100081)
                                and spec.options == (0x21 if spec.directory else 0x60), "original_open_flags_changed")
                        if spec.parent is None:
                            trace.counts["rootOpens"] += 1
                        else:
                            require(spec.parent in self._owned and spec.parent in trace.handles
                                    and native_api.valid_component(spec.name), "original_relative_parent_missing")
                            trace.counts["relativeOpens"] += 1
                            if fixture.reparse_witnesses is not None:
                                parent = trace.handles[spec.parent]
                                entered_parent = (spec.parent, parent["generation"], parent["id"])
                                entered_relative = trace.role(parent["path"].rstrip("\\") + "\\" + spec.name)
                        if trace.over_budget_batch:
                            trace.after_over_budget_opens += 1
                        fixture.real_entry(self, spec)
                    if api == "DeviceIoControl" and fixture.case == "pending-failstop":
                        require(self._entered is not None and fixture.seam_done and spec is None,
                                "pending_original_classifier_entry")
                        fixture.checks["realFsctlEntry"] = True
                        # Last pre-entry action; in particular NO later budget
                        # exception can impersonate the pending classifier exit.
                        fixture.emit("pending-entry", prefix=True)
                    value = function(*actual)
                    # Only scalar return/status bookkeeping. Do not inspect an
                    # unclassified output arena or emit after pending/unknown IO.
                    raw.extend((value, self._b.c.get_last_error()))
                    observed["returned"] += 1
                    return value
                entered.__name__ = api
                try:
                    result = super()._invoke(entered, arguments, keep, completion=completion)
                except native_api.NativeError as error:
                    if raw:
                        observed["completed"] += 1
                        observed["errors"] += 1
                        if spec is not None:
                            status = raw[0] & 0xFFFFFFFF
                            fixture.completed_open_error(spec, status, error.category)
                            if fixture.reparse_witnesses is not None:
                                # Only this post-classification callback can
                                # credit a refusal; no parent/child is reopened.
                                parent = trace.handles.get(spec.parent)
                                completed_parent = (None if parent is None else
                                    (spec.parent, parent["generation"], parent["id"]))
                                _reparse_witness_refusal(fixture.reparse_witnesses, entered_relative,
                                    spec.name, spec.directory, entered_parent, completed_parent,
                                    spec.parent in self._owned,
                                    completion == "open" and api == "NtCreateFile" and self._entered is None
                                    and not self._poisoned and self._pinned is None,
                                    status, error.category)
                    trace.event("completed-error", api, error.category)
                    raise
                if raw:
                    observed["completed"] += 1
                    if completion == "directory" and not raw[0]:
                        observed["errors"] += 1  # Real ERROR_NO_MORE_FILES, not a zero-byte invented EOF.
                trace.event("completed", api)
                for item in keep:
                    try:
                        size = self._b.c.sizeof(item)
                    except (TypeError, ValueError):
                        continue
                    trace.counts["maxBufferBytes"] = max(trace.counts["maxBufferBytes"], size)
                if spec is not None:
                    require(result in self._owned and self._entered is None, "original_open_not_registered")
                    path = spec.name if spec.parent is None else trace.handles[spec.parent]["path"].rstrip("\\") + "\\" + spec.name
                    trace.generation += 1
                    trace.handles[result] = {"generation": trace.generation, "path": path, "id": None,
                                             "directory": spec.directory, "metadata": None, "aliasCounted": False}
                    trace.counts["acquired"] += 1
                    trace.counts["live"] = len(trace.handles)
                    trace.counts["maxLive"] = max(trace.counts["maxLive"], len(trace.handles))
                    require(len(trace.handles) <= 144, "reader_live_bound")
                    # Record the registered slot first: a known observation
                    # failure must not prevent the original owner's sole close.
                    identity = fixture.native.identity(result)
                    trace.handles[result]["id"] = identity
                    relative = trace.role(path)
                    # Configuration requested a FILE. The later ordinary walk
                    # may legitimately inspect that same spelling as a directory.
                    trace.config_opened |= not spec.directory and relative == "release/mobile-release.json"
                    if fixture.case == "candidate-limit" and re.fullmatch(r"candidate[0-9]{3}/build.gradle", relative):
                        trace.opened_candidates += 1
                    if identity in fixture.outside_ids:
                        trace.counts["outsideAcquired"] += 1
                    if fixture.mapping_changed:
                        fixture.later_project_opens += 1
                    if any(ord(c) > 127 for c in spec.name):
                        fixture.unicode_opens += 1
                    fixture.completed_open(spec, path, identity)
                    trace.event("registered", trace.generation, digest(identity[1]), identity[0], spec.directory)
                return result

            def open_child(self, parent, name, directory):
                fixture.before_open(self, parent, name, directory)
                return super().open_child(parent, name, directory)

            def metadata(self, handle):
                result = super().metadata(handle)
                record = trace.handles[handle]
                trace.counts["metadataChecks"] += 1
                if record["id"] == (result.volume, result.file_id):
                    trace.counts["identitiesMatched"] += 1
                else:
                    trace.counts["violations"] += 1
                record["metadata"] = result
                if record["id"] in fixture.outside_ids and fixture.case == "link-children" and not record["aliasCounted"]:
                    if trace.role(record["path"]) == "hardlinked/build.gradle" and not result.directory and result.links >= 2:
                        trace.counts["aliasMetadataAcquired"] += 1
                        record["aliasCounted"] = True
                fixture.observed_metadata(record, result)
                return result

            def directory_batch(self, handle, restart):
                record = trace.handles[handle]
                result = super().directory_batch(handle, restart)
                if result is None:
                    trace.counts["directoryEof"] += 1
                else:
                    entries = native_api.decode_directory_batch(result)
                    trace.counts["directoryRecords"] += len(entries)
                    if len(entries) > 10000 - inventory.counts["entries"]:
                        trace.over_budget_batch = True
                    for entry in entries:
                        path = record["path"].rstrip("\\") + "\\" + entry.name
                        relative = trace.role(path)
                        if relative in fixture.observed_entry_paths:
                            require(len(trace.entries) < 64 or path in trace.entries, "selected_entry_bound")
                            trace.entries[path] = entry.file_id
                            trace.entry_kinds[path] = entry.directory
                        if fixture.reparse_witnesses is not None:
                            _reparse_witness_entry(fixture.reparse_witnesses, relative,
                                (handle, record["generation"], record["id"]), entry.name,
                                entry.file_id, entry.directory, entry.attributes, entry.reparse_tag)
                fixture.after_directory(self, handle, result)
                return result

            def read(self, handle, count):
                record = trace.handles[handle]
                role = trace.selected_read(record["path"])
                stats = trace.reads.setdefault(role, {"calls": 0, "bytes": 0, "eof": 0, "short": 0})
                require(len(trace.reads) <= 32, "selected_read_witness_bound")
                result = super().read(handle, count)
                if record["id"] in fixture.outside_ids:
                    trace.outside_bytes += len(result)
                if fixture.case in ("short-alias", "case-alias") and record["id"] == fixture.alias_object_id:
                    fixture.alias_reads += len(result)
                stats["bytes"] += len(result)
                stats["eof"] += not result
                stats["short"] += bool(result) and len(result) < count
                trace.counts["readBytes"] += len(result)
                trace.counts["readEof"] += not result
                trace.largest_return = max(trace.largest_return, len(result))
                require(len(result) <= count <= 65536 and trace.counts["readBytes"] <= 8 * 1024 * 1024, "reader_byte_bound")
                fixture.after_read(self, handle, result)
                return result

            def normalized_name(self, handle):
                result = super().normalized_name(handle)
                record = trace.handles[handle]
                if fixture.case in ("short-alias", "case-alias") and record["id"] == fixture.alias_object_id:
                    fixture.alias_name_veto = result != record["path"]
                return result

            def drive_mapping(self, drive):
                fixture.before_mapping(self, drive)
                return super().drive_mapping(drive)

            def _raw_close(self, handle):
                observed = trace.calls["CloseHandle"]
                record = trace.handles.pop(handle)
                trace.counts["live"] = len(trace.handles)
                trace.counts["closeAttempts"] += 1
                observed["entered"] += 1
                try:
                    result = super()._raw_close(handle)
                except BaseException:
                    trace.counts["closeFailed"] += 1
                    raise
                observed["returned"] += 1
                observed["completed"] += 1
                observed["errors"] += not result
                trace.counts["closeSucceeded" if result else "closeFailed"] += 1
                trace.event("closed", record["generation"], result)
                return result

        self.native = ObservedNative(lambda: windows._tick(inventory))
        return self.native


class Fixture:
    def __init__(self, descriptor: dict, inputs: dict, root: Path, data: dict):
        self.descriptor, self.inputs, self.root, self.data = descriptor, inputs, root, data
        self.case = descriptor["id"]
        self.project, self.outside, self.scratch = root / "project", root / "outside", root / "scratch"
        self.native = FixtureNative(inputs)
        self.trace = ReaderTrace(self)
        self.checks = dict.fromkeys(CHECKS[self.case])
        self.journal = []
        self.dacl_comparison = None
        self.restored = False
        self.outside_ids = set()
        self.observed_entry_paths = {"android/app/build.gradle", "release/mobile-release.json", "walk-parent/build.gradle"}
        self.unicode_opens = 0
        self.reparse_witnesses = None
        self.collision_batches = 0
        self.mapping_changed = False
        self.mapping_queries = 0
        self.later_project_opens = 0
        self.alias = None
        self.alias_target = None
        self.alias_acquired = 0
        self.alias_reads = 0
        self.alias_read_calls = 0
        self.alias_name_veto = False
        self.reader_entered = False
        self.reader_returned = False
        self.seam_done = False
        self.file_ending_done = self.directory_ending_done = False
        self.thread = None
        self.thread_joined = False
        self.event = self.holder = None
        self.overlapped = self.returned = None
        self.emitted_bytes = 0
        self.emitted = 0
        self.emission_lock = threading.Lock()
        spelling = str(self.project)
        if spelling.startswith("\\\\?\\"):
            spelling = spelling[4:]
        require(re.match(r"^[A-Za-z]:\\", spelling) is not None, "ordinary_project_drive")
        self.drive = spelling[:2].upper()
        self.device = self.native.query_mapping(self.drive)
        require(type(self.device) is str and re.fullmatch(r"\\Device\\HarddiskVolume[0-9]{1,10}", self.device) is not None,
                "ordinary_local_volume_required")
        self.project_nt = self.device + spelling[2:]
        self.project_id = self.native.path_identity(self.project)
        volume = self.native.open(self.project)
        name = self.native.c.create_unicode_buffer(261)
        self.native.call(self.native.k.GetVolumeInformationByHandleW, (volume, None, 0, None, None, None, name, 261), (name,))
        require(name.value == "NTFS", "ordinary_ntfs_required")
        self.native.profile["filesystem"] = name.value
        self.native.close(volume)
        self.request_root = str(self.project)
        if self.request_root.startswith("\\\\?\\"):
            self.request_root = self.request_root[4:]
        if self.case == "ordinary-zip":
            self.request_root = "\\\\?\\" + self.request_root
        self.request_config = "release/mobile-release.json"
        self.input_root = spelling
        # Outside canaries are task-owned, finite and still ordinary at setup.
        # Their complete IDs let observations distinguish metadata-only in-tree
        # hardlinks from any actual outside acquisition/descent in W3.
        stack = [self.outside]
        seen = 0
        while stack:
            path = stack.pop()
            seen += 1
            require(seen <= 128, "outside_fixture_bound")
            self.outside_ids.add(self.native.path_identity(path))
            details = path.lstat()
            if stat.S_ISDIR(details.st_mode):
                with os.scandir(path) as entries:
                    children = list(entries)
                for entry in children:
                    require(not entry.is_symlink() and not getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0) & 0x400,
                            "outside_fixture_link")
                    stack.append(Path(entry.path))
        # A failed constructor never publishes a diagnostically usable fixture.
        self.diagnostic_ready = True
        self.diagnostic_attempted = False

    def diagnose_failure(self, stage: str, error: BaseException) -> None:
        """One best-effort write from retained scalar facts; never a close receipt."""
        try:
            attempted = self.diagnostic_attempted
            self.diagnostic_attempted = True  # Latch even silence/serialization/write failure.
            if attempted is not False or self.diagnostic_ready is not True:
                return
            n, trace = self.native, self.trace
            # No lock, snapshot, constructor, join or probe may make these clear.
            if (n.entered is not None or n.wait_entered is not None or n.pinned is not None
                    or (n.pending_arena is not None and n.pending_complete is not True)
                    or (self.thread is not None and self.thread_joined is not True)):
                return
            reader = trace.native
            if reader is None:
                if type(trace.instances) is not int or trace.instances != 0:
                    return
                reader_state = (trace.instances, False, None, None, None)
            else:
                if (type(trace.instances) is not int or trace.instances != 1 or reader._entered is not None
                        or reader._poisoned is not False or reader._pinned is not None):
                    return
                reader_state = (trace.instances, True, True, reader._poisoned, True)
            fixture_state = (self.diagnostic_ready, n.entered is None, n.wait_entered is None, n.pinned is None,
                             n.pending_arena is None, n.pending_complete, self.thread is None, self.thread_joined)
            reason = None
            if type(error) is NativeFailure:
                reason = "fixture_native_unavailable"
                if self.case == "short-alias" and stage in ("setup", "restoration"):
                    reason = _short_alias_error_reason(error.api, error.code)
                    if reason is None:
                        return  # Pending/invalid native state has no diagnostic permission.
            elif type(error) is FixtureFailure:
                arguments = error.args
                if type(arguments) is tuple and len(arguments) == 1:
                    reason = arguments[0]
            raw = _failure_diagnostic(self.case, self.descriptor["nonce"], stage, reason,
                                      fixture_state, reader_state, (attempted, self.emitted, self.emitted_bytes), self.dacl_comparison)
            if raw is None:
                return
            self.emitted += 1
            self.emitted_bytes += len(raw)  # Reserve the existing allowance before the sole attempt.
            os.write(2, raw)  # No retry, even on a partial write. Original failure/status wins.
        except BaseException:
            return

    def emit(self, phase: str, *, prefix: bool = False) -> None:
        # Only a known-complete checkpoint or a PRE-entry witness. Never call
        # this after the production pending/unknown classifier has been entered.
        with self.emission_lock:
            self.emitted += 1
            require(self.emitted <= 4, "fixture_checkpoint_bound")
            message = {"schemaVersion": 1, "scope": SCOPE, "id": self.case, "nonce": self.descriptor["nonce"],
                       "phase": phase, "reader": self.trace.snapshot("prefix" if prefix else "complete"),
                       "fixture": self.evidence("prefix" if prefix else "complete")}
            raw = b"MRK_WINDOWS_SNAPSHOT_V1 " + canonical(message) + b"\n"
            self.emitted_bytes += len(raw)
            require(self.emitted_bytes <= 64 * 1024, "fixture_stderr_bound")
            offset = 0
            while offset < len(raw):
                count = os.write(2, raw[offset:])
                require(count > 0, "fixture_stderr_write")
                offset += count

    def evidence(self, state: str) -> dict:
        pending = ("none" if self.native.pending_arena is None else
                   "completed" if self.native.pending_complete else "retained")
        thread = "none" if self.thread is None else "joined" if self.thread_joined else "not-observed"
        event = "none" if self.event is None else "retained" if self.event in self.native.held else "closed"
        return {"state": state, **self.native.counts, "pending": pending, "thread": thread, "event": event,
                "restored": self.restored if state == "complete" else None,
                "resourcesSettledBy": "returned-closes", "data": self.data,
                "profile": self.native.profile, "checks": dict(self.checks)}

    def held_mutation(self, path: Path, kind: str) -> dict:
        require(len(self.journal) < 16, "fixture_restoration_bound")
        writer = self.native.open(path, WRITE_ATTRIBUTES)
        metadata = self.native.open(path, READ_ATTRIBUTES)
        identity = self.native.identity(metadata)
        # The writer has ONLY FILE_WRITE_ATTRIBUTES. Do not widen its rights or
        # rely on an undocumented ID query on it. The retained metadata object's
        # unchanged ID and observed tag/case transition bind the mutation below.
        record = {"kind": kind, "path": path, "writer": writer, "metadata": metadata, "id": identity, "changed": False}
        self.journal.append(record)
        return record

    def short_alias(self, path: Path) -> str:
        """Retain the original object; add only its missing, fixed genuine alias."""
        n = self.native
        require(len(self.journal) < 16, "fixture_restoration_bound")
        metadata = n.open(path, READ_ATTRIBUTES)
        identity = n.identity(metadata)
        tag = n.info(metadata, 9, n.Tag)
        require(bool(tag.FileAttributes & 0x10) and not tag.FileAttributes & 0x400,
                "short_alias_ordinary_directory")
        observed = n.short_name(path)
        selection = _short_alias_selection(path.name, observed)
        require(selection is not None, "real_short_alias_unavailable")
        # Absence and original custody are recorded BEFORE any alias mutation.
        record = {"kind": "short-alias", "path": path, "metadata": metadata, "id": identity,
                  "originalAbsent": selection == "absent", "originalName": observed, "changed": False}
        self.journal.append(record)
        if selection == "absent":
            # DELETE is required by the modern API, but must never be held across
            # the product's intentionally no-FILE_SHARE_DELETE reader admission.
            setter = n.open(path, DELETE | READ_ATTRIBUTES)
            require(n.identity(setter) == identity, "short_alias_setter_identity")
            n.call(n.k.SetFileShortNameW, (setter, "MRKSNP~1"))
            record["changed"] = True  # The original call has actually returned success.
            observed = n.short_name(path)
            require(observed == "MRKSNP~1" and n.identity(metadata) == identity,
                    "real_short_alias_unavailable")
            n.close(setter)  # Sole positive close is required before any product open.
        self.alias_object_id = identity
        return observed

    def junction(self, path: Path, target: Path) -> dict:
        record = self.held_mutation(path, "junction")
        self.native.set_junction(record["writer"], target)
        record["changed"] = True
        tag = self.native.info(record["metadata"], 9, self.native.Tag)
        require(tag.FileAttributes & 0x400 and tag.ReparseTag == MOUNT_TAG
                and self.native.identity(record["metadata"]) == record["id"], "fixture_junction_observation")
        record["reparse"] = (record["id"], bool(tag.FileAttributes & 0x10), tag.ReparseTag)
        return record

    def mapping(self, target: str) -> None:
        self.native.local_non_system()
        self.checks["localNonSystemToken"] = True
        letter = next((x for x in ("Z:", "Y:", "X:") if self.native.query_mapping(x) is None), None)
        require(letter is not None, "unused_local_drive_required")
        self.checks["aliasInitiallyAbsent"] = True
        self.native.call(self.native.k.DefineDosDeviceW, (9, letter, target))
        self.alias, self.alias_target = letter, target
        require(self.native.query_mapping(letter) == target, "local_drive_definition")

    def remove_mapping(self) -> None:
        require(self.alias is not None and self.native.query_mapping(self.alias) == self.alias_target, "mapping_not_owned")
        self.native.call(self.native.k.DefineDosDeviceW, (15, self.alias, self.alias_target))
        require(self.native.query_mapping(self.alias) is None, "mapping_removal_unconfirmed")
        self.alias = self.alias_target = None
        self.checks["mappingRemoved"] = True

    def canary(self, label: str) -> bytes:
        return f"outside-canary:{self.case}:{label}\n".encode("ascii")

    def prepare(self) -> None:
        n = self.native
        if self.case in ("ordinary-source", "ordinary-zip"):
            self.checks["genuineCore"] = True  # Full source/ZIP inventory was compared before import.
            self.checks["spelling"] = "verbatim" if self.case == "ordinary-zip" else "ordinary"
        elif self.case == "link-children":
            reparse_setup = {}
            file_link, directory_link = self.project / "linked-file/build.gradle", self.project / "linked-dir"
            n.call(n.k.CreateSymbolicLinkW, (str(file_link), str(self.outside / "file-canary"), 2))
            n.call(n.k.CreateSymbolicLinkW, (str(directory_link), str(self.outside / "symlink-dir"), 3))
            for path, field in ((file_link, "fileSymlinkTag"), (directory_link, "directorySymlinkTag")):
                handle = n.open(path)
                tag = n.info(handle, 9, n.Tag)
                require(tag.FileAttributes & 0x400 and tag.ReparseTag == SYMLINK_TAG, "real_symlink_required")
                self.checks[field] = tag.ReparseTag
                identity = n.identity(handle)
                relative = "linked-file/build.gradle" if path == file_link else "linked-dir"
                reparse_setup[relative] = (identity, bool(tag.FileAttributes & 0x10), tag.ReparseTag)
                n.close(handle)
                self.journal.append({"kind": "delete-link", "path": path, "id": identity, "changed": True})
            junction = self.junction(self.project / "junction-dir", self.outside / "junction-dir")
            reparse_setup["junction-dir"] = junction["reparse"]
            self.reparse_witnesses = _reparse_witness_state(reparse_setup)
            self.checks["junctionTag"] = MOUNT_TAG
            hardlink = self.project / "hardlinked/build.gradle"
            n.call(n.k.CreateHardLinkW, (str(hardlink), str(self.outside / "hardlink-canary"), None))
            handle = n.open(hardlink)
            standard = n.info(handle, 1, n.Standard)
            identity = n.identity(handle)
            self.checks["hardlinkCount"] = standard.NumberOfLinks
            self.checks["hardlinkIdMatch"] = identity == n.path_identity(self.outside / "hardlink-canary")
            require(standard.NumberOfLinks >= 2 and self.checks["hardlinkIdMatch"], "real_hardlink_required")
            n.close(handle)
            self.journal.append({"kind": "delete-link", "path": hardlink, "id": identity, "changed": True})
        elif self.case in ("reparse-root", "reparse-ancestor"):
            path = self.project if self.case == "reparse-root" else self.project / "ancestor"
            self.junction(path, self.outside / "target")
            self.checks["junctionTag"] = MOUNT_TAG
            suffix = Path("marker.txt") if self.case == "reparse-root" else Path("next/marker.txt")
            unsafe_id = n.read_control(path / suffix, self.canary("root"))
            expected = n.path_identity(self.outside / "target" / suffix)
            require(unsafe_id == expected, "unsafe_full_path_control_required")
            self.checks["unsafeControlMatched"] = True
            if self.case == "reparse-ancestor":
                self.request_root = str(self.project / "ancestor/next")
        elif self.case in ("short-alias", "case-alias"):
            exact = self.project / ("LongSnapshotDirectory" if self.case == "short-alias" else "CaseExact")
            if self.case == "short-alias":
                alias_name = self.short_alias(exact)
            else:
                alias_name = "caseexact"
                self.alias_object_id = n.path_identity(exact)
            alias = exact.parent / alias_name
            self.checks["sameObject"] = n.path_identity(alias) == self.alias_object_id
            self.checks["aliasObserved"] = True
            self.checks["spellingDiffers"] = alias_name != exact.name
            require(self.checks["sameObject"] and self.checks["spellingDiffers"], "real_alias_required")
            self.request_root = str(alias)
        elif self.case == "case-collision":
            record = self.held_mutation(self.project / "collision", "case")
            require(n.info(record["metadata"], 23, n.U32).value == 0, "ordinary_case_mode_required")
            n.set_case(record["writer"], 1)
            record["changed"] = True
            self.checks["enabledFlags"] = n.info(record["metadata"], 23, n.U32).value
            first, second = self.project / "collision/build.gradle", self.project / "collision/BUILD.GRADLE"
            first_id = n.file_write(first, b"// lower case control\n", case_sensitive=True)
            second_id = n.file_write(second, b"// upper case control\n", case_sensitive=True)
            require(first_id != second_id, "distinct_case_collision_required")
            record["children"] = [(first, first_id), (second, second_id)]
            self.checks["distinctIds"], self.checks["collisionFiles"] = True, 2
        elif self.case == "subst-drive":
            self.mapping(self.project_nt)
            self.checks["subtreeMappingObserved"] = n.query_mapping(self.alias) == self.project_nt
            self.request_root = self.alias + "\\selected"
        elif self.case == "unc":
            self.request_root = "\\\\mrk-invalid.invalid\\share\\selected"
        elif self.case == "device":
            self.request_root = "\\\\.\\C:\\selected"
        elif self.case == "ads":
            self.request_config = "release/mobile-release.json:stream"
        elif self.case in ("root-reparse-race", "config-reparse-race", "walk-reparse-race", "case-mode-race"):
            name = {"root-reparse-race": "held", "config-reparse-race": "release", "walk-reparse-race": "walk-parent",
                    "case-mode-race": "release"}[self.case]
            self.mutation_record = self.held_mutation(self.project / name, "case" if self.case == "case-mode-race" else "junction")
            if self.case == "root-reparse-race":
                self.request_root = str(self.project / "held/next")
            if self.case != "case-mode-race":
                # Same ordinary object/access masks are accessible BEFORE reader
                # sharing is established. Attribute-only mutation is separate.
                for access in (2, DELETE):
                    handle = n.open(self.mutation_record["path"], access)
                    n.close(handle)
        elif self.case == "acl-type":
            self.deny_data()
        elif self.case == "ending-metadata-case":
            self.file_record = self.held_mutation(self.project / "android/app/build.gradle", "time")
            self.file_record["basic"] = n.info(self.file_record["metadata"], 0, n.Basic)
            self.directory_record = self.held_mutation(self.project / "empty-ending", "case")
        elif self.case == "drive-map-change":
            self.mapping(self.device)
            self.checks["initialVolumeMapping"] = n.query_mapping(self.alias) == self.device
            ordinary = str(self.project)
            if ordinary.startswith("\\\\?\\"):
                ordinary = ordinary[4:]
            self.request_root = self.alias + ordinary[2:]
        elif self.case in ("oplock-release", "oplock-withhold", "pending-failstop"):
            target = self.project / "oplock/build.gradle" if self.case != "pending-failstop" else self.scratch / "pending.bin"
            self.holder = n.open(target, 0x100081, flags=OVERLAPPED_FLAG | NOFOLLOW)
            self.event = n.call(n.k.CreateEventW, (None, 1, 0, None), kind="handle")
            self.overlapped, self.returned = n.Overlapped(), n.U32(0xFFFFFFFF)
            self.overlapped.hEvent = self.event
            n.retain("oplock", (self.overlapped, self.returned))
            if self.case != "pending-failstop":
                n.grant_oplock(self.holder, self.event, self.overlapped, self.returned)
                self.checks["grantPending"] = True
                self.thread = threading.Thread(target=self.observe_oplock, name="fixed-snapshot-oplock-observer", daemon=False)
                self.thread.start()

    def deny_data(self) -> None:
        n, c = self.native, self.native.c
        targets = ((self.project / "read-denied/build.gradle", False), (self.project / "list-denied", True))
        require(len(self.journal) + 2 <= 16, "fixture_restoration_bound")
        for path, _ in targets:
            n.absent(path)  # BOTH original absences precede any exclusive creation.
        world = bytes.fromhex("010100000000000100000000")
        acl = (struct.pack("<BBHHH", 2, 0, 48, 2, 0) + struct.pack("<BBHI", 1, 0, 20, 1) + world
               + struct.pack("<BBHI", 0, 0, 20, 0x1F01FF) + world)
        descriptor = c.create_string_buffer(struct.pack("<BBHIIII", 1, 0, 0x9004, 0, 0, 0, 20) + acl, 68)
        attributes = n.Security(c.sizeof(n.Security), c.cast(descriptor, c.c_void_p), 0)
        n.retain("created-denial", (descriptor, attributes))
        self.checks["denialPoliciesConfirmed"] = 0
        for path, directory in targets:
            if directory:
                # No returned handle: only the following verified open can own it.
                n.call(n.k.CreateDirectoryW, (str(path), c.byref(attributes)), (descriptor, attributes))
            handle = n.open(path, 0x20080, creation=3 if directory else 1, sharing=7,
                            security=None if directory else attributes)
            standard, tag = n.info(handle, 1, n.Standard), n.info(handle, 9, n.Tag)
            require(standard.Directory == int(directory) and not standard.DeletePending
                    and bool(tag.FileAttributes & 0x10) == directory and not tag.FileAttributes & 0x400
                    and (directory or (standard.NumberOfLinks == 1 and standard.EndOfFile == 0)),
                    "fixture_created_denial_type")
            identity = n.identity(handle)
            installed, needed = c.create_string_buffer(16 * 1024), n.U32()
            n.call(n.a.GetKernelObjectSecurity, (handle, 4, installed, len(installed), c.byref(needed)), (installed, needed))
            require(20 <= needed.value <= len(installed), "fixture_dacl_not_effective")
            readback = bytes(installed.raw[:needed.value])
            policy = _dacl_policy(readback)
            require(policy is not None and policy[0] in (0x9004, 0x9404)
                    and _installed_deny_data_dacl(readback), "fixture_dacl_not_effective")
            self.journal.append({"kind": "created-denial", "path": path, "handle": handle, "id": identity})
            self.checks["denialPoliciesConfirmed"] += 1  # Not a reader-denial witness.

    def observe_oplock(self) -> None:
        n = self.native
        try:
            n.wait_oplock_event(self.event)
            consumed = n.U32(0xFFFFFFFF)
            n.call(n.k.GetOverlappedResult, (self.holder, n.c.byref(self.overlapped), n.c.byref(consumed), 0),
                   (self.overlapped, consumed))
            n.pending_complete = True
            require(self.reader_entered and not self.reader_returned, "oplock_not_original_reader_block")
            self.checks["breakSignalled"] = self.checks["completionKnown"] = True
            if self.case == "oplock-release":
                self.checks["blockedBeforeRelease"] = True
            else:
                self.checks["readerReturnedBeforeStop"] = False
                self.checks["holderReleasedBeforeStop"] = False
            self.emit("oplock-break", prefix=True)
            if self.case == "oplock-release":
                n.close(self.holder)
                self.checks["holderCloseReturned"] = True
            # A body return is not a Thread.join receipt. The withhold case
            # deliberately records thread=not-observed until process settlement.
        except BaseException:
            n.abort((self, self.thread, self.overlapped))

    def before_open(self, reader, parent: int, name: str, directory: bool) -> None:
        trace, n = self.trace, self.native
        parent_record = trace.handles[parent]
        relative_parent = trace.role(parent_record["path"])
        relative = name if parent_record["path"] == self.project_nt else relative_parent + "/" + name
        targets = {"root-reparse-race": "held/next", "config-reparse-race": "release/mobile-release.json",
                   "walk-reparse-race": "walk-parent/build.gradle", "case-mode-race": "release/mobile-release.json",
                   "replace": "android/app/build.gradle", "disappear": "android/app/build.gradle",
                   "config-disappear": "release/mobile-release.json", "pending-failstop": "oplock/build.gradle"}
        if self.case not in targets or self.seam_done or relative != targets[self.case]:
            return
        require(parent in reader._owned and reader._entered is None and parent_record["metadata"] is not None,
                "last_precheck_original_parent_required")
        require(time.monotonic() < trace.inventory.deadline, "seam_after_reader_deadline")
        self.seam_done = True
        if self.case == "pending-failstop":
            self.checks["originalParentHeld"] = True
            n.pending_arena = (self, n, self.holder, self.event, self.overlapped, self.returned)
            # The real original classifier gets the REAL FSCTL BOOL/last-error
            # under its original entered arena. No fabricated status callback.
            try:
                reader._boolean(n.k.DeviceIoControl,
                    (self.holder, BATCH_OPLOCK, None, 0, None, 0, n.c.byref(self.returned), n.c.byref(self.overlapped)),
                    (self, n, self.holder, self.event, self.overlapped, self.returned))
            except BaseException:
                # Only a known ordinary return/error can reach this branch.
                # Real _abort never unwinds; no logging after unknown completion.
                n.pending_complete = True
                self.checks["afterCallMarker"] = True
                self.emit("pending-returned", prefix=True)
                raise
            n.pending_complete = True
            self.checks["afterCallMarker"] = True
            self.emit("pending-returned", prefix=True)
            raise FixtureFailure("pending_classifier_returned")
        if self.case in ("replace", "disappear", "config-disappear"):
            full = parent_record["path"].rstrip("\\") + "\\" + name
            require(full in trace.entries, "mutation_requires_actual_enumerated_entry")
            old_id = trace.entries[full]
            self.checks["entryObserved"] = True
            target = self.project / relative
            n.delete(target, (parent_record["id"][0], old_id))
            if self.case == "replace":
                replacement = n.file_write(target, b'android { defaultConfig { applicationId "org.fixture.replaced" } }\n')
                self.replaced_id = replacement
                self.replaced_entry_id = old_id
                require(replacement[1] != old_id, "replacement_requires_distinct_id")
            return
        record = self.mutation_record
        self.checks["parentIdSame"] = parent_record["id"] == record["id"]
        require(self.checks["parentIdSame"], "mutation_parent_identity")
        self.checks["mutationAccess"] = WRITE_ATTRIBUTES
        if self.case == "case-mode-race":
            n.set_case(record["writer"], 1)
            record["changed"] = True
            self.checks["enabledFlags"] = n.info(record["metadata"], 23, n.U32).value
            require(self.checks["enabledFlags"] == 1, "case_mode_mutation_required")
        else:
            for access, field in ((2, "sharingWriteDenied"), (DELETE, "sharingDeleteDenied")):
                try:
                    unexpected = n.open(record["path"], access)
                except NativeFailure as error:
                    require(error.code == 32, "ordinary_sharing_denial_required")
                    self.checks[field] = True
                else:
                    n.close(unexpected)
                    raise FixtureFailure("ordinary_sharing_control_failed")
            self.checks["preparatoryDeletes"] = 0
            if self.case == "walk-reparse-race":
                full = parent_record["path"].rstrip("\\") + "\\" + name
                require(full in trace.entries, "walk_mutation_requires_enumerated_placeholder")
                n.delete(record["path"] / name, (record["id"][0], trace.entries[full]))
                self.checks["preparatoryDeletes"] = 1
            # Parent was empty at setup, or became empty by the separately
            # owned deletion above. No metadata veto is inserted into product.
            n.set_junction(record["writer"], self.outside / "target")
            record["changed"] = True
            tag = n.info(record["metadata"], 9, n.Tag)
            require(tag.ReparseTag == MOUNT_TAG and tag.FileAttributes & 0x400, "actual_mutation_tag_required")
            self.checks["mutationTag"], self.checks["mutationSucceeded"] = tag.ReparseTag, True
            suffix, label = ((Path("next/marker.txt"), "root") if self.case == "root-reparse-race" else
                             (Path("mobile-release.json"), "config") if self.case == "config-reparse-race" else
                             (Path("build.gradle"), "walk"))
            observed = n.read_control(record["path"] / suffix, self.canary(label))
            expected = n.path_identity(self.outside / "target" / suffix)
            require(observed == expected and observed in self.outside_ids, "unsafe_mutation_lookup_control")
            self.checks["unsafeControlMatched"] = True
        require(n.identity(record["metadata"]) == parent_record["id"], "mutated_original_parent_changed_identity")

    def real_entry(self, reader, spec) -> None:
        if spec.parent is None:
            return
        record = self.trace.handles[spec.parent]
        relative = self.trace.role(record["path"] + "\\" + spec.name)
        if self.case.startswith(("root-reparse-", "config-reparse-", "walk-reparse-")) or self.case == "case-mode-race":
            target = {"root-reparse-race": "held/next", "config-reparse-race": "release/mobile-release.json",
                      "walk-reparse-race": "walk-parent/build.gradle", "case-mode-race": "release/mobile-release.json"}.get(self.case)
            if self.seam_done and relative == target:
                self.checks["originalRelativeEntry"] = spec.parent in reader._owned
                self.checks["entryBeforeDeadline"] = time.monotonic() < self.trace.inventory.deadline
                require(self.checks["originalRelativeEntry"] and self.checks["entryBeforeDeadline"], "mutation_entry_witness")
        if self.case in ("oplock-release", "oplock-withhold") and relative == "oplock/build.gradle":
            require(not self.reader_entered and not self.native.pending_complete, "unique_original_oplock_opener")
            self.reader_entered = True
            self.checks["originalReaderEntered"] = True
            self.emit("reader-entry", prefix=True)

    def completed_open(self, spec, path: str, identity: tuple[int, bytes]) -> None:
        relative = self.trace.role(path)
        if self.case == "replace" and relative == "android/app/build.gradle" and self.seam_done:
            self.checks["originalIdDiffers"] = identity == self.replaced_id and identity[1] != self.replaced_entry_id
            require(self.checks["originalIdDiffers"], "original_replacement_identity_required")
        if self.case in ("short-alias", "case-alias") and identity == self.alias_object_id:
            self.alias_acquired += 1
        if self.case in ("oplock-release", "oplock-withhold") and relative == "oplock/build.gradle":
            self.reader_returned = True
            if self.case == "oplock-release":
                self.checks["originalReaderReturned"] = True
            else:
                raise FixtureFailure("withheld_oplock_reader_returned")
        if self.case == "depth-path-limit" and relative != "@ancestor":
            depth = len(relative.split("/"))
            if spec.directory:
                self.deepest_admitted = max(getattr(self, "deepest_admitted", 0), depth)
                if depth > 12:
                    self.depth13_opens = getattr(self, "depth13_opens", 0) + 1
            if len(relative.encode("utf-8")) > 512:
                self.oversized_opens = getattr(self, "oversized_opens", 0) + 1

    def completed_open_error(self, spec, status: int, category: str) -> None:
        relative = "@root" if spec.parent is None else self.trace.role(self.trace.handles[spec.parent]["path"] + "\\" + spec.name)
        if self.case in ("reparse-root", "reparse-ancestor") and status == 0xC000050B:
            self.checks["rootRefused"] = True
        if self.case in ("disappear", "config-disappear") and status == 0xC0000034:
            target = "release/mobile-release.json" if self.case == "config-disappear" else "android/app/build.gradle"
            if relative == target and self.seam_done:
                self.checks["actualMissingReturn"] = True
        if self.case == "acl-type" and status == 0xC0000022:
            if relative == "read-denied/build.gradle":
                self.checks["fileAccessDenied"] = True
            elif relative == "list-denied":
                self.checks["directoryAccessDenied"] = True
        if self.case == "acl-type" and relative == "release/mobile-release.json" and status in (0xC00000BA, 0xC0000103):
            self.checks["configDirectoryRefused"] = True

    def observed_metadata(self, record: dict, result) -> None:
        if self.case == "ending-metadata-case":
            relative = self.trace.role(record["path"])
            if relative == "android/app/build.gradle" and self.file_ending_done:
                self.checks["writeMetadataChanged"] = result.write != self.file_record["basic"].LastWriteTime
            elif relative == "empty-ending" and self.directory_ending_done:
                self.checks["caseFlagsChanged"] = result.case_flags == 1

    def after_read(self, reader, handle: int, block: bytes) -> None:
        if self.case == "ending-metadata-case" and not block and not self.file_ending_done:
            record = self.trace.handles[handle]
            if self.trace.role(record["path"]) == "android/app/build.gradle":
                mutation = self.file_record
                require(record["id"] == mutation["id"], "ending_file_original_identity")
                value = self.native.Basic()
                value.LastWriteTime = mutation["basic"].LastWriteTime + 10000
                self.native.call(self.native.k.SetFileInformationByHandle,
                    (mutation["writer"], 0, self.native.c.byref(value), self.native.c.sizeof(value)), (value,))
                mutation["changed"] = True
                self.file_ending_done = True
                self.checks["genuineFileEof"] = True

    def after_directory(self, reader, handle: int, block: bytes | None) -> None:
        if self.case == "ending-metadata-case" and block is None and not self.directory_ending_done:
            record = self.trace.handles[handle]
            if self.trace.role(record["path"]) == "empty-ending":
                mutation = self.directory_record
                require(record["id"] == mutation["id"], "ending_directory_original_identity")
                self.native.set_case(mutation["writer"], 1)
                mutation["changed"] = True
                self.directory_ending_done = True
                self.checks["genuineDirectoryEof"] = True

    def before_mapping(self, reader, drive: str) -> None:
        self.mapping_queries += 1
        if self.case == "drive-map-change" and self.mapping_queries == 2:
            require(drive == self.alias and self.native.query_mapping(self.alias) == self.device, "ending_original_mapping")
            self.native.call(self.native.k.DefineDosDeviceW, (15, self.alias, self.alias_target))
            require(self.native.query_mapping(self.alias) is None, "intermediate_mapping_removal")
            self.alias_target = self.project_nt
            self.native.call(self.native.k.DefineDosDeviceW, (9, self.alias, self.alias_target))
            require(self.native.query_mapping(self.alias) == self.alias_target, "ending_subtree_definition")
            self.mapping_changed = True
            self.checks["endingSubtreeMapping"] = True

    def restore(self) -> None:
        n, c = self.native, self.native.c
        if self.thread is not None:
            self.thread.join(timeout=3)
            if self.thread.is_alive():
                n.abort((self, self.thread, self.overlapped))
            self.thread_joined = True
            require(self.case == "oplock-release" and n.pending_complete, "oplock_original_join_required")
            self.checks["observerJoined"] = True
            require(self.holder not in n.held and self.checks["holderCloseReturned"] is True, "oplock_holder_close_required")
            n.close(self.event)
            self.checks["eventCloseReturned"] = True
        restored_links, restored_reparse, removed_created = 0, 0, 0
        for record in reversed(self.journal):
            kind = record["kind"]
            if kind == "short-alias":
                # _finish proved every original reader call/close before restore.
                # This is a NEW registered setter, never reuse of an uncertain one.
                require(n.identity(record["metadata"]) == record["id"], "short_alias_restore_identity")
                if record["changed"]:
                    require(record["originalAbsent"] is True and n.short_name(record["path"]) == "MRKSNP~1",
                            "short_alias_restore_owned_name")
                    setter = n.open(record["path"], DELETE | READ_ATTRIBUTES)
                    require(n.identity(setter) == record["id"], "short_alias_restore_setter_identity")
                    n.call(n.k.SetFileShortNameW, (setter, ""))
                    require(n.short_name(record["path"]) == record["originalName"]
                            and n.identity(record["metadata"]) == record["id"], "short_alias_restore_absence")
                    n.close(setter)
                    record["changed"] = False
                else:
                    require(record["originalAbsent"] is False
                            and n.short_name(record["path"]) == record["originalName"], "short_alias_existing_preserved")
                n.close(record["metadata"])
                continue
            if kind == "delete-link":
                n.delete(record["path"], record["id"])
                restored_links += 1
                continue
            if kind == "created-denial":
                require(n.identity(record["handle"]) == record["id"], "fixture_created_denial_identity")
                n.delete(record["path"], record["id"])  # Original sharing=7 holder spans the delete-handle check/close.
                n.close(record["handle"])
                n.absent(record["path"])  # Only after both consuming closes; pending/access-denied is not absent.
                removed_created += 1
                continue
            require(n.identity(record["metadata"]) == record["id"], "restore_original_object")
            if record["changed"]:
                if kind == "junction":
                    n.clear_junction(record["writer"])
                    tag = n.info(record["metadata"], 9, n.Tag)
                    require(not tag.FileAttributes & 0x400, "reparse_removal_not_confirmed")
                    restored_reparse += 1
                    restored_links += 1
                elif kind == "case":
                    for path, identity in record.get("children", ()):
                        n.delete(path, identity, case_sensitive=True)
                    n.set_case(record["writer"], 0)
                    require(n.info(record["metadata"], 23, n.U32).value == 0, "case_restoration_not_confirmed")
                elif kind == "time":
                    value = n.Basic()
                    value.LastWriteTime = record["basic"].LastWriteTime
                    n.call(n.k.SetFileInformationByHandle, (record["writer"], 0, c.byref(value), c.sizeof(value)), (value,))
                    require(n.info(record["metadata"], 0, n.Basic).LastWriteTime == value.LastWriteTime, "time_restoration_not_confirmed")
                else:
                    raise FixtureFailure("unknown_restoration_kind")
            n.close(record["metadata"])
            n.close(record["writer"])
        self.journal.clear()
        if self.alias is not None:
            self.remove_mapping()
        if self.case == "link-children":
            self.checks["restoredLinks"] = restored_links
        elif self.case in ("reparse-root", "reparse-ancestor"):
            self.checks["reparseRestored"] = restored_reparse
        elif self.case in ("root-reparse-race", "config-reparse-race", "walk-reparse-race"):
            self.checks["reparseRestored"] = restored_reparse == 1
        elif self.case in ("case-collision", "case-mode-race"):
            self.checks["caseRestored"] = True
        elif self.case == "acl-type":
            self.checks["createdObjectsRemoved"] = removed_created
            self.checks["initialAbsenceRestored"] = removed_created == 2
        elif self.case == "ending-metadata-case":
            self.checks["attributesRestored"] = True
        n.close_all()
        n.retained_arenas.clear()  # Every request completed and every sole close returned.
        self.restored = True

    def finish(self, result: dict | None, error_code: str | None, policy) -> None:
        try:
            self._finish(result, error_code, policy)
        except Exception as error:
            self.diagnose_failure("reduction", error)
            raise

    def _finish(self, result: dict | None, error_code: str | None, policy) -> None:
        """Reduce only genuine DTO/collector/native observations; never fabricate IO."""
        trace, case = self.trace, self.case
        reader = trace.snapshot()
        require(reader["live"] == reader["closeFailed"] == reader["violations"] == 0
                and reader["acquired"] == reader["closeAttempts"] == reader["closeSucceeded"], "reader_original_closes")
        require(all(item["entered"] == item["returned"] == item["completed"] for item in reader["calls"]),
                "reader_unclassified_entry")
        require(reader["outsideReads"] == reader["outsideDescent"] == 0
                and reader["outsideAcquired"] == reader["aliasMetadataAcquired"]
                and (case == "link-children" or reader["outsideAcquired"] == 0), "reader_outside_boundary")
        errors = {"reparse-root": {"unsafe_path", "snapshot_unavailable"},
                  "reparse-ancestor": {"unsafe_path", "snapshot_unavailable"},
                  "root-reparse-race": {"unsafe_path", "snapshot_unavailable"},
                  "short-alias": {"unsafe_path", "snapshot_unavailable"},
                  "case-alias": {"unsafe_path", "snapshot_unavailable"},
                  "subst-drive": {"snapshot_unavailable"},
                  "unc": {"unsafe_path"}, "device": {"unsafe_path"}, "ads": {"unsafe_path"}}
        if case in errors:
            require(result is None and error_code in errors[case], "required_native_refusal")
        else:
            require(error_code is None and type(result) is dict, "required_native_snapshot")
        issues, sources, config, scan = set(), {}, {}, {}
        if result is not None:
            require(set(result) == {"root", "observedAt", "observationScope", "config", "discovery", "assurance", "issues"}
                    and result["root"] == self.request_root and result["observationScope"] == "single-request-non-atomic",
                    "genuine_snapshot_shape")
            expected_assurance = {"basis": "static-text", "projectCodeExecuted": False, "toolsProbed": False,
                                  "credentialsRead": False, "gitObserved": False, "storeContacted": False,
                                  "writesPerformed": False, "releaseReadiness": "unknown"}
            require(canonical(result["assurance"]) == canonical(expected_assurance), "false_assurance_required")
            config, discovery = result["config"], result["discovery"]
            require(set(config) == {"path", "state", "data", "issues"} and config["path"] == self.request_config
                    and set(discovery) == {"state", "partial", "hints", "scan", "limits"}
                    and discovery["state"] == "unverified" and discovery["limits"] == policy.LIMITS,
                    "genuine_snapshot_contract")
            require(type(result["issues"]) is list and len(result["issues"]) <= 64, "genuine_issue_bound")
            issues = {item["code"] for item in result["issues"]}
            scan = discovery["scan"]
            require(trace.inventory is not None and scan == trace.inventory.counts
                    and scan["sourceBytes"] == trace.counts["readBytes"], "genuine_inventory_accounting")
            sources = trace.inventory.sources
            if case in ("ordinary-source", "ordinary-zip"):
                require(discovery["partial"] is False and not issues and config["state"] == "format-valid", "ordinary_snapshot_incomplete")
                expected = strict(ordinary_bytes(self.project / "release/mobile-release.json", MAX_FILE), MAX_FILE)
                self.checks["configExact"] = config["data"] == expected
                hints = discovery["hints"]
                self.checks["androidExact"] = hints.get("android") == {
                    "module": ":android:app", "buildFile": "android/app/build.gradle", "applicationId": "org.fixture.app"}
                self.checks["iosExact"] = hints.get("ios") == {
                    "projects": ["ios/Fixture.xcodeproj"], "workspaces": [], "schemes": [], "bundleIds": ["org.fixture.ios"],
                    "generatedProjectSources": [], "bundleId": "org.fixture.ios", "project": "ios/Fixture.xcodeproj"}
                self.checks["versionNotDisclosed"] = (hints.get("versionSource") == "release/version.properties"
                    and hints.get("versionNameKey") == "VERSION_NAME" and hints.get("versionBuildKey") == "BUILD_NUMBER"
                    and b"9.9.9" not in canonical(hints))
                require(set(hints) == {"android", "ios", "versionSource", "versionNameKey", "versionBuildKey"}, "ordinary_hint_shape")
                self.checks["unicodeOpens"] = self.unicode_opens
            elif case != "oplock-release":
                require(discovery["partial"] is True and bool(issues), "required_partial_observation")
            if case in ("config-reparse-race", "case-mode-race", "acl-type", "config-disappear", "drive-map-change"):
                require(config["state"] == "unavailable" and config["data"] is None, "untrusted_configuration")
        def read(role: str, key: str) -> int:
            return trace.reads.get(role, {}).get(key, 0)
        if case == "link-children":
            self.checks["excludedReparses"] = len(self.reparse_witnesses["credited"])
            self.checks["hardlinkReadBytes"] = read("hardlinked/build.gradle", "bytes")
            require("hardlinked/build.gradle" not in sources and reader["aliasMetadataAcquired"] >= 1,
                    "hardlink_metadata_veto_required")
        elif case in ("reparse-root", "reparse-ancestor"):
            require(self.checks["rootRefused"] is True, "root_reparse_native_refusal_required")
        elif case in ("short-alias", "case-alias"):
            self.checks["aliasAcquired"], self.checks["aliasReadBytes"] = self.alias_acquired, self.alias_reads
            require(self.alias_name_veto and self.alias_acquired == 1 and self.alias_read_calls == 0, "normalized_alias_veto_required")
        elif case == "case-collision":
            self.checks["collisionDirectoryBatches"] = self.collision_batches
        elif case == "subst-drive":
            self.checks["rootOpens"] = reader["rootOpens"]
        elif case in ("unc", "device", "ads"):
            self.checks["readerFfiEntries"] = sum(item["entered"] for item in reader["calls"])
            self.checks["readerInstances"] = trace.instances
            self.checks["unsafePathRefused"] = error_code == "unsafe_path"
        elif case in ("root-reparse-race", "config-reparse-race", "walk-reparse-race"):
            self.checks["outsideAcquired"] = reader["outsideAcquired"]
            self.checks["outsideReadBytes"] = trace.outside_bytes
        elif case == "case-mode-race":
            self.checks["missingNotTrusted"] = config["state"] == "unavailable"
        elif case == "acl-type":
            self.checks["accessibleSiblingRead"] = read("sibling/build.gradle", "eof") > 0 and "sibling/build.gradle" in sources
            observed_directory = trace.entry_kinds.get(self.project_nt + "\\release\\mobile-release.json") is True
            self.checks["configDirectoryRefused"] = (observed_directory and not trace.config_opened
                                                    and config["state"] == "unavailable")
        elif case == "read-eof-size":
            self.checks.update(emptyEof=read("empty", "eof") > 0 and read("empty", "bytes") == 0,
                invalidUtf8Refused="snapshot.encoding" in issues and "invalid/build.gradle" not in sources and read("invalid", "eof") > 0,
                shortFinalRead=read("multi", "short") > 0, multichunkEof=read("multi", "calls") >= 3 and read("multi", "eof") > 0,
                exactLimitEof=read("exact", "bytes") == 524288 and read("exact", "eof") > 0,
                oversizeReadBytes=read("oversize", "bytes"), largestRequest=trace.largest_request, largestReturn=trace.largest_return)
            require("snapshot.file-size" in issues and "oversize/build.gradle" not in sources, "oversize_veto_required")
        elif case == "entry-limit":
            self.checks.update(returnedRecords=reader["directoryRecords"], chargedEntries=scan["entries"],
                               overBudgetChildOpens=trace.after_over_budget_opens, entryLimitIssue="snapshot.entry-limit" in issues)
        elif case == "candidate-limit":
            self.checks.update(chargedCandidates=scan["sourceFiles"],
                refusedExtraCandidate=trace.opened_candidates == 127 and "snapshot.file-limit" in issues,
                sourceFileLimitIssue="snapshot.file-limit" in issues)
        elif case == "aggregate-limit":
            cap_not_eof = any(read(f"budget{index:02}/build.gradle", "bytes") == 524288
                              and read(f"budget{index:02}/build.gradle", "eof") == 0 for index in range(16))
            self.checks.update(chargedBytes=scan["sourceBytes"], extraByteRead=read("extra/build.gradle", "bytes"),
                               capNotEof=cap_not_eof and scan["sourceBytes"] == 8388608, byteLimitIssue="snapshot.byte-limit" in issues)
        elif case == "depth-path-limit":
            self.checks.update(deepestAdmitted=getattr(self, "deepest_admitted", 0),
                depth13Opens=getattr(self, "depth13_opens", 0), oversizedPathOpens=getattr(self, "oversized_opens", 0),
                depthIssue="snapshot.depth-limit" in issues, pathIssue="snapshot.path-limit" in issues,
                siblingRead=read("sibling/build.gradle", "eof") > 0 and "sibling/build.gradle" in sources)
        elif case == "replace":
            self.checks["replacementReadBytes"] = read("android/app/build.gradle", "bytes")
            self.checks["changedIssue"] = "snapshot.changed" in issues and "android/app/build.gradle" not in sources
        elif case in ("disappear", "config-disappear"):
            self.checks["changedIssue"] = "snapshot.changed" in issues
            self.checks["missingNotTrusted"] = (config["state"] == "unavailable" if case == "config-disappear"
                                                 else "android/app/build.gradle" not in sources)
        elif case == "ending-metadata-case":
            self.checks["fileChangeVeto"] = "android/app/build.gradle" not in sources and "snapshot.changed" in issues
            self.checks["directoryCaseVeto"] = self.checks["caseFlagsChanged"] is True and "snapshot.unsafe-file" in issues
        elif case == "drive-map-change":
            self.checks["changedIssue"] = "snapshot.changed" in issues
            self.checks["laterProjectOpens"] = self.later_project_opens
        # No complete telemetry is emitted on a setup/collector/cleanup failure.
        # The original engine exits nonzero and Rust retains the case instead.
        try:
            self.restore()
        except Exception as error:
            self.diagnose_failure("restoration", error)
            raise
        require(set(self.checks) == set(CHECKS[case]) and all(value is not None for value in self.checks.values()),
                "native_predicate_not_observed")
        require(self.native.counts["acquired"] == self.native.counts["closeAttempts"] == self.native.counts["closeSucceeded"]
                and self.native.counts["live"] == self.native.counts["closeFailed"] == 0, "fixture_original_closes")
        self.emit("complete")


def main() -> int:
    descriptor, inputs, root, core, data = admit()
    # Exactly the original core selection, once. No fake engine/package, site,
    # project path, executable fallback or capability-enable switch.
    require(str(core) not in sys.path, "core_inserted_twice")
    sys.path.insert(0, str(core))
    from mobile_release import api, _desktop_engine
    from mobile_release.api import _snapshot as policy, _snapshot_windows as windows, _snapshot_windows_native as native_api
    for module, relative in ((api, "mobile_release/api/__init__.py"), (_desktop_engine, "mobile_release/_desktop_engine.py"),
                             (policy, "mobile_release/api/_snapshot.py"), (windows, "mobile_release/api/_snapshot_windows.py"),
                             (native_api, "mobile_release/api/_snapshot_windows_native.py")):
        require(Path(module.__file__) == core / relative, "genuine_core_origin")
    require(policy._WINDOWS_SNAPSHOT_QUALIFIED is False and api.snapshot_available() is False, "public_gate_must_stay_closed")
    fixture = Fixture(descriptor, inputs, root, data)
    try:
        fixture.prepare()
    except Exception as error:
        fixture.diagnose_failure("setup", error)
        raise
    original_factory, original_dispatch = windows._new_native, api.project_snapshot
    called = False
    def dispatch(selected_root: object, config_path: object = "release/mobile-release.json"):
        nonlocal called
        validated_refusal = None
        try:
            require(not called and type(selected_root) is str and selected_root == fixture.input_root
                    and config_path == "release/mobile-release.json", "fixed_snapshot_request_required")
            called = True
            windows._new_native = lambda inventory: fixture.trace.attach(windows, native_api, inventory)
            result, code = None, None
            try:
                try:
                    result = windows.project_snapshot(fixture.request_root, fixture.request_config)
                except api.ApiError as error:
                    code = error.code
                    fixture.finish(None, code, policy)
                    validated_refusal = error
                    raise  # Preserve the original genuine API refusal and engine transport.
                fixture.finish(result, None, policy)
                return result
            finally:
                windows._new_native = original_factory
                try:
                    require(policy._WINDOWS_SNAPSHOT_QUALIFIED is False and api.snapshot_available() is False, "public_gate_changed")
                except Exception as error:
                    fixture.diagnose_failure("reduction", error)
                    raise
        except Exception as error:
            # A genuine ApiError with successful finish is the required refusal,
            # not a fixture failure. Nested finish catches have already latched.
            if error is not validated_refusal:
                fixture.diagnose_failure("reader", error)
            raise
    api.project_snapshot = dispatch
    try:
        status = _desktop_engine.main()  # Original one-shot protocol, pipe custody and bounded response.
        try:
            require(called, "fixed_snapshot_not_requested")
        except Exception as error:
            fixture.diagnose_failure("reduction", error)
            raise
        return status
    finally:
        api.project_snapshot = original_dispatch


if __name__ == "__main__":
    try:
        status = main()
    except Exception:
        status = 78  # No traceback, SDK paths, fixture content or credentials.
    raise SystemExit(status)
