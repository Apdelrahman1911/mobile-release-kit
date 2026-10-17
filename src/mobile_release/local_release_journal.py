"""Private local release record storage; never Store/GO or rollback authority.

The native caller must supply its selected key/enrollment, hold project exclusion,
check the Keychain head/successor and settle the new checkpoint after disk append.
A valid MAC or reopened disk journal does not establish any of those facts.
No CLI, renderer, environment, key generation, update, delete or replay interface.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from uuid import UUID

from ._github_preflight_journal import (Journal as _Custodian, JournalError, canonical,
                                         MAX_PATH_BYTES, MAX_PATH_COMPONENTS)

MAX_OPERATIONS = 64
MAX_ENTRIES = 1 + 8 * MAX_OPERATIONS
MAX_RECORD_BYTES = 8192
_DOMAIN = b"mobile-release-kit:local-release-record:v1\0"
_ENROLLMENT = frozenset(("projectLocator", "projectBinding", "projectId", "keyId", "keyRevision"))
_FIELDS = _ENROLLMENT | {"documentType", "schemaVersion", "origin", "sequence", "previousSha256",
                         "operationId", "phase", "payload", "mac"}
_NEXT = {"inputs-pending": "inputs-ready", "inputs-ready": "prepare-pending",
         "prepare-pending": "prepared", "promotion-pending": "prepared", "prepared": "execute-pending",
         "execute-pending": "settled-success"}
_DIGESTS = {
    "inputs-pending": {"configurationSha256", "versionSha256"},
    "inputs-ready": {"candidateSha256"},
    "prepare-pending": {"candidateSha256", "confirmationSha256"},
    "prepared": {"candidateSha256", "intentSha256", "storePreconditionSha256"},
    "execute-pending": {"intentSha256", "confirmationSha256"},
    "settled-success": {"intentSha256", "receiptSha256"},
}


class LocalJournalError(JournalError):
    def __init__(self):
        super().__init__("Local release history is unavailable; preserve it for recovery")


def _need(value):
    if not value:
        raise LocalJournalError()


def _sha(value, length=64):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None


def _uuid(value):
    if type(value) is not str or len(value) != 36:
        return False
    try:
        parsed = UUID(value)
        return parsed.version == 4 and str(parsed) == value
    except ValueError:
        return False


def _int(value, maximum, minimum=1):
    return type(value) is int and minimum <= value <= maximum


def _enrollment(value):
    _need(type(value) is dict and set(value) == _ENROLLMENT
          and all(_sha(value[k]) for k in ("projectLocator", "projectBinding"))
          and all(_uuid(value[k]) for k in ("projectId", "keyId"))
          and type(value["keyRevision"]) is int and value["keyRevision"] == 1)
    return dict(value)


def _payload(phase, payload):
    _need(type(phase) is str and 0 < len(phase) <= 23 and type(payload) is dict)
    if phase == "genesis":
        _need(set(payload) == {"rootIdentity"})
        root = payload["rootIdentity"]
        _need(type(root) is dict and set(root) == {"device", "inode", "uid", "gid", "mode"}
              and all(_int(root[k], (1 << 64) - 1, 0) for k in ("device", "inode", "uid", "gid"))
              and root["inode"] > 0 and root["uid"] > 0
              and _int(root["mode"], 0o7777, 0) and root["mode"] & 0o7022 == 0)
    elif phase in _DIGESTS:
        keys = _DIGESTS[phase]
        extra = {"sourceCommit", "sourceTree"} if phase == "inputs-pending" else (
            {"authorizationId", "assignmentRevision"} if phase == "execute-pending" else set())
        _need(set(payload) == keys | extra and all(_sha(payload[k]) for k in keys))
        if phase == "inputs-pending":
            _need(all(_sha(payload[k], 40) for k in extra))
        if phase == "execute-pending":
            _need(_uuid(payload["authorizationId"]) and _int(payload["assignmentRevision"], (1 << 32) - 2))
    elif phase == "promotion-pending":
        _need(set(payload) == {"stage", "candidateOperationId", "candidateSha256",
            "predecessorOperationId", "predecessorReceiptSha256", "sourceCommit", "sourceTree",
            "configurationSha256", "versionSha256", "metadataSha256", "confirmationSha256"}
            and payload["stage"] in {"external-testing", "production-submit"}
            and all(_uuid(payload[k]) for k in ("candidateOperationId", "predecessorOperationId"))
            and all(_sha(payload[k], 40) for k in ("sourceCommit", "sourceTree"))
            and all(_sha(payload[k]) for k in ("candidateSha256", "predecessorReceiptSha256",
                "configurationSha256", "versionSha256", "metadataSha256", "confirmationSha256")))
    elif phase == 'target-reconciled':
        _need(set(payload)=={'intentSha256','receiptSha256','executeAuthorizationId',
              'recoveryAuthorizationId','assignmentRevision','preservedAttempt','priorExecutionFinality'}
              and all(_sha(payload[k]) for k in ('intentSha256','receiptSha256'))
              and all(_uuid(payload[k]) for k in ('executeAuthorizationId','recoveryAuthorizationId'))
              and payload['executeAuthorizationId']!=payload['recoveryAuthorizationId']
              and _int(payload['assignmentRevision'],(1<<32)-2)
              and payload['priorExecutionFinality']=='not-established')
        marker_data(payload['preservedAttempt'])
    elif phase in ("settled-failure", "reconciliation-required"):
        reasons = ({"cancelled", "validation", "native-failure", "resource-close", "store-refused"}
                   if phase == "settled-failure" else
                   {"interrupted", "response-unknown", "cleanup-unknown", "checkpoint-unknown"})
        _need(set(payload) == {"phase", "reason"} and type(payload["phase"]) is str
              and payload["phase"] in _NEXT and type(payload["reason"]) is str and payload["reason"] in reasons)
    else:
        raise LocalJournalError()


def marker_data(value):
    """Closed conserved-file DATA, never original custody or name authority."""
    if value is None:return
    _need(type(value) is dict and set(value)=={'name','binding'} and type(value['name']) is str
          and re.fullmatch('[0-9a-f]{64}\\.pending',value['name']) is not None)
    b=value['binding']
    _need(type(b) is dict and set(b)=={'device','inode','uid','gid','mode','links','size','mtime','ctime','sha256'}
          and all(_int(b[k],(1<<64)-1,0) for k in ('device','inode','uid','gid'))
          and b['inode']>0 and b['uid']>0 and type(b['mode']) is int and b['mode']==0o600
          and type(b['links']) is int and b['links']==1 and _int(b['size'],8192)
          and all(type(b[k]) is int and -(1<<63)<=b[k]<(1<<63) for k in ('mtime','ctime'))
          and _sha(b['sha256']))


def recovery_chain(rows, operation):
    _need(type(rows) is list and len(rows) in (5,6) and all(r['operationId']==operation for r in rows)
          and [r['phase'] for r in rows[:5]]==['inputs-pending','inputs-ready','prepare-pending','prepared','execute-pending'])
    if len(rows)==6:
        _need(rows[-1]['phase'] in {'settled-failure','reconciliation-required'}
              and rows[-1]['payload']['phase']=='execute-pending')
    _need(rows[3]['payload']['intentSha256']==rows[4]['payload']['intentSha256'])
    return rows


def promotion_lineage(rows, *, operation_id, payload):
    """Closed journal DATA only; raw predecessor receipt/original custody separate.

    Called on the current authenticated journal prefix before appending a NEW
    later-stage operation. No supplied receipt summary can replace its last row.
    Returns original candidate and immediate predecessor rows, not a Store grant.
    """
    _payload("promotion-pending", payload)
    _need(type(rows) is list and 1 <= len(rows) <= MAX_ENTRIES - 4 and _uuid(operation_id)
          and all(type(row) is dict for row in rows))
    ids = {row["operationId"] for row in rows if row["operationId"] is not None}
    _need(operation_id not in ids and len(ids) < MAX_OPERATIONS)
    candidate_id, predecessor_id = payload["candidateOperationId"], payload["predecessorOperationId"]
    last = rows[-1]
    _need(last["phase"] == "settled-success" and last["operationId"] == predecessor_id
          and last["payload"]["receiptSha256"] == payload["predecessorReceiptSha256"])
    candidate = [row for row in rows if row["operationId"] == candidate_id]
    _need([row["phase"] for row in candidate] == ["inputs-pending", "inputs-ready",
          "prepare-pending", "prepared", "execute-pending", "settled-success"]
          and all(candidate[i]["payload"]["candidateSha256"] == payload["candidateSha256"] for i in (1, 2, 3)))
    _need(all(not (row["phase"] == "promotion-pending"
          and row["payload"]["candidateOperationId"] == candidate_id
          and row["payload"]["stage"] == payload["stage"]) for row in rows))
    if payload["stage"] == "external-testing":
        _need(predecessor_id == candidate_id)
        predecessor = candidate
    else:
        _need(predecessor_id != candidate_id)
        predecessor = [row for row in rows if row["operationId"] == predecessor_id]
        _need([row["phase"] for row in predecessor] == ["promotion-pending", "prepared",
              "execute-pending", "settled-success"])
        first = predecessor[0]["payload"]
        _need(first["stage"] == "external-testing" and first["candidateOperationId"] == candidate_id
              and first["candidateSha256"] == payload["candidateSha256"]
              and first["predecessorOperationId"] == candidate_id
              and first["predecessorReceiptSha256"] == candidate[-1]["payload"]["receiptSha256"]
              and predecessor[1]["payload"]["candidateSha256"] == payload["candidateSha256"])
    return candidate, predecessor


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result)
        result[key] = value
    return result


def _constant(_):
    raise LocalJournalError()


def _decode(raw, enrollment, key):
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_RECORD_BYTES and raw.endswith(b"\n")
          and raw.count(b"\n") == 1)
    try:
        row = json.loads(raw, object_pairs_hook=_pairs,
                         parse_constant=_constant)
        _need(type(row) is dict and set(row) == _FIELDS
              and row["documentType"] == "local-release-journal" and row["origin"] == "local-desktop"
              and type(row["schemaVersion"]) is int and row["schemaVersion"] == 1
              and _enrollment({k: row[k] for k in _ENROLLMENT}) == enrollment
              and _int(row["sequence"], MAX_ENTRIES)
              and (row["previousSha256"] is None or _sha(row["previousSha256"]))
              and (row["operationId"] is None or _uuid(row["operationId"])) and _sha(row["mac"]))
        _payload(row["phase"], row["payload"])
        _need(canonical(row) + b"\n" == raw)
        payload = {k: v for k, v in row.items() if k != "mac"}
        expected = hmac.digest(key, _DOMAIN + canonical(payload), "sha256").hex()
        _need(hmac.compare_digest(expected, row["mac"]))
        return row
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise LocalJournalError() from None


class LocalReleaseJournal(_Custodian):
    """Disk/authentication prerequisite, NOT an executable release capability.

    `_append` is private orchestration storage. Its returned head is DATA only:
    the external original owner must independently settle the native anchor and
    fresh authorization. In particular disk-only rollback can parse successfully.
    """
    _leaf_pattern = re.compile(r"[0-9]{4}\.json\Z", re.ASCII)
    _max_entries = MAX_ENTRIES
    _max_total_bytes = MAX_ENTRIES * MAX_RECORD_BYTES

    def __init__(self, home, *, end, enrollment, key):
        self.enrollment = _enrollment(enrollment)
        _need(type(key) is bytes and len(key) == 32)
        super().__init__(home, end=end)
        self.suffix = (".local", "share", "mobile-release-kit", "local-releases", enrollment["projectLocator"])
        _need(len(self.parts) + len(self.suffix) <= MAX_PATH_COMPONENTS
              and len(("/" + "/".join((*self.parts, *self.suffix))).encode("utf-8")) <= MAX_PATH_BYTES)
        self._key = bytearray(key)  # Only this owned copy is erased at close.
        self._close_errors = ()
        self.failed = False
        self._rows = []
        self._operations = {}
        self._existing_only = False

    def _may_create_directory(self):
        return not self._existing_only

    def open_existing(self):
        _need(not self.opened and not self.closed)
        self._existing_only = True
        return self.open()

    def history_summary(self):
        self._point()
        self._post()
        result = []
        final = {row["operationId"]: row for row, _ in self._rows if row["operationId"] is not None}
        _need(len(final) <= MAX_OPERATIONS)
        for operation, row in final.items():
            result.append({"operationId": operation, "phase": row["phase"],
                           "recoveryRequired": row["phase"] not in {"settled-success", "settled-failure", "target-reconciled"}})
        return result

    def _leaf_limit(self, name):
        return MAX_RECORD_BYTES

    def _point(self):
        _need(self.opened and not self.closed and not self.failed and self.root is not None)
        self._time()

    def open(self):
        try:
            _need(not self.failed)
            return super().open()
        except BaseException:
            self.failed = True
            raise

    def _close(self, fd):
        try:
            super()._close(fd)
        except BaseException:
            self.failed = True
            raise

    def _accept(self, row, raw):
        sequence = len(self._rows) + 1
        _need(row["sequence"] == sequence and row["previousSha256"] == (
            None if not self._rows else self._rows[-1][1]))
        phase, operation = row["phase"], row["operationId"]
        if sequence == 1:
            _need(phase == "genesis" and operation is None)
        else:
            _need(phase != "genesis" and operation is not None)
            last = self._rows[-1][0]
            # Unknown Store/checkpoint effects cannot be hidden by a new ID.
            _need(last["phase"] != "reconciliation-required" or phase=='target-reconciled')
            if phase=='target-reconciled':
                rows=recovery_chain([r for r,_ in self._rows if r['operationId']==operation],operation)
                _need(operation==last['operationId'])
                old,new=rows[4]['payload'],row['payload']
                _need(new['executeAuthorizationId']==old['authorizationId']
                      and new['assignmentRevision']==old['assignmentRevision']
                      and new['intentSha256']==old['intentSha256']
                      and all(r['payload'].get('recoveryAuthorizationId')!=new['recoveryAuthorizationId'] for r,_ in self._rows))
            elif phase == "promotion-pending":
                promotion_lineage([existing for existing, _ in self._rows],
                                  operation_id=operation, payload=row["payload"])
            elif phase == "inputs-pending":
                _need(operation not in self._operations and len(self._operations) < MAX_OPERATIONS
                      and last["phase"] in {"genesis", "settled-success", "settled-failure", "target-reconciled"})
            else:
                _need(operation == last["operationId"] and last["phase"] in _NEXT)
                if phase in ("settled-failure", "reconciliation-required"):
                    _need(row["payload"]["phase"] == last["phase"])
                else:
                    _need(_NEXT[last["phase"]] == phase)
                    for name in ("candidateSha256", "intentSha256"):
                        if name in last["payload"] and name in row["payload"]:
                            _need(last["payload"][name] == row["payload"][name])
        return hashlib.sha256(raw).hexdigest()

    def _retain(self, row, digest):
        self._rows.append((row, digest))
        if row["operationId"] is not None:
            self._operations[row["operationId"]] = row["phase"]

    def _load(self):
        names = self._names()
        _need(names == {f"{n:04d}.json" for n in range(1, len(names) + 1)})
        for name in sorted(names):
            raw = self._read(name)
            row = _decode(raw, self.enrollment, self._key)
            self._retain(row, self._accept(row, raw))
        _need(self._names() == names)

    def head(self):
        try:
            self._point()
            self._post()
            return {"sequence": len(self._rows), "sha256": self._rows[-1][1] if self._rows else None}
        except BaseException:
            self.failed = True
            raise

    def _append(self, *, expected_head, operation_id, phase, payload):
        """Durable storage only. No subsequent native/Store action is started."""
        try:
            _need(type(expected_head) is dict and set(expected_head) == {"sequence", "sha256"}
                  and _int(expected_head["sequence"], MAX_ENTRIES, 0)
                  and (expected_head["sha256"] is None or _sha(expected_head["sha256"]))
                  and (operation_id is None or _uuid(operation_id))
                  and expected_head == self.head() and len(self._rows) < MAX_ENTRIES)
            _payload(phase, payload)
            row = {"documentType": "local-release-journal", "schemaVersion": 1, "origin": "local-desktop",
                   **self.enrollment, "sequence": len(self._rows) + 1, "previousSha256": expected_head["sha256"],
                   "operationId": operation_id, "phase": phase, "payload": payload}
            row["mac"] = hmac.digest(self._key, _DOMAIN + canonical(row), "sha256").hex()
            raw = canonical(row) + b"\n"
            row = _decode(raw, self.enrollment, self._key)  # Detach all caller-owned nested values.
            digest = self._accept(row, raw)
            self._create(f"{row['sequence']:04d}.json", raw)
            self._retain(row, digest)  # Only after actual file/parent fsync/readback/close.
            return self.head()
        except BaseException:
            self.failed = True
            raise

    def close(self):
        _need(not self.closed)
        self.closed = True
        errors = []
        try:
            try:
                if self.root is not None:
                    self._post()
            except BaseException as error:
                errors.append(error)
            while self.ancestors:
                fd, _, _, _ = self.ancestors.pop()  # Retire once before close.
                try:
                    self._close(fd)
                except BaseException as error:
                    errors.append(error)  # Still attempt every independent original.
            self.root = None
        finally:
            self._key[:] = b"\0" * len(self._key)
            self._close_errors = tuple(errors)
        if errors:
            self.failed = True
            fatal = next((error for error in errors if not isinstance(error, Exception)), None)
            if fatal is not None:
                raise fatal
            raise LocalJournalError() from None
