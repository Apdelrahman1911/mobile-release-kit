"""Canonical primary export on the SAME History original; no transport/runner.

Native owns the fixed destination and final publication. These functions only
verify the original handoff and write its two already-held candidate inodes.
"""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from ._desktop_github_history_protocol import (
    _identity, canonical, require,
)
from .build_inputs import _FD
from .github_history import GIB, MIB, _hex, _integer, _keys

CONSENT = "github-candidate-primary-download-v1"
RECEIPT = "download-receipt.json"
RECEIPT_LIMIT = 4096
DESTINATION_RESERVE = GIB + MIB


def names(selection):
    require(selection.stage == "candidate" and selection.platform in ("android", "ios"))
    final = f"candidate-{selection.run_id}-attempt-{selection.attempt}-{selection.platform}"
    return final, "." + final + ".pending", "app-release.aab" if selection.platform == "android" else "app.ipa"


def native(value, context):
    """Closed private initial DATA. Only native admission supplies these pins."""
    names(context.selection)
    row = _keys(value, ("consentVersion", "parentIdentity", "stagingIdentity", "primaryIdentity", "receiptIdentity"))
    require(row["consentVersion"] == CONSENT)
    out = {"consentVersion": CONSENT}
    for key in ("parentIdentity", "stagingIdentity", "primaryIdentity", "receiptIdentity"):
        directory = key in ("parentIdentity", "stagingIdentity")
        identity = _identity(row[key], directory=directory)
        require(identity["mode"] == (stat.S_IFDIR | 0o700 if directory else stat.S_IFREG | 0o600))
        if not directory:
            require(identity["bytes"] == "0" and identity["flags"] == 0)
        out[key] = identity
    require(len({(v["device"], v["inode"]) for k, v in out.items() if k != "consentVersion"}) == 4
            and len({v["uid"] for k, v in out.items() if k != "consentVersion"}) == 1)
    return out


def candidate(value, context):
    row = _keys(value, ("primarySha256", "primaryBytes", "receiptSha256", "receiptBytes"))
    names(context.selection)
    _hex(row["primarySha256"], 64); _hex(row["receiptSha256"], 64)
    _integer(row["primaryBytes"], 1, GIB)
    _integer(row["receiptBytes"], 1, RECEIPT_LIMIT)
    return dict(row)


def _stable(observed):
    return (observed.st_dev, observed.st_ino, observed.st_mode, observed.st_uid,
            observed.st_gid, observed.st_nlink, getattr(observed, "st_flags", 0))


class Download:
    """A facet of one retained HistoryOperation, never a second IO owner."""

    def __init__(self, operation):
        operation.require_owner()
        require(operation.request.native.get("download") is not None)
        self.operation = operation
        self.pins = native(operation.request.native["download"], operation.request.context)
        self.final, self.pending, self.primary = names(operation.request.context.selection)
        self.parent = self.staging = None
        self.files = []
        self.entered = self.finished = False
        self.handoff = self.handoff_path = None
        self.handoff_entered = False
        self.result = None

    def check(self):
        op = self.operation
        op.require_owner()
        require(op.candidate_download is self)
        op.checkpoint()

    def _directory(self, parent, name, pin):
        from .desktop_github_history import _wire_identity
        op = self.operation
        slot = _FD(op.guard)  # The original ledger retains before open.
        number = slot.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        self.check()
        require(_wire_identity(os.fstat(number), True) == pin
                and _wire_identity(os.stat(name, dir_fd=parent, follow_symlinks=False), True) == pin
                and pin["uid"] == os.geteuid())
        return slot

    def admit(self):
        self.check()
        require(self.parent is None and self.staging is None)
        op = self.operation
        # Reuse the actual held config parent (release), not a reopened chain.
        rows = [r for r in op.sources if r[0].lexical_path / r[1] == op.root / "release/mobile-release.json"]
        require(len(rows) == 1)
        release = rows[0][0]
        release.check()
        self.parent = self._directory(release.fd, "downloads", self.pins["parentIdentity"])
        self.staging = self._directory(self.parent.number, self.pending, self.pins["stagingIdentity"])
        require(op.names(self.staging.number, 2) == sorted((self.primary, RECEIPT)))
        work = next(d for d in op.directories if d.lexical_path == op.work)
        destination, scratch = os.fstatvfs(self.parent.number), os.fstatvfs(work.fd)
        for value in (destination, scratch):
            require(value.f_frsize > 0 and value.f_bavail >= 0)
        same = os.fstat(self.parent.number).st_dev == os.fstat(work.fd).st_dev
        require(destination.f_bavail * destination.f_frsize >= DESTINATION_RESERVE + (5 * GIB if same else 0)
                and scratch.f_bavail * scratch.f_frsize >= 5 * GIB)
        for name, key in ((self.primary, "primaryIdentity"), (RECEIPT, "receiptIdentity")):
            from .desktop_github_history import _wire_identity
            slot = _FD(op.guard)
            self.files.append((name, slot, key))  # Retain before the actual open.
            fd = slot.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.staging.number)
            require(_wire_identity(os.fstat(fd)) == self.pins[key]
                    and _wire_identity(os.stat(name, dir_fd=self.staging.number, follow_symlinks=False)) == self.pins[key])
        self.post()

    def post(self):
        from .desktop_github_history import _wire_identity
        self.check()
        op = self.operation
        release = next(r[0] for r in op.sources if r[0].lexical_path / r[1] == op.root / "release/mobile-release.json")
        release.check()
        require(self.parent is not None and self.staging is not None
                and _wire_identity(os.fstat(self.parent.number), True) == self.pins["parentIdentity"]
                and _wire_identity(os.stat("downloads", dir_fd=release.fd, follow_symlinks=False), True) == self.pins["parentIdentity"]
                and _wire_identity(os.fstat(self.staging.number), True) == self.pins["stagingIdentity"]
                and _wire_identity(os.stat(self.pending, dir_fd=self.parent.number, follow_symlinks=False), True) == self.pins["stagingIdentity"])
        for name, slot, key in self.files:
            held = os.fstat(slot.number)
            pin = self.pins[key]
            require((str(held.st_dev), str(held.st_ino), held.st_mode, held.st_uid, held.st_gid, str(held.st_nlink), getattr(held, "st_flags", 0))
                    == (pin["device"], pin["inode"], pin["mode"], pin["uid"], pin["gid"], pin["nlink"], 0)
                    and _stable(held) == _stable(os.stat(name, dir_fd=self.staging.number, follow_symlinks=False)))
        self.check()

    def allow_handoff(self, github, artifact, destination):
        self.check()
        require(github.history is self.operation and self.entered and not self.finished
                and not self.handoff_entered and artifact is self.handoff and destination == self.handoff_path)
        self.handoff_entered = True  # Consume before any HTTP/extraction effect.

    def _write(self, index, blocks, expected, length):
        self.post()
        _, slot, _ = self.files[index]
        require(os.fstat(slot.number).st_size == 0)
        digest, total = hashlib.sha256(), 0
        for block in blocks:
            self.check()
            require(type(block) is bytes and 0 < len(block) <= 65536)
            total += len(block)
            require(total <= length)
            digest.update(block)
            view = memoryview(block)
            while view:
                self.check()
                count = os.write(slot.number, view)
                require(type(count) is int and 0 < count <= len(view))
                view = view[count:]
        require(total == length and digest.hexdigest() == expected)
        self.check()
        os.fsync(slot.number)
        self.post()
        require(os.fstat(slot.number).st_size == length)

    def prepare(self, github, root, intent):
        from .workflow import artifact_name, _validate_handoff
        self.check()
        op = self.operation
        require(not self.entered and self.staging is not None and len(self.files) == 2
                and github.history is op and op.final_observation is not None
                and op.final_observation["outcome"] in ("mutated", "reconciled")
                and op.parsed.get(id(intent), (None,))[0] is intent)
        self.entered = True
        run = intent["authorizedBy"]["runId"]
        artifact = github.artifact(run, artifact_name("candidate", op.request.context.selection.platform, "handoff"))
        require(artifact is not None and artifact["workflow_run"]["head_sha"] == intent["operationSource"]["commit"])
        self.handoff, self.handoff_path = artifact, op.work / "handoff"
        binary_root = github.download(artifact, self.handoff_path, handoff=True)
        _validate_handoff(binary_root, op.request.context.selection.platform, intent, history=op)
        # This is the same immutable embedded proof already authenticated by
        # Verifier.final/intent; all reads still check the original extracted FD.
        proof = op.read_json(root / "operation/intent-provenance.json")
        require(proof["producer"] == intent["authorizedBy"])
        job = github.job(proof["producer"], "candidate", proof["jobKey"], proof["jobId"])
        github.verify_attestation(binary_root / self.primary, proof, job)
        records = [r for r in intent["artifacts"] if r["fileName"] == self.primary]
        require(len(records) == 1 and 0 < records[0]["size"] <= GIB)
        record = records[0]
        with op.reader(binary_root / self.primary) as reader:
            require(reader.size == record["size"])
            def blocks():
                while reader.position < reader.size:
                    yield reader.read(min(65536, reader.size - reader.position))
            self._write(0, blocks(), record["sha256"], record["size"])
        observed = op.final_observation
        receipt = canonical({"schemaVersion": 1, "assurance": "authenticated-historical-candidate-only",
            "context": op.request.context.value(), "authorizedBy": intent["authorizedBy"],
            "artifactId": str(artifact["id"]), "artifactSha256": artifact["digest"][7:],
            "candidateManifestSha256": observed["candidateManifestSha256"],
            "operationIntentSha256": observed["operationIntentSha256"], "provenanceSha256": observed["provenanceSha256"],
            "primary": {"fileName": self.primary, "bytes": record["size"], "sha256": record["sha256"]}}, RECEIPT_LIMIT)
        receipt_sha = hashlib.sha256(receipt).hexdigest()
        self._write(1, (receipt,), receipt_sha, len(receipt))
        self.post()
        require(op.names(self.staging.number, 2) == sorted((self.primary, RECEIPT)))
        self.result = candidate({"primarySha256": record["sha256"], "primaryBytes": record["size"],
            "receiptSha256": receipt_sha, "receiptBytes": len(receipt)}, op.request.context)
        self.finished = True
        # All these actual copies close through HistoryOperation.cleanup before
        # the terminal. Native-held originals independently hash/publish/close.
