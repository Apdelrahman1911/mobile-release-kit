"""Three exclusive siblings beside the SAME iOS archive/IPA; never copy them."""
from __future__ import annotations
import hashlib
import json
import os
import stat
from .build_inputs import _file
from .local_candidate_publish import CandidateBundlePublisher
from .local_candidate_bundle import MANIFEST, MANIFEST_BYTES, need
from .local_release_journal import canonical
from .local_ios_candidate_bundle import SCOPE, archive_digest, manifest_data, summary_data, signing_data


class IOSCandidatePublisher(CandidateBundlePublisher):
    """Reuse only the existing bounded writer/positive-close machinery.

    No Android constructor, AAB reader, registry or artifact permission is used.
    The exact iOS owner supplies its independently retained original namespace.
    """
    def __init__(self, owner):
        from .local_ios_candidate_create import IOSCandidateCreateRun
        need(type(owner) is IOSCandidateCreateRun and owner.publisher is None and owner.build_settled)
        self.owner = owner; self.guard = owner.guard; self.handoff = owner.composition.handoff
        self.names = {'archive.xcarchive', 'export'}; self.files = []; self.source = None
        self.iterator = None; self.scan_state = 'new'; self.closed = self.failed = False
        self.summary = self.digest = None
        owner.publisher = self

    def point(self):
        need(not self.closed and not self.failed and self.owner.publisher is self)
        self.owner.point(); self.handoff._candidate_check(self.owner)
        for name, slot, expected in self.files:
            if expected is not None:
                actual = os.fstat(slot.number)
                named = os.stat(name, dir_fd=self.parent_number(), follow_symlinks=False)
                need(not getattr(actual, 'st_flags', 0) and not getattr(named, 'st_flags', 0)
                     and _file(actual) == expected == _file(named))

    def parent_number(self):
        return self.handoff.parent.fd

    def scan(self):
        self.point(); need(self.scan_state in {'new', 'closed'}); self.scan_state = 'acquiring'
        try:
            self.iterator = os.scandir(self.parent_number()); self.scan_state = 'open'; names = []
            for entry in self.iterator:
                self.point(); need(len(names) < 5); names.append(entry.name)
            need(len(names) == len(self.names) and set(names) == self.names)
        finally:
            if self.iterator is not None:
                original, self.iterator = self.iterator, None; self.scan_state = 'closing'
                try:
                    original.close()
                except BaseException as error:
                    self.scan_state = 'unknown'; self.guard._abort(error); raise
                self.scan_state = 'closed'
            elif self.scan_state == 'acquiring':
                self.scan_state = 'unknown'; self.failed = True

    def publish(self):
        self.scan(); parent = os.fstat(self.parent_number())
        need(stat.S_ISDIR(parent.st_mode) and stat.S_IMODE(parent.st_mode) == 0o700
             and parent.st_uid == os.getuid() == os.geteuid() and not getattr(parent, 'st_flags', 0))
        comp = self.owner.composition; h = self.handoff; snapshot = comp.metadata_snapshot
        need(0 < snapshot.size <= 512 << 20)
        free = os.fstatvfs(self.parent_number())
        need(free.f_bavail * free.f_frsize >= snapshot.size + 65536 + MANIFEST_BYTES)
        # Second reads, against original pre-close inventory AND inode table.
        inventory = h._candidate_inventory(self.owner)
        for _ in h._candidate_blocks(self.owner):
            pass
        archive = {'directory': 'archive.xcarchive', 'entries': len(inventory),
            'bytes': sum(v.size for v in inventory.values() if v is not None), 'sha256': archive_digest(inventory)}
        rows = [{'fileName': 'export/' + h.ipa.name, 'bytes': h._ipa_inventory.size,
                 'sha256': h._ipa_inventory.sha256}]
        blocks = self._metadata_blocks()
        try:
            rows.append(self._write('store-metadata.zip', blocks, size=snapshot.size, expected=snapshot.sha256))
        finally:
            blocks.close()
        report = h._result; need(0 < len(report) <= 65536)
        rows.append(self._write('validation-report.json', self._bytes(report), size=len(report),
                                expected=hashlib.sha256(report).hexdigest()))
        build = json.loads(report); saved = build['usedVersion']
        record = comp.signing_record
        need(record is not None and record[0] is self.owner.run.operation._ipa
             and record[1] == _file(os.fstat(h.ipa.slot.number))
             and record[2] == h._ipa_inventory)
        signing = signing_data(json.loads(record[3]))
        manifest = {'schemaVersion': 1, 'scope': SCOPE, 'operationId': self.owner.operation_id,
            'enrollment': self.owner.enrollment, 'sourceCommit': comp.source_binding['commit'],
            'sourceTree': comp.source_binding['tree'], 'savedConfig': build['usedConfig'], 'savedVersion': saved,
            'bundleId': comp.bundle_id, 'signing': signing, 'files': rows, 'archive': archive}
        raw = canonical(manifest) + b'\n'
        manifest_data(raw, operation_id=self.owner.operation_id, enrollment=self.owner.enrollment,
                      pending=self.owner.pending_payload)
        self.digest = hashlib.sha256(raw).hexdigest()
        self._write(MANIFEST, self._bytes(raw), size=len(raw), expected=self.digest)
        self.summary = summary_data({'operationId': self.owner.operation_id, 'candidateSha256': self.digest,
            'sourceCommit': manifest['sourceCommit'], 'sourceTree': manifest['sourceTree'], 'bundleId': comp.bundle_id,
            'version': {k: saved[k] for k in ('name', 'build')}, 'files': rows, 'archive': archive,
            'observation': 'current-bundle-only', 'priorCreateFinality': 'not-established'})
        self.scan(); return self.digest

    def post(self):
        self.point(); need(self.summary is not None and len(self.files) == 3)
        need(archive_digest(self.handoff._candidate_inventory(self.owner)) == self.summary['archive']['sha256'])
        for _ in self.handoff._candidate_blocks(self.owner):
            pass
        expected = {row['fileName']: row for row in self.summary['files'][1:]}
        expected[MANIFEST] = {'bytes': self.files[-1][2]['size'], 'sha256': self.digest}
        for name, slot, _ in self.files:
            need(self._hash(slot.number, expected[name]['bytes']) == expected[name]['sha256'])
        self.scan()
