"""Actual iOS Create on the existing signed operation and original project loan."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
from uuid import UUID
from . import _desktop_ios_archive_protocol as wire
from . import local_ios_candidate_protocol as candidate
from .build_inputs import _attempt_all
from .local_candidate_create import _CreateJournal, CandidateCreateRun
from .local_release_candidate import LocalCandidateError, _need
from .local_release_journal import MAX_ENTRIES, LocalJournalError


class IOSCandidateCreateRun:
    def __init__(self, engine):
        from ._desktop_ios_archive_engine import _Engine
        from .desktop_ios_archive import IOSArchiveRun
        from ._desktop_candidate_input_control import CandidateCreateInput
        _need(type(engine) is _Engine and engine.candidate is None and type(engine.service) is IOSArchiveRun
              and wire.candidate_create(engine.request.context) and type(engine.input.candidate_input) is CandidateCreateInput)
        self.engine = engine; self.run = engine.service; self.source = engine.input; self.guard = engine.guard
        self.request = self.run.request; self.input = self.source.candidate_input
        self.operation_id = str(UUID(hex=self.request.operation_id))
        self.request_binding = wire._encode(wire._request_binding(self.request))
        self.composition = self.publisher = None
        self.journals = []; self.key = self.enrollment = None
        self.pending_head = self.pending_payload = self.root_identity = None
        self.project_ancestry = ()
        self.build_settled = self.closing = self.closed = False
        self.failure = self.result = self.quote = None
        self.descriptors = set(); self.fd_peak = 0; self.non_fd_reserve = 64
        engine.candidate = self.run._candidate_inputs = self
        from .local_ios_candidate_source import IOSCandidateComposition
        IOSCandidateComposition(self)

    def point(self):
        _need(self.engine.candidate is self and self.run._candidate_inputs is self and not self.closed
              and not self.closing and self.input.request is self.request
              and wire._encode(wire._request_binding(self.request)) == self.request_binding)
        self.guard.check(); self.input.post()
        _need(self.source.require_operation() is self.run.operation)

    def register_descriptor(self, slot):
        # The original _FD remains sole acquisition/close owner; this is only
        # the same fixed candidate's aggregate pre-open accounting.
        _need(slot.guard is self.guard and slot.open_state == 'NEW' and slot.number is None
              and not self.closed and self.engine.candidate is self)
        self.descriptors = {s for s in self.descriptors if s.close_state != 'CLOSED'}
        self.descriptors.add(slot)

    def preopen(self, slot):
        _need(slot in self.descriptors and slot.guard is self.guard and slot.open_state == 'NEW'
              and not self.closed)
        live = sum(s.open_state != 'NEW' and s.close_state != 'CLOSED' for s in self.descriptors)
        _need(live + 1 + self.non_fd_reserve <= 256)
        self.fd_peak = max(self.fd_peak, live + 1 + self.non_fd_reserve)

    def reserve(self, *, metadata_directories, scratch):
        self.point(); comp = self.composition
        _need(comp.source is not None and type(metadata_directories) is int and metadata_directories >= 0)
        source = comp.source.descriptor_quote()
        journal = len(Path(self.request.native['candidateHistory']['home']).parts) + 7
        metadata = metadata_directories + 3  # held directories + leaf + reader/iterator overlap
        # Sum, not a max: ordinary _command_process parent 12 IO +8 native
        # duplicates; _profile_process._Outer 2 nulls+3pipes+8 native duplicates;
        # ios_profiles scratch 3; local_signing home/hold/session/native/profile
        # directory replacement/staging/read/iterator conservatively10; stdio,
        # input/import baseline8; inherited project loan1; six spare transients.
        # These raw originals remain reserved on every failure/cleanup path.
        external = 64 + source + metadata + journal
        live = sum(s.open_state != 'NEW' and s.close_state != 'CLOSED' for s in self.descriptors)
        op = self.run.operation
        # Fixed projected roots/tools and original cleanup descent must have
        # room before signing. Deep/unusual output still meets the same checked
        # per-open aggregate rather than inheriting old192+snapshot142 caps.
        tools = sum(len(Path(op.request.native['toolchain'][k]).parts) for k in ('developerDir', 'sdk')) + 3
        minimum = 3 + tools + 16 + 33 + len(scratch.parent.path.parts) + 3
        _need(external + live + minimum <= 256)
        self.non_fd_reserve = max(self.non_fd_reserve, external)
        self.quote = {'source': source, 'metadata': metadata, 'journal': journal, 'raw': 64,
                      'minimumKnownFuture': minimum, 'total': 256}
        return dict(self.quote)

    def before_build(self, bound):
        self.point(); comp = self.composition; op = self.run.operation
        _need(comp.source.calls == 6 and comp.source_binding is not None and self.quote is not None
              and not self.journals and op.inputs is bound and self.source.material is None
              and all(v in {'new', 'not-configured'} for v in op._roles.values()))
        project = op.invocation._original_project
        self.project_ancestry = tuple((v.st_dev, v.st_ino) for v in (os.fstat(s.number) for s in project.directory.slots))
        self.enrollment, self.key = self.input.exchange('lease-ready', {})
        _need(type(self.key) is bytearray and len(self.key) == 32)
        journal = self._open_journal(); head = journal.head(); last = journal._rows[-1][0] if journal._rows else None
        if last is None or last['phase'] not in {'genesis', 'settled-success', 'settled-failure', 'target-reconciled'}:
            self.failure = 'recovery-required'; raise LocalCandidateError('Local candidate history requires recovery')
        _need(head['sequence'] <= MAX_ENTRIES - 2 and self.operation_id not in journal._operations
              and len(journal._operations) < 64)
        self.input.exchange('history-head', head); self.point(); _need(journal.head() == head)
        self.pending_payload = {'configurationSha256': hashlib.sha256(bound.saved.configuration.raw).hexdigest(),
            'versionSha256': hashlib.sha256(bound.saved.version_raw).hexdigest(),
            'sourceCommit': comp.source_binding['commit'], 'sourceTree': comp.source_binding['tree']}
        self.pending_head = journal._append(expected_head=head, operation_id=self.operation_id,
                                            phase='inputs-pending', payload=self.pending_payload)
        self.input.exchange('inputs-pending', self.pending_head); self.point(); _need(journal.head() == self.pending_head)
        CandidateCreateRun._retire_journal(journal)

    def _open_journal(self):
        self.point(); _need(len(self.journals) < 2 and self.enrollment is not None and self.key is not None)
        journal = _CreateJournal(self); self.journals.append(journal); journal.open_existing()
        root = os.fstat(journal.root)
        observed = (root.st_dev, root.st_ino, root.st_mode, root.st_uid, root.st_gid)
        if self.root_identity is None:
            self.root_identity = observed
        else:
            _need(observed == self.root_identity)
        genesis = journal._rows[0][0]['payload']['rootIdentity'] if journal._rows else None
        native = self.request.native['rootIdentity']
        _need(genesis == {'device': int(native['device']), 'inode': int(native['inode']),
            'mode': native['mode'] & 0o7777, 'uid': native['uid'], 'gid': native['gid']})
        return journal

    def _build_cut(self):
        self.point(); comp = self.composition; op = self.run.operation
        _need(not self.build_settled and self.run._run_claimed and self.run._close_claimed and self.run.primary is None
              and op.closed() and op.signing.account_closed() and op.signing.inputs_closed()
              and self.pending_head is not None and self.input.reply_step == 3
              and all(j.closed and not j.ancestors and not j._close_errors for j in self.journals)
              and comp.source_closed and not comp.failed and len(comp._source_rows) == 8
              and all(r['returned'] and r['code'] == 0 for r in comp._source_rows)
              and comp.source_settled() and not self.source.closed and self.guard.handler_state != 'RESTORED')
        comp._facts(); comp.metadata_data(); h = comp.handoff
        _need(h.captured and not h.failed and not h.closed and not h.producer_joined and not h._reading
              and h._result == wire._encode(self.run._candidate))
        h._post(); self.build_settled = True

    def finish_build(self):
        self._build_cut(); journal = self._open_journal()
        _need(journal.head() == self.pending_head and journal._rows[-1][0]['operationId'] == self.operation_id
              and journal._rows[-1][0]['phase'] == 'inputs-pending'
              and journal._rows[-1][0]['payload'] == self.pending_payload)
        from .local_ios_candidate_publish import IOSCandidatePublisher
        publisher = IOSCandidatePublisher(self); digest = publisher.publish()
        ready = journal._append(expected_head=self.pending_head, operation_id=self.operation_id,
                                phase='inputs-ready', payload={'candidateSha256': digest})
        self.input.exchange('inputs-ready', ready); self.point(); _need(journal.head() == ready)
        publisher.post(); self.point()
        report = {'schemaVersion': 1, 'scope': 'local-ios-candidate-inputs', 'headSequence': ready['sequence'],
                  'candidateInputs': json.loads(json.dumps(publisher.summary)), 'build': json.loads(comp_result(self))}
        self.close(); _need(self.originals_closed())
        self.result = report

    def remember(self, error):
        if self.failure is None:
            self.failure = 'journal-unavailable' if isinstance(error, LocalJournalError) else 'candidate-inputs-unavailable'

    def close(self):
        if self.closed:
            _need(self.originals_closed()); return
        self.closing = True; actions = []
        if self.publisher is not None and not self.publisher.closed:
            actions.append(self.publisher.close)
        actions.extend(j.close for j in self.journals if not j.closed)
        comp = self.composition
        if comp is not None:
            if comp.metadata is not None and not comp.metadata.closed:
                actions.append(comp.metadata._close)
            if comp.metadata_scratch is not None:
                actions.append(comp.metadata_scratch.cleanup)
            actions.append(lambda: comp.handoff._candidate_close(self))
        try:
            _attempt_all(self.guard, actions)
        except BaseException as error:
            self.remember(error); self.guard._abort(error); raise
        finally:
            if self.key is not None:
                self.key[:] = b'\0' * len(self.key)
            self.closed = True
        _need(self.originals_closed())

    def original_flags(self):
        comp = self.composition; h = None if comp is None else comp.handoff
        retained = (comp is None or h.closed and not h.iterators and all(r.slot.close_state == 'CLOSED' for r in h.originals)
            and (h.parent is None or all(s.close_state == 'CLOSED' for s in h.parent.slots))
            and comp.metadata_closed() and (comp.metadata_scratch is None or CandidateCreateRun._scratch_closed(comp.metadata_scratch)))
        publisher = self.publisher is None or self.publisher.originals_closed()
        journal = all(j.closed and not j.ancestors and not j._close_errors for j in self.journals)
        return {'candidateInputsClosed': bool(self.closed and retained and publisher),
                'journalClosed': bool(self.closed and journal and (self.key is None or not any(self.key))),
                'leaseClosed': self.input.closed}

    def originals_closed(self):
        flags = self.original_flags()
        return flags['candidateInputsClosed'] and flags['journalClosed']

    def terminal(self, base):
        flags = self.original_flags(); comp = self.composition
        value = {**base, 'lifetime': {**base['lifetime'], **flags, 'sourceCommands': sum(r.get('count', 0) for r in comp._source_rows)}}
        if not all(flags.values()):
            value.update(outcome='unknown', reason='cleanup-unknown', result=None)
            if value['disposition']['output'] == 'retained-local-result':
                value['disposition'] = {**value['disposition'], 'output': 'retained-incomplete'}
        elif base['outcome'] == 'complete':
            _need(self.result is not None and self.build_settled and self.result['build'] == base['result'])
            value['result'] = self.result
        elif self.failure is not None and base['reason'] == 'protocol-error':
            value['reason'] = self.failure
        candidate.terminal(value, self.request)
        return value


def comp_result(owner):
    return owner.composition.handoff._result
