"""Same iOS invocation/source/metadata composition, not a second build owner."""
from __future__ import annotations
from contextlib import contextmanager
import hashlib
import json
import os
import re
from .local_release_candidate import LocalCandidateError, _need
from .local_release_source import LocalSourceObservation, _retain_source
from .local_release_metadata import LocalMetadataSource
from .local_ios_candidate import LocalIOSBuildHandoff
from .build_inputs import FiniteScratch


class IOSCandidateComposition:
    def __init__(self, owner):
        from .local_ios_candidate_create import IOSCandidateCreateRun
        _need(type(owner) is IOSCandidateCreateRun and owner.composition is None)
        self.owner = owner; self.run = owner.run
        self.source = self.source_binding = self.metadata = self.metadata_scratch = self.metadata_snapshot = None
        self.handoff = LocalIOSBuildHandoff(self.run)
        self.handoff._candidate_owner = owner
        self._source_rows = []; self._source_pending = None
        self.failed = self.source_closed = False
        self.bundle_id = None
        self.signing_record = None
        self.quote = None
        owner.composition = self
        self.run.operation._local_candidate = self

    def _owner(self):
        _need(self.owner.composition is self and self.run._candidate_inputs is self.owner
              and self.run.operation._local_candidate is self)
        self.run.operation.owner()

    def _fail(self, error=None):
        self._owner(); self.failed = True; self.handoff._fail()
        if error is not None:
            self.owner.remember(error)

    def _settled_source_calls(self):
        return sum(row['settled'] for row in self._source_rows)

    def _facts(self):
        op = self.run.operation; facts = self.run.guard.lifetime_ledger.verdict()
        _need(op.signing.commands_settled() and facts.complete and facts.cleanup_complete
              and facts.contained and not facts.fatal
              and facts.commands == len(op.signing.commands) + self._settled_source_calls()
              and facts.profile_calls == len(op.signing.profiles))
        return facts

    def _arm_source(self, source, arguments, timeout, limit):
        self._owner(); op = self.run.operation
        _need(source is self.source and source._composition is self and source.execution_source is None
              and source.endpoint == self.run.source.work_end and not self.failed and not self.owner.closed
              and self._source_pending is None and op._pending is None and len(self._source_rows) < 8)
        index = len(self._source_rows)
        if index < 6:
            _need(not op.prepared and all(v in {'new', 'not-configured'} for v in op._roles.values())
                  and self.run.source.material is None and not op.signing.commands and not op.signing.profiles)
        else:
            self._metadata_cut()
        initial = ((['config', '--local', '--no-includes', '--null', '--list'], 65536),
            (['rev-parse', '--shared-index-path', 'HEAD', 'HEAD^{tree}'], 1024),
            (['ls-files', '--stage', '-z'], 2 << 20), (['ls-files', '-v', '-z'], 2 << 20))
        if index < 4:
            _need(arguments == initial[index][0] and limit == initial[index][1])
        elif index == 4:
            _need(len(arguments) == 5 and arguments[:4] == ['ls-tree', '-r', '-z', '--full-tree']
                  and re.fullmatch(r'[0-9a-f]{40}', arguments[4]) is not None and limit == 2 << 20)
        else:
            _need(arguments == ['status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignore-submodules=none']
                  and limit == 2 << 20)
        facts = self._facts()
        row = {'before': facts.commands, 'attempted': False, 'returned': False, 'settled': False,
               'code': None, 'slot': None, 'command': None, 'timeout': timeout, 'limit': limit}
        self._source_rows.append(row); self._source_pending = row

    def _bind_source_command(self, source, argv, environment):
        self._owner(); row = self._source_pending
        _need(source is self.source and row is not None and row['command'] is None)
        row['command'] = (tuple(argv), dict(environment))

    def source_command(self, argv, *, environ, cwd, timeout, capture, text, cleanup, scope, binding, evidence, on_start):
        self._owner(); row = self._source_pending
        _need(row is not None and row['command'] is not None and not row['attempted']
              and tuple(argv) == row['command'][0] and environ == row['command'][1]
              and cwd == self.run.operation.root and capture is True and text is False and cleanup is False
              and scope is binding is evidence is on_start is None and not self.failed
              and type(timeout) is int and 0 < timeout <= row['timeout'] <= 10)
        self.source._unchanged()
        row['attempted'] = True
        return timeout, row['limit']

    def bind_slot(self, engine, slot):
        from ._command_process import CommandOutcomeSlot, _Outer
        self._owner(); row = self._source_pending
        _need(row is not None and row['attempted'] and row['slot'] is None
              and type(engine) is _Outer and type(slot) is CommandOutcomeSlot
              and engine.guard is self.run.guard and engine.owns is False
              and engine.scope is engine.binding is engine._store_timing is None
              and engine.slot is slot and slot._engine is engine and slot._scope is None
              and slot._nonce == engine.nonce and slot.read() is None
              and self.run.guard.lifetime_ledger._command is slot)
        row['slot'] = slot

    def _outcome(self, row):
        from ._desktop_ios_signed_operation import original_outcome
        return original_outcome(row['slot'], self.run.guard, None, None)

    def _source_returned(self, source, result):
        self._owner(); row = self._source_pending
        _need(source is self.source and row is not None and row['attempted'])
        outcome = self._outcome(row); facts = self.run.guard.lifetime_ledger.verdict()
        _need(outcome is not None and outcome.result_integrity == 'complete'
              and outcome.termination == 'normal-exit' and outcome.returncode == result.returncode
              and facts.complete and facts.cleanup_complete and facts.contained and not facts.fatal
              and facts.commands == row['before'] + 1)
        row.update(returned=True, settled=True, code=result.returncode, count=1)
        self._source_pending = None
        self._facts()
        if result.returncode != 0:
            self._fail()

    def _source_error(self, source, error):
        self._owner(); row = self._source_pending
        _need(source is self.source and row is not None)
        facts = self.run.guard.lifetime_ledger.verdict()
        count = facts.commands - row['before']
        _need(count in {0, 1})
        row['count'] = count
        row['settled'] = bool(row['attempted'] and self._outcome(row) is not None
            and facts.complete and facts.cleanup_complete and facts.contained and not facts.fatal
            and facts.commands == row['before'] + 1)
        self._source_pending = None; self._fail(error)

    def source_settled(self):
        self._owner()
        return self._source_pending is None and all(not r['attempted'] or r['settled']
            and self._outcome(r) is not None for r in self._source_rows)

    def _metadata_cut(self):
        self._owner(); op = self.run.operation; signing = op.signing
        _need(not self.failed and not op.close_claimed and op.inputs is not None
              and op.commands_settled() and op.snapshot_closed() and signing.inputs_closed()
              and signing.session is not None and signing.session.closed and signing.session._disposal_complete
              and signing.session.fd is None and signing.session.native_fd is None and signing.lease.active is None
              and op.files.work_disposition() == 'removed')

    def metadata_quote(self, directories, scratch):
        self.quote = self.owner.reserve(metadata_directories=directories, scratch=scratch)
        return self.quote['total']

    @contextmanager
    def source_scope(self, bound):
        self._owner(); op = self.run.operation
        _need(self.source is None and op.inputs is bound and op.invocation.project_owner is not None)
        self.source = LocalSourceObservation(op.invocation, bound.saved.configuration.raw, bound.saved.version_raw,
                                             self.run.source.work_end, None)
        self.source._composition = self
        self.metadata = LocalMetadataSource(self.source, platform='ios')
        self.metadata_scratch = FiniteScratch('store-metadata', self.run.guard, op.root / '.mobile-release')
        self.bundle_id = bound.saved.configuration.bundle_id
        self.quote = self.owner.reserve(metadata_directories=0, scratch=self.metadata_scratch)
        try:
            with _retain_source(self.source):
                observed = self.source.observed
                self.source_binding = {"commit": observed.commit, "tree": observed.tree,
                                       "ref": observed.ref, "branch": observed.branch}
                self.metadata._reserve_ios(self, self.metadata_scratch)
                self.owner.before_build(bound)
                yield
            _need(self.source.closed and all(all(s.state in {'UNACQUIRED', 'CLOSED'}
                for s in reader.descriptors) for reader in self.source.readers))
            for reader in self.source.readers:
                reader.assert_closed()
            self.source_closed = True
        except BaseException as error:
            self._fail(error); raise

    def before_capture(self):
        self._metadata_cut()
        _need(self.source.calls == 6 and self.metadata_snapshot is None)
        self.metadata_scratch.acquire()
        self.metadata_snapshot = self.metadata_scratch.metadata_archive(self.metadata.root, platform='ios', _source=self.metadata)
        _need(self.source.calls == 7)
        self.metadata_scratch.require(self.metadata_snapshot)

    def metadata_closed(self):
        from .local_candidate_create import CandidateCreateRun
        return self.metadata is None or CandidateCreateRun._metadata_closed(self.metadata)

    def metadata_data(self):
        self._owner()
        _need(self.metadata_snapshot is not None and self.metadata.final_post and self.metadata.closed
              and not self.metadata.failed and self.source_closed and self.metadata_closed())
        self.metadata_scratch.require(self.metadata_snapshot)
