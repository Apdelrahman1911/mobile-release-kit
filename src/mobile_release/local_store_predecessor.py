"""Bounded original predecessor inputs, not Store/consent or old-tail authority.

The existing Store/History owner must first admit the native journal anchor and
current candidate/source. This reader neither supplies those grants nor appends a
row. It pins the two/four literal prepared+receipt namespaces and consumes them
only after final original-byte/roster POST. No recovery/marker fallback exists.
"""
from contextlib import ExitStack
import hashlib
import json
import os
from uuid import UUID

from .build_inputs import _Directory, _StoreNamespace, _scope, _read_file
from .cancellation import DefaultCancellation
from .local_release_journal import LocalReleaseJournal, canonical, promotion_lineage, external_readiness_chain, _need
from .local_release_intent import decode_local_operation_intent, MAX_LOCAL_INTENT_BYTES
from .local_release_receipt import validate_local_execution_receipt, MAX_LOCAL_RECEIPT_BYTES
from .local_prepared_review import decode_quote, MEMORY_LIMIT, RETAINED_JOURNAL
from .provenance import canonical_json_bytes, validate_store_precondition, _reject_duplicate_pairs, external_production_blocker

_PREPARED = {'operation-intent.json': MAX_LOCAL_INTENT_BYTES, 'store-precondition.json': 4 << 20}
_METADATA_LIMIT = 512 << 20
_FACTS_LIMIT = 64 << 10


def _identity(value):
    return dict(device=value.st_dev, inode=value.st_ino, mode=value.st_mode & 0o7777,
                uid=value.st_uid, gid=value.st_gid)


class StorePredecessorInputs:
    """Private input custodian; construction is DATA-only, acquire is single-use.

    `project` is a borrowed real original Directory (normally Invocation project),
    never a Path supplied as proof. Its ownership/close remains with that caller.
    `descriptor_quote` is additive to the caller's whole remaining phase quote;
    the local floor below also counts actual borrowed project/journal originals.
    """
    def __init__(self, project, journal, guard, *, operation_id, payload, platform):
        _need(type(project) is _Directory and isinstance(journal, LocalReleaseJournal)
              and type(guard) is DefaultCancellation and project.guard is guard
              and platform in ('android', 'ios'))
        self.project, self.journal, self.guard = project, journal, guard
        self.operation_id, self.payload = operation_id, json.loads(canonical(payload))
        self.platform, self.root = platform, project.path
        self.scope = ExitStack(); self.readers = []; self.bindings = []
        self.iterator = None; self.scan_state = 'new'
        self.started = self.acquired = self.failed = self.close_claimed = self.closed = False
        self._prefix = (); self._facts = None; self.readiness_owner=None

    def descriptor_quote(self):
        _need(self.payload.get('stage') in ('external-testing', 'production-submit'))
        count = 2 if self.payload['stage'] == 'external-testing' else 5 if self.platform=='ios' else 4
        if getattr(self,'readiness_owner',None) is not None:count=5
        return count * (len(self.root.parts) + 4) + 2  # one leaf or scan plus bounded transient

    def _point(self):
        self.guard.check(); self.project.check()
        _need(not self.journal.closed and not self.journal.failed)
        self.journal.head()  # POST original journal names/bytes, no new native call.
        if self._prefix:
            _need(tuple(d for _, d in self.journal._rows[:len(self._prefix)]) == self._prefix)
        _need(self.journal._rows[0][0]['payload']['rootIdentity'] == _identity(os.fstat(self.project.fd)))

    def _names(self, out, expected):
        self._point(); out.check()
        _need(self.iterator is None and self.scan_state in ('new', 'closed'))
        self.scan_state = 'acquiring'
        try:
            self.iterator = os.scandir(out.fd); self.scan_state = 'open'; names = set()
            for entry in self.iterator:
                self._point(); out.check()
                _need(len(names) < len(expected) and entry.name in expected and entry.name not in names)
                names.add(entry.name)
            _need(names == set(expected))
        finally:
            original, self.iterator = self.iterator, None
            if original is not None:
                self.scan_state = 'closing'
                try: original.close()
                except BaseException as error:
                    self.scan_state = 'unknown'; self.guard._abort(error); raise
                self.scan_state = 'closed'
            elif self.scan_state == 'acquiring':
                self.scan_state = 'unknown'; self.guard._abort(ValueError('Predecessor scan did not settle'))
        out.check(); self._point()

    def _open(self, leaf, names):
        # Literal closed components; no caller pathname/roster admission.
        out = _StoreNamespace(self.root, self.guard, include_store=False,
            _descendants=('store', 'local', leaf), _create=False)
        self.readers.append(out)  # original registered before possible acquire
        self.scope.enter_context(_scope(out, self.guard, False))
        _need(_identity(os.fstat(out.parent.fd)) == _identity(os.fstat(self.project.fd)))
        self.bindings.append((out, names, {})); self._names(out, names)
        return out, self.bindings[-1][2]

    def _read(self, out, bindings, name, limit, *, collect=True):
        self._point(); out.check()
        observed = _read_file(out.fd, name, self.guard, limit, private=True, binding_only=not collect)
        _need(observed is not None)
        binding, raw = observed
        previous = bindings.get(name)
        _need(previous is None or previous == (binding, limit))
        if previous is None: bindings[name] = (binding, limit)
        out.check(); self._point()
        return binding, raw

    def _completed(self, rows, stage, *, readiness=False):
        operation_id = rows[0]['operationId']; later = stage != 'candidate'
        names = dict(_PREPARED)
        if later: names['store-metadata.zip'] = _METADATA_LIMIT
        out, bindings = self._open(UUID(operation_id).hex, names)
        _, raw = self._read(out, bindings, 'operation-intent.json', MAX_LOCAL_INTENT_BYTES)
        own = decode_quote(raw, MAX_LOCAL_INTENT_BYTES, checkpoint=self._point) - RETAINED_JOURNAL
        _need(RETAINED_JOURNAL + 3 * own + (16 << 20) <= MEMORY_LIMIT)
        intent = decode_local_operation_intent(raw, platform=self.platform, stage=stage)
        prepared, pending, settled = [r['payload'] for r in rows[-3:]]
        start = rows[0]['payload']; prepare_pending = start if later else rows[2]['payload']
        digest = intent['integrity']['sha256']; authority = intent['preparedBy']
        _need(intent['project'] == self.journal.enrollment and intent['operationId'] == operation_id
              and intent['candidateSha256'] == prepared['candidateSha256'] == prepare_pending['candidateSha256']
              and digest == prepared['intentSha256'] == pending['intentSha256'] == settled['intentSha256']
              and authority['confirmationSha256'] == prepare_pending['confirmationSha256'] == pending['confirmationSha256']
              and authority['assignment']['expectedRevision'] == pending['assignmentRevision']
              and intent['operationSource']['commit'] == start['sourceCommit']
              and intent['operationSource']['tree'] == start['sourceTree']
              and intent['configuration']['sha256'] == start['configurationSha256'])
        if later:
            _need(intent['candidateOperationId'] == start['candidateOperationId']
                  and intent['stage'] == start['stage']
                  and intent['configuration']['metadataSha256'] == start['metadataSha256'])
        else:
            _need(intent['candidateSha256'] == rows[1]['payload']['candidateSha256'])
        expected_snapshot = hashlib.sha256(canonical_json_bytes(intent['storePrecondition'])).hexdigest()
        executed = dict(authority, purpose='execute', authorizationId=pending['authorizationId'], intentSha256=digest)
        facts = {key: intent[key] for key in ('operationId','candidateSha256','candidateSource','application','version',
                 'artifacts','signing','configuration','operationSource','predecessors','destination')}
        facts.update(stage=stage, intentSha256=digest, receiptSha256=settled['receiptSha256'])
        if later: facts['candidateOperationId'] = intent['candidateOperationId']
        # Only fixed finite facts survive this parsed graph, never two snapshots.
        _need(len(canonical(facts)) <= _FACTS_LIMIT)
        del intent, authority
        snapshot_binding, snapshot_raw = self._read(out, bindings, 'store-precondition.json', 4 << 20)
        _need(snapshot_binding['sha256'] == prepared['storePreconditionSha256']
              and decode_quote(snapshot_raw, 4 << 20, checkpoint=self._point) + len(raw) + _FACTS_LIMIT <= MEMORY_LIMIT)
        snapshot = json.loads(snapshot_raw, object_pairs_hook=_reject_duplicate_pairs,
                              parse_constant=lambda _: _need(False))
        validate_store_precondition(snapshot, stage=stage, platform=self.platform)
        _need(hashlib.sha256(canonical_json_bytes(snapshot)).hexdigest() == expected_snapshot)
        del snapshot, snapshot_raw
        if later:
            metadata, _ = self._read(out, bindings, 'store-metadata.zip', _METADATA_LIMIT, collect=False)
            artifact = facts['artifacts'][1]
            _need(metadata['sha256'] == artifact['sha256'] == facts['configuration']['metadataSha256']
                  and metadata['size'] == artifact['size'])
        receipt_out, receipt_bindings = self._open(UUID(operation_id).hex + '-execute-' + UUID(pending['authorizationId']).hex,
                                                   {'raw-store-receipt.json': MAX_LOCAL_RECEIPT_BYTES})
        receipt_binding, receipt_raw = self._read(receipt_out, receipt_bindings, 'raw-store-receipt.json', MAX_LOCAL_RECEIPT_BYTES)
        receipt_quote = decode_quote(receipt_raw, MAX_LOCAL_RECEIPT_BYTES, checkpoint=self._point) - RETAINED_JOURNAL
        _need(receipt_binding['sha256'] == settled['receiptSha256']
              and RETAINED_JOURNAL + 3 * own + receipt_quote + (16 << 20) <= MEMORY_LIMIT)
        receipt = validate_local_execution_receipt(receipt_raw, intent_data=raw, authority_data=canonical(executed),
            purpose='execute', expected_intent_sha256=digest, platform=self.platform, stage=stage)
        if stage == 'external-testing' and self.platform == 'ios' and not readiness:
            # Reuse only the shared recorded-state predicate, not CI authority.
            _need(external_production_blocker({'readback': {'state': receipt['state']}}, platform='ios') is None)
        facts['state'] = receipt['state']; facts['result'] = receipt['result']
        _need(receipt['result'] == 'accepted')
        del receipt, receipt_raw, raw, executed
        self._names(out, names); self._names(receipt_out, {'raw-store-receipt.json'})
        return facts

    def _readiness_receipt(self, rows, facts):
        _need(self.platform=='ios');external_readiness_chain(rows,rows[0]['operationId'],ready=True)
        suffix=rows[4]['payload'];operation=rows[0]['operationId']
        original=next((entry for entry in self.bindings if entry[0].path.name==UUID(operation).hex),None)
        _need(original is not None);out,_,bindings=original
        _,raw=self._read(out,bindings,'operation-intent.json',MAX_LOCAL_INTENT_BYTES)
        own=decode_quote(raw,MAX_LOCAL_INTENT_BYTES,checkpoint=self._point)-RETAINED_JOURNAL
        _need(RETAINED_JOURNAL+3*own+(16<<20)<=MEMORY_LIMIT)
        intent=decode_local_operation_intent(raw,platform='ios',stage='external-testing')
        authority=dict(intent['preparedBy'],purpose='external-readiness',authorizationId=suffix['refreshAuthorizationId'],
            intentSha256=suffix['intentSha256'],executionReceiptSha256=suffix['executionReceiptSha256'])
        current,values=self._open(UUID(operation).hex+'-external-readiness-'+UUID(suffix['refreshAuthorizationId']).hex,
            {'raw-store-receipt.json':MAX_LOCAL_RECEIPT_BYTES})
        binding,body=self._read(current,values,'raw-store-receipt.json',MAX_LOCAL_RECEIPT_BYTES)
        _need(binding['sha256']==suffix['readinessReceiptSha256'] and suffix['executionReceiptSha256']==facts['receiptSha256'])
        from .local_release_receipt import validate_local_readiness_receipt
        receipt=validate_local_readiness_receipt(body,intent_data=raw,authority_data=canonical(authority),
            expected_intent_sha256=suffix['intentSha256'],execution_receipt_sha256=facts['receiptSha256'])
        return receipt

    def acquire(self, *, prepared=False, _history=None, _readiness=None):
        _need(not self.started and not self.close_claimed); self.started = True
        try:
            self._point()
            if _readiness is not None:self.readiness_owner=_readiness
            _need(len(self.project.slots) + len(self.journal.ancestors) + self.descriptor_quote() + 4 <= 256)
            rows = [r for r, _ in self.journal._rows]
            if _readiness is not None:
                from .local_store_reconcile import LocalStoreReconcileRun
                from .local_release_history import LocalHistoryRun
                live=type(_readiness) is LocalStoreReconcileRun
                _need((live and _readiness.readiness and _readiness.stage_predecessors is self
                    and self.journal in _readiness.journals and _readiness.stage_id==self.operation_id)
                    or (type(_readiness) is LocalHistoryRun and _readiness.stage_inputs is self and _readiness.journal is self.journal
                        and _readiness.request.context['action']=='review-external-readiness'
                        and _readiness.request.context['stageOperationId']==self.operation_id))
                _need(_readiness.invocation._original_project.directory is self.project and self.platform=='ios' and not prepared and _history is None)
                self.readiness_owner=_readiness
                selected=[r for r in rows if r['operationId']==self.operation_id]
                external_readiness_chain(selected,self.operation_id,ready=not live)
                _need(selected[0]['payload']==self.payload and (not live or rows[-4:]==selected and 11<=len(rows)<=508))
                prefix=rows[:next(i for i,r in enumerate(rows) if r['operationId']==self.operation_id)]
                candidate,_=promotion_lineage(prefix,operation_id=self.operation_id,payload=self.payload)
                self._prefix=tuple(d for _,d in self.journal._rows)
                c=self._completed(candidate,'candidate');e=self._completed(selected[:4],'external-testing',readiness=True)
                _need(e['candidateOperationId']==c['operationId'] and e['candidateSha256']==c['candidateSha256']
                    and e['predecessors']=={'candidateManifestSha256':c['candidateSha256'],'candidateReceiptSha256':c['receiptSha256']}
                    and all(e[k]==c[k] for k in ('application','version','signing','candidateSource'))
                    and [a for a in e['artifacts'] if a['kind']!='metadata']==[a for a in c['artifacts'] if a['kind']!='metadata'])
                result={'candidate':c,'predecessor':c,'external':e}
                if not live:result['readiness']=self._readiness_receipt(selected,e)
                self._facts=canonical(result);_need(len(self._facts)<=2*_FACTS_LIMIT)
                self.post();self.acquired=True;return
            _need(type(prepared) is bool)
            if _history is not None:
                from .local_release_history import LocalHistoryRun
                _need(type(_history) is LocalHistoryRun and _history.stage_inputs is self
                      and _history.journal is self.journal and _history.invocation._original_project.directory is self.project
                      and _history.request.context['stageOperationId']==self.operation_id
                      and _history.request.context['action'] in {'review-stage-prepared','review-stage-execution'})
                selected=[r for r in rows if r['operationId']==self.operation_id]
                expected=['promotion-pending','prepared']
                if _history.request.context['action']=='review-stage-execution':expected+=['execute-pending','settled-success']
                _need([r['phase'] for r in selected]==expected and selected[0]['payload']==self.payload)
                prefix=rows[:next(i for i,r in enumerate(rows) if r['operationId']==self.operation_id)]
            elif prepared:
                selected=[r for r in rows if r['operationId']==self.operation_id]
                _need(len(selected)==2 and [r['phase'] for r in selected]==['promotion-pending','prepared']
                      and rows[-2:]==selected and selected[0]['payload']==self.payload)
                prefix=rows[:-2]
            else:prefix=rows
            candidate, predecessor = promotion_lineage(prefix, operation_id=self.operation_id, payload=self.payload)
            self._prefix = tuple(d for _, d in self.journal._rows)
            c = self._completed(candidate, 'candidate')
            ready=predecessor[-1]['phase']=='external-ready'
            _need(not ready or self.platform=='ios')
            p = c if predecessor is candidate or predecessor == candidate else self._completed(predecessor[:4], 'external-testing',readiness=ready)
            if ready:
                self._readiness_receipt(predecessor,p)
                p['readinessReceiptSha256']=predecessor[-1]['payload']['readinessReceiptSha256']
            if p is not c:
                _need(p['candidateOperationId'] == c['operationId'] and p['candidateSha256'] == c['candidateSha256']
                      and p['predecessors'] == {'candidateManifestSha256': c['candidateSha256'], 'candidateReceiptSha256': c['receiptSha256']}
                      and all(p[k] == c[k] for k in ('application','version','signing','candidateSource'))
                      and [a for a in p['artifacts'] if a['kind'] != 'metadata'] == [a for a in c['artifacts'] if a['kind'] != 'metadata'])
            _need(p['operationId'] == self.payload['predecessorOperationId'] and p['receiptSha256'] == self.payload['predecessorReceiptSha256'])
            self._facts = canonical({'candidate': c, 'predecessor': p})
            _need(len(self._facts) <= 2 * _FACTS_LIMIT)
            self.post(); self.acquired = True
        except BaseException:
            self.failed = True; raise

    def facts(self):
        _need(self.acquired and not self.failed and not self.close_claimed)
        self.post()
        return json.loads(self._facts)  # bounded detached DATA; never original custody

    def post(self):
        _need(self.started and not self.close_claimed)
        try:
            self._point()
            for out, names, bindings in self.bindings:
                self._names(out, names)
                _need(set(bindings) == set(names))
                for name, (binding, limit) in bindings.items():
                    _need(_read_file(out.fd, name, self.guard, limit, private=True, binding_only=True) == (binding, b''))
                self._names(out, names); out.check()
            self._point()
        except BaseException:
            self.failed = True; raise

    def close(self):
        if self.close_claimed: return
        error = None
        try:
            if self.acquired and not self.failed: self.post()
        except BaseException as caught:
            error = caught; self.failed = True
        finally:
            self.close_claimed = True
            try: self.scope.close()
            except BaseException as caught:
                self.failed = True
                if error is None: error = caught
            self.closed = self.iterator is None and self.scan_state in ('new','closed') and all(r.closed() for r in self.readers)
            self._facts = None
        if error is not None: raise error
        _need(self.closed)
