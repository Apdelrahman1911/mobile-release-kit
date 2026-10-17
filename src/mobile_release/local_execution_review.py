"""Current completed execution files under History, never old-tail repair."""
from __future__ import annotations
import os
from uuid import UUID
from ._desktop_local_history_protocol import require
from . import _desktop_store_execute_protocol as execute_data
from .build_inputs import _app_private_directory, _read_file
from .local_prepared_review import (_prepared_files, _scan, decode_quote,
    MEMORY_LIMIT, RETAINED_JOURNAL)
from .local_release_intent import decode_local_operation_intent, MAX_LOCAL_INTENT_BYTES
from .local_release_journal import canonical
from .local_release_receipt import MAX_LOCAL_RECEIPT_BYTES, validate_local_execution_receipt

NAME = 'raw-store-receipt.json'

def _intent_quote(raw, checkpoint):
    own = decode_quote(raw, MAX_LOCAL_INTENT_BYTES, checkpoint=checkpoint) - RETAINED_JOURNAL
    # The validator independently decodes the original intent and authority;
    # quote all overlapping graphs BEFORE any such allocations, as Execute does.
    require(RETAINED_JOURNAL + 3 * own + (16 << 20) <= MEMORY_LIMIT)
    return own

def _authority(raw, rows):
    intent = decode_local_operation_intent(raw)
    pending, settled = rows[4]['payload'], rows[5]['payload']
    prepared = intent['preparedBy']; digest = intent['integrity']['sha256']
    require(pending['intentSha256'] == settled['intentSha256'] == digest
        and pending['confirmationSha256'] == prepared['confirmationSha256']
        and pending['assignmentRevision'] == prepared['assignment']['expectedRevision'])
    # These comparison fields are from authenticated intent + journal, NEVER
    # copied from the receipt we are about to validate against them.
    return dict(prepared, purpose='execute', authorizationId=pending['authorizationId'], intentSha256=digest)

def review_execution(owner, enrollment):
    from .local_release_history import LocalHistoryRun
    require(type(owner) is LocalHistoryRun and owner.request.context['action'] == 'review-execution')
    with _prepared_files(owner, enrollment) as (prepared, intent_raw, rows):
        intent_quote = _intent_quote(intent_raw, owner.checkpoint)
        authority = _authority(intent_raw, rows)
        operation_id = owner.request.context['candidateOperationId']
        leaf = UUID(operation_id).hex + '-execute-' + UUID(authority['authorizationId']).hex
        path = owner.root / '.mobile-release/store/local' / leaf
        with _app_private_directory(path, app_root=owner.root, cancellation=owner.guard, create=False) as out:
            require(out is not None); owner.prepared_readers.append(out)
            root = os.fstat(out.parent.fd)
            require((root.st_dev, root.st_ino, root.st_mode, root.st_uid, root.st_gid) == owner.source.lease_identity)
            _scan(owner, out, kind='execution')
            observed = _read_file(out.fd, NAME, owner.guard, MAX_LOCAL_RECEIPT_BYTES, private=True)
            require(observed is not None)
            binding, raw = observed; del observed
            require(binding['sha256'] == rows[5]['payload']['receiptSha256'])
            receipt_quote = decode_quote(raw, MAX_LOCAL_RECEIPT_BYTES, checkpoint=owner.checkpoint) - RETAINED_JOURNAL
            require(RETAINED_JOURNAL + 3 * intent_quote + receipt_quote + (16 << 20) <= MEMORY_LIMIT)
            receipt = validate_local_execution_receipt(raw, intent_data=intent_raw,
                authority_data=canonical(authority), purpose='execute', expected_intent_sha256=prepared['intentSha256'])
            summary = {key: prepared[key] for key in ('operationId', 'candidateSha256', 'intentSha256',
                'sourceCommit', 'sourceTree', 'applicationId', 'version', 'destination')}
            summary.update(receiptSha256=binding['sha256'], authorizationId=authority['authorizationId'],
                observedAt=receipt['observedAt'], result=receipt['result'], limitations=list(execute_data.LIMITATIONS))
            del raw, receipt
            # Pure existing 13-field validator; not an Execute lifetime result.
            execute_data.validate_result(dict(schemaVersion=1, scope='local-android-store-execute',
                headSequence=owner.journal.head()['sequence'], executionReceipt=summary))
            _scan(owner, out, kind='execution')
            observed = _read_file(out.fd, NAME, owner.guard, MAX_LOCAL_RECEIPT_BYTES, private=True, binding_only=True)
            require(observed == (binding, b''))
            _scan(owner, out, kind='execution'); out.check(); owner.checkpoint()
        require(out.closed()); owner.checkpoint()
        # The enclosing original prepared namespace now POSTs both original
        # leaf bindings and its roster before its consuming close.
    summary.update(observation='current-execution-files-only', priorExecutionFinality='not-established')
    return summary
