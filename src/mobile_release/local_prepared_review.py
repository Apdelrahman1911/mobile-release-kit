"""Current prepared files under the existing History lease; no Store authority."""
from __future__ import annotations
import hashlib
import json
import os
from uuid import UUID
from ._desktop_local_history_protocol import require
from .build_inputs import _app_private_directory, _read_file
from .local_candidate_bundle import CandidateBundleReview
from .local_release_intent import decode_local_operation_intent, MAX_LOCAL_INTENT_BYTES
from .provenance import canonical_json_bytes, validate_store_precondition, _reject_duplicate_pairs
from ._desktop_store_prepare_protocol import LIMITATIONS

FILES = {'operation-intent.json': MAX_LOCAL_INTENT_BYTES, 'store-precondition.json': 4 << 20}
MEMORY_LIMIT = 96 << 20
# Journal loading still has its original 513*8192*8 allowance. At this later
# phase each retained row includes <=8192 original raw bytes PLUS <=8192 for
# its fixed-schema decoded row/hash/stat/name index (bounded tokens/digests and
# one tiny payload dictionary). The load decoder/canonical temporaries retired.
RETAINED_JOURNAL = 513 * 16384

def decode_quote(raw, maximum, *, checkpoint=None):
    """Pre-allocation quote, not a JSON grammar or an authority decoder.

    Same byte traversal as History's bounded JSON readers. Count object keys,
    values, containers and quoted bytes BEFORE stdlib creates pairs/objects.
    256/cell covers transient pairs + object slots + canonical encoder chunks;
    8/quoted byte covers decoded strings and canonical copies; 5/raw byte covers
    retained bytes plus worst-width input text. Only ONE parsed document lives.
    """
    require(type(raw) is bytes and 0 < len(raw) <= maximum)
    depth = nodes = quoted_bytes = 0
    quoted = escaped = primitive = False
    for index, byte in enumerate(raw):
        if checkpoint is not None and index % (64 << 10) == 0: checkpoint()
        if quoted:
            quoted_bytes += 1
            if escaped: escaped = False
            elif byte == 92: escaped = True
            elif byte == 34: quoted = False
            continue
        if byte == 34: quoted, primitive = True, False; nodes += 1
        elif byte in (91, 123): depth += 1; nodes += 1; primitive = False
        elif byte in (93, 125): depth -= 1; primitive = False
        elif byte in (9, 10, 13, 32, 44, 58): primitive = False
        elif not primitive: nodes += 1; primitive = True
        require(0 <= depth <= 64)
    require(not quoted and not escaped and depth == 0)
    quote = RETAINED_JOURNAL + 5 * len(raw) + 8 * quoted_bytes + 256 * nodes + (1 << 20)
    require(quote <= MEMORY_LIMIT)
    if checkpoint is not None: checkpoint()
    return quote

def _scan(owner, out):
    owner.checkpoint(); out.check()
    require(owner.prepared_scan_state in {'new', 'closed'} and owner.prepared_iterator is None)
    owner.prepared_scan_state = 'acquiring'
    try:
        owner.prepared_iterator = os.scandir(out.fd); owner.prepared_scan_state = 'open'
        names = []
        for entry in owner.prepared_iterator:
            owner.checkpoint(); out.check(); require(len(names) < len(FILES)); names.append(entry.name)
        require(len(names) == len(FILES) and set(names) == set(FILES))
    finally:
        if owner.prepared_iterator is not None:
            original, owner.prepared_iterator = owner.prepared_iterator, None
            owner.prepared_scan_state = 'closing'
            try: original.close()
            except BaseException as error:
                owner.prepared_scan_state = 'unknown'; owner.guard._abort(error); raise
            owner.prepared_scan_state = 'closed'
        elif owner.prepared_scan_state == 'acquiring':
            owner.prepared_scan_state = 'unknown'; owner.guard._abort(ValueError('Prepared directory original unsettled'))
    owner.checkpoint(); out.check()

def _intent(raw, *, enrollment, operation_id, rows, manifest, checkpoint):
    decode_quote(raw, FILES['operation-intent.json'], checkpoint=checkpoint)
    value = decode_local_operation_intent(raw)
    first, ready, pending, prepared = [r['payload'] for r in rows]
    source = value['operationSource']; version = value['version']; snapshot = value['storePrecondition']
    require(value['project'] == enrollment and value['operationId'] == operation_id
        and value['candidateSha256'] == ready['candidateSha256'] == pending['candidateSha256'] == prepared['candidateSha256']
        and value['integrity']['sha256'] == prepared['intentSha256']
        and source['commit'] == manifest['sourceCommit'] == first['sourceCommit']
        and source['tree'] == manifest['sourceTree'] == first['sourceTree']
        and value['application']['id'] == manifest['applicationId']
        and version == {'marketing': manifest['savedVersion']['name'], 'build': manifest['savedVersion']['build']}
        and value['configuration'] == {'path': 'release/mobile-release.json', 'sha256': first['configurationSha256'],
                                       'metadataSha256': manifest['files'][1]['sha256']}
        and value['preparedBy']['confirmationSha256'] == pending['confirmationSha256']
        and value['signing'] == [{'platform': 'android', 'kind': 'android-upload', 'certificateSha256': manifest['signerSha256']}])
    for actual, expected in zip(value['artifacts'], manifest['files']):
        require(actual['fileName'] == expected['fileName'] and actual['size'] == expected['bytes']
                and actual['sha256'] == expected['sha256'] and actual['architectures'] == [])
    summary = dict(operationId=operation_id, candidateSha256=value['candidateSha256'],
        intentSha256=value['integrity']['sha256'], storePreconditionSha256=prepared['storePreconditionSha256'],
        sourceCommit=source['commit'], sourceTree=source['tree'], applicationId=value['application']['id'],
        version={'name': version['marketing'], 'build': version['build']}, destination=value['destination'],
        observedAt=snapshot['observedAt'], limitations=list(LIMITATIONS),
        observation='current-prepared-files-only', priorPrepareFinality='not-established')
    # The original raw snapshot digest is checked separately, NEVER substituted
    # with this semantic comparison of two independently parsed documents.
    return summary, hashlib.sha256(canonical_json_bytes(snapshot)).hexdigest()

def _snapshot(raw, expected, *, checkpoint=None):
    decode_quote(raw, FILES['store-precondition.json'], checkpoint=checkpoint)
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=_reject_duplicate_pairs,
        parse_constant=lambda _: require(False))
    validate_store_precondition(value, stage='candidate', platform='android')
    require(hashlib.sha256(canonical_json_bytes(value)).hexdigest() == expected)

def review_prepared(owner, enrollment):
    from .local_release_history import LocalHistoryRun
    require(type(owner) is LocalHistoryRun and owner.request.context['action'] == 'review-prepared')
    operation_id = owner.request.context['candidateOperationId']
    rows = [r for r, _ in owner.journal._rows if r['operationId'] == operation_id]
    require(owner.journal.head()['sequence'] >= 5 and [r['phase'] for r in rows] ==
            ['inputs-pending', 'inputs-ready', 'prepare-pending', 'prepared'])
    n = owner.request.native['rootIdentity']
    require(owner.journal._rows[0][0]['payload']['rootIdentity'] == dict(device=int(n['device']), inode=int(n['inode']),
        mode=n['mode'] & 0o7777, uid=n['uid'], gid=n['gid']))
    bundle = CandidateBundleReview(owner, operation_id=operation_id, enrollment=enrollment,
        pending=rows[0]['payload'], candidate_sha256=rows[1]['payload']['candidateSha256'])
    bundle.acquire(); bundle.finish()  # Genuine full hashes and positive close before the two-file phase.
    require(bundle.closed and not bundle.failed)
    path = owner.root / '.mobile-release/store/local' / UUID(operation_id).hex
    with _app_private_directory(path, app_root=owner.root, cancellation=owner.guard, create=False) as out:
        require(out is not None); owner.prepared_readers.append(out)
        actual = os.fstat(out.parent.fd)
        require((actual.st_dev, actual.st_ino, actual.st_mode, actual.st_uid, actual.st_gid) == owner.source.lease_identity)
        _scan(owner, out)
        observed = _read_file(out.fd, 'operation-intent.json', owner.guard, FILES['operation-intent.json'], private=True)
        require(observed is not None)
        intent_binding, raw = observed; del observed
        summary, snapshot_digest = _intent(raw, enrollment=enrollment, operation_id=operation_id, rows=rows, manifest=bundle.value, checkpoint=owner.checkpoint)
        del raw  # _intent's complete parsed graph has already returned/retired.
        out.check(); owner.checkpoint()
        observed = _read_file(out.fd, 'store-precondition.json', owner.guard, FILES['store-precondition.json'], private=True)
        require(observed is not None)
        snapshot_binding, raw = observed; del observed
        require(snapshot_binding['sha256'] == rows[3]['payload']['storePreconditionSha256'])
        _snapshot(raw, snapshot_digest, checkpoint=owner.checkpoint); del raw
        # Every leaf is re-read under its original identity/hash after parsing.
        # No descriptor-number reuse is mistaken for a continuing file original.
        _scan(owner, out)
        for name, binding in (('operation-intent.json', intent_binding), ('store-precondition.json', snapshot_binding)):
            observed = _read_file(out.fd, name, owner.guard, FILES[name], private=True, binding_only=True)
            require(observed is not None and observed[0] == binding and observed[1] == b'')
        _scan(owner, out); out.check(); owner.checkpoint()
    require(out.closed()); owner.checkpoint()
    return summary
