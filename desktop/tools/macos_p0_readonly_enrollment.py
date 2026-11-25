"""Passive P0 DATA correspondence; no download/mount/install/native authority.

The native adapter must hold authentic Originals, exact source/tool/transport
and public qualification inputs before passing bounded original bytes here.
The checked-in anchor file is intentionally unconfigured. Observed inventory
length is never an input nomination and no update/history is activated here.
"""
import hashlib
import json

ANCHORS = 'desktop/macos-installed-inputs/p0-readonly-enrollment.json'
TARGETS = ('aarch64-apple-darwin', 'x86_64-apple-darwin')
LIMIT = 512 * 1024 * 1024
INVENTORY_LIMIT = 1024 * 1024
DESCRIPTOR_LIMIT = 16384
SIGNATURE_LIMIT = 512
OUTPUT_LIMIT = 2 * 1024 * 1024
MEMBERS = ('MobileReleaseKit.dmg', 'PREVIEW.json')
# P0 installing lineage only; global removal qualification remains independent.
ROLES = ('finalize-package', 'package-install', 'finalize-image')


class Refused(ValueError):
    """Only fixed DATA refusal tokens; never append input or native output."""


def need(value, reason):
    if not value:
        raise Refused(reason)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def hx(value, width=64):
    return type(value) is str and len(value) == width and any(c != '0' for c in value) and all(c in '0123456789abcdef' for c in value)


def positive(value):
    return type(value) is str and 0 < len(value) <= 20 and value[0] != '0' and value.isascii() and value.isdecimal()


def member(value, name, maximum=LIMIT):
    need(type(value) is dict and set(value) == {'name', 'bytes', 'sha256'} and value['name'] == name
         and type(value['bytes']) is int and 0 < value['bytes'] <= maximum and hx(value['sha256']), 'enrollment-member')
    return dict(value)


def anchors_data(document, target, stager):
    """SOURCE-owned authority before any bytes are observed; never enroll itself."""
    need(target in TARGETS and type(document) is dict, 'enrollment-anchor-shape')
    if document == {'schemaVersion': 1, 'mode': 'unconfigured'}:
        raise Refused('enrollment-qualified-p0-unconfigured')
    need(set(document) == {'schemaVersion', 'mode', 'targets'} and type(document['schemaVersion']) is int
         and document['schemaVersion'] == 1 and document['mode'] == 'configured'
         and type(document['targets']) is dict and set(document['targets']) == set(TARGETS), 'enrollment-anchor-shape')
    for selected, row in document['targets'].items():
        if row == {'mode': 'unconfigured'}:
            if selected == target: raise Refused('enrollment-qualified-target-unconfigured')
            continue
        need(type(row) is dict and set(row) == {'source', 'tree', 'runId', 'runAttempt', 'jobId', 'artifactId',
             'artifactBytes', 'artifactSha256', 'qualificationEvidenceSha256', 'members', 'package', 'descriptor',
             'signature', 'inventorySha256', 'runtimeManifestSha256', 'packageVersion', 'release', 'signingIdentity', 'qualificationArtifact'}, 'enrollment-anchor-fields')
        need(hx(row['source'], 40) and hx(row['tree'], 40) and all(positive(row[k]) for k in ('runId', 'runAttempt', 'jobId', 'artifactId'))
             and type(row['artifactBytes']) is int and 0 < row['artifactBytes'] <= LIMIT
             and all(hx(row[k]) for k in ('artifactSha256', 'qualificationEvidenceSha256', 'inventorySha256', 'runtimeManifestSha256')),
             'enrollment-anchor-identity')
        need(type(row['members']) is list and len(row['members']) == len(MEMBERS), 'enrollment-artifact-roster')
        observed = [member(v, name) for v, name in zip(row['members'], MEMBERS)]
        need(sum(v['bytes'] for v in observed) <= LIMIT, 'enrollment-artifact-bound')
        member(row['package'], 'Install.pkg'); member(row['descriptor'], 'producer.json', DESCRIPTOR_LIMIT)
        member(row['signature'], 'producer.sig', SIGNATURE_LIMIT)
        stager.build_release_data(stager.canonical({'schemaVersion': 1, 'packageVersion': row['packageVersion'], 'release': row['release']}), target=selected)
        qualifier = row['qualificationArtifact']
        need(type(qualifier) is dict and set(qualifier) == {'artifactId', 'artifactBytes', 'artifactSha256',
             'memberName', 'memberBytes', 'memberSha256'} and positive(qualifier['artifactId'])
             and type(qualifier['artifactBytes']) is int and 0 < qualifier['artifactBytes'] <= 256 * 1024
             and hx(qualifier['artifactSha256']) and qualifier['artifactId'] != row['artifactId']
             and qualifier['memberName'] == 'public-verification-evidence.json'
             and type(qualifier['memberBytes']) is int and 0 < qualifier['memberBytes'] <= 128 * 1024
             and qualifier['memberSha256'] == row['qualificationEvidenceSha256'], 'enrollment-qualification-artifact')
        identity = row['signingIdentity']
        need(type(identity) is dict and set(identity) == {'teamIdentifier', 'leafCertificateSha1', 'leafCertificateSha256'}
             and identity['teamIdentifier'] == '7CGZ2343AA'
             and identity['leafCertificateSha1'] == '5effa7d19bbe005b19c1617833cbe22186c2af96'
             and hx(identity['leafCertificateSha256']), 'enrollment-g2-source-identity')
    return document['targets'][target]


def qualification_data(body, row, target, stager, public):
    """Correspondence to already independently reviewed original qualification."""
    need(type(body) is bytes and 0 < len(body) <= 128 * 1024 and sha(body) == row['qualificationEvidenceSha256'], 'enrollment-qualification-anchor')
    value = stager.decode(body)
    need(type(value) is dict and value.get('kind') == 'mrk-public-verification-evidence-v1'
         and type(value.get('schemaVersion')) is int and value['schemaVersion'] == 1
         and value.get('diagnosticOnly') is True and value.get('productReady') is False
         and all(value.get(k) == row[k] for k in ('source', 'runId', 'runAttempt'))
         and value.get('workflowSource') == row['source'] and value.get('target') == target, 'enrollment-qualification-context')
    source = value.get('sourceInventory')
    need(type(source) is dict and source.get('receiptState') == 'observed' and source.get('tree') == row['tree'], 'enrollment-qualification-source')
    phases = value.get('phases')
    need(type(phases) is dict, 'enrollment-qualification-phases')
    for name in ROLES:
        phase = phases.get(name)
        need(type(phase) is dict and phase.get('receiptState') == 'observed'
             and phase.get('recordedPassed') is True and phase.get('correlationMatches') is True
             and all(phase.get(k) is True for k in ('originalClosesKnown', 'targetRetired', 'outerFinalityRequired'))
             and phase.get('failure') is None, 'enrollment-qualification-originals')
        calls = phase.get('originalCalls')
        need(type(calls) is dict and calls.get('unclassifiedCount') == 0 and type(calls.get('calls')) is list and calls['calls']
             and all(type(v) is dict and v.get('entered') is True and v.get('returned') is True and v.get('capturesSettled') is True
                     and type(v.get('returncode')) is int and v['returncode'] in ((0, 1) if v.get('role') in ('installer-log-cursor', 'installer-log-capture') else (0,))
                     for v in calls['calls']), 'enrollment-qualification-calls')
        contexts = phase.get('credentialContexts')
        need(type(contexts) is list and all(type(v) is dict and all(v.get(k) is True for k in ('retired', 'closed', 'searchRestored', 'defaultUnchanged')) for v in contexts),
             'enrollment-qualification-credentials')
    context = {k: row[k] for k in ('source', 'runId', 'runAttempt')}; context.update(workflowSource=row['source'], target=target)
    deliveries = value.get('deliveries')
    need(type(deliveries) is dict and all(type(deliveries.get(k)) is dict and deliveries[k].get('receiptState') == 'observed' and deliveries[k].get('sourceTree') == row['tree']
                                         for k in ('preview',)), 'enrollment-qualification-deliveries')
    return context, deliveries


def artifact_data(bodies, row, context, deliveries, stager, public):
    """Two exact held flat carrier members; no path or removal waiver."""
    need(type(bodies) is dict and set(bodies) == set(MEMBERS), 'enrollment-artifact-roster')
    for selected in row['members']:
        body = bodies[selected['name']]
        need(type(body) is bytes and len(body) == selected['bytes'] and sha(body) == selected['sha256'], 'enrollment-artifact-original')
    for name, removal, key in (('PREVIEW.json', False, 'preview'),):
        need(public.project_summary(stager.decode(bodies[name]), context, removal) == deliveries[key], 'enrollment-artifact-public-join')
    preview = stager.decode(bodies['PREVIEW.json'])
    need(all(preview.get(k) == row[v]['sha256'] for k, v in (('packageSha256', 'package'), ('descriptorSha256', 'descriptor'), ('signatureSha256', 'signature')))
         and preview.get('packageSize') == row['package']['bytes']
         and preview.get('runtimeManifestSha256') == row['runtimeManifestSha256']
         and preview.get('installerInventorySha256') == row['inventorySha256']
         and preview.get('distributionSha256') == row['members'][0]['sha256']
         and preview.get('distributionBytes') == row['members'][0]['bytes']
         and all(preview.get(k) is True for k in ('originalInstallerReturnedZero', 'originalPackageGroupReturnedZero',
             'originalObservationMountDetached', 'originalImageFinalizationReturnedZero', 'originalFinalImageMountDetached',
             'finalImageScopedNotarizationObserved')), 'enrollment-preview-originals')
    return bodies[MEMBERS[0]]


def mounted_data(originals, row, target, stager):
    """Actual unchanged package parsers; inventory digest precedes observed size."""
    need(type(originals) is dict and set(originals) == {'Install.pkg', 'producer.json', 'producer.sig'}
         and all(type(v) is tuple and len(v) == 2 and type(v[0]) is bytes and type(v[1]) is int for v in originals.values()), 'enrollment-mounted-roster')
    bodies = {k: v[0] for k, v in originals.items()}
    for key in ('package', 'descriptor', 'signature'):
        selected = row[key]; body = bodies[selected['name']]
        need(type(body) is bytes and len(body) == selected['bytes'] and sha(body) == selected['sha256'], 'enrollment-mounted-original')
    # Caller separately proves root/UID/nlink/readonly. Never manufacture modes.
    stager.distribution_layout_data(list(originals), 'Install.pkg', bodies, originals)
    descriptor = stager.maintenance_producer_data(bodies['producer.json'], target=target)
    releases = descriptor['releaseSet']; release = releases['current']
    need(not releases['acceptedPredecessors'] and len(descriptor['signingPolicies']) == 1
         and all(release[k] == row[v] for k, v in (('sourceCommit', 'source'), ('runtimeManifestSha256', 'runtimeManifestSha256'),
                 ('inventorySha256', 'inventorySha256'), ('packageVersion', 'packageVersion'), ('release', 'release')))
         and release['packageSha256'] == row['package']['sha256'], 'enrollment-release-original')
    policy = descriptor['signingPolicies'][0]
    need(policy['sha256'] == release['signingPolicySha256'] and all(policy['policy'][k] == v for k, v in row['signingIdentity'].items()), 'enrollment-policy-original')
    selection = stager.BuildSelection(target, row['packageVersion'], row['release'])
    members = stager.install_product_members(bodies['Install.pkg'])
    if stager.INSTALL_COMPONENT in members:
        component = stager.xar_members(members[stager.INSTALL_COMPONENT])
    else:
        component = {k: members[stager.INSTALL_COMPONENT + '/' + k] for k in ('PackageInfo', 'Scripts')}
    need(set(component) == {'PackageInfo', 'Scripts'}, 'enrollment-product-component')
    stager.package_info(component['PackageInfo'], selection=selection)
    packed = component['Scripts']; archive = stager.inflate(packed, LIMIT, gzip=True) if packed[:2] == b'\x1f\x8b' else packed
    scripts = stager.cpio_members(archive); key = 'input/' + stager.INSTALLATION_INVENTORY_NAME
    need(key in scripts and type(scripts[key][0]) is bytes and scripts[key][1] == 0o444, 'enrollment-original-inventory')
    inventory = scripts[key][0]
    rows = stager.observation_inventory_bytes(inventory, row['inventorySha256'], row['runtimeManifestSha256'], selection=selection)
    result = {'schemaVersion': 1, 'kind': 'mrk-p0-readonly-enrollment-data-v1', 'target': target,
            'source': row['source'], 'tree': row['tree'], 'runId': row['runId'], 'runAttempt': row['runAttempt'],
            'jobId': row['jobId'], 'artifactId': row['artifactId'], 'artifactSha256': row['artifactSha256'],
            'qualificationEvidenceSha256': row['qualificationEvidenceSha256'], 'members': row['members'],
            'package': row['package'], 'descriptor': row['descriptor'], 'signature': row['signature'],
            'inventory': {'name': stager.INSTALLATION_INVENTORY_NAME, 'bytes': len(inventory), 'sha256': sha(inventory)},
            'inventoryDocument': stager.decode(inventory), 'release': release, 'signingPolicy': policy,
            'inventoryFiles': len(rows), 'inventoryPayloadBytes': sum(v['size'] for v in rows.values()),
            'nativeQualificationInferred': False, 'updateActivated': False, 'productReady': False}
    return result, inventory


def prospective_capacity_data(enrollment, old_inventory, current_inventory, current_binding, target, stager, update):
    """Actual staged inventories; no future P1 package/descriptor is required."""
    old = stager.maintenance_release_data(enrollment['release'], target)
    need(type(old_inventory) is bytes and sha(old_inventory) == enrollment['inventory']['sha256']
         and len(old_inventory) == enrollment['inventory']['bytes'], 'enrollment-retained-inventory-encoding')
    need(type(current_binding) is dict and set(current_binding) == {'source', 'runtimeManifestSha256',
         'inventorySha256', 'packageVersion', 'release'} and hx(current_binding['source'], 40)
         and hx(current_binding['runtimeManifestSha256']) and hx(current_binding['inventorySha256']), 'enrollment-staged-current-binding')
    stager.build_release_data(stager.canonical({'schemaVersion': 1, 'packageVersion': current_binding['packageVersion'],
        'release': current_binding['release']}), target=target)
    need(old['sourceCommit'] != current_binding['source'] and old['release'] != current_binding['release']
         and tuple(map(int, old['packageVersion'].split('.'))) < tuple(map(int, current_binding['packageVersion'].split('.'))), 'enrollment-two-generations')
    counts = []
    for release, body in ((old, old_inventory), (current_binding, current_inventory)):
        rows = stager.observation_inventory_bytes(body, release['inventorySha256'], release['runtimeManifestSha256'],
            selection=stager.BuildSelection(target, release['packageVersion'], release['release']))
        metadata = len(body) + 3 * 16384
        counts.append((len(rows), sum(v['size'] for v in rows.values()) + metadata))
    return {**update.aggregate_data(counts, stager.MAX_FILES, stager.MAX_BYTES,
             len(stager.MAINTENANCE_GATE_BYTES) + len(stager.REGISTRATION_GATE_BYTES)), 'finalizedPairDataStillRequired': True, 'updateActivated': False}


def collect_data(anchor_document, target, qualification_body, artifact_bodies, mounted_bodies, stager, public):
    row = anchors_data(anchor_document, target, stager)
    context, deliveries = qualification_data(qualification_body, row, target, stager, public)
    artifact_data(artifact_bodies, row, context, deliveries, stager, public)
    result, inventory = mounted_data(mounted_bodies, row, target, stager)
    need(len(json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')) <= OUTPUT_LIMIT, 'enrollment-output-bound')
    return result, inventory
