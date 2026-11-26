"""Current candidate carrier DATA admission; no download, install or CLI entry.

Loaded by a trusted checkout consumer. Historical fixed-carrier execution remains
separate; successful parsing grants neither native nor Store authority.
"""
import io
import re
import zipfile

from desktop.tools.macos_fixed_carrier_resume import (
    CANDIDATE_MEMBERS, RETAINED_OBSERVER_MEMBERS, RETAINED_GIT_MEMBERS, LIMIT, REPOSITORY, WORKFLOW, WORKFLOW_ID,
    canonical, decode, need, sha, zip_data, zip_directory_data,
)

CANDIDATE_BRANCH = 'verify/desktop-macos-candidate'
CANDIDATE_STEPS = (
    'Standard Installer only is privileged; never execute the app or Python as root',
    'Notarize, staple and verify only the final user image',
    'Stage the current signed candidate only after actual installation and final-image verification',
    'Retain the complete candidate for independent installed-app testing',
)


def candidate_selection_data(row):
    """Caller-nominated DATA only; neither a download nor installation authority.

    The consumer must obtain the nomination from trusted repository/run metadata,
    never from the downloaded candidate. No historical ORIGIN is changed.
    """
    need(type(row) is dict and set(row) == {'source', 'tree', 'target', 'runId', 'runAttempt',
         'jobId', 'artifactId', 'artifactBytes', 'artifactSha256'}, 'candidate-nomination')
    need(row['target'] in ('aarch64-apple-darwin', 'x86_64-apple-darwin')
         and all(type(row[k]) is str and re.fullmatch(r'[1-9][0-9]{0,19}', row[k])
                 for k in ('runId', 'runAttempt', 'jobId', 'artifactId'))
         and all(type(row[k]) is str and re.fullmatch(r'[0-9a-f]{40}', row[k])
                 and row[k] != '0' * 40 for k in ('source', 'tree'))
         and type(row['artifactBytes']) is int and 22 <= row['artifactBytes'] <= LIMIT
         and type(row['artifactSha256']) is str and re.fullmatch(r'[0-9a-f]{64}', row['artifactSha256'])
         and row['artifactSha256'] != '0' * 64, 'candidate-nomination')
    return dict(row)


def candidate_metadata_data(run, job, artifact, nomination):
    row = candidate_selection_data(nomination)
    need(type(run) is dict and type(job) is dict and type(artifact) is dict, 'candidate-metadata')
    need(all(type(run.get(k)) is int and run[k] == int(row[v]) for k, v in
             (('id', 'runId'), ('run_attempt', 'runAttempt')))
         and run.get('head_sha') == row['source'] and run.get('head_branch') == CANDIDATE_BRANCH
         and run.get('event') == 'push'
         and run.get('path') == WORKFLOW and type(run.get('workflow_id')) is int
         and run['workflow_id'] == WORKFLOW_ID and type(run.get('repository')) is dict
         and run['repository'].get('full_name') == REPOSITORY, 'candidate-producer-run')
    steps = job.get('steps')
    need(all(type(job.get(k)) is int and job[k] == int(row[v]) for k, v in
             (('id', 'jobId'), ('run_id', 'runId'), ('run_attempt', 'runAttempt')))
         and job.get('head_sha') == row['source'] and job.get('name') in ('normal-installed-' + row['target'], 'prepared-installed-' + row['target'])
         and type(steps) is list and 4 <= len(steps) <= 256
         and all(type(s) is dict and type(s.get('number')) is int and 0 < s['number'] <= 256 for s in steps)
         and len({s['number'] for s in steps}) == len(steps), 'candidate-producer-job')
    previous = 0
    for name in CANDIDATE_STEPS:
        selected = [s for s in steps if s.get('name') == name]
        need(len(selected) == 1 and selected[0].get('status') == 'completed'
             and selected[0].get('conclusion') == 'success' and selected[0]['number'] > previous,
             'candidate-producer-stage-closed')
        previous = selected[0]['number']
    # A later UI failure/cancellation does not invalidate already-closed package
    # stages. Conversely whole-job success cannot substitute for those stages.
    origin = artifact.get('workflow_run')
    need(type(artifact.get('id')) is int and artifact['id'] == int(row['artifactId'])
         and artifact.get('name') == 'mobile-release-kit-macos26-' + row['target'] + '-candidate-'
             + row['source'] + '-' + row['runId'] + '-' + row['runAttempt']
         and artifact.get('expired') is False and type(artifact.get('size_in_bytes')) is int
         and artifact['size_in_bytes'] == row['artifactBytes']
         and artifact.get('digest') == 'sha256:' + row['artifactSha256']
         and type(origin) is dict and type(origin.get('id')) is int and origin['id'] == run['id']
         and origin.get('head_sha') == row['source'] and origin.get('head_branch') == CANDIDATE_BRANCH,
         'candidate-artifact-metadata')
    return row


def candidate_preview_data(body, nomination):
    row = candidate_selection_data(nomination)
    need(type(body) is bytes and 0 < len(body) <= CANDIDATE_MEMBERS['PREVIEW.json'], 'candidate-preview-bound')
    value = decode(body)
    platform_name = 'macOS26-arm64' if row['target'] == 'aarch64-apple-darwin' else 'macOS26-x86_64'
    need(type(value) is dict and type(value.get('schemaVersion')) is int and value['schemaVersion'] == 2
         and (value.get('sourceCommit'), value.get('sourceTree'), value.get('runId'), value.get('runAttempt'),
              value.get('platform'), value.get('workflow'), value.get('workflowRef')) ==
             (row['source'], row['tree'], row['runId'], row['runAttempt'], platform_name, WORKFLOW,
              REPOSITORY + '/' + WORKFLOW + '@refs/heads/' + CANDIDATE_BRANCH)
         and value.get('scope') == 'current-macos-candidate' and value.get('packageRole') == 'ordinary-image'
         and value.get('instrumented') is False
         and all(value.get(k) == 'passed' for k in ('normalBuild', 'packageAudit', 'installationReadback'))
         and all(value.get(k) is True for k in ('originalInstallerReturnedZero', 'originalPackageGroupReturnedZero',
             'originalObservationMountDetached', 'originalImageFinalizationReturnedZero',
             'originalFinalImageMountDetached', 'finalImageScopedNotarizationObserved'))
         and all(value.get(k) is False for k in ('fullM2Qualified', 'maintenanceQualified', 'fullUIQualified',
             'distributionQualified', 'productReady'))
         and all(value.get(k) == 'unexecuted' for k in ('automaticWindowOpen', 'normalQuit', 'ordinaryEntryRoute'))
         and value.get('directPayloadPreMain') == 'unqualified' and value.get('manualUIAcceptance') == 'pending'
         and value.get('unexecutedReason') == 'candidate-export-before-independent-ui-verification',
         'candidate-preview-correspondence')
    need(all(type(value.get(k)) is int and 0 < value[k] <= LIMIT for k in ('distributionBytes', 'packageSize'))
         and all(type(value.get(k)) is str and re.fullmatch(r'[0-9a-f]{64}', value[k]) and value[k] != '0' * 64
                 for k in ('distributionSha256', 'packageSha256', 'descriptorSha256', 'signatureSha256',
                           'runtimeManifestSha256', 'installerInventorySha256')),
         'candidate-preview-image-binding')
    return value


def candidate_members(body, nomination, clock, *, before_image=None):
    """Authenticate a candidate's exact three members; never extract or execute."""
    row = candidate_selection_data(nomination)
    need(type(body) is bytes and len(body) == row['artifactBytes'] and sha(body) == row['artifactSha256'],
         'candidate-outer-zip-pin')
    zip_directory_data(body, 3)
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        infos = archive.infolist()
        need(len(infos) == 3 and {i.filename for i in infos} == set(CANDIDATE_MEMBERS), 'candidate-zip-roster')
        small = {}
        for info in infos:
            clock.check()
            need(not info.is_dir() and 0 < info.file_size <= CANDIDATE_MEMBERS[info.filename], 'candidate-member-bound')
            if info.filename != 'MobileReleaseKit.dmg':
                with archive.open(info) as member:
                    small[info.filename] = member.read(CANDIDATE_MEMBERS[info.filename] + 1)
                    need(len(small[info.filename]) == info.file_size and member.read(1) == b'', 'candidate-member-bound')
        preview = candidate_preview_data(small['PREVIEW.json'], row)
        image = next(info for info in infos if info.filename == 'MobileReleaseKit.dmg')
        need(image.file_size == preview['distributionBytes'], 'candidate-image-declared-size')
        if before_image is not None:
            clock.check()
            before_image(preview['distributionBytes'])
            clock.check()
        wanted = [{'name': name, 'bytes': len(content), 'sha256': sha(content)} for name, content in small.items()]
        wanted.append({'name': 'MobileReleaseKit.dmg', 'bytes': preview['distributionBytes'],
                       'sha256': preview['distributionSha256']})
    # The outer artifact authenticates PREVIEW; PREVIEW binds the actual DMG.
    # Neither replaces native producer/signature verification or fresh readback.
    return zip_data(body, {'kind': 'candidate', 'bytes': row['artifactBytes'],
                           'sha256': row['artifactSha256'], 'members': wanted}, clock)


# A separate, explicitly nonshipping input. None of the ordinary candidate's
# PREVIEW/final-image/installation gates above is relaxed for these bytes.
RETAINED_OBSERVER_IMAGE = 'distribution/MobileReleaseKit.dmg'
RETAINED_OBSERVER_OPERATIONS = ('install-retained-observer', 'install-retained-git-observer')
RETAINED_GIT_SELECTION_PATH = 'desktop/macos-installed-inputs/retained-git-observer-selection.json'
RETAINED_GIT_TUPLE = ('ed91b0dd582ca35a6dc57556aa73d60f1fc852a2', '40132594293', '1')
RETAINED_OBSERVER_STEPS = (
    'Build the current nonshipping observer',
    'Record the effective pinned compiler and preflight configured observer DATA',
    'Assemble the current observer and sign code inside-out (never --deep)',
    'Notarize and staple the signed payload, then bind Installer inputs',
    'Compile the fixed ordinary root Installer before credential admission',
    'Build the fixed one-shot root Installer and scripts-only package',
    'Sign and notarize the same completed observer package before final P',
    'Standard Installer only is privileged; never execute the app or Python as root',
    'Retain only nonshipping candidate detach diagnostics and images',
)


def retained_git_context(environment):
    """Only the explicit original Git27 continuation; all old routes stay26."""
    git = environment.get('MRK_CANDIDATE_MODE') == RETAINED_OBSERVER_OPERATIONS[1]
    if git:
        expected = {'MRK_CANDIDATE_SOURCE': RETAINED_GIT_TUPLE[0],
            'MRK_MACOS_INSTALL_SOURCE_COMMIT': RETAINED_GIT_TUPLE[0],
            'MRK_MACOS_TARGET': 'aarch64-apple-darwin', 'MRK_MACOS_RUNNER': 'xcode-27',
            'MRK_MACOS_MACHINE': 'arm64', 'MRK_MACOS_HOSTED_JOB': 'github-hosted-xcode27-arm64',
            'MRK_MACOS_NATIVE_SCOPE': 'git-native', 'MRK_MACOS_PACKAGE_ROLE': 'installed-shell-observation',
            'MRK_MACOS_STORE_RUNTIME': 'signed-component',
            'DEVELOPER_DIR': '/Library/Developer/CommandLineTools'}
        need(all(environment.get(key) == value for key, value in expected.items())
             and environment.get('MRK_EXPECTED_SHA') == environment.get('GITHUB_SHA'), 'retained-git-context')
    return git


def retained_observer_selection_data(value):
    """Trusted helper SOURCE selects one artifact; the artifact never selects it."""
    need(type(value) is dict and set(value) == {'schemaVersion', 'kind', 'packageRole', 'nativeScope', 'origin', 'members'}
         and type(value['schemaVersion']) is int and value['schemaVersion'] == 1
         and value['kind'] == 'retained-observer-source-selection-v1'
         and value['packageRole'] == 'installed-shell-observation' and value['nativeScope'] in ('tool-setup', 'git-native'),
         'retained-observer-selection')
    origin = candidate_selection_data(value['origin'])
    need(origin['target'] == 'aarch64-apple-darwin', 'retained-observer-target')
    git = value['nativeScope'] == 'git-native'
    need(not git or tuple(origin[key] for key in ('source', 'runId', 'runAttempt')) == RETAINED_GIT_TUPLE,
         'retained-git-original-tuple')
    limits = RETAINED_GIT_MEMBERS if git else RETAINED_OBSERVER_MEMBERS
    members = value['members']
    need(type(members) is list and len(members) == len(limits), 'retained-observer-members')
    for item, name in zip(members, sorted(limits)):
        cap = limits[name]
        need(type(item) is dict and set(item) == {'name', 'bytes'} and item['name'] == name
             and type(item['bytes']) is int and (0 if cap == 0 else 1) <= item['bytes'] <= cap,
             'retained-observer-member')
    need(sum(item['bytes'] for item in members) <= LIMIT, 'retained-observer-expanded-bound')
    return dict(value, origin=origin, members=[dict(item) for item in members])


def retained_observer_metadata_data(run, job, artifact, selection):
    selected = retained_observer_selection_data(selection)
    row = selected['origin']
    git = selected['nativeScope'] == 'git-native'
    suffix = '-git-native' if git else ''
    need(type(run) is dict and type(job) is dict and type(artifact) is dict, 'retained-observer-metadata')
    need(all(type(run.get(k)) is int and run[k] == int(row[v]) for k, v in
             (('id', 'runId'), ('run_attempt', 'runAttempt')))
         and run.get('head_sha') == row['source'] and run.get('head_branch') == CANDIDATE_BRANCH
         and run.get('event') == 'push' and run.get('path') == WORKFLOW
         and type(run.get('workflow_id')) is int and run['workflow_id'] == WORKFLOW_ID
         and type(run.get('repository')) is dict and run['repository'].get('full_name') == REPOSITORY
         and run.get('status') == 'completed', 'retained-observer-producer-run')
    steps = job.get('steps')
    need(all(type(job.get(k)) is int and job[k] == int(row[v]) for k, v in
             (('id', 'jobId'), ('run_id', 'runId'), ('run_attempt', 'runAttempt')))
         and job.get('head_sha') == row['source'] and job.get('name') == 'normal-installed-' + row['target'] + suffix
         and job.get('status') == 'completed' and job.get('labels') == ['xcode-27' if git else 'macos-26']
         and type(steps) is list and len(RETAINED_OBSERVER_STEPS) <= len(steps) <= 256
         and all(type(s) is dict and type(s.get('number')) is int and 0 < s['number'] <= 256 for s in steps)
         and len({s['number'] for s in steps}) == len(steps), 'retained-observer-producer-job')
    previous = 0
    for name in RETAINED_OBSERVER_STEPS:
        matches = [s for s in steps if s.get('name') == name]
        outcomes = ('success', 'failure') if name == RETAINED_OBSERVER_STEPS[-2] else ('success',)
        need(len(matches) == 1 and matches[0].get('status') == 'completed'
             and matches[0].get('conclusion') in outcomes and matches[0]['number'] > previous,
             'retained-observer-producer-stage')
        previous = matches[0]['number']
    # A failed original package-install is NOT installation authority. Only the
    # preceding completed signing stages and this exact upload admit raw bytes.
    origin = artifact.get('workflow_run')
    need(type(artifact.get('id')) is int and artifact['id'] == int(row['artifactId'])
         and artifact.get('name') == 'candidate-detach-nonshipping-unqualified-diagnostics-' + row['target'] + suffix
             + '-' + row['source'] + '-' + row['runId'] + '-' + row['runAttempt']
         and artifact.get('expired') is False and type(artifact.get('size_in_bytes')) is int
         and artifact['size_in_bytes'] == row['artifactBytes']
         and artifact.get('digest') == 'sha256:' + row['artifactSha256']
         and type(origin) is dict and type(origin.get('id')) is int and origin['id'] == run['id']
         and origin.get('head_sha') == row['source'] and origin.get('head_branch') == CANDIDATE_BRANCH,
         'retained-observer-artifact-metadata')
    return selected


def retained_observer_members(body, selection, clock, *, before_image=None):
    """Validate/hash the exact five retained originals; keep only the main image."""
    selected = retained_observer_selection_data(selection)
    origin = selected['origin']
    need(type(body) is bytes and len(body) == origin['artifactBytes'] and sha(body) == origin['artifactSha256'],
         'retained-observer-zip-pin')
    zip_directory_data(body, len(selected['members']))
    if before_image is not None:
        clock.check()
        # Fund the sole output before BytesIO or its growable buffer is created.
        before_image(next(item['bytes'] for item in selected['members'] if item['name'] == RETAINED_OBSERVER_IMAGE))
        clock.check()
    return zip_data(body, {'kind': 'retained-git-observer' if selected['nativeScope'] == 'git-native' else 'retained-observer', 'bytes': origin['artifactBytes'],
        'sha256': origin['artifactSha256'], 'members': selected['members']}, clock)


def retained_observer_memory_requirement(selection, retained, *, image_bytes=None):
    """Source-bounded allocation phases; no OS reservation or measured RSS claim."""
    selected = retained_observer_selection_data(selection)
    image = next(item['bytes'] for item in selected['members'] if item['name'] == RETAINED_OBSERVER_IMAGE)
    need(type(retained) is int and 0 <= retained <= 1 << 30
         and (image_bytes is None or type(image_bytes) is int and image_bytes == image),
         'retained-observer-memory-bound')
    archive = selected['origin']['artifactBytes']
    # Original.read: growable ZIP plus final bytes (or a resize), with no image.
    # Decode: immutable ZIP + at most one BytesIO copy; only the main image's
    # growable/final copies overlap. Codec/metadata chunks fit the same 16MiB.
    copies = 3 * archive if image_bytes is None else 2 * archive + 3 * image
    return copies + (16 << 20) + retained + (512 << 20) + (1 << 30)


def stager_failure_data(error, value, origins, expected_path):
    """Only the source-loaded parser's bounded failure DATA; never its inputs."""
    try:
        from pathlib import Path
        from types import ModuleType, FunctionType
        import sys
        path = str(expected_path)
        module = sys.modules.get('_mrk_candidate_stager')
        if (type(module) is not ModuleType or vars(module).get('__file__') != path
                or vars(module).get('__name__') != '_mrk_candidate_stager'):
            return value
        source = vars(module)
        parsers = tuple(source.get(name) for name in ('install_product_members', 'xar_members'))
        namespace, filename = origins[1]
        boundary = namespace.get('mounted_data')
        if not all(type(fn) is FunctionType and fn.__globals__ is ns and fn.__code__.co_filename == name
                   for fn, ns, name in ((boundary, namespace, filename), *((fn, source, path) for fn in parsers))):
            return value
        labels = source.get('INSTALL_PRODUCT_AUDIT_REASONS')
        if not (type(labels) is frozenset and 0 < len(labels) <= 64
                and all(type(label) is str and re.fullmatch(r'[a-z][a-z0-9-]{0,95}', label) for label in labels)):
            return value
        frames, boundary_seen, parser_seen = [], False, False
        tb = BaseException.__traceback__.__get__(error)
        for _ in range(32):
            if tb is None: break
            frame, code = tb.tb_frame, tb.tb_frame.f_code
            boundary_seen |= code is boundary.__code__ and frame.f_globals is namespace
            parser_seen |= boundary_seen and frame.f_globals is source and any(code is fn.__code__ for fn in parsers)
            for ns, name in (*origins, (source, path)):
                if (frame.f_globals is ns and code.co_filename == name
                        and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', code.co_name)
                        and type(tb.tb_lineno) is int and 0 < tb.tb_lineno < 1000000):
                    frames.append({'file': Path(name).name, 'function': code.co_name, 'line': tb.tb_lineno})
                    frames = frames[-8:]
                    break
            tb = tb.tb_next
        if not parser_seen: return value
        result = dict(value, sourceFrames=frames)
        refused = source.get('Refused')
        if type(refused) is type and vars(refused).get('__module__') == '_mrk_candidate_stager' and type(error) is refused:
            labels = labels | frozenset(('xar-header', 'xar-header-bound', 'xar-toc-size', 'xar-toc',
                'scripts-only-package-no-payload', 'xar-member-bound', 'xar-member-encoding',
                'xar-member-size', 'scripts-package-required', 'compressed-data-bound'))
            parts = BaseException.args.__get__(error)
            result['exceptionClass'] = 'Refused'
            result['reason'] = (parts[0] if len(parts) == 1 and type(parts[0]) is str
                                and len(parts[0]) <= 96 and parts[0] in labels else 'unavailable')
        return result
    except BaseException:
        return value


def retained_observer_install_receipt_data(value, selection, helper_source, helper_tree, run, attempt, work_identity):
    """Closed new consumer DATA. Caller must ALSO hold its actual post-return0.

    This record never certifies its own future exit, old Installer finality,
    unavailable old work bindings, native qualification or shipping readiness.
    """
    selected = retained_observer_selection_data(selection)
    origin = selected['origin']
    def digest(value, size=64):
        return type(value) is str and re.fullmatch('[0-9a-f]{' + str(size) + '}', value) is not None and value != '0' * size
    need(digest(helper_source, 40) and digest(helper_tree, 40)
         and all(type(v) is str and re.fullmatch(r'[1-9][0-9]{0,19}', v) for v in (run, attempt))
         and type(work_identity) in (list, tuple) and len(work_identity) == 3
         and all(type(v) is int and v > 0 for v in work_identity), 'retained-observer-consumer-context')
    expected = {'schemaVersion': 1, 'scope': 'retained-observer-fresh-install',
        'packageRole': selected['packageRole'], 'nativeScope': selected['nativeScope'], 'target': origin['target'],
        'nomination': origin, 'helperSource': helper_source, 'helperTree': helper_tree,
        'consumerRunId': run, 'consumerRunAttempt': attempt, 'consumerWorkDirectory': list(work_identity),
        'nativeProducerSignatureVerified': True, 'installedSignaturesVerified': True,
        'originalInstallerReturnedZero': True, 'sameRequestReadback': True, 'originalMountDetached': True,
        'originalClosesKnown': True, 'workloadsKnownSettled': True, 'privateOutputsRetired': True,
        'productReady': False, 'uiQualified': False, 'p0Qualified': False}
    fields = {'members', 'image', 'package', 'descriptor', 'signature', 'inventory', 'release', 'freshInstall'}
    need(type(value) is dict and set(value) == set(expected) | fields
         and all(type(value[k]) is type(v) and value[k] == v for k, v in expected.items()),
         'retained-observer-install-handoff')
    members = value['members']
    need(type(members) is list and len(members) == len(selected['members']), 'retained-observer-handoff-members')
    for row, wanted in zip(members, selected['members']):
        need(type(row) is dict and set(row) == {'name', 'bytes', 'sha256'}
             and row['name'] == wanted['name'] and type(row['bytes']) is int and row['bytes'] == wanted['bytes']
             and digest(row['sha256']) and (row['bytes'] != 0 or row['sha256'] == sha(b'')),
             'retained-observer-handoff-member')
    need(value['image'] == next(row for row in members if row['name'] == RETAINED_OBSERVER_IMAGE),
         'retained-observer-handoff-image')
    for key, name, cap in (('package', 'Install.pkg', LIMIT), ('descriptor', 'producer.json', 16384),
                           ('signature', 'producer.sig', 512), ('inventory', 'install-inventory.json', 12 << 20)):
        row = value[key]
        need(type(row) is dict and set(row) == {'name', 'bytes', 'sha256'} and row['name'] == name
             and type(row['bytes']) is int and 0 < row['bytes'] <= cap and digest(row['sha256']),
             'retained-observer-handoff-control')
    release = value['release']
    need(type(release) is dict and set(release) == {'profile', 'packageIdentifier', 'bundleIdentifier',
        'packageVersion', 'release', 'sourceCommit', 'protocolSha256', 'runtimeManifestSha256',
        'inventorySha256', 'signingPolicySha256', 'packageSha256'}
         and release['profile'] == 'fixed-macos26-arm64-maintenance-v2'
         and release['packageIdentifier'] == 'dev.mobile-release-kit.desktop.installed'
         and release['bundleIdentifier'] == 'dev.mobile-release-kit.desktop'
         and release['sourceCommit'] == origin['source']
         and type(release['packageVersion']) is str and len(release['packageVersion']) <= 32
         and re.fullmatch(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)', release['packageVersion'])
         and all(int(part) <= 0xffffffff for part in release['packageVersion'].split('.'))
         and type(release['release']) is str and len(release['release']) <= 128
         and re.fullmatch(r'macos26-arm64-[a-z0-9_.-]*[a-z0-9]', release['release'])
         and all(digest(release[k]) for k in ('protocolSha256', 'runtimeManifestSha256', 'inventorySha256',
                                              'signingPolicySha256', 'packageSha256'))
         and release['packageSha256'] == value['package']['sha256']
         and release['inventorySha256'] == value['inventory']['sha256'], 'retained-observer-handoff-release')
    fresh = value['freshInstall']
    need(type(fresh) is dict and set(fresh) == {'requestId', 'invocation', 'instance', 'stateSha256', 'resultSha256'}
         and all(digest(fresh[k], 32 if k in ('requestId', 'invocation', 'instance') else 64) for k in fresh),
         'retained-observer-handoff-fresh-install')
    need(len(canonical(value)) <= 16384, 'retained-observer-handoff-bound')
    return value
