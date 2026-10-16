"""Current candidate carrier DATA admission; no download, install or CLI entry.

Loaded by a trusted checkout consumer. Historical fixed-carrier execution remains
separate; successful parsing grants neither native nor Store authority.
"""
import io
import re
import zipfile

from desktop.tools.macos_fixed_carrier_resume import (
    CANDIDATE_MEMBERS, LIMIT, REPOSITORY, WORKFLOW, WORKFLOW_ID,
    decode, need, sha, zip_data, zip_directory_data,
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
         and job.get('head_sha') == row['source'] and job.get('name') == 'normal-installed-' + row['target']
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


def candidate_members(body, nomination, clock):
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
        wanted = [{'name': name, 'bytes': len(content), 'sha256': sha(content)} for name, content in small.items()]
        wanted.append({'name': 'MobileReleaseKit.dmg', 'bytes': preview['distributionBytes'],
                       'sha256': preview['distributionSha256']})
    # The outer artifact authenticates PREVIEW; PREVIEW binds the actual DMG.
    # Neither replaces native producer/signature verification or fresh readback.
    return zip_data(body, {'kind': 'candidate', 'bytes': row['artifactBytes'],
                           'sha256': row['artifactSha256'], 'members': wanted}, clock)


