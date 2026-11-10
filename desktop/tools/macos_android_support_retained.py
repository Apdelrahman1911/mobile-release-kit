"""Project the unchanged signed Android capsule from a successful retained part.

The supplier's expired service envelope is not recreated. Its three original
members keep their SOURCE pins and signing receipt; no retained program runs.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

_spec = importlib.util.spec_from_file_location('mrk_retained_part_transport',
    Path(__file__).with_name('macos_candidate_part_transport.py'))
T = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(T)


ARTIFACT = 13731635223
ARTIFACT_BYTES = 215455359
ARTIFACT_SHA = '0ab342b4ef0eac7b96ade39937801a6aed5c9d2950123f5ff3f6ec445cc43543'
ORIGIN = dict(source='f778beb993691330c56b59059de5c8d970fbb27d',
              tree='bdd9e77af2c626e435e02f9fbebfd229ef6a06a7',
              target='aarch64-apple-darwin', runId='42745647519', runAttempt='1',
              jobId='129597395171', nativeScope='disabled', hostProfile='macos-26')
PREFIX = 'work/signed-android-transport/'


def project(archive, destination, expected):
    """Only SOURCE-selected inert members cross into a fresh destination."""
    manifest = T.archive_manifest(archive)
    T.need(manifest['part'] == 'prepare' and manifest['origin'] == ORIGIN
           and manifest['dependencies'] == [], 'android-retained-original-part')
    rows = {row['path'][len(PREFIX):]: row for row in manifest['members']
            if row['path'].startswith(PREFIX)}
    T.need(set(rows) == set(expected) and len(rows) == 3
           and all('/' not in name and name not in ('', '.', '..') for name in rows),
           'android-retained-capsule-roster')
    for name, (size, digest) in expected.items():
        row = rows[name]
        T.need(row['bytes'] == size and row['sha256'] == digest
               and row['mode'] in (0o400, 0o444, 0o600, 0o644),
               'android-retained-source-pin')
    destination.mkdir(mode=0o700)
    with T.original(archive, T.P.TOTAL_LIMIT + T.P.MANIFEST_LIMIT + 16 * 1024**2) as (stream, info):
        entries = T.archive_entries(stream, info.st_size, maximum_members=T.P.MAX_MEMBERS + 1)
        for name, (size, digest) in expected.items():
            copied = T.exclusive(destination / name,
                lambda output: T.stream_member(stream, entries[PREFIX + name], size, output), 0o644)
            T.need(copied == digest, 'android-retained-member-hash')
            with T.original(destination / name, size) as (output, observed):
                T.need(observed.st_size == size
                       and hashlib.file_digest(output, 'sha256').hexdigest() == digest,
                       'android-retained-copy-readback')
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--work', required=True, type=Path)
    args = parser.parse_args()
    T.need(args.work.is_absolute(), 'android-retained-work-path')
    root = args.work / 'signed-android-retained-part'
    T.need(sorted(p.name for p in root.iterdir()) == ['PART.zip'], 'android-retained-download-roster')
    run = T.api_json('repos/' + T.P.REPOSITORY + '/actions/runs/' + ORIGIN['runId'])
    job = T.api_json('repos/' + T.P.REPOSITORY + '/actions/jobs/' + ORIGIN['jobId'])
    artifact = T.api_json('repos/' + T.P.REPOSITORY + '/actions/artifacts/' + str(ARTIFACT))
    T.need(artifact.get('id') == ARTIFACT and artifact.get('size_in_bytes') == ARTIFACT_BYTES
           and artifact.get('digest') == 'sha256:' + ARTIFACT_SHA,
           'android-retained-service-pin')
    T.P.service_metadata_data(run, job, artifact, 'prepare', ORIGIN)
    with T.S.android_signed_source() as (_module, relation, _manifest_sha, _rows, _producer, _service):
        expected = {a.file_name: (a.derived.size, a.derived.sha256) for a in relation.archives}
        expected['android-support-signed-receipt.json'] = (relation.receipt.size, relation.receipt.sha256)
    destination = args.work / 'signed-android-transport'
    manifest = project(root / 'PART.zip', destination, expected)
    capsule = argparse.Namespace(bundletool_archive=destination / 'bundletool-all-1.18.3.jar',
        aapt2_archive=destination / 'aapt2-8.9.2-12782657-osx.jar',
        android_support_signed_receipt=destination / 'android-support-signed-receipt.json')
    result = T.S.android_support_command(capsule)
    proof = dict(kind='unchanged-signed-android-capsule-from-retained-prepare',
        retainedPart=T.P.metadata_data(run, job, artifact, manifest), capsule=result,
        members=[dict(name=name, bytes=size, sha256=digest) for name, (size, digest) in expected.items()],
        originalSupplierServiceEnvelopeRecreated=False, retainedProgramsExecuted=False, signingExecuted=False)
    T.write(args.work / 'android-support-retained-transport.json', T.P.canonical(proof))
    print(json.dumps(proof, sort_keys=True))


if __name__ == '__main__':
    main()
