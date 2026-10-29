"""Intermediate provenance and retry planning DATA; no hosted/native calls."""
import copy
import json
import unittest

from desktop.tools import macos_candidate_parts as P


def fixture(part='prepare', scope='tool-setup'):
    origin = dict(source='1' * 40, tree='2' * 40, target=P.TARGET, runId='41', runAttempt='1',
                  jobId='42', nativeScope=scope, hostProfile=P.PROFILES[scope][1])
    dependencies = [dict(part=name, origin=dict(origin, jobId=str(100 + i)), artifactId=str(200 + i),
                         artifactSha256='a' * 64, manifestSha256='b' * 64)
                    for i, name in enumerate(P.ancestors(part))]
    manifest = dict(schemaVersion=1, scope=P.SCOPE, part=part, origin=origin, dependencies=dependencies,
                    workName='mrk-macos-installed.ABC123de', directories=[],
                    members=[dict(path='work/runtime/manifest.json', bytes=6, mode=0o444, sha256=P.sha(b'inert\n'))],
                    originalCallerZero=True, originalReadsClosed=True,
                    nativeAuthority=False, installed=False, productReady=False)
    run = dict(id=41, run_attempt=1, workflow_id=363563168, head_sha=origin['source'], head_branch=P.BRANCH, event='push',
               path=P.WORKFLOW, repository={'full_name': P.REPOSITORY},
               head_commit={'id': origin['source'], 'tree_id': origin['tree']})
    names = (*P.ORIGINAL_CUTS[part], *P.EXTRA_STEPS.get(part, ()),
             'Verify and freeze completed part originals', 'Upload immutable completed part')
    job = dict(id=42, run_id=41, run_attempt=1, head_sha=origin['source'], status='completed', conclusion='success',
               name=P.job_name(part, origin), labels=[origin['hostProfile']],
               steps=[dict(name=name, status='completed', conclusion='success') for name in names])
    artifact = dict(id=43, expired=False, name=P.artifact_name(part, origin), size_in_bytes=1024,
                    digest='sha256:' + '3' * 64,
                    workflow_run=dict(id=41, head_sha=origin['source'], head_branch=P.BRANCH))
    return manifest, run, job, artifact


class CandidatePartsDataTests(unittest.TestCase):
    def test_graph_keeps_all_original_cuts_and_all_signing_dependencies(self):
        cuts = [cut for part in P.PARTS for cut in P.ORIGINAL_CUTS[part]]
        self.assertEqual(len(cuts), 17)
        self.assertEqual(len(set(cuts)), 17)
        self.assertEqual(set(P.PARTS), set(P.ORIGINAL_CUTS))
        seen = set()
        for part, dependencies in P.PARTS.items():
            self.assertTrue(set(dependencies) <= seen)
            self.assertNotIn(part, P.ancestors(part))
            seen.add(part)
        self.assertTrue({'observer', 'resident', 'vault', 'frontend', 'sign-cli', 'sign-remover'} <= set(P.ancestors('assemble')))
        self.assertEqual(set(P.ancestors('final-package')), set(P.PARTS) - {'final-package'})

    def test_failed_signing_retries_without_rebuilding_completed_compilers(self):
        statuses = dict.fromkeys(P.PARTS, 'success')
        statuses.update({'sign-cli': 'failure', 'assemble': 'skipped', 'notarize-payload': 'skipped',
                         'installer': 'skipped', 'scripts-package': 'skipped', 'final-package': 'skipped',
                         })
        self.assertEqual(P.ready_parts(statuses), ('sign-cli',))
        statuses['sign-cli'] = 'running'
        self.assertEqual(P.ready_parts(statuses), ())
        statuses['sign-cli'] = 'success'
        self.assertEqual(P.ready_parts(statuses), ('assemble',))
        self.assertTrue(all(statuses[k] == 'success' for k in ('observer', 'cli', 'remover', 'resident')))
        before = copy.deepcopy(statuses)
        P.ready_parts(statuses)
        self.assertEqual(statuses, before)
        self.assertEqual(P.ready_parts(dict.fromkeys(P.PARTS, 'pending')), ('prepare',))
        for wrong in ({}, dict(statuses, foreign='success'), dict(statuses, prepare=True)):
            with self.assertRaises(ValueError): P.ready_parts(wrong)

    def test_each_part_and_host_admits_only_actual_successful_source_bound_job(self):
        for part in P.PARTS:
            for scope in P.PROFILES:
                with self.subTest(part=part, scope=scope):
                    manifest, run, job, artifact = fixture(part, scope)
                    before = copy.deepcopy((manifest, run, job, artifact))
                    admitted = P.metadata_data(run, job, artifact, manifest)
                    self.assertEqual(admitted['part'], part)
                    self.assertEqual(admitted['origin'], manifest['origin'])
                    self.assertEqual(admitted['artifactSha256'], artifact['digest'][7:])
                    self.assertEqual(admitted['manifestSha256'], P.sha(P.canonical(manifest)))
                    self.assertEqual((manifest, run, job, artifact), before)
                    self.assertFalse(manifest['nativeAuthority'] or manifest['installed'] or manifest['productReady'])
                    # A later rerun can consume this original completed attempt;
                    # the actual job must continue to identify attempt1.
                    run['run_attempt'] = 2
                    self.assertEqual(P.metadata_data(run, job, artifact, manifest), admitted)

    def test_successful_receipt_cannot_replace_job_steps_artifact_source_or_host(self):
        manifest, run, job, artifact = fixture('observer')
        for where, key, value in (
            ('run', 'head_sha', '4' * 40), ('run', 'path', 'foreign.yml'), ('run', 'event', 'workflow_dispatch'),
            ('run', 'head_branch', 'main'), ('run', 'run_attempt', True),
            ('job', 'status', 'in_progress'), ('job', 'conclusion', 'failure'), ('job', 'run_attempt', 2),
            ('job', 'run_attempt', True), ('job', 'head_sha', '4' * 40), ('job', 'id', 44),
            ('job', 'name', 'foreign'), ('job', 'labels', ['macos-26-intel']),
            ('artifact', 'expired', True), ('artifact', 'digest', 'sha256:bad'),
            ('artifact', 'name', 'old-source'), ('artifact', 'size_in_bytes', P.TOTAL_LIMIT + 1),
        ):
            values = {'run': copy.deepcopy(run), 'job': copy.deepcopy(job), 'artifact': copy.deepcopy(artifact)}
            values[where][key] = value
            with self.subTest(where=where, key=key), self.assertRaises(ValueError):
                P.metadata_data(values['run'], values['job'], values['artifact'], manifest)
        for changed in ('missing', 'duplicate', 'skipped', 'failure'):
            wrong = copy.deepcopy(job)
            if changed == 'missing': wrong['steps'].pop(0)
            elif changed == 'duplicate': wrong['steps'].append(copy.deepcopy(wrong['steps'][0]))
            else: wrong['steps'][0]['conclusion'] = changed
            with self.subTest(changed=changed), self.assertRaises(ValueError): P.metadata_data(run, wrong, artifact, manifest)
        for key in ('source', 'tree'):
            wrong = copy.deepcopy(run); wrong['head_commit']['id' if key == 'source' else 'tree_id'] = '5' * 40
            with self.assertRaises(ValueError): P.metadata_data(wrong, job, artifact, manifest)

    def test_changed_app_scope_run_or_dependency_is_never_compatible(self):
        manifest, *_ = fixture('assemble')
        for field, wrong in (('source', '4' * 40), ('tree', '5' * 40), ('runId', '99'),
                             ('nativeScope', 'git-native'), ('hostProfile', 'xcode-27')):
            value = copy.deepcopy(manifest); value['dependencies'][0]['origin'][field] = wrong
            with self.subTest(field=field), self.assertRaises(ValueError): P.manifest_data(value)
        for mutate in (lambda v: v['dependencies'].pop(),
                       lambda v: v['dependencies'].reverse(),
                       lambda v: v['dependencies'].append(v['dependencies'][0]),
                       lambda v: v['dependencies'][0].update(artifactSha256='private-path')):
            value = copy.deepcopy(manifest); mutate(value)
            with self.assertRaises(ValueError): P.manifest_data(value)

    def test_checkpoint_rejects_partial_unknown_duplicate_or_credential_members(self):
        manifest, *_ = fixture()
        for key, value in (('schemaVersion', True), ('originalCallerZero', False), ('originalReadsClosed', False),
                           ('nativeAuthority', True), ('installed', True), ('productReady', True),
                           ('members', [])):
            wrong = copy.deepcopy(manifest); wrong[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): P.manifest_data(wrong)
        for path in ('../private', 'work/../private', '/work/file', 'work//file', 'work/file\x00',
                     'work\\file', 'home/credentials', 'work/credential-active/identity',
                     'work/private/identity.keychain-db', 'work/private/certificate.p12'):
            wrong = copy.deepcopy(manifest); wrong['members'][0]['path'] = path
            with self.subTest(path=path), self.assertRaises(ValueError): P.manifest_data(wrong)
        for field, value in (('bytes', True), ('bytes', -1), ('bytes', P.MEMBER_LIMIT + 1),
                             ('mode', 0o4755), ('sha256', '0' * 64)):
            wrong = copy.deepcopy(manifest); wrong['members'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): P.manifest_data(wrong)
        wrong = copy.deepcopy(manifest); wrong['members'] *= 2
        with self.assertRaises(ValueError): P.manifest_data(wrong)
        wrong = copy.deepcopy(manifest)
        wrong['members'] = [dict(wrong['members'][0], path=p) for p in ('work/one', 'work/one/child')]
        with self.assertRaises(ValueError): P.manifest_data(wrong)
        # Public runtime modules and public certificates are not signing stores.
        for path in ('work/runtime/credentials.py', 'work/runtime/cacert.pem'):
            P.path_data(path)

    def test_json_is_canonical_bounded_and_duplicate_keys_cannot_change_authority(self):
        manifest, *_ = fixture()
        self.assertEqual(P.manifest_data(P.decode(P.canonical(manifest))), manifest)
        for body in (b'{"a":1,"a":2}\n', b'{"a":NaN}\n', b'{}', b'{}\n ',
                     b'x' * (P.MANIFEST_LIMIT + 1), b''):
            with self.assertRaises(ValueError): P.decode(body)


if __name__ == '__main__':
    unittest.main()
