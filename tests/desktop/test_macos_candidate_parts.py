"""Intermediate provenance and retry planning DATA; no hosted/native calls."""
import copy
import json
import os
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


"""Check actual packaging source bytes against their unchanged source readers.

This is DATA-only: parse source, never import packaging or execute a native tool.
The early candidate DATA job runs these checks before compilation or signing.
"""
import ast
import hashlib
from pathlib import Path
import stat
import unittest

ROOT = Path(__file__).absolute().parents[2]
TOOLS = ROOT / "desktop/tools"
KIB = 1024
MIB = 1024 * KIB


def literal(node, names):
    if isinstance(node, ast.Constant) and type(node.value) in (str, int):
        return node.value
    if isinstance(node, ast.Name):
        return names[node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return tuple(literal(item, names) for item in node.elts)
    if isinstance(node, ast.BinOp):
        left, right = literal(node.left, names), literal(node.right, names)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.LShift):
            return left << right
    if (isinstance(node, ast.IfExp) and isinstance(node.test, ast.Compare)
            and len(node.test.ops) == 1 and isinstance(node.test.ops[0], ast.Eq)):
        same = literal(node.test.left, names) == literal(node.test.comparators[0], names)
        return literal(node.body if same else node.orelse, names)
    raise ValueError("unsupported source-reader expression")


def assignments(tree, names=None):
    result = dict(names or {})
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                result[node.targets[0].id] = literal(node.value, result)
            except (KeyError, ValueError, TypeError):
                pass
    return result


def function(tree, name):
    selected = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(selected) != 1:
        raise ValueError("one fixed source-reader function required: " + name)
    return selected[0]


def source_calls(tree):
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == "source_original"]


def loop_readers(tree, name, names):
    method = function(tree, name)
    names = assignments(method, names)
    rows = []
    for loop in (node for node in ast.walk(method) if isinstance(node, ast.For)):
        try:
            items = literal(loop.iter, names)
        except (KeyError, ValueError, TypeError):
            continue
        for item in items:
            current = dict(names)
            targets = (loop.target,) if isinstance(loop.target, ast.Name) else loop.target.elts
            values = (item,) if isinstance(loop.target, ast.Name) else item
            current.update((target.id, value) for target, value in zip(targets, values))
            for call in source_calls(loop):
                try:
                    path, cap = literal(call.args[0], current), literal(call.args[2], current)
                except (KeyError, ValueError, TypeError, IndexError):
                    continue
                if isinstance(path, str) and path.startswith("desktop/tools/") and path.endswith(".py"):
                    rows.append((path, cap))
    return rows


class MacPackagingSourceLimits(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper_body = cls.read_source("desktop/tools/macos_android_helper_package.py", MIB)
        cls.helper = ast.parse(cls.helper_body)
        cls.names = assignments(cls.helper)

    @staticmethod
    def read_source(relative, cap):
        path = ROOT / relative
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= cap:
            raise AssertionError(f"{relative}: {before.st_size} bytes exceeds source reader {cap}")
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
                    getattr(info, "st_flags", 0))
        with path.open("rb") as original:
            if identity(os.fstat(original.fileno())) != identity(before):
                raise AssertionError("source changed before DATA read: " + relative)
            body = original.read(cap + 1)
            if identity(os.fstat(original.fileno())) != identity(before):
                raise AssertionError("source changed during DATA read: " + relative)
        if len(body) != before.st_size or identity(path.lstat()) != identity(before):
            raise AssertionError("source changed after DATA read: " + relative)
        return body

    def test_all_three_packaging_stager_readers_and_helper_fit(self):
        expected = [("desktop/tools/stage_macos_installed.py", 512 * KIB),
                    ("desktop/tools/macos_android_helper_package.py", MIB)]
        for name in ("notarize_payload", "finalize_image", "finalize_package"):
            with self.subTest(reader=name):
                rows = loop_readers(self.helper, name, self.names)
                self.assertEqual(rows, expected, "source-reader contract changed; audit its real bounds")
                for path, cap in rows:
                    self.read_source(path, cap)

    def test_python_and_removal_sibling_source_readers_fit(self):
        expected = {
            "python_prepare": [
                ("macos_python_supplier_transport.py", MIB), ("macos_cpython_orchestrator.py", MIB),
                ("macos_cpython_source_build.py", MIB), ("macos_cpython_source_probe.py", MIB),
                ("stage_macos_installed.py", MIB), ("macos_android_helper_package.py", MIB)],
            "removal_preload": [("macos_xcode_host_preparation.py", 512 * KIB),
                                ("macos_normal_ui_runner.py", 512 * KIB)],
        }
        for name, wanted in expected.items():
            with self.subTest(reader=name):
                rows = loop_readers(self.helper, name, self.names)
                self.assertEqual(rows, [("desktop/tools/" + path, cap) for path, cap in wanted])
                for path, cap in rows:
                    self.read_source(path, cap)

    def test_direct_host_and_setup_source_readers_fit(self):
        for name, role, path, cap in (
            ("removal_baseline_admit", "removal-baseline-host-source", "macos_xcode_host_preparation.py", 512 * KIB),
            ("normal_mount_host", "source-package-mount-host", "macos_xcode_host_preparation.py", 97065),
            ("verify_xcode_setup_package", "setup-log-reader-source", "stage_macos_installed.py", MIB),
        ):
            with self.subTest(reader=name):
                selected = [call for call in source_calls(function(self.helper, name))
                            if len(call.args) >= 3 and isinstance(call.args[1], ast.Constant)
                            and call.args[1].value == role]
                self.assertEqual(len(selected), 1)
                call = selected[0]
                self.assertEqual((literal(call.args[0], self.names), literal(call.args[2], self.names)),
                                 ("desktop/tools/" + path, cap))
                body = self.read_source("desktop/tools/" + path, cap)
                if name == "normal_mount_host":
                    self.assertEqual(len(body), 97065)
                    self.assertEqual(hashlib.sha256(body).hexdigest(),
                                     "ae198b3615450a474d948b32145735bbfa16635fb7871d0ef7c31efdc3bd785e")

    def test_shared_resume_module_roster_including_aqua_fits(self):
        parsed = ast.parse(self.read_source("desktop/tools/macos_fixed_carrier_resume.py", MIB))
        names = assignments(parsed)
        self.assertEqual(names["SOURCE_MODULE_LIMIT"], MIB)
        rows = names["SOURCE_FILES"]
        self.assertIn("desktop/tools/macos_aqua_qualification.py", rows)
        self.assertIn("desktop/tools/stage_macos_installed.py", rows)
        for path in rows:
            with self.subTest(source=path):
                self.read_source(path, names["SOURCE_MODULE_LIMIT"])


if __name__ == '__main__':
    unittest.main()
