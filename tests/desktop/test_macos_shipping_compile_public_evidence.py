"""Shipping compile artifact DATA only; no inline owner/bootstrap execution."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/desktop-macos-installed.yml'
SOURCE, RUN_ID, ATTEMPT = 'a' * 40, '123', '1'






def programs():
    # Exercise the actual current reducers, not a reconstructed historical YAML.
    workflow = WORKFLOW.read_text()
    script = (ROOT / "desktop/tools/macos_shipping_image_compile.sh").read_text()
    result = []
    for source, marker, indent in (
        (workflow, "PY_SHIPPING_COMPILE_ADMIT", "          "),
        (script, "PY_SHIPPING_IMAGE_COMPILE", ""),
    ):
        opening = "<<'" + marker + "'\n"
        assert source.count(opening) == 1
        body = source.split(opening, 1)[1].split(indent + marker + "\n", 1)[0]
        assert all(not line.strip() or line.startswith(indent) for line in body.splitlines())
        result.append("".join(line[len(indent):] if line.startswith(indent) else line
                              for line in body.splitlines(True)))
    return workflow, result


def reducers(program):
    names = {'need', 'compile_public_data'}
    nodes = [node for node in ast.parse(program).body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert len(nodes) == 2 and {node.name for node in nodes} == names
    namespace = dict(json=json, re=re)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<genuine-shipping-public-DATA>', 'exec'), namespace)
    return namespace['compile_public_data']


def receipt():
    roles = ('node-version', 'npm-version', 'rustc-version', 'cargo-version', 'npm-ci', 'frontend-build', 'shipping-image-build')
    value = dict(schemaVersion=1, scope='fixed-arm-shipping-image-compile-only', source=SOURCE,
                 workflowSource=SOURCE, runId=RUN_ID, runAttempt=ATTEMPT, target='aarch64-apple-darwin',
                 originalPending=False, sourcePost=True, toolsPost=True, frontendGenerated=True,
                 facadeArtifactVerified=True, inputOriginalsKnown=True, toolOriginalsClosed=True,
                 generatedOutputsRetired=True, shippingGraphCompiled=True, installedQualified=False,
                 runtimeQualified=False, launched=False, signed=False, pythonControllerPrepared=True,
                 pythonControllerPost=True, pythonControllerRetired=True, failure=None,
                 sourceInventoryBytes=256, sourceInventorySha256='b' * 64,
                 facadeArtifact=dict(bytes=4096, sha256='c' * 64, identity=['PRIVATE-SENTINEL']))
    value['commands'] = [dict(role=role, argv=['PRIVATE-SENTINEL'], returned=True, capturesSettled=True,
                             returncode=0, stdoutBytes=1, stderrBytes=0,
                             stdoutSha256='d' * 64, stderrSha256=hashlib.sha256(b'').hexdigest()) for role in roles]
    return value




class ShippingCompilePublicEvidenceData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        absent = object()
        prior = {name: cls.__dict__.get(name, absent) for name in ("workflow", "programs", "projectors")}
        def restore_original_bindings():
            for name, value in prior.items():
                if value is absent:
                    if name in cls.__dict__: delattr(cls, name)
                else: setattr(cls, name, value)
        cls.addClassCleanup(restore_original_bindings)  # Enrolled before fallible SOURCE setup.
        cls.workflow, cls.programs = programs()
        cls.projectors = tuple(reducers(program) for program in cls.programs)

    def project(self, value):
        observed = [project(value, SOURCE, RUN_ID, ATTEMPT) for project in self.projectors]
        self.assertEqual(observed[0], observed[1])
        return observed[0]

    def test_full_success_keeps_genuine_compile_closure_and_hashes_only(self):
        value = receipt()
        nodes = [node for node in ast.parse(self.programs[1]).body if
                 isinstance(node, ast.FunctionDef) and node.name in ('cleanup_allowed_data', 'passed_data') or
                 isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'ROLES']
        self.assertEqual(len(nodes), 3)
        genuine = {}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<genuine-existing-compile-acceptance>', 'exec'), genuine)
        self.assertTrue(genuine['passed_data'](value))
        observed = self.project(value)
        self.assertTrue(observed['facts']['shippingGraphCompiled'])
        self.assertEqual(len(observed['facts']), 16)
        self.assertEqual(len(observed['commands']), 7)
        self.assertEqual(observed['sourceInventory'], dict(bytes=256, sha256='b' * 64))
        self.assertEqual(observed['facadeArtifact'], dict(bytes=4096, sha256='c' * 64))
        self.assertEqual({key: observed[key] for key in ('source', 'workflowSource', 'runId', 'runAttempt', 'target')},
                         {key: value[key] for key in ('source', 'workflowSource', 'runId', 'runAttempt', 'target')})
        for old, new in zip(value['commands'], observed['commands'], strict=True):
            self.assertEqual(new, {key: old[key] for key in old if key != 'argv'})
        self.assertNotIn('PRIVATE-SENTINEL', json.dumps(observed))
        self.assertNotIn('publicationComplete', observed)

    def test_preparation_failure_keeps_missing_distinct_from_false(self):
        value = receipt()
        for name in ('originalPending', 'sourcePost', 'toolsPost', 'frontendGenerated', 'facadeArtifactVerified',
                     'toolOriginalsClosed', 'generatedOutputsRetired', 'sourceInventoryBytes', 'sourceInventorySha256', 'facadeArtifact'):
            del value[name]
        value.update(commands=[], shippingGraphCompiled=False, pythonControllerPrepared=False,
                     pythonControllerPost=False, pythonControllerRetired=False,
                     failure=dict(stage='python-create', kind='PRIVATE-SENTINEL', condition='controller-operation'))
        observed = self.project(value)
        self.assertIsNone(observed['facts']['originalPending'])
        self.assertIsNone(observed['facts']['sourcePost'])
        self.assertIs(observed['facts']['pythonControllerPrepared'], False)
        self.assertIs(observed['facts']['shippingGraphCompiled'], False)
        self.assertIsNone(observed['sourceInventory'])
        self.assertEqual(observed['failure'], dict(stage='python-create', condition='controller-operation', ownerDiagnostic=None))
        value['failure']['ownerDiagnostic'] = dict(available=False)
        self.assertEqual(self.project(value)['failure']['ownerDiagnostic'], dict(available=False, typedFacts=[], chainTruncated=None))
        value['failure']['ownerDiagnostic'] = dict(available=False, typedFacts=[], chainTruncated=False)
        self.assertIs(self.project(value)['failure']['ownerDiagnostic']['chainTruncated'], False)

    def test_nonzero_and_unknown_originals_are_never_upgraded_to_success(self):
        value = receipt()
        value.update(shippingGraphCompiled=False, originalPending=True, inputOriginalsKnown=False,
                     toolOriginalsClosed=False, generatedOutputsRetired=False,
                     failure=dict(stage='shipping-image-build', condition='cargo-document', ownerDiagnostic=dict(
                         available=True, chainTruncated=True, typedFacts=[dict(kind='process-error', reason='output-bound',
                         ownerFailureMask=5, dispatched=True, contained=False, cleanupComplete=None)])))
        value['commands'] = value['commands'][:6]
        value['commands'][-1]['returncode'] = 70
        observed = self.project(value)
        self.assertFalse(observed['facts']['shippingGraphCompiled'])
        self.assertTrue(observed['facts']['originalPending'])
        self.assertEqual(observed['commands'][-1]['returncode'], 70)
        self.assertEqual(observed['failure']['ownerDiagnostic'], value['failure']['ownerDiagnostic'])
        value['commands'][-1]['returncode'] = -9
        self.assertEqual(self.project(value)['commands'][-1]['returncode'], -9)
        value['failure'].update(stage='PRIVATE-SENTINEL', condition='PRIVATE-SENTINEL')
        self.assertEqual(self.project(value)['failure']['stage'], 'other')
        self.assertEqual(self.project(value)['failure']['condition'], 'unclassified')

    def test_private_fields_are_not_traversed_or_stringified(self):
        class Private:
            def __str__(self):
                raise AssertionError('private stringification')
            def __iter__(self):
                raise AssertionError('private traversal')
        value = receipt()
        private = Private()
        value.update(pythonController=private, pythonControllerObserved=private, pythonControllerRuntime=private,
                     toolOriginals=private, facadeArtifactObserved=private, release=private, arbitrary=private)
        value['facadeArtifact']['identity'] = private
        for row in value['commands']:
            row['argv'] = private
            row['cwd'] = private
        value.update(shippingGraphCompiled=False, failure=dict(stage='admission', kind=private, private=private))
        before_keys = tuple(value)
        observed = self.project(value)
        self.assertEqual(tuple(value), before_keys)
        self.assertIs(value['arbitrary'], private)
        self.assertEqual(set(observed), {'kind', 'schemaVersion', 'scope', 'source', 'workflowSource', 'runId',
            'runAttempt', 'target', 'facts', 'commands', 'sourceInventory', 'facadeArtifact', 'failure'})
        self.assertNotIn('identity', json.dumps(observed))
        self.assertNotIn('argv', json.dumps(observed))

    def test_typed_context_roles_hashes_and_success_consistency_refuse_mutations(self):
        changes = [lambda v: v.update(schemaVersion=True), lambda v: v.update(source='0' * 40),
            lambda v: v.update(workflowSource='b' * 40), lambda v: v.update(runId='124'),
            lambda v: v.update(runAttempt='2'), lambda v: v.update(target='x86_64-apple-darwin'),
            lambda v: v.update(scope='installed'), lambda v: v.update(shippingGraphCompiled=1),
            lambda v: v.update(sourcePost=None), lambda v: v.update(signed=True),
            lambda v: v['commands'].append(copy.deepcopy(v['commands'][-1])),
            lambda v: v['commands'][1].update(role='node-version'),
            lambda v: v['commands'][0].update(returncode=True),
            lambda v: v['commands'][0].update(returncode=2**31),
            lambda v: v['commands'][0].update(returncode=-(2**31)-1),
            lambda v: v['commands'][0].update(returned=1),
            lambda v: v['commands'][0].update(stdoutBytes=True),
            lambda v: v['commands'][0].update(stdoutBytes=4096, stderrBytes=1),
            lambda v: v['commands'][4].update(stdoutBytes=4*1024*1024+1),
            lambda v: v['commands'][0].update(stderrSha256='A'*64),
            lambda v: v.update(sourceInventoryBytes=0), lambda v: v.pop('sourceInventorySha256'),
            lambda v: v['facadeArtifact'].update(bytes=256*1024*1024+1), lambda v: v['facadeArtifact'].pop('sha256'),
            lambda v: v.update(failure={}), lambda v: v.update(failure=dict(stage='admission', condition=[])),
            lambda v: v.update(failure=dict(stage='admission', ownerDiagnostic=dict(available=1))),
            lambda v: v.update(failure=dict(stage='admission', ownerDiagnostic=dict(available=False, typedFacts=[{}])))]
        for name in ('sourcePost', 'toolsPost', 'frontendGenerated', 'facadeArtifactVerified', 'inputOriginalsKnown',
                     'toolOriginalsClosed', 'generatedOutputsRetired', 'pythonControllerPrepared', 'pythonControllerPost', 'pythonControllerRetired'):
            changes.append(lambda v, name=name: v.update({name: False}))
        changes += [lambda v: v.update(originalPending=True), lambda v: v['commands'].pop(),
                    lambda v: v['commands'][0].update(returncode=70), lambda v: v['commands'][0].update(capturesSettled=False)]
        for index, change in enumerate(changes):
            value = receipt(); change(value)
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.project(value)
        bad_owner = dict(kind='process-error', reason='output-bound', ownerFailureMask=1,
                         dispatched=True, contained=False, cleanupComplete=None)
        for field, item in (('kind', 'PRIVATE-SENTINEL'), ('reason', 'PRIVATE-SENTINEL'),
                            ('ownerFailureMask', True), ('ownerFailureMask', 64), ('contained', 1)):
            value = receipt(); row = dict(bad_owner, **{field: item})
            value.update(shippingGraphCompiled=False, failure=dict(stage='admission',
                ownerDiagnostic=dict(available=True, typedFacts=[row], chainTruncated=False)))
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.project(value)

    def test_full_maximum_observation_roster_fits_existing_sixteen_kib(self):
        value = receipt()
        value.update(shippingGraphCompiled=False, sourceInventoryBytes=2*1024*1024)
        value['facadeArtifact']['bytes'] = 256*1024*1024
        for index, row in enumerate(value['commands']):
            row.update(stdoutBytes=4096 if index < 4 else 4*1024*1024, returncode=-(2**31))
        owner_row = dict(kind='process-error', reason='command-failed-or-incomplete', ownerFailureMask=63,
                         dispatched=False, contained=False, cleanupComplete=False)
        value['failure'] = dict(stage='shipping-image-build', condition='controller-original-changed',
                               ownerDiagnostic=dict(available=True, typedFacts=[copy.deepcopy(owner_row) for _ in range(16)], chainTruncated=True))
        observed = self.project(value)
        self.assertEqual(len(observed['failure']['ownerDiagnostic']['typedFacts']), 16)
        self.assertLessEqual(len((json.dumps(observed, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode('ascii')), 16384)
        value['failure']['ownerDiagnostic']['typedFacts'].append(copy.deepcopy(owner_row))
        with self.assertRaises(ValueError): self.project(value)
