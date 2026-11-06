"""Shipping compile artifact DATA only; no inline owner/bootstrap execution."""
import ast
import copy
import hashlib
import json
import math
import subprocess
from types import SimpleNamespace
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
        ((ROOT / ".github/actions/macos-candidate-recipes/compile_work/action.yml").read_text(), "PY_SHIPPING_COMPILE_ADMIT", "        "),
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
                 isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id in ('ROLES', 'REMAINING_SCOPE', 'REMAINING_ROLES')]
        self.assertEqual(len(nodes), 5)
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

    def genuine_functions(self, names):
        nodes = [node for node in ast.parse(self.programs[1]).body
                 if isinstance(node, ast.FunctionDef) and node.name in names]
        self.assertEqual({node.name for node in nodes}, set(names))
        namespace = dict(json=json, re=re, math=math, Path=Path, subprocess=subprocess,
                         TARGET='aarch64-apple-darwin')
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<genuine-compile-DATA>', 'exec'), namespace)
        return namespace

    def extended_receipt(self):
        value = receipt()
        roles = ('resident-image-build', 'shipping-image-build', 'vault-helper-build',
                 'installed-cli-build', 'observer-build', 'application-libtest-build')
        value.update(scope='fixed-arm-remaining-roles-and-libtest-compile-only', sourceTree='f' * 40,
                     libtestRetained=True, testsExecuted=False)
        value['commands'] = value['commands'][:6] + [dict(value['commands'][-1], role=role) for role in roles]
        specifications = (
            ('desktop/helpers/macos-android-register', 'mrk_resident_image', 'cdylib', False, '3', []),
            ('desktop/helpers/macos-desktop-image', 'mrk_desktop_image', 'cdylib', False, '3', []),
            ('desktop/helpers/macos-vault-helper', 'mrk-vault-keychain', 'bin', False, '3', []),
            ('desktop/src-tauri', 'mrk', 'bin', False, '3', ['installed-cli']),
            ('desktop/src-tauri', 'installed-shell-observation', 'test', True, '0',
             ['custom-protocol', 'desktop-shell', 'macos-installed-observation']),
            ('desktop/src-tauri', 'mobile_release_desktop', 'lib', True, '1', []))
        value['compiledArtifacts'] = [dict(role=role, manifest=path + '/Cargo.toml', target=target,
            kind=kind, test=test, optLevel=opt, features=features, bytes=4096, sha256='a' * 64,
            cargoStdoutSha256='d' * 64) for role, (path, target, kind, test, opt, features)
            in zip(roles, specifications, strict=True)]
        return value

    def test_six_role_success_and_each_unsettled_failure_use_actual_projectors(self):
        value = self.extended_receipt()
        self.assertEqual(len(self.project(value)['compiledArtifacts']), 6)
        caps = (1200, 1200, 600, 900, 1200, 1200)
        for index, cap in enumerate(caps, 6):
            failed = copy.deepcopy(value)
            role = failed['commands'][index]['role']
            failed.update(commands=failed['commands'][:index], compiledArtifacts=failed['compiledArtifacts'][:index-6],
                          shippingGraphCompiled=False, originalPending=True, libtestRetained=False)
            failed['failure'] = dict(stage=role, condition=None, attempt=dict(role=role, resultReturned=False,
                timing=dict(startedAfterMilliseconds=1000, elapsedMilliseconds=cap * 1000,
                            timeoutSeconds=cap)))
            observed = self.project(failed)
            self.assertTrue(observed['facts']['originalPending'])
            self.assertFalse(observed['facts']['shippingGraphCompiled'])
            self.assertFalse(observed['failure']['attempt']['resultReturned'])
            self.assertEqual(len(observed['commands']), index)
            failed['failure']['attempt']['resultReturned'] = True
            with self.subTest(role=role), self.assertRaises(ValueError): self.project(failed)
            row = dict(value['commands'][index], returncode=101, timing=copy.deepcopy(failed['failure']['attempt']['timing']))
            failed['commands'].append(row)
            failed['originalPending'] = False
            failed['failure']['condition'] = 'compile-original-nonzero'
            observed = self.project(failed)
            self.assertTrue(observed['failure']['attempt']['resultReturned'])
            self.assertEqual(observed['commands'][-1]['returncode'], 101)
            self.assertFalse(observed['facts']['shippingGraphCompiled'])

    def test_settled_nonzero_retains_exact_result_timing_without_becoming_success(self):
        value = self.extended_receipt()
        value.update(shippingGraphCompiled=False, libtestRetained=False)
        timing = dict(startedAfterMilliseconds=2000, elapsedMilliseconds=3000, timeoutSeconds=1200)
        value['commands'][-1].update(returncode=101, timing=timing)
        value['failure'] = dict(stage='application-libtest-build', condition='compile-original-nonzero',
            attempt=dict(role='application-libtest-build', resultReturned=True, timing=timing))
        observed = self.project(value)
        self.assertEqual(observed['commands'][-1]['returncode'], 101)
        self.assertEqual(observed['failure']['condition'], 'compile-original-nonzero')
        self.assertEqual(observed['commands'][-1]['timing'], timing)
        for field, invalid in (('timeoutSeconds', 1201), ('timeoutSeconds', True),
                               ('startedAfterMilliseconds', -1), ('elapsedMilliseconds', -1)):
            changed = copy.deepcopy(value)
            changed['failure']['attempt']['timing'][field] = invalid
            with self.subTest(field=field), self.assertRaises(ValueError): self.project(changed)

    def test_original_deadline_finality_and_other_finite_reasons_survive_existing_reducer(self):
        aqua = ast.parse((ROOT / 'desktop/tools/macos_aqua_qualification.py').read_text())
        nodes = [node for node in aqua.body if isinstance(node, ast.FunctionDef)
                 and node.name in ('_owner_exception_diagnostic', '_git_read_command_failure')]
        def need(ok, reason):
            if not ok: raise ValueError(reason)
        namespace = dict(need=need)
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<existing-Aqua-diagnostic-DATA>', 'exec'), namespace)
        class ProcessError(Exception): pass
        class ProcessCleanupError(ProcessError): pass
        class ProcessOutcomeUnknown(ProcessError): pass
        class ProcessInterrupted(KeyboardInterrupt): pass
        owner = SimpleNamespace(ProcessError=ProcessError, ProcessCleanupError=ProcessCleanupError,
                                ProcessOutcomeUnknown=ProcessOutcomeUnknown, ProcessInterrupted=ProcessInterrupted)
        reducer = namespace['_owner_exception_diagnostic']
        genuine = self.genuine_functions(('owner_error_data',))['owner_error_data']
        reasons = {'owned command exceeded its original deadline': 'original-deadline',
                   'owned command ended with an incomplete frame': 'incomplete-frame',
                   'owned command cancellation handlers could not be restored': 'handler-restore'}
        for message, reason in reasons.items():
            error = ProcessError(message)
            error.dispatched, error.contained, error.cleanup_complete = True, False, False
            error.owner_failure_mask = None
            error.owner_finality_diagnostic = (1, 1, 1048575, 15, 63)
            observed = genuine(error, owner, reducer)
            row = observed['typedFacts'][0]
            self.assertEqual(row['reason'], reason)
            self.assertEqual(row['ownerFinality'], [1, 1, 1048575, 15, 63])
            self.assertFalse(row['contained'])
            namespace['_git_read_command_failure'](dict(category='process', reason=reason, command='unknown',
                ordinal=1, dispatched=True, contained=False, cleanupComplete=False, failureMask=None,
                ownerFinality=row['ownerFinality']))
            error.owner_finality_diagnostic = (True, 1, 0, 0, None)
            self.assertIsNone(genuine(error, owner, reducer)['typedFacts'][0]['ownerFinality'])
        chain = None
        for _ in range(17):
            current = ProcessError('owned command exceeded its original deadline')
            current.owner_finality_diagnostic = (1, 1, 1048575, 15, 63)
            current.__cause__ = chain
            chain = current
        observed = genuine(chain, owner, reducer)
        self.assertEqual(len(observed['typedFacts']), 16)
        self.assertTrue(observed['chainTruncated'])
        value = self.extended_receipt()
        value.update(shippingGraphCompiled=False, originalPending=True, libtestRetained=False,
                     failure=dict(stage='application-libtest-build', ownerDiagnostic=observed))
        for index, row in enumerate(value['commands']):
            row['timing'] = dict(startedAfterMilliseconds=1000000, elapsedMilliseconds=1000000,
                                 timeoutSeconds=15 if index < 4 else 300 if index == 4 else 180 if index == 5 else 600)
        result = self.project(value)
        self.assertLessEqual(len((json.dumps(result, sort_keys=True, separators=(',', ':'))+'\n').encode()), 16384)
        self.assertTrue(result['facts']['originalPending'])
        self.assertFalse(result['facts']['shippingGraphCompiled'])
        value['failure']['ownerDiagnostic']['typedFacts'][0]['ownerFinality'] = ['PRIVATE-SENTINEL']
        self.assertIsNone(self.project(value)['failure']['ownerDiagnostic']['typedFacts'][0]['ownerFinality'])

    def test_integer_timeout_never_extends_endpoint_and_refuses_fractional_last_second(self):
        function = self.genuine_functions(('need', 'command_timeout_data'))['command_timeout_data']
        for role_cap in (1200, 1200, 600, 900, 1200, 1200):
            for remaining, expected in ((2000.5, role_cap), (1.5, 1), (1.0, 1)):
                result = function(role_cap, 100.0 + remaining, 100.0)
                self.assertIs(type(result), int)
                self.assertEqual(result, expected)
                self.assertLessEqual(100.0 + result, 100.0 + remaining)
            for remaining in (0.5, 0.0, -1.0, float('nan'), float('inf')):
                with self.subTest(cap=role_cap, remaining=remaining), self.assertRaises(ValueError):
                    function(role_cap, 100.0 + remaining, 100.0)

    def test_actual_role_calls_keep_commands_caps_and_cleanup_margin(self):
        namespace = self.genuine_functions(('need', 'commands_data'))
        commands = namespace['commands_data'](Path('/node'), Path('/npm'), Path('/rust'), Path('/work'), 'remaining-arm64')
        self.assertEqual(len(commands), 12)
        self.assertIn('profile.release.package.mobile-release-kit-desktop.opt-level=1', commands[6])
        self.assertNotIn('--config', commands[7])
        self.assertIn('--features', commands[9])
        self.assertIn('installed-shell-observation', commands[10])
        self.assertEqual(commands[11][-2:], ['--lib', '--no-run'])
        main = next(node for node in ast.parse(self.programs[1]).body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        deadline = next(node for node in main.body if isinstance(node, ast.Assign) and
                        isinstance(node.targets[0], ast.Tuple) and [item.id for item in node.targets[0].elts] == ['work_end', 'hard_end'])
        for extended, outer in ((True, 7080), (False, 1440)):
            values = dict(start=0, extended=extended)
            exec(compile(ast.Module(body=[deadline], type_ignores=[]), '<actual-compile-deadline-DATA>', 'exec'), values)
            self.assertEqual(values['hard_end'] - values['work_end'], 120)
            self.assertEqual(outer - values['hard_end'], 30)
        self.assertIn("&& 118 || 24", self.workflow)
        self.assertIn("&& 140 || 35", self.workflow)
        source_action = (ROOT / '.github/actions/macos-candidate-recipes/shipping_compile/action.yml').read_text()
        self.assertIn('deadline = clock() + 10', source_action)
        self.assertIn('PY_SHIPPING_SOURCE_ADMISSION', source_action)
        self.assertIn('uses: "./.github/actions/macos-candidate-recipes/compile_work"', self.workflow)
        self.assertIn('uses: "./.github/actions/macos-candidate-recipes/shipping_compile"', self.workflow)
        gate = self.workflow.index('Check compile failure evidence and timing with source DATA only')
        self.assertLess(gate, self.workflow.index('Select the fixed Node frontend compiler'))
        self.assertIn('timeout-minutes: 1', self.workflow[gate:gate+220])
        self.assertIn(' -I -S -B tests/desktop/test_macos_shipping_compile_public_evidence.py', self.workflow)
        for condition in ('compile-deadline', 'compile-no-work-left', 'compile-original-return'):
            value = receipt()
            value.update(shippingGraphCompiled=False, failure=dict(stage='shipping-image-build', condition=condition))
            self.assertEqual(self.project(value)['failure']['condition'], condition)


    def test_optional_elapsed_observation_uses_scope_bound_and_never_invents_return(self):
        function = self.genuine_functions(('command_elapsed_data',))['command_elapsed_data']
        self.assertEqual(function(1000, 10.0, 11.0, False), 1000)
        self.assertEqual(function(0, 0.0, 1440.0, False), 1440000)
        self.assertIsNone(function(0, 0.0, 1440.001, False))
        self.assertEqual(function(0, 0.0, 1440.001, True), 1440001)
        self.assertIsNone(function(0, 0.0, 7080.001, True))
        self.assertIsNone(function(0, 0.0, float('nan'), False))
        program = ast.parse(self.programs[1])
        loop = next(node for node in ast.walk(program) if isinstance(node, ast.For)
                    and any(isinstance(child, ast.Name) and child.id == 'argv_rows' for child in ast.walk(node.iter)))
        append_index = next(i for i, node in enumerate(loop.body) if isinstance(node, ast.Expr)
                            and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute)
                            and node.value.func.attr == 'append')
        statements = loop.body[append_index:append_index+2]
        self.assertIsInstance(statements[1], ast.Assign)
        actual = compile(ast.Module(body=statements, type_ignores=[]), '<actual-original-result-recording>', 'exec')
        class RefusedAppend(list):
            def append(self, value): raise MemoryError('simulated evidence allocation refusal')
        for rows, raises in ((RefusedAppend(), True), ([], False)):
            attempt = dict(resultReturned=False, timing=dict(startedAfterMilliseconds=1,
                           elapsedMilliseconds=None, timeoutSeconds=1200))
            namespace = dict(receipt=dict(commands=rows), active_attempt=attempt, role='shipping-image-build',
                             argv=['cargo'], result=SimpleNamespace(returncode=101, stdout=b'error', stderr=b''),
                             hashlib=hashlib)
            if raises:
                with self.assertRaises(MemoryError): exec(actual, namespace)
                self.assertFalse(attempt['resultReturned'])
            else:
                exec(actual, namespace)
                self.assertTrue(attempt['resultReturned'])
                self.assertEqual(rows[-1]['returncode'], 101)


    def test_only_validated_settled_nonzero_compiler_results_retain_failure_streams(self):
        genuine = self.genuine_functions(('need', 'returned_data', 'command_elapsed_data'))
        program = ast.parse(self.programs[1])
        loop = next(node for node in ast.walk(program) if isinstance(node, ast.For)
                    and any(isinstance(child, ast.Name) and child.id == 'argv_rows' for child in ast.walk(node.iter)))
        call = next(i for i, node in enumerate(loop.body) if isinstance(node, ast.Try)
                    and any(isinstance(child, ast.Attribute) and child.attr == 'run_owned' for child in ast.walk(node)))
        stop = next(i for i, node in enumerate(loop.body) if isinstance(node, ast.Assign)
                    and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'produced')
        actual = compile(ast.Module(body=loop.body[call:stop], type_ignores=[]), '<actual-settled-result-capture>', 'exec')
        class Unresolved(Exception): pass
        for index in range(5, 12):
            for result_kind in ('nonzero', 'passing', 'unresolved', 'malformed'):
                argv = ['cargo', 'build']
                result = subprocess.CompletedProcess(argv, 101 if result_kind == 'nonzero' else 0,
                                                     stdout=b'compiler JSON original', stderr=b'compiler diagnostic original')
                def invoke(*args, **kwargs):
                    if result_kind == 'unresolved': raise Unresolved()
                    return object() if result_kind == 'malformed' else result
                outputs = {}
                attempt = dict(resultReturned=False, timing=dict(startedAfterMilliseconds=0,
                               elapsedMilliseconds=None, timeoutSeconds=1200))
                namespace = dict(genuine, owner=SimpleNamespace(run_owned=invoke), argv=argv, environment={},
                    cwd=Path('/checkout'), timeout=1200, cap=4*1024*1024, command_start=0.0,
                    time=SimpleNamespace(monotonic=lambda: 1.0), extended=True, active_attempt=attempt,
                    pending=True, receipt=dict(commands=[], originalPending=True), role='role-' + str(index),
                    index=index, outputs=outputs, hashlib=hashlib)
                with self.subTest(index=index, result=result_kind):
                    if result_kind in ('unresolved', 'malformed'):
                        with self.assertRaises((Unresolved, ValueError)): exec(actual, namespace)
                        self.assertTrue(namespace['pending'])
                        self.assertFalse(attempt['resultReturned'])
                    else:
                        exec(actual, namespace)
                        self.assertFalse(namespace['pending'])
                        self.assertTrue(attempt['resultReturned'])
                    selected = {name for name in outputs if name.startswith('failed-command.')}
                    if index >= 6 and result_kind == 'nonzero':
                        self.assertEqual(selected, {'failed-command.stdout', 'failed-command.stderr'})
                        self.assertEqual(len(outputs), 2)  # No duplicate role-named pair.
                        row = namespace['receipt']['commands'][-1]
                        for stream in ('stdout', 'stderr'):
                            raw = outputs['failed-command.' + stream]
                            self.assertIs(raw, getattr(result, stream))
                            self.assertEqual(len(raw), row[stream + 'Bytes'])
                            self.assertEqual(hashlib.sha256(raw).hexdigest(), row[stream + 'Sha256'])
                    else:
                        self.assertEqual(selected, set())
        section = self.workflow.split('      - name: Preserve only bounded public compile evidence;', 1)[1].split(
            '      - name: Retain the exact unsigned', 1)[0]
        names = re.findall(r'^            \$\{\{ steps.compile_work.outputs.root \}\}/([^\n]+)$', section, re.M)
        self.assertEqual(names, ['compile-receipt.json', 'failed-command.stdout', 'failed-command.stderr'])


if __name__ == '__main__':
    unittest.main()
