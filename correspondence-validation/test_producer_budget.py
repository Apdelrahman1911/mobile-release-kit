"""DATA-only coverage of the diagnostic cold producer budget and refusals."""
import copy
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from desktop.tools import macos_android_helper_package as helper

path = Path(__file__).with_name('diagnostic_producer_prefix.py')
spec = importlib.util.spec_from_file_location('_diagnostic_budget_prefix', path)
prefix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prefix)


class ProducerBudget(unittest.TestCase):
    def setUp(self):
        self.binding = {'executionApproved': True, 'productSource': 'a' * 40,
                        'preparedOrigin': {'source': 'a' * 40},
                        'runnerSourceCommit': 'b' * 40,
                        'runnerBranch': 'codex/macos-correspondence-diagnostic'}
        prefix.EXECUTION_BINDING = self.binding
        self.owner = object.__new__(prefix.PrefixOwner)
        self.owner.phase = 'package-install'
        self.owner.target = helper.ARM_TARGET
        self.owner.checkout = Path('/Users/runner/work/mobile-release-kit/mobile-release-kit/prepared-built-source')
        self.owner.environment = {'GITHUB_SHA': 'b' * 40, 'GITHUB_WORKFLOW_SHA': 'b' * 40,
                                  'GITHUB_REF': 'refs/heads/codex/macos-correspondence-diagnostic',
                                  'GITHUB_JOB': 'correspondence-diagnostic'}
        self.owner.prepared_binding = SimpleNamespace(source='a' * 40, origin={'source': 'a' * 40},
                                                     manifest={'packageRole': 'ordinary-image'},
                                                     native_compatible=False)

    def test_cross_source_cold_profile_without_native_compatibility_claim(self):
        self.assertEqual(helper.Operation.package_compiler_seconds(self.owner), 480)
        self.assertEqual(self.owner.package_compiler_seconds(), 900)
        self.assertFalse(self.owner.prepared_binding.native_compatible)

    def test_wrong_source_origin_context_and_route_refused(self):
        changes = [lambda o: setattr(o, 'phase', 'other'),
                   lambda o: setattr(o, 'target', 'other'),
                   lambda o: setattr(o, 'checkout', Path('/inert')),
                   lambda o: setattr(o.prepared_binding, 'source', 'c' * 40),
                   lambda o: setattr(o.prepared_binding, 'origin', {}),
                   lambda o: o.prepared_binding.manifest.update(packageRole='other'),
                   lambda o: o.environment.update(GITHUB_SHA='c' * 40),
                   lambda o: o.environment.update(GITHUB_WORKFLOW_SHA='c' * 40),
                   lambda o: o.environment.update(GITHUB_REF='refs/heads/other'),
                   lambda o: o.environment.update(GITHUB_JOB='other')]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                owner = copy.deepcopy(self.owner)
                change(owner)
                with self.assertRaisesRegex(helper.Refused, 'diagnostic-producer-cold-profile-binding'):
                    owner.package_compiler_seconds()
        self.binding['executionApproved'] = False
        with self.assertRaises(helper.Refused):
            self.owner.package_compiler_seconds()

    def test_only_producer_roles_receive_existing_cold_budget(self):
        for role in ['producer-tests', 'producer-build']:
            self.assertEqual(helper.package_timeout_data(0, 900_000_000_000, 900,
                phase='package-install', role=role, prepared_compiler=True), 897)
            with self.assertRaises(helper.Refused):
                helper.package_timeout_data(0, 1000_000_000_000, 901,
                    phase='package-install', role=role, prepared_compiler=True)
        for role in ['producer-emitter', 'installer', 'detach', 'signing']:
            with self.assertRaises(helper.Refused):
                helper.package_timeout_data(0, 1000_000_000_000, 900,
                    phase='package-install', role=role, prepared_compiler=True)

    def test_shared_endpoint_is_not_renewed_for_build(self):
        endpoint = 900_000_000_000
        remaining = helper.package_timeout_data(700_000_000_000, endpoint, 900,
            phase='package-install', role='producer-build', prepared_compiler=True)
        self.assertEqual(remaining, 197)
        with self.assertRaises(helper.Refused):
            helper.package_timeout_data(898_000_000_000, endpoint, 900,
                phase='package-install', role='producer-build', prepared_compiler=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
