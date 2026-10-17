"""Fixed candidate-purpose behavior; inert host observations, no native calls."""
import importlib.util
import io
from contextlib import ExitStack, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'desktop/tools' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

HELPER = load('candidate_helper', 'macos_android_helper_package.py')
STAGER = load('candidate_stager', 'stage_macos_installed.py')

class CandidateAdmission(unittest.TestCase):
    def environment(self, target):
        h = HELPER
        _, arch, _ = h.build_profile(target)
        source = 'a' * 40
        return dict(GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted', RUNNER_OS='macOS', RUNNER_ARCH=arch,
            GITHUB_EVENT_NAME='push', GITHUB_REPOSITORY='Apdelrahman1911/mobile-release-kit',
            GITHUB_WORKSPACE=str(h.CHECKOUT), GITHUB_SHA=source, GITHUB_WORKFLOW_SHA=source,
            GITHUB_REF=h.CANDIDATE_REF,
            GITHUB_WORKFLOW_REF='Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-installed.yml@'+h.CANDIDATE_REF,
            MRK_EXPECTED_SHA=source, MRK_MACOS_INSTALL_SOURCE_COMMIT=source, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1',
            MRK_MACOS_PACKAGE_ROLE='ordinary-image', MRK_MACOS_SAME_PACKAGE_SCOPE='disabled',
            MRK_MACOS_WORK=str(h.WORK_PARENT/'mrk-macos-installed.AbC12345'), RUSTUP_TOOLCHAIN=h.rust_toolchain(target),
            DEVELOPER_DIR='/Library/Developer/CommandLineTools', MACOSX_DEPLOYMENT_TARGET='26.0')

    def host(self, target):
        h = HELPER
        stack = ExitStack()
        stack.enter_context(patch.object(h.sys, 'platform', 'darwin'))
        stack.enter_context(patch.object(h.sys, 'maxsize', 2**63-1))
        stack.enter_context(patch.object(h, '__file__', str(h.CHECKOUT/'desktop/tools/macos_android_helper_package.py')))
        stack.enter_context(patch.multiple(h.os, uname=Mock(return_value=SimpleNamespace(machine=h.build_profile(target)[0])),
            getuid=Mock(return_value=501), geteuid=Mock(return_value=501), getgid=Mock(return_value=20), getegid=Mock(return_value=20)))
        return stack

    def test_candidate_permits_only_current_carrier_production_and_signed_tool_projection(self):
        h = HELPER
        allowed = ('prepare', 'sign-vault-helper', 'sign-remover', 'sign-applications-launcher', 'verify-before',
            'sign-desktop-image', 'sign-desktop-payload', 'sign-root-app', 'verify-after',
            'notarize-payload', 'sign-root-installer', 'finalize-package', 'package-install', 'finalize-image',
            'sign-xcode-setup', 'finalize-xcode-setup-package', h.XCODE_SETUP_VERIFY)
        for target in (h.ARM_TARGET, h.INTEL_TARGET):
            env = self.environment(target)
            with self.host(target):
                for phase in allowed:
                    self.assertEqual(h.admit(env, target=target, phase=phase), Path(env['MRK_MACOS_WORK']))
                for phase in ('package-remove', 'finalize-remove-image', 'same-package-noop', 'prepare-removal-observers',
                              'python-shipping', 'sign-history-provider', 'update-baseline', 'prepare-app-absence', 'unknown', None):
                    with self.subTest(target=target, phase=phase), self.assertRaises(h.Refused):
                        h.admit(env, target=target, phase=phase)
                for phase in ('select-github-tools-signed', 'project-history-provider', 'project-github-seal'):
                    h.tool_data_context(env, phase, target)
                for phase in ('select-github-tools-build', 'sign-history-provider', 'unknown'):
                    with self.assertRaises(h.Refused): h.tool_data_context(env, phase, target)
                for key, value in [('GITHUB_EVENT_NAME', 'workflow_dispatch'), ('GITHUB_WORKFLOW_SHA', 'b'*40),
                    ('GITHUB_REF', 'refs/heads/unrelated'), ('MRK_MACOS_PACKAGE_ROLE', 'installed-shell-observation'),
                    ('MRK_MACOS_SAME_PACKAGE_SCOPE', 'same-package-noop')]:
                    with self.subTest(key=key), self.assertRaises(h.Refused):
                        h.admit(dict(env, **{key:value}), target=target, phase='prepare')
                old = dict(env, GITHUB_REF=h.APP_SIGNATURE_REF,
                    GITHUB_WORKFLOW_REF=env['GITHUB_WORKFLOW_REF'].replace(h.CANDIDATE_REF, h.APP_SIGNATURE_REF))
                self.assertEqual(h.admit(old, target=target, phase='prepare'), Path(env['MRK_MACOS_WORK']))
                with self.assertRaises(h.Refused): h.admit(old, target=target, phase='finalize-image')

    def companion_environment(self, target):
        h = HELPER
        env = dict(self.environment(target), GITHUB_EVENT_NAME='workflow_dispatch',
                   MRK_MACOS_XCODE_SETUP_SCOPE='companion-only', GITHUB_REF=h.XCODE_SETUP_REF)
        env['GITHUB_WORKFLOW_REF'] = env['GITHUB_WORKFLOW_REF'].replace(h.CANDIDATE_REF,h.XCODE_SETUP_REF)
        return env

    def test_companion_dispatch_is_exact_three_phases_and_original_constructor(self):
        h = HELPER
        phases = ('sign-xcode-setup', 'finalize-xcode-setup-package', h.XCODE_SETUP_VERIFY)
        for target in (h.ARM_TARGET, h.INTEL_TARGET):
            env = self.companion_environment(target)
            with self.host(target):
                for phase in phases:
                    with self.subTest(target=target, phase=phase):
                        self.assertEqual(h.admit(env, target=target, phase=phase), Path(env['MRK_MACOS_WORK']))
                for phase in ('prepare', 'finalize-package', 'package-install', 'finalize-image',
                              'sign-root-installer', 'verify-after', 'unknown', None):
                    with self.subTest(phase=phase), self.assertRaises(h.Refused):
                        h.admit(env, target=target, phase=phase)
                bad = [('GITHUB_EVENT_NAME','push'), ('GITHUB_EVENT_NAME','pull_request'),
                       ('MRK_MACOS_XCODE_SETUP_SCOPE','disabled'), ('MRK_MACOS_XCODE_SETUP_SCOPE','other'),
                       ('GITHUB_REF', h.APP_SIGNATURE_REF), ('GITHUB_REF', h.CANDIDATE_REF), ('GITHUB_REPOSITORY','foreign/repo'),
                       ('GITHUB_WORKFLOW_SHA','b'*40), ('MRK_MACOS_INSTALL_SOURCE_COMMIT','b'*40),
                       ('GITHUB_WORKFLOW_REF','foreign/workflow'), ('MRK_MACOS_SAME_PACKAGE_SCOPE','same-package-noop')]
                for key, value in bad:
                    with self.subTest(key=key, value=value), self.assertRaises(h.Refused):
                        h.admit(dict(env, **{key:value}), target=target, phase=phases[0])
                missing = dict(env); del missing['MRK_MACOS_XCODE_SETUP_SCOPE']
                with self.assertRaises(h.Refused): h.admit(missing,target=target,phase=phases[0])
                # Workflow absence alone is not authority: even a forged push
                # with ordinary default scope on the new ref must be refused.
                with self.assertRaises(h.Refused):
                    h.admit(dict(env,GITHUB_EVENT_NAME='push',MRK_MACOS_XCODE_SETUP_SCOPE='disabled'),target=target,phase=phases[0])
            # The real verification constructor opens no original until execute;
            # its explicit route and credential-free admission is not bypassed.
            args = (SimpleNamespace(), h.CHECKOUT, Path(env['MRK_MACOS_WORK']), h.XCODE_SETUP_VERIFY)
            operation = h.Operation(*args, env, STAGER, target=target)
            self.assertEqual(operation.entries, [])
            self.assertTrue(operation.setup_verify)
            for key, value in [('GITHUB_EVENT_NAME','push'), ('MRK_MACOS_XCODE_SETUP_SCOPE','disabled'),
                               ('GITHUB_REF',h.APP_SIGNATURE_REF), ('MRK_MACOS_STORE_RUNTIME','signed-component'),
                               (h.CREDENTIAL_VARIABLES[0],'inert-forbidden')]:
                with self.subTest(constructor=key), self.assertRaises(h.Refused):
                    h.Operation(*args, dict(env, **{key:value}), STAGER, target=target)

    def test_companion_wrong_dispatch_refuses_before_stager_or_owner_load(self):
        h = HELPER
        env = self.companion_environment(h.ARM_TARGET)
        with self.host(h.ARM_TARGET), patch.dict(h.os.environ,env,clear=True), \
             patch.object(h,'entrypoint',return_value=('prepare',h.ARM_TARGET)), \
             patch.object(h,'load_data') as loader, redirect_stderr(io.StringIO()):
            self.assertEqual(h.main(),1)
        loader.assert_not_called()
        with self.host(h.ARM_TARGET), self.assertRaises(h.Refused) as caught:
            h.admit(env,target=h.ARM_TARGET,phase='prepare')
        self.assertEqual(h.failure_exception(caught.exception)["reason"], 'candidate-companion-event-scope')

    def test_unconfigured_candidate_refuses_before_loading_execution_owner(self):
        h = HELPER
        env = self.environment(h.ARM_TARGET)
        def read(path, _limit):
            if path == h.CHECKOUT/'.git/HEAD': return (env['GITHUB_SHA']+'\n').encode()
            if path == h.CHECKOUT/h.PRODUCER_PROFILE: return b'schema=1\nstate=unconfigured\n'
            if path == h.CHECKOUT/h.PROFILE: return h.UNCONFIGURED_PROFILE
            self.fail('unexpected source read')
        stager = SimpleNamespace(read=read, packaging_signing_data=STAGER.packaging_signing_data)
        for phase, selected in [('prepare',env), (h.XCODE_SETUP_VERIFY,self.companion_environment(h.ARM_TARGET))]:
            with self.subTest(phase=phase), self.host(h.ARM_TARGET), patch.dict(h.os.environ, selected, clear=True), \
                 patch.object(h, 'entrypoint', return_value=(phase,h.ARM_TARGET)), \
                 patch.object(h,'load_data',return_value=stager) as loader, redirect_stderr(io.StringIO()):
                self.assertEqual(h.main(), 1)
            self.assertEqual(loader.call_count,1)
            self.assertEqual(loader.call_args.args[1], 'stage_macos_installed.py')
