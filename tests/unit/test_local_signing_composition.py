"""Actual broadened preflight admission and cancellation composition."""
from __future__ import annotations

import io
import os
import signal
import sys
import tempfile
import unittest
from contextlib import ExitStack, contextmanager, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mobile_release import cli, ios_profiles, local_signing as signing, preflight as preflight_module
from mobile_release.cancellation import DefaultCancellation, OwnedTemporaryDirectory, cancellation_owner
from mobile_release.config import load_config
from mobile_release.errors import CredentialError
from mobile_release.inspection import InspectionDeadline
from mobile_release.reporting import Report
from .helpers import android_config, ios_config, write_project
from .ios_entitlement_helpers import profile
from .local_signing_helpers import NativeSigningModel
from workflow.local_signing_regression_catalog import PREFLIGHT_CANCELLATION_VARIANTS


def _materializer_directory(original, private, created, *args, **kwargs):
    """Route only this fixture's materializer into its real model input root."""
    if kwargs.get('prefix') != 'mobile-release-build-inputs-':
        return original(*args, **kwargs)
    assert not args and set(kwargs) == {'prefix'}, 'materializer allocation contract changed'
    owner = original(dir=private, **kwargs)
    created.append(Path(owner.name))
    return owner


class SigningCompositionTests(unittest.TestCase):
    def test_only_enabled_signed_ios_builds_acquire_the_account_lease(self):
        with tempfile.TemporaryDirectory(prefix='mrk-admission-matrix-') as name:
            root = Path(name)
            for config_value, platform in ((ios_config(), 'ios'), (android_config(), 'android')):
                config = load_config(write_project(root / platform, config_value, platform=platform))
                for mode in ('offline', 'online', 'signing'):
                    for builds in (False, True):
                        for selected in (('ios',), ('android',), ('android', 'ios'), ()):
                            required = mode == 'signing' and builds and platform == 'ios' and 'ios' in selected
                            marker = Report(command='fixture')
                            with self.subTest(platform=platform, mode=mode, builds=builds, selected=selected), \
                                 patch.object(preflight_module, '_preflight', return_value=marker) as inner, \
                                 patch.object(preflight_module, 'local_signing_lease', side_effect=signing.SigningBusy('busy')) as lease:
                                result = preflight_module.preflight(config, mode=mode, run_builds=builds, platforms=iter(selected))
                                self.assertEqual(lease.call_count, int(required))
                                self.assertEqual(inner.call_count, int(not required))
                                if not required:
                                    self.assertIs(result, marker)
                                    self.assertEqual(inner.call_args.kwargs['platforms'], selected)

    def test_cli_status_and_recovery_exit_codes_and_fixed_confirmation_interface(self):
        for status, expected in (('idle', 0), ('busy', 1), ('pending', 1)):
            with patch.object(signing, 'signing_status', return_value={'status': status}), redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(['local-signing', 'status']), expected)
        for status, expected in (('absent', 0), ('recovered', 0), ('recovered-with-conflict', 1)):
            with patch.object(signing, 'recover_signing', return_value={'status': status}) as recover, redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(['local-signing', 'recover', '--session', 'e' * 32,
                                          '--confirm', signing.CONFIRMATION]), expected)
                recover.assert_called_once_with('e' * 32, signing.CONFIRMATION, manual=False)

    def test_foreign_and_mixed_signal_owners_are_never_silently_overwritten_or_borrowed(self):
        originals = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        foreign = lambda *_: None
        try:
            with tempfile.TemporaryDirectory(prefix='mrk-handler-owner-') as name:
                home = Path(name)
                signal.signal(signal.SIGTERM, foreign)
                with signing.local_signing_lease(home=home) as lease:
                    self.assertIs(cancellation_owner(None, CredentialError, 'restore')[0], lease.cancellation)
                    self.assertIs(signal.getsignal(signal.SIGTERM), foreign)
                self.assertIs(signal.getsignal(signal.SIGTERM), foreign)
                with self.assertRaisesRegex(CredentialError, 'handlers'):
                    with signing.local_signing_lease(home=home):
                        signal.signal(signal.SIGINT, foreign)
                self.assertIs(signal.getsignal(signal.SIGINT), foreign)
                self.assertEqual(signing.signing_status(home=home)['status'], 'idle')
                a, b = (DefaultCancellation(CredentialError, 'restore') for _ in range(2))
                signal.signal(signal.SIGINT, originals[signal.SIGINT])
                a.install(); a.activate()  # Actual original INT token; TERM remains foreign.
                signal.signal(signal.SIGTERM, originals[signal.SIGTERM])
                try:
                    b.install(); b.activate()  # Actual original TERM token; never adopt a's INT.
                    with self.assertRaisesRegex(CredentialError, 'different owners'):
                        with signing.local_signing_lease(home=home): self.fail('mixed handlers admitted')
                finally:
                    b.restore()
                    a.restore()
        finally:
            for sig, handler in originals.items(): signal.signal(sig, handler)

    @unittest.skipUnless(sys.platform == 'darwin', 'native profile caller is macOS-only')
    def test_full_preflight_shares_one_guard_through_early_authentication_signing_build_and_late_authentication(self):
        self.exercise_full_preflight()

    @unittest.skipUnless(sys.platform == 'darwin', 'native profile caller is macOS-only')
    def test_real_early_and_late_profile_cleanup_signals_under_full_preflight_never_return_cancelled_content(self):
        for variant in PREFLIGHT_CANCELLATION_VARIANTS:
            with self.subTest(variant=variant):
                self.run_preflight_cancellation_variant(variant)

    def run_preflight_cancellation_variant(self, variant):
        self.assertIn(variant, PREFLIGHT_CANCELLATION_VARIANTS)
        stage, edge, signum = variant
        self.exercise_full_preflight(cancel_at=(stage, edge), signum={"INT": signal.SIGINT, "TERM": signal.SIGTERM}[signum])

    def exercise_full_preflight(self, *, cancel_at=None, signum=signal.SIGINT):
        # Keep the real public preflight, materializer, signing session, private
        # profile scratch/capture and filesystem transitions. Only unavailable
        # credentialed signing/Xcode checks are modeled, not their owners.
        from mobile_release import _profile_process as profile_owner
        from mobile_release._lifetime_evidence import ProfileCallEvidence
        from mobile_release._profile_callers import consume_profile_evidence
        from workflow.profile_process_fixture import (
            FixtureWorkspace, ProfileBindings, _assert_native_finality,
            assert_fixture_idle, retain_fixture_custody,
        )
        from .local_signing_helpers import fictional_signing_profile

        assert_fixture_idle()
        with FixtureWorkspace(prefix='mrk-preflight-composition-') as workspace:
            root = workspace.path.resolve()  # macOS /var alias is not a permitted private input path.
            home = root / 'home'; home.mkdir(mode=0o700)
            private = root / 'private'; private.mkdir(mode=0o700)
            config = load_config(write_project(root / 'project', ios_config(), platform='ios'))
            p12, source = private / 'identity.p12', private / 'profile'
            p12.write_bytes(b'fictional-p12'); p12.chmod(0o600)
            source.write_bytes(b'fictional-profile-canary'); source.chmod(0o600)
            source_details = source.stat()
            source_identity = source_details.st_dev, source_details.st_ino
            values = {'MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PATH': str(p12),
                      'MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD': 'fictional',
                      'MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_PATH': str(source)}
            model = NativeSigningModel(home)
            held, stages, scratches, issued, returned, calls = [], [], [], [], [], []
            originals = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
            original_close = ios_profiles._close_profile_descriptor
            original_acquire = ios_profiles.ScratchLease.acquire
            original_cleanup = ios_profiles.ScratchLease.cleanup
            original_capture = profile_owner.capture_profile
            original_mkdtemp = tempfile.mkdtemp
            original_temporary_directory = tempfile.TemporaryDirectory
            material_directories = []

            @contextmanager
            def lease_context():
                with signing.local_signing_lease(home=home) as lease:
                    held.append(lease)
                    yield lease

            def check_guard(stage):
                actual, owns = cancellation_owner(None, CredentialError, 'restore')
                self.assertFalse(owns)
                self.assertIs(actual, held[0].cancellation)
                held[0].assert_owner()
                stages.append(stage)

            def authenticate(stage):
                assert_fixture_idle()
                check_guard(stage)
                guard = held[0].cancellation
                deadline = InspectionDeadline()
                evidence = ProfileCallEvidence(operation='load')
                case_root = root / stage
                case_root.mkdir(mode=0o700)
                finalities, leases = [], []
                binding = None
                primary = translated = None

                def interrupt(edge):
                    if cancel_at == (stage, edge) and not issued:
                        issued.append((stage, edge))
                        # Only this current case process is a signal target;
                        # fixture files never grant authority over reported PIDs.
                        os.kill(os.getpid(), signum)

                def close(descriptor):
                    details = os.fstat(descriptor)
                    is_source = (details.st_dev, details.st_ino) == source_identity
                    original_close(descriptor)
                    if is_source:
                        interrupt('read-cleanup')

                def mkdtemp(*args, **kwargs):
                    self.assertFalse(args)
                    self.assertEqual(kwargs, {'prefix': 'mobile-release-profile-auth-'})
                    # Preserve real acquisition, modes and owner bookkeeping;
                    # do not depend on tempfile's cached TMPDIR selection.
                    return original_mkdtemp(dir=case_root, **kwargs)

                def acquire(scratch):
                    leases.append(scratch)
                    directory = original_acquire(scratch)
                    scratches.append(directory)
                    self.assertEqual(directory.parent, case_root)
                    return directory

                def capture(directory, clock, *, cancellation=None, finality):
                    check_guard('capture')
                    self.assertIs(clock, deadline)
                    self.assertIs(cancellation, guard)
                    self.assertEqual(len(leases), 1)
                    self.assertIs(finality, leases[0]._finality)
                    finalities.append(finality)
                    return original_capture(directory, clock, cancellation=cancellation, finality=finality)

                def cleanup(scratch):
                    original_cleanup(scratch)
                    self.assertEqual(scratch.state, 'REMOVED')
                    self.assertEqual(scratch._finality.state, 'FINALIZED')
                    interrupt('cms-cleanup')

                try:
                    # These patches cover only the dedicated real reader/CMS
                    # invocation, never the fictional signing material or any
                    # command-model lifetime using the shared native APIs.
                    with patch.object(ios_profiles, '_close_profile_descriptor', side_effect=close):
                        evidence._expect('READER')
                        content = ios_profiles.read_profile_bytes(
                            source, deadline=deadline, cancellation=guard, _evidence=evidence,
                        )
                        self.assertEqual(content, b'fictional-profile-canary')
                        binding = ProfileBindings(case_root, 'success')
                        binding.deadline = deadline
                        with binding, \
                             patch.object(ios_profiles.tempfile, 'mkdtemp', side_effect=mkdtemp), \
                             patch.object(ios_profiles.ScratchLease, 'acquire', new=acquire), \
                             patch.object(ios_profiles.ScratchLease, 'cleanup', new=cleanup), \
                             patch.object(profile_owner, 'capture_profile', side_effect=capture):
                            evidence._expect('OUTER_CMS')
                            authenticated = ios_profiles.authenticate_cms(
                                content, deadline=deadline, cancellation=guard, _evidence=evidence,
                            )
                except BaseException as error:
                    primary = error
                try:
                    # The actual caller adapter consumes the sidecar only after
                    # original cleanup; no result/finality receipt is fabricated.
                    consume_profile_evidence(
                        evidence, primary=primary, message='composition profile lifetime is unconfirmed',
                    )
                except BaseException as error:
                    translated = error
                calls.append((stage, evidence, primary))
                try:
                    verdict = evidence.verdict()
                    self.assertIs(evidence._guard, guard)
                    self.assertIs(evidence._ledger, guard.lifetime_ledger)
                    self.assertTrue(verdict.complete and verdict.cleanup_complete and verdict.contained)
                    self.assertFalse(verdict.fatal or verdict.blocked)
                    self.assertEqual(verdict.handler_state, 'BORROWED_VALID')
                    if cancel_at == (stage, 'read-cleanup'):
                        self.assertIsNone(binding)
                        self.assertFalse(finalities or leases)
                        self.assertEqual(set(evidence._bindings), {'READER'})
                        self.assertTrue(verdict.positive_no_native_attempt)
                        self.assertEqual(verdict.validator_dispatch, 'NOT_SENT')
                    else:
                        self.assertIsNotNone(binding)
                        self.assertEqual(binding.patch_state, 'CLOSED')
                        self.assertEqual(len(finalities), 1)
                        self.assertEqual(len(leases), 1)
                        finality = finalities[0]
                        self.assertEqual(finality.state, 'FINALIZED')
                        self.assertTrue(finality.cleanup_allowed)
                        self.assertEqual(set(evidence._bindings), {'READER', 'OUTER_CMS'})
                        self.assertEqual(verdict.native_attempt, 'ATTEMPT_ARMED')
                        self.assertEqual(verdict.validator_dispatch, 'RUN_ATTEMPT_ARMED')
                        self.assertIs(finality._owner.cancellation, guard)
                        binding.assert_local_leases(finality._owner)
                        _assert_native_finality(case_root)
                        self.assertTrue(binding.payload_eof)
                        self.assertIn(id(binding.payload_reader), binding.raw_eofs)
                        self.assertEqual(leases[0].state, 'REMOVED')
                        self.assertFalse(leases[0].retained or leases[0].path.exists())
                        # Release observer references only after original
                        # waits, joins, channel EOFs and local closes are proven.
                        binding.release_fixture_references()
                    assert_fixture_idle()
                except BaseException:
                    retain_fixture_custody(binding if binding is not None else evidence)
                    raise
                if translated is not None:
                    if isinstance(primary, (KeyboardInterrupt, SystemExit)):
                        self.assertIs(translated, primary)
                    raise translated
                if primary is not None:
                    raise primary
                self.assertEqual(authenticated, b'verified-content')
                returned.append(stage)

            def validate(*args, **kwargs):
                self.assertIs(kwargs['cancellation'], held[0].cancellation)
                authenticate('early')
                return []

            def build(config, *, signed, signing_session, execution_source=None):
                check_guard('build')
                self.assertTrue(signed)
                self.assertIs(signing_session, held[0].active)
                self.assertIsNotNone(execution_source)
                self.assertEqual(signing_session.run(['build'], kind='build').returncode, 0)
                return {}

            real_body = preflight_module._preflight
            def body(*args, **kwargs):
                report = real_body(*args, **kwargs)
                self.assertIsNone(held[0].active)
                authenticate('late')
                return report

            with ExitStack() as patches:
                for target, function in (('local_signing_lease', lease_context), ('_preflight', body),
                                          ('validate_signing_material', validate), ('run_ios_build', build)):
                    patches.enter_context(patch.object(preflight_module, target, side_effect=function))
                patches.enter_context(patch.object(preflight_module, 'doctor', side_effect=lambda *_, **__: Report(command='fixture')))
                patches.enter_context(patch.object(preflight_module, 'resolve_credential_values', return_value=values))
                patches.enter_context(patch.object(preflight_module, 'credential_findings', return_value=[]))
                patches.enter_context(patch.object(preflight_module, 'effective_identity_findings', return_value=[]))
                patches.enter_context(patch('mobile_release.credentials._run_private', side_effect=model))
                patches.enter_context(patch('mobile_release.credentials.tempfile.TemporaryDirectory',
                                            side_effect=lambda *args, **kwargs: _materializer_directory(
                                                original_temporary_directory, private, material_directories,
                                                *args, **kwargs)))
                # Independent fictional material metadata only. Dedicated early
                # and late profile calls above still use the real capture owner.
                patches.enter_context(patch('mobile_release.credentials._authenticated_signing_profile',
                                            side_effect=fictional_signing_profile))
                if cancel_at:
                    with self.assertRaises(KeyboardInterrupt) as interruption:
                        preflight_module.preflight(config, mode='signing', platforms=('ios',), run_builds=True)
                else:
                    result = preflight_module.preflight(config, mode='signing', platforms=('ios',), run_builds=True)
            if cancel_at:
                self.assertEqual(issued, [cancel_at])
                self.assertIs(interruption.exception, calls[-1][2])
                self.assertNotIn(cancel_at[0], returned)
                self.assertEqual('build' in stages, cancel_at[0] == 'late')
                self.assertEqual([item[0] for item in calls], ['early'] if cancel_at[0] == 'early' else ['early', 'late'])
            else:
                self.assertEqual([item.code for item in result.findings if item.status.value == 'FAIL'],
                                 ['ios.archive.symbols', 'ios.ipa'])  # No fictional build is upload evidence.
                self.assertEqual(stages, ['early', 'capture', 'build', 'late', 'capture'])
                self.assertEqual(returned, ['early', 'late'])
            self.assertTrue(all(not path.exists() for path in scratches))
            self.assertEqual(len(material_directories), int(cancel_at is None or cancel_at[0] == 'late'))
            self.assertTrue(all(path.parent == private and not os.path.lexists(path)
                                for path in material_directories))
            self.assertFalse(list(root.glob('model-bridge-*')))
            self.assertEqual(model.preferences, model.original)
            self.assertEqual(signing.signing_status(home=home)['status'], 'idle')
            self.assertEqual({sig: signal.getsignal(sig) for sig in originals}, originals)
            for _, evidence, _ in calls:
                self.assertTrue(evidence.verdict().cleanup_complete)
                self.assertEqual(evidence.verdict().handler_state, 'RESTORED')
            ledger = held[0].cancellation.lifetime_ledger.verdict()
            self.assertTrue(ledger.complete)
            self.assertFalse(ledger.fatal)
            # Any adverse assertion leaves the original workspace/custody
            # retained for the native Session owner, never recursive fallback.
            workspace.allow_removal()


if __name__ == '__main__': unittest.main()
