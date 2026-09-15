"""Inert H/N observation contracts, never native execution or custody evidence."""
from __future__ import annotations

import ast
import copy
import hashlib
import os
import tempfile
import threading
import unittest
from pathlib import Path
from types import MethodType, SimpleNamespace
from unittest.mock import Mock, patch

from mobile_release import _command_process as command
from mobile_release import local_signing as signing
from mobile_release.errors import CredentialError
from unit import local_signing_persistent as persistent
from workflow import local_signing_bridge as bridge
from workflow import local_signing_persistent_fixture as fixture
from workflow import local_signing_semantic_catalog as catalog
from workflow import local_signing_semantic_fixture as semantic


class ObservationContractTests(unittest.TestCase):
    @staticmethod
    def inert_arming_context():
        """Predicate inputs only: no original worker, lease or receipt is issued."""
        session = object.__new__(signing.SigningSession)
        session.lease = SimpleNamespace(home=Path('/fictional-observation/home'))
        session._recovery_attempt = None
        session._committed_controls = {'state.json': b'PREPARED'}
        source = object.__new__(command.AccountExecutionSource)
        source._lease, source._authorization = session.lease, None
        source._check = Mock(side_effect=AssertionError('observer reentered source admission'))
        scope = object.__new__(command.AccountExecutionScope)
        scope._source, scope.nonce, scope._used = source, b'n' * 16, True
        binding = object.__new__(command.JournalledCommandBinding)
        binding._session, binding._scope = session, scope
        binding._arm = session._arm_original_command
        binding._arm_attempted, binding._arm_retired = True, False
        binding.validate_reservation = Mock(side_effect=AssertionError('observer reentered arm admission'))
        session._command_scope, session._command_binding = scope, binding
        scope._binding = binding
        slot = object.__new__(command.CommandOutcomeSlot)
        slot._scope, slot._nonce, slot._value = scope, scope.nonce, None
        scope._outcome = slot
        engine = object.__new__(command._Outer)
        engine.nonce, engine.slot, engine.scope, engine.binding = scope.nonce, slot, scope, binding
        slot._engine = engine
        engine.phase, engine.prepared, engine.sealed = 'PREPARED', {}, False
        engine.child = SimpleNamespace(wait_state='OWNED', numeric_retired=False)
        engine.ctx = SimpleNamespace(check=Mock(), launch_retired=False, tasks=(),
            child_acquisition=SimpleNamespace(child=engine.child, settled=True, cleanup_unknown=False))
        engine.wire = SimpleNamespace(eof=False, poisoned=False)
        engine.create_route = SimpleNamespace(attempted=False, retired=False)
        engine.run_route = SimpleNamespace(attempted=False, retired=False)
        reservation = object.__new__(command.OriginalCommandReservation)
        reservation._engine, reservation.nonce = engine, scope.nonce
        binding._arming_reservation = reservation
        arming = (signing.SigningSession._arm_original_command.__code__, session, reservation)
        return session, arming

    def test_original_arm_observation_is_passive_and_rejects_substituted_live_bindings(self):
        for recovery in (False, True):
            session, arming = self.inert_arming_context()
            binding, scope = session._command_binding, session._command_scope
            engine = scope.outcome._engine
            if recovery:
                attempt = object.__new__(signing._RecoveryAttempt)
                attempt.check = Mock(side_effect=AssertionError('observer reentered recovery admission'))
                session._recovery_attempt = scope._source._authorization = attempt
            # A selected AFTER-replace cut deliberately has different published
            # and committed bytes. No authority recheck or generation advance is
            # permitted by this data observer.
            published = {'state.json': b'ARMED'}
            before = dict(binding.__dict__), dict(scope.__dict__), dict(session._committed_controls)
            with patch.object(signing, '_control', side_effect=AssertionError('observer read controls')) as controls:
                result = semantic._observe_original_reservation(session, arming)
            self.assertEqual(result, dict(beforeGrant=True, originalArmingCallback=True,
                originalReservationBound=True, createAttempted=False, runAttempted=False))
            self.assertEqual(before, (binding.__dict__, scope.__dict__, session._committed_controls))
            self.assertEqual(published, {'state.json': b'ARMED'})
            controls.assert_not_called()
            binding.validate_reservation.assert_not_called()
            scope._source._check.assert_not_called()
            engine.ctx.check.assert_called_once_with()  # Real prepared_reservation predicate.
            if recovery:
                attempt.check.assert_not_called()

            for obj, name, wrong in (
                (binding, '_session', object()), (binding, '_scope', object()),
                (scope, '_binding', object()), (scope._source, '_lease', object()),
                (scope._source, '_authorization', object()),
                (binding._arming_reservation, '_engine', object()),
                (scope.outcome, '_scope', object()), (engine, 'slot', object()),
                (binding._arming_reservation, 'nonce', b'x' * 16),
                (binding, '_arm_attempted', False), (binding, '_arm_retired', True),
                (engine.create_route, 'attempted', True), (engine.run_route, 'attempted', True),
                (binding, '_arm', lambda _reservation: None),
            ):
                with self.subTest(recovery=recovery, field=name), patch.object(obj, name, wrong):
                    with self.assertRaises(AssertionError):
                        semantic._observe_original_reservation(session, arming)
            for wrong in (None, (arming[0], object(), arming[2]),
                          (arming[0], session, object()), (self.inert_arming_context.__code__, session, arming[2])):
                with self.assertRaises(AssertionError):
                    semantic._observe_original_reservation(session, wrong)

            # Exercise the actual stack scanner without fabricating a frame.
            # Its service-thread fallback can observe the session, but cannot
            # invent an active original arm when called directly from this test.
            session.pid, session.token, session.identity, session.state = os.getpid(), 'a' * 32, {}, None
            with tempfile.TemporaryDirectory(prefix='mrk-arm-observation-inert-') as temporary:
                root = Path(temporary)
                fixture.initialize(root)
                session.lease.home = root / 'home'
                session.path = session.lease.home / signing.LEASE_DIRECTORY / ('session-' + session.token)
                trace = semantic.SemanticTrace(root, 'inert')
                trace._fence_session = (session, None, None, os.getpid())
                with patch.object(semantic, '_observe_original_reservation',
                                  wraps=semantic._observe_original_reservation) as observed:
                    with self.assertRaisesRegex(AssertionError, 'callback is not active'):
                        trace.observe_context({'details': {}})
                observed.assert_called_once_with(session, None)
        tree = ast.parse(Path(semantic.__file__).read_text())
        observer = next(node for node in ast.walk(tree)
                        if isinstance(node, ast.FunctionDef) and node.name == 'observe_context')
        self.assertFalse(any(isinstance(node, ast.Attribute) and node.attr == 'validate_reservation'
                             for node in ast.walk(observer)))

    def test_production_recovery_still_rejects_intermediate_control_generation(self):
        session, _arming = self.inert_arming_context()
        session.journal_failed = session.unresolved = False
        session.fd = None  # The bounded _control seam below must not touch a descriptor.
        session.cancellation = SimpleNamespace(lifetime_ledger=SimpleNamespace(fatal=False))
        session.lease.active, session.lease._recovery_mode = session, True
        session.lease.cancellation, session.lease.assert_owner = session.cancellation, Mock()
        attempt = object.__new__(signing._RecoveryAttempt)
        attempt.session, attempt.lease = session, session.lease
        attempt.pid, attempt.owner_thread = os.getpid(), threading.current_thread()
        attempt.revoked, attempt.active_query = False, None
        with patch.object(signing, '_control', side_effect=lambda _fd, name, **_:
                          {'state.json': b'ARMED'}.get(name)):
            with self.assertRaisesRegex(CredentialError, 'recovery control generation changed'):
                attempt.check(session)
        self.assertEqual(session._committed_controls, {'state.json': b'PREPARED'})

    def test_composition_materializer_routes_only_its_private_directory_and_keeps_real_cleanup(self):
        from unit import test_local_signing_composition as composition
        from workflow import profile_installation_fixture as profile_fixture

        _materializer_directory = persistent._materializer_directory
        self.assertIs(composition._materializer_directory, _materializer_directory)
        self.assertIs(profile_fixture._materializer_directory, _materializer_directory)

        with tempfile.TemporaryDirectory(prefix='mrk-materializer-route-inert-') as name:
            root, created = Path(name), []
            private = root / 'private'
            private.mkdir(mode=0o700)
            for fail_body in (False, True):
                with self.subTest(fail_body=fail_body):
                    owner = _materializer_directory(tempfile.TemporaryDirectory, private, created,
                                                    prefix='mobile-release-build-inputs-')
                    actual = Path(owner.name)
                    self.assertEqual(actual.parent, private)
                    self.assertEqual(created[-1], actual)
                    body_error = ValueError('inert body interruption')
                    try:
                        with owner:
                            (actual / 'fictional-input').write_bytes(b'fixture')
                            if fail_body:
                                raise body_error
                    except ValueError as error:
                        self.assertTrue(fail_body)
                        self.assertIs(error, body_error)
                    self.assertFalse(os.path.lexists(actual))
            allocation_error = OSError('inert allocation failure')
            failing = Mock(side_effect=allocation_error)
            with self.assertRaisesRegex(OSError, 'allocation failure') as caught:
                _materializer_directory(failing, private, created, prefix='mobile-release-build-inputs-')
            self.assertIs(caught.exception, allocation_error)
            failing.assert_called_once_with(dir=private, prefix='mobile-release-build-inputs-')
            untouched = Mock()
            with self.assertRaisesRegex(AssertionError, 'allocation contract changed'):
                _materializer_directory(untouched, private, created,
                                        prefix='mobile-release-build-inputs-', dir=root)
            untouched.assert_not_called()
            ordinary = Mock(wraps=tempfile.TemporaryDirectory)
            with _materializer_directory(ordinary, private, created,
                                         prefix='mobile-release-profile-auth-', dir=root) as name:
                self.assertEqual(Path(name).parent, root)
            ordinary.assert_called_once_with(prefix='mobile-release-profile-auth-', dir=root)
            self.assertEqual(len(created), 2)
            self.assertEqual(list(private.iterdir()), [])

    def test_original_snapshot_is_validated_before_acquisition_and_never_renews_the_deadline(self):
        with tempfile.TemporaryDirectory(prefix="mrk-original-input-inert-") as temporary:
            root = Path(temporary)
            fixture.initialize(root)
            argv, observed = ["/usr/bin/security", "default-keychain", "-d", "user"], []
            class ObserveStop(Exception):
                pass
            def stop(model, command_argv):
                observed.append((model, command_argv))
                argv[:] = [None]  # Later caller mutation cannot change the captured original input.
                raise ObserveStop
            model = persistent.PersistentSigningModel(root, trace=SimpleNamespace(observe_original_command=stop))
            with patch.object(bridge, "Namespace", side_effect=AssertionError("must not acquire")) as acquire:
                with self.assertRaises(ObserveStop):
                    model(argv)
                self.assertEqual(observed, [(model, ("/usr/bin/security", "default-keychain", "-d", "user"))])
                self.assertEqual(argv, [None])
                for invalid in ([b"not-text"], ["item"] * 65):
                    with self.subTest(invalid=len(invalid)), self.assertRaisesRegex(AssertionError, "bounded fictional"):
                        model(invalid)
                self.assertEqual(len(observed), 1)
                model.trace = SimpleNamespace(observe_original_command=lambda _model, _argv: observed.append("hook"))
                with patch.object(persistent.time, "monotonic", side_effect=[100.0, 131.0]), \
                        self.assertRaisesRegex(AssertionError, "original cutoff expired"):
                    model(["build"], timeout=30)
                self.assertEqual(observed[-1], "hook")
                acquire.assert_not_called()
            # Source-level transport assertion supplements the actual
            # pre-acquisition execution above; it is not a HELLO/target receipt.
            tree = ast.parse(Path(persistent.__file__).read_text())
            method = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "__call__")
            transported = [value for node in ast.walk(method) if isinstance(node, ast.Dict)
                           for key, value in zip(node.keys, node.values)
                           if isinstance(key, ast.Constant) and key.value == "argv"]
            self.assertEqual(len(transported), 1)
            self.assertEqual(ast.dump(transported[0]), ast.dump(ast.parse("list(command_argv)", mode="eval").body))

    def test_native_prefixes_are_closed_and_require_actual_proper_source_bytes(self):
        self.assertEqual(set(catalog.NATIVE_PREFIXES), {"database", "lock", "transaction-stage"})
        self.assertEqual(len(catalog.CASES), 131)
        self.assertFalse(catalog.definition()["completeRequiredUnion"])
        for name, payload in catalog.NATIVE_PREFIX_CONTENT.items():
            row = catalog.case("N/native-prefix/" + name)
            self.assertEqual((row.kind, row.manual, row.expected), ("native-prefix", "none", catalog.REFUSED))
            self.assertEqual(row.resolution, catalog.CONFLICT if name == "transaction-stage" else catalog.RECOVERED)
            self.assertIs(row.selector, catalog.NATIVE_PREFIXES[name])
            self.assertEqual((row.selector.phase, row.selector.slot, row.selector.origin, row.selector.edge),
                             ("setup", "native", "model", "partial"))
            with tempfile.TemporaryDirectory(prefix="mrk-prefix-bytes-inert-") as temporary:
                path = Path(temporary) / "fixed-source-effect"
                prefix = payload[:max(1, len(payload) // 2)]
                path.write_bytes(prefix)
                path.chmod(0o600)
                actual = semantic._read_expected_file(path, payload, partial=True)
                self.assertEqual(actual["size"], len(prefix))
                self.assertEqual(actual["sha256"], hashlib.sha256(prefix).hexdigest())
                for invalid in (payload, b"x" * len(prefix)):
                    path.write_bytes(invalid)
                    with self.subTest(name=name, invalid=len(invalid)), \
                            self.assertRaisesRegex(AssertionError, "proper native prefix"):
                        semantic._read_expected_file(path, payload, partial=True)
                path.unlink()
                path.symlink_to(Path(temporary) / "absent")
                with self.assertRaisesRegex(AssertionError, "evidence inode"):
                    semantic._read_expected_file(path, payload, partial=True)

    def test_checkpoint_observation_follows_original_return_and_never_records_a_failed_write(self):
        with tempfile.TemporaryDirectory(prefix="mrk-checkpoint-return-inert-") as temporary:
            root = Path(temporary)
            fixture.initialize(root)
            trace = semantic.HealthyTrace(root, "inert")
            # Real checkpoint/remember_preferences algorithms, but no lease,
            # descriptor, process or native operation is acquired by this unit.
            session = object.__new__(signing.SigningSession)
            preferences = {"default": "fictional", "search": ["fictional"]}
            session.state = {"revision": 0, "preferences": copy.deepcopy(preferences)}
            session.observe = lambda: copy.deepcopy(preferences)
            observations = []
            session._write = lambda name, value: observations.append(("write", name, value["revision"]))
            session.checkpoint = MethodType(trace.checkpoint_wrapper(signing.SigningSession.checkpoint), session)
            def returned(actual, caller):
                self.assertIs(actual, session)
                self.assertEqual(observations[-1], ("write", "state.json", session.state["revision"]))
                observations.append(("returned", caller))
            with patch.object(trace, "checkpoint_return", side_effect=returned) as recorded:
                session.remember_preferences(preferences)
                self.assertEqual(observations, [("write", "state.json", 1), ("returned", "remember_preferences")])
                def failed(_name, _value):
                    raise OSError("inert original write did not return")
                session._write = failed
                with self.assertRaisesRegex(OSError, "did not return"):
                    session.remember_preferences(preferences)
                self.assertEqual(recorded.call_count, 1)
            with patch.object(trace, "checkpoint_return", side_effect=AssertionError("late observation failure")):
                session._write = lambda _name, _value: None
                with self.assertRaisesRegex(AssertionError, "late observation failure"):
                    session.remember_preferences(preferences)
            # Pin the real file at pre-setup command3, not first checkpoint14.
            # A later mutually consistent disk/live/committed replacement must
            # still fail the original immutable-intent comparison.
            session.path = root / "inert-intent"
            session.path.mkdir(mode=0o700)
            session.intent = {"synthetic-inert-intent": 1}
            content = signing._json(session.intent)
            session._committed_controls = {"intent.json": content}
            path = session.path / "intent.json"
            path.write_bytes(content)
            path.chmod(0o600)
            trace.command_ordinal = 3
            trace.observe_intent(session, initial=True)
            self.assertEqual(trace.intent_bytes, content)
            session.intent = {"synthetic-inert-intent": 2}
            session._committed_controls["intent.json"] = signing._json(session.intent)
            path.write_bytes(session._committed_controls["intent.json"])
            with self.assertRaisesRegex(AssertionError, "initial setup intent changed"):
                trace.observe_intent(session)

    @staticmethod
    def inert_healthy_data(root):
        """DATA-only counterexample base; never written as a native result."""
        token = "a" * 32
        keychain = str(root / "home" / signing.LEASE_DIRECTORY / ("session-" + token) / "keychain" / catalog.DB_NAME)
        baseline = {"default": "fictional-original", "search": ["fictional-original", "fictional-second"]}
        preferences = {"baseline": baseline, "search": {"default": baseline["default"], "search": [keychain]},
                       "active": {"default": keychain, "search": [keychain]}}
        value = {"sessionToken": token, "snapshot": {"session": None, "keychain": keychain, "original": baseline,
            "nativeCalls": [{"command": name, "mutation": mutation, "recovery": recovery}
                            for name, mutation, recovery in semantic.HEALTHY_COMMANDS]},
            "events": [{"index": index, "operation": "inert-placeholder"} for index in range(1, 462)]}
        commands = [{"ordinal": number, "command": name, "mutation": mutation,
                     "phase": "setup" if number < 27 else "build" if number == 27 else "cleanup"}
                    for number, (name, mutation, _recovery) in enumerate(semantic.HEALTHY_COMMANDS, 1)]
        files = {name: {"device": 1, "inode": number, "size": len(semantic.FICTIONAL_PEM), "mode": 0o644,
                       "sha256": hashlib.sha256(semantic.FICTIONAL_PEM).hexdigest()}
                 for number, name in enumerate(semantic.EXTRACT_NAMES, 1)}
        for command, name in zip(commands[5:11], (*semantic.EXTRACT_NAMES, *semantic.IMPORT_NAMES)):
            command["inputPath"] = "<ROOT>/private/" + name
            if command["command"] == "import":
                command["inputFile"] = dict(files[name])
        commands[8]["inputFile"]["mode"] = 0o600
        checkpoints = []
        for number, (caller, completed, role, search, default, cleanup) in enumerate(semantic.HEALTHY_CHECKPOINTS, 1):
            state = {"revision": number, "preferences": preferences[role], "inflight": None, "conflict": False,
                     "searchAttempted": search, "defaultAttempted": default, "cleanupStarted": cleanup,
                     "native": {catalog.DB_NAME: {"device": 1, "inode": 100}} if completed < 40 else {},
                     "profile": {"phase": "stage-removed" if completed < 40 else "resolved"}}
            checkpoints.append({"ordinal": number, "caller": caller, "completedModelCalls": completed,
                "eventPosition": completed * 10, "state": state, "stateSha256": hashlib.sha256(signing._json(state)).hexdigest(),
                "intentSha256": "b" * 64})
        effects = []
        transitions = (("baseline", "baseline"),) * 3 + (
            ("baseline", "search"), ("search", "active"), ("active", "search"), ("search", "baseline"))
        for number, ((operation, phase, occurrence, ordinal), (before, after)) in enumerate(zip(semantic.HEALTHY_EFFECTS, transitions)):
            index = ordinal * 10
            row = {"eventIndex": index, "operation": operation, "phase": phase, "occurrence": occurrence,
                   "commandOrdinal": ordinal, "beforePreferences": preferences[before], "afterPreferences": preferences[after]}
            if number < 3:
                name = semantic.EXTRACT_NAMES[number]
                row.update(path="<ROOT>/private/" + name, file=files[name])
            effects.append(row)
            value["events"][index - 1] = {"index": index, "operation": "native-effect/" + operation,
                "slot": "native", "origin": "model", "phase": phase, "occurrence": occurrence, "details": {}, "succeeded": True}
        value["events"][-1] = {"index": 461, "operation": "replace", "slot": catalog.SESSION + "/completed.pending",
                                "origin": catalog.LOCAL + "_write", "succeeded": True}
        value["healthyContexts"] = {"commands": commands, "checkpoints": checkpoints, "effects": effects}
        return value

    def test_healthy_data_contract_rejects_missing_changed_and_misordered_contexts(self):
        root = Path("/fictional-inert-root")  # This data predicate performs no filesystem or native work.
        value = self.inert_healthy_data(root)
        semantic.assert_healthy_observation(root, value)
        for variant in ("missing-checkpoint", "changed-state", "wrong-import", "early-effect", "early-terminal"):
            changed = copy.deepcopy(value)
            contexts = changed["healthyContexts"]
            if variant == "missing-checkpoint":
                contexts["checkpoints"].pop()
            elif variant == "changed-state":
                row = contexts["checkpoints"][1]
                row["state"]["searchAttempted"] = False
                row["stateSha256"] = hashlib.sha256(signing._json(row["state"])).hexdigest()
            elif variant == "wrong-import":
                contexts["commands"][8]["inputPath"] = "<ROOT>/private/signing-certificate.pem"
            elif variant == "early-effect":
                row = contexts["effects"][3]
                actual = changed["events"][row["eventIndex"] - 1]
                row["eventIndex"] = 159
                changed["events"][158] = {**actual, "index": 159}
            else:
                changed["events"][-1]["index"] = 450
            with self.subTest(variant=variant), self.assertRaises(AssertionError):
                semantic.assert_healthy_observation(root, changed)


class RecoveryRefusalContractTests(unittest.TestCase):
    @staticmethod
    def inert_refusal(error, expected, *, unknown=True, unchanged=True,
                      intent_unchanged=True, manual_events=()):
        """Exercise recovery_flow arbitration with every account/native entry vetoed.

        These are inert classifier inputs, not journals, TTYs or recovery receipts.
        No production lease, command owner, filesystem fact or timer is acquired.
        """
        from contextlib import ExitStack, nullcontext
        from workflow import local_signing_case_owner as case_owner

        root, token = Path('/fictional-inert-recovery'), 'a' * 32
        before = {'session': token, 'controls': {'intent.json': {'fictional': 'original'}}}
        after = copy.deepcopy(before)
        if not intent_unchanged:
            after['controls']['intent.json'] = {'fictional': 'changed'}
        identity = {'device': 1, 'inode': 2, 'sha256': 'fictional-classifier-data'}
        unknown_files = {'owned-item': identity} if unknown else {}
        actual = identity if unchanged else {**identity, 'inode': 3}
        order, issued = [], []
        snapshots = iter((before, after))
        def snapshot(_root):
            order.append('snapshot')
            return next(snapshots)
        def refuse(*_args, **_kwargs):
            try:
                raise error
            except CredentialError as original:
                issued.append(original.__traceback__)
                raise
        oracle = SimpleNamespace(assert_sentinels=Mock(side_effect=lambda: order.append('sentinels')))
        trace = SimpleNamespace(events=list(manual_events), installed=lambda: nullcontext(), result=lambda: {})
        result, caught, original_traceback = None, None, None
        with ExitStack() as patches:
            patches.enter_context(patch.object(case_owner, 'CASE_DEADLINE', 1000.0))
            patches.enter_context(patch.object(case_owner, 'remaining', return_value=1.0))
            patches.enter_context(patch.object(case_owner, 'adapter_progress'))
            patches.enter_context(patch.object(signing, 'signing_status',
                return_value={'status': 'pending', 'session': token}))
            patches.enter_context(patch.object(signing, 'recover_signing', new=refuse))
            patches.enter_context(patch.object(fixture, 'snapshot', new=snapshot))
            patches.enter_context(patch.object(fixture, 'uncertainty', return_value=unknown_files))
            patches.enter_context(patch.object(fixture, 'PersistentSigningModel',
                return_value=SimpleNamespace(oracle=oracle)))
            pending = patches.enter_context(patch.object(fixture, 'assert_pending'))
            facts = patches.enter_context(patch.object(fixture, 'facts', return_value=actual))
            try:
                result = fixture.recovery_flow(root, trace, original_token=token, expected_status=expected)
            except BaseException as original:
                caught, original_traceback = original, original.__traceback__
        return SimpleNamespace(result=result, error=caught, traceback=original_traceback,
            issued=issued, order=order, oracle=oracle, pending=pending, facts=facts, root=root)

    def test_unexpected_recovery_refusal_keeps_original_error_and_traceback(self):
        for expected, message in (
            (catalog.RECOVERED, 'unknown native staging remains; fictional input'),
            (catalog.REFUSED, 'fictional unrecognized private recovery failure'),
            (None, 'fictional unrecognized private recovery failure'),
        ):
            with self.subTest(expected=expected, recognized='unknown native staging' in message):
                original = CredentialError(message)
                observed = self.inert_refusal(original, expected)
                self.assertIs(observed.error, original)
                self.assertIsNone(observed.result)
                self.assertEqual(len(observed.issued), 1)
                frames, frame = [], observed.traceback
                while frame is not None:
                    frames.append(frame)
                    frame = frame.tb_next
                self.assertTrue(any(frame is observed.issued[0] for frame in frames))
                self.assertEqual(observed.order, ['snapshot', 'snapshot', 'sentinels'])
                observed.oracle.assert_sentinels.assert_called_once_with()
                observed.pending.assert_not_called()
                observed.facts.assert_not_called()

    def test_known_negative_recovery_still_requires_resource_intent_and_manual_invariants(self):
        original = CredentialError('native transaction identity is unknown; fictional input')
        observed = self.inert_refusal(original, catalog.REFUSED)
        self.assertIsNone(observed.error)
        self.assertEqual(observed.result['refused'], str(original))
        self.assertEqual(observed.result['expectedStatus'], catalog.REFUSED)
        self.assertFalse(observed.result['idleAndRenewedAdmission'])
        self.assertEqual(observed.order, ['snapshot', 'snapshot', 'sentinels'])
        observed.pending.assert_called_once_with(observed.root)
        observed.facts.assert_called_once_with(observed.root / 'owned-item')
        for changed in ({'unknown': False}, {'unchanged': False}, {'intent_unchanged': False},
                        {'manual_events': ({'operation': 'manual/input'},)}):
            with self.subTest(changed=changed):
                observed = self.inert_refusal(CredentialError(str(original)), catalog.REFUSED, **changed)
                self.assertIsInstance(observed.error, AssertionError)
                self.assertIsNone(observed.result)
                self.assertEqual(observed.order, ['snapshot', 'snapshot', 'sentinels'])
