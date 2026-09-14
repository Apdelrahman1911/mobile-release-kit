"""Inert H/N observation contracts, never native execution or custody evidence."""
from __future__ import annotations

import ast
import copy
import hashlib
import tempfile
import unittest
from pathlib import Path
from types import MethodType, SimpleNamespace
from unittest.mock import patch

from mobile_release import local_signing as signing
from unit import local_signing_persistent as persistent
from workflow import local_signing_bridge as bridge
from workflow import local_signing_persistent_fixture as fixture
from workflow import local_signing_semantic_catalog as catalog
from workflow import local_signing_semantic_fixture as semantic


class ObservationContractTests(unittest.TestCase):
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
