"""Direct genuine lifecycle cases using the existing original worker owner.

No inventory replay, assigned journal, copied live session or alternate selector
is admitted.  This module is not a standalone executor or the complete matrix.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import sys
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from mobile_release import local_signing as signing
from workflow import local_signing_persistent_fixture as fixture
from workflow import local_signing_semantic_catalog as catalog
from workflow.local_signing_matrix_contract import digest
from workflow.local_signing_workload import recovery_timeout, worker_timeout


def _observe_original_reservation(session, arming):
    """Observe the live original arm without reentering recovery admission.

    An AFTER-replace cut precedes directory fsync and committed-control advance.
    Production validates before/after that durable transition; an observer must
    not demand the completed generation in the middle of the original write.
    """
    from mobile_release import _command_process as command

    assert type(session) is signing.SigningSession
    binding, scope = session._command_binding, session._command_scope
    assert type(binding) is command.JournalledCommandBinding
    assert type(scope) is command.AccountExecutionScope
    assert binding._session is session and binding._scope is scope and scope._binding is binding
    assert type(scope._source) is command.AccountExecutionSource and scope._source._lease is session.lease
    assert scope._source._authorization is session._recovery_attempt
    assert binding._arm_attempted and not binding._arm_retired
    reservation = binding._arming_reservation
    assert type(reservation) is command.OriginalCommandReservation
    engine, slot = reservation._engine, scope.outcome
    assert type(engine) is command._Outer and type(slot) is command.CommandOutcomeSlot
    assert engine is slot._engine and engine.slot is slot and slot._scope is scope
    assert engine.scope is scope and engine.binding is binding and scope._used
    assert reservation.nonce == scope.nonce == engine.nonce == slot._nonce
    assert slot.read() is None
    original = signing.SigningSession._arm_original_command
    assert getattr(binding._arm, '__self__', None) is session
    assert getattr(binding._arm, '__func__', None) is original
    assert (arming is not None and arming[0] is original.__code__
            and arming[1] is session and arming[2] is reservation), 'original arming callback is not active'
    assert engine.prepared_reservation()
    assert not engine.create_route.attempted and not engine.run_route.attempted
    return dict(beforeGrant=True, originalArmingCallback=True,
                originalReservationBound=True, createAttempted=False, runAttempted=False)


class SemanticTrace(fixture.Trace):
    """Match the actual tuple/one-based ordinal, then assert its live context."""
    def __init__(self, root, name, selector=None, *, expected_sequence=None, after_effect=None):
        super().__init__(root, name, after_effect=after_effect)
        assert selector is None or type(selector) is catalog.Selector
        self.selector = selector
        self.expected_sequence = expected_sequence
        self.selected_event = self.selected_context = self.write_payload = None
        self.manual_before = None

    def observe_context(self, event):
        # Observe real stack-owned sessions only. Native-model callbacks arrive
        # on the actual service thread, so they use the session captured by the
        # genuine original _fence_observation_policy call, never a fake record.
        frame, session, writing, callers, arming = sys._getframe(1), None, None, [], None
        try:
            for _ in range(64):
                if frame is None:
                    break
                module, name = frame.f_globals.get("__name__"), frame.f_code.co_name
                if module in {"mobile_release.local_signing", "mobile_release.credentials"}:
                    for key in ("self", "session"):
                        value = frame.f_locals.get(key)
                        if type(value) is signing.SigningSession:
                            if session is not None:
                                assert session is value, "two actual signing sessions in one selected event"
                            session = value
                    if module == "mobile_release.local_signing":
                        callers.append(name)
                        if frame.f_code is signing.SigningSession._arm_original_command.__code__:
                            assert arming is None, "nested original arming callback"
                            arming = (frame.f_code, frame.f_locals.get("self"), frame.f_locals.get("reservation"))
                        if name == "_write":
                            assert writing is None, "nested selected control write"
                            writing = (frame.f_locals["name"], frame.f_locals["data"])
                frame = frame.f_back
        finally:
            del frame
        if session is None and self._fence_session is not None:
            session, _descriptor, _identity, original = self._fence_session
            assert original == os.getpid(), "foreign original session observation"
        assert type(session) is signing.SigningSession and session.pid == os.getpid()
        assert session.lease.home == self.root / "home" and session.path == (
            self.root / "home" / signing.LEASE_DIRECTORY / ("session-" + session.token)), "selected session escaped case"
        assert self.session_token in {None, session.token}, "selected session token changed"
        self.session_token = session.token
        state = copy.deepcopy(session.state)
        operation = None if state is None else state["inflight"]
        result = {"sessionToken": session.token, "sessionIdentity": copy.deepcopy(session.identity),
            "statePresent": state is not None, "liveState": state,
            "operationKind": None if operation is None else operation["kind"],
            "operationPhase": None if operation is None else operation["phase"],
            "commandSequence": None if state is None else state["commandSequence"],
            "profilePhase": None if state is None else state["profile"]["phase"],
            "cleanupStarted": None if state is None else state["cleanupStarted"],
            "recoveryAttempt": session._recovery_attempt is not None,
            "writeName": None if writing is None else writing[0],
            "writeCaller": next((name for name in callers if name not in {"_write", "checkpoint", "_read_regular", "_control"}), None),
            "manualAction": event["details"].get("action"),
            "beforeBinding": session._command_binding is None}
        if writing is not None:
            assert type(writing[1]) is bytes and 0 < len(writing[1]) <= signing.CONTROL_LIMIT
            self.write_payload = writing[1]
            result["writePayloadBytes"] = len(writing[1])
            result["writePayloadSha256"] = hashlib.sha256(writing[1]).hexdigest()
        result["beforeGrant"] = False
        binding = session._command_binding
        if binding is not None and binding._arming_reservation is not None:
            result.update(_observe_original_reservation(session, arming))
        if self.expected_sequence is not None:
            assert result["commandSequence"] == self.expected_sequence, "selected original operation sequence changed"
        return result

    def begin(self, operation, slot, origin, details):
        event = super().begin(operation, slot, origin, details)
        if self.selector is not None and self.selector.routes(event):
            assert self.selected_event is None, "selected semantic tuple repeated"
            self.selected_event = event
            self.selected_context = self.observe_context(event)
            self.selector.check_context(self.selected_context)
            assert self.selected_context["recoveryAttempt"] == (event["phase"] == "recovery"), \
                "selected original/recovery caller differs"
            if operation == "manual/input":
                self.manual_before = fixture.snapshot(self.root)
            if self.selector.edge == "before":
                self.cut(event, "before")
        return event

    def partial(self, event):
        return self.selector is not None and event is self.selected_event and self.selector.edge == "partial"

    def end(self, event, *, succeeded, error=None):
        super().end(event, succeeded=succeeded, error=error)
        if event is self.selected_event and self.selector.edge == "after":
            assert succeeded and error is None, "selected semantic operation did not succeed"
            self.cut(event, "after")

    def cut(self, event, edge):
        assert event is self.selected_event and edge == self.selector.edge and self.selector.routes(event)
        context = self.observe_context(event)
        self.selector.check_context(context)
        assert context["sessionToken"] == self.selected_context["sessionToken"]
        record = {"event": event, "edge": edge, "selector": self.selector.record(),
                  "sessionToken": self.session_token, "context": context, "snapshot": fixture.snapshot(self.root)}
        if event["operation"] in {"write", "buffer.write"}:
            path = self.root / event["slot"].removeprefix("<ROOT>/").replace("<TOKEN>", self.session_token)
            actual, _details = fixture.read_fixture_file(path, limit=signing.CONTROL_LIMIT, empty=True)
            intended = fixture.PROFILE if event["operation"] == "buffer.write" else self.write_payload
            assert type(intended) is bytes and len(intended) > 1
            if edge == "partial":
                assert 0 < len(actual) < len(intended) and actual == intended[:len(actual)], "not an actual proper write prefix"
            elif edge == "before":
                assert actual == b"", "before-write stage is not empty"
            record["physicalWrite"] = {"bytes": len(actual), "intendedBytes": len(intended),
                "sha256": hashlib.sha256(actual).hexdigest(), "intendedSha256": hashlib.sha256(intended).hexdigest(),
                "properPrefix": edge == "partial"}
        if event["operation"].startswith("command-fence/"):
            assert self._fence_evidence is not None, "missing genuine held original-C checkpoint"
            record["originalCFenceObservation"] = copy.deepcopy(self._fence_evidence)
        if self.manual_before is not None:
            record["manualBefore"] = self.manual_before
        self.extend_cut(record)
        assert not (self.root / (self.name + "-cut.json")).exists(), "selected cut output already exists"
        fixture.write_json(self.root / (self.name + "-cut.json"), record)
        os._exit(fixture.CRASH)  # Original O really exits; this does not kill/settle C.

    def extend_cut(self, record):
        pass

    def result(self):
        assert self.selector is None, {"selectedSemanticCutNotReached": self.selector.record()}
        return super().result()


_D, _L = ("default-keychain", False, False), ("list-keychains", False, False)
HEALTHY_COMMANDS = (
    _D, _L,
    ("create-keychain", True, False), ("set-keychain-settings", True, False), ("unlock-keychain", True, False),
    *(("openssl", True, False),) * 3, *(("import", True, False),) * 3,
    ("set-key-partition-list", True, False), _D, _L, _D, _L,
    ("list-keychains", True, False), _D, _L, _D, _L,
    ("default-keychain", True, False), _D, _L, _D, _L, ("build", True, False),
    _D, _L, _D, _L, ("default-keychain", True, False), _D, _L,
    _D, _L, ("list-keychains", True, False), _D, _L,
    ("delete-keychain", True, False), _D, _L, _D, _L, _D, _L, _D, _L, _D, _L,
)
# Direct caller, actual completed model calls, preferences, attempted flags,
# cleanupStarted. These are checkpoint RETURNS, not os.replace after-events.
HEALTHY_CHECKPOINTS = (
    ("activate", 14, "baseline", False, False, False),
    ("activate", 16, "baseline", True, False, False),
    ("remember_preferences", 19, "search", True, False, False),
    ("activate", 21, "search", True, True, False),
    ("remember_preferences", 24, "active", True, True, False),
    ("remember_preferences", 26, "active", True, True, False),
    ("cleanup_native", 27, "active", True, True, True),
    ("cleanup_native", 34, "search", True, True, True),
    ("cleanup_native", 39, "baseline", True, True, True),
    ("cleanup_profile", 44, "baseline", True, True, True),
    ("cleanup_profile", 46, "baseline", True, True, True),
)
HEALTHY_EFFECTS = (
    ("extract", "setup", 1, 6), ("extract", "setup", 2, 7), ("extract", "setup", 3, 8),
    ("preference/search", "setup", 1, 17), ("preference/default", "setup", 1, 22),
    ("preference/default", "cleanup", 1, 32), ("preference/search", "cleanup", 1, 37),
)
EXTRACT_NAMES = ("signing-certificate.pem", "signing-private-key.pem", "signing-chain.pem")
IMPORT_NAMES = (EXTRACT_NAMES[1], EXTRACT_NAMES[0], EXTRACT_NAMES[2])
FICTIONAL_PEM = b"-----BEGIN CERTIFICATE-----\nfictional-not-a-certificate\n"
assert len(HEALTHY_COMMANDS) == 50


def _model_state(root):
    content, details = fixture.read_fixture_file(root / "observed-native.json", limit=65536)
    assert stat.S_IMODE(details.st_mode) == 0o600 and details.st_nlink == 1
    value = fixture.strict_json(content.decode("utf-8"))
    assert type(value) is dict and set(value) == {"original", "preferences", "keychain", "revisions", "calls"}
    assert type(value["revisions"]) is int and value["revisions"] >= 0
    return value


def _call_signatures(calls):
    assert type(calls) is list and len(calls) <= 50
    assert all(type(row) is dict and set(row) == {"command", "mutation", "recovery"}
               and type(row["command"]) is str and type(row["mutation"]) is bool
               and type(row["recovery"]) is bool for row in calls)
    return tuple((row["command"], row["mutation"], row["recovery"]) for row in calls)


def _read_expected_file(path, expected, *, partial=False):
    content, info = fixture.read_fixture_file(path, limit=len(expected))
    assert info.st_nlink == 1, "observed effect file was linked"
    if partial:
        assert 0 < len(content) < len(expected) and content == expected[:len(content)], \
            "not the source-defined proper native prefix"
    else:
        assert content == expected, "observed effect bytes differ from fixed source"
    return {"device": info.st_dev, "inode": info.st_ino, "mode": stat.S_IMODE(info.st_mode),
            "size": info.st_size, "sha256": hashlib.sha256(content).hexdigest()}


class OriginalInputTrace(SemanticTrace):
    """Observe O's actual immutable input; never inspect nonexistent W frames."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.original_model = self.original_session = self.original_input = None
        self.original_model_before = None
        self.command_ordinal = 0

    def observe_original_command(self, model, command_argv):
        assert type(model) is fixture.PersistentSigningModel and model.root == self.root
        assert model.trace is self and not model.recovery and not model.auto_add
        assert type(command_argv) is tuple, "original command was not snapshotted"
        # This _call frame really belongs to O, unlike execute_model/file_write.
        frame, session = sys._getframe(1), None
        try:
            for _ in range(64):
                if frame is None:
                    break
                if frame.f_code is signing.SigningSession._call.__code__:
                    assert session is None, "ambiguous original caller"
                    session = frame.f_locals["self"]
                frame = frame.f_back
        finally:
            del frame
        assert type(session) is signing.SigningSession and session.runner is model
        assert self.original_model is None or self.original_model is model
        assert self.original_session is None or self.original_session is session
        self.original_model, self.original_session = model, session
        self.original_input = command_argv
        self.original_model_before = copy.deepcopy(model.state)
        self.command_ordinal = len(model.state["calls"]) + 1
        self.bound_session()

    def bound_session(self):
        session = self.original_session
        assert type(session) is signing.SigningSession and session.pid == os.getpid() and not session.closed
        assert session.runner is self.original_model and self.original_model.trace is self
        assert session.lease.home == self.root / "home" and session.path == (
            self.root / "home" / signing.LEASE_DIRECTORY / ("session-" + session.token))
        opened, named = os.fstat(session.fd), session.path.lstat()
        assert stat.S_ISDIR(opened.st_mode) and stat.S_IMODE(opened.st_mode) == 0o700 and opened.st_uid == os.getuid()
        assert (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid, opened.st_gid) == (
            named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_gid)
        assert session.identity == {"device": opened.st_dev, "inode": opened.st_ino}
        assert self.session_token in {None, session.token}
        self.session_token = session.token
        if self._fence_session is not None:
            observed, descriptor, identity, original = self._fence_session
            assert observed is session and descriptor == session.fd and identity == session.identity
            assert original == os.getpid()
        return session


class NativePrefixTrace(OriginalInputTrace):
    def __init__(self, root, name, prefix):
        super().__init__(root, name, catalog.NATIVE_PREFIXES[prefix])
        self.prefix = prefix

    def extend_cut(self, record):
        session, argv = self.bound_session(), self.original_input
        expected_command = "set-keychain-settings" if self.prefix == "transaction-stage" else "create-keychain"
        assert len(argv) == 5 and argv[0] == "/usr/bin/security" and argv[1] == expected_command
        assert argv[-1] == str(session.keychain)
        if expected_command == "set-keychain-settings":
            assert argv[2:4] == ("-lut", "21600")
        else:
            assert argv[2] == "-p"
        before = self.original_model_before
        assert _call_signatures(before["calls"]) == HEALTHY_COMMANDS[:self.command_ordinal - 1]
        assert self.command_ordinal == (4 if self.prefix == "transaction-stage" else 3)
        assert before["revisions"] == 0
        record["originalCommand"] = {"command": expected_command, "ordinal": self.command_ordinal,
                                     "keychain": catalog.KEYCHAIN + "/" + catalog.DB_NAME,
                                     "revisionBefore": before["revisions"]}
        record["physicalWrite"] = native_prefix_proof(self.root, self.prefix, record)


def native_prefix_proof(root, name, cut):
    """Compare actual physical bytes/oracle/state, not an alleged W operand."""
    selector = catalog.NATIVE_PREFIXES[name]
    assert cut["selector"] == selector.record() and selector.routes(cut["event"]) and cut["edge"] == "partial"
    selector.check_context(cut["context"])
    assert cut["context"]["recoveryAttempt"] is False
    observed, token = cut["snapshot"], cut["sessionToken"]
    state, model = _state(observed), _model_state(root)
    assert state["inflight"]["kind"] == ("settings" if name == "transaction-stage" else "create")
    assert _phase(observed) == "ARMED" and not state["cleanupStarted"] and not state["conflict"]
    assert observed["session"] == token and observed["preferences"] == observed["original"] == state["preferences"]
    assert set(observed["controls"]) == {"intent.json", "state.json"} and not observed["fences"]
    assert state["profile"]["phase"] == "stage-removed"
    installed = _profile(observed, fixture.UUID + ".mobileprovision")
    assert installed["sha256"] == hashlib.sha256(fixture.PROFILE).hexdigest()
    assert state["profile"]["ownedIdentity"] == {key: installed[key] for key in ("device", "inode")}
    assert _profile(observed, ".mobile-release-profile-" + token) is None
    ordinal = 4 if name == "transaction-stage" else 3
    assert cut["originalCommand"] == {"command": "set-keychain-settings" if ordinal == 4 else "create-keychain",
        "ordinal": ordinal, "keychain": catalog.KEYCHAIN + "/" + catalog.DB_NAME, "revisionBefore": 0}
    assert _call_signatures(model["calls"]) == HEALTHY_COMMANDS[:ordinal]
    assert model["calls"] == observed["nativeCalls"] and model["preferences"] == observed["preferences"]
    assert model["revisions"] == (1 if ordinal == 4 else 0)
    native = _native_identities(observed)
    expected_names = {catalog.DB_NAME} if name == "database" else {catalog.DB_NAME, catalog.LOCK_NAME}
    if name == "transaction-stage":
        expected_names.add("native-atomic-stage")
        assert state["native"] == {key: native[key] for key in (catalog.DB_NAME, catalog.LOCK_NAME)}
    else:
        assert not state["native"]
    assert set(native) == expected_names
    directory = root / "home" / signing.LEASE_DIRECTORY / ("session-" + token) / "keychain"
    assert model["keychain"] == str(directory / catalog.DB_NAME) == observed["keychain"]
    oracle = fixture.ResourceOracle(root)
    oracle.assert_sentinels()
    oracle_native = oracle.read()["native"]
    selected_name = selector.operation.removeprefix("native-effect/write/")
    proof = None
    for filename in sorted(expected_names):
        selected = filename == selected_name
        payload = catalog.NATIVE_PREFIX_CONTENT[name] if selected else (
            catalog.NATIVE_PREFIX_CONTENT["database"] if filename == catalog.DB_NAME else catalog.NATIVE_PREFIX_CONTENT["lock"])
        path = directory / filename
        facts = _read_expected_file(path, payload, partial=selected)
        relative = str(path.relative_to(root))
        assert facts["mode"] == 0o600 and facts == observed["native"][relative] == oracle_native[relative]
        if selected:
            proof = {"name": filename, "bytes": facts["size"], "intendedBytes": len(payload),
                "sha256": facts["sha256"], "intendedSha256": hashlib.sha256(payload).hexdigest(),
                "facts": facts, "properPrefix": True, "revisionAtCut": model["revisions"]}
    assert proof is not None and fixture.uncertainty(root, observed), "native prefix lost its genuine unknown-resource state"
    return proof


class HealthyTrace(OriginalInputTrace):
    def __init__(self, root, name):
        super().__init__(root, name)
        self.commands, self.checkpoints, self.effects = [], [], []
        self.effect_pending = None
        self.intent_bytes = None

    def preferences(self, role):
        baseline = copy.deepcopy(self.original_model_before["original"])
        if role in {"search", "active"}:
            baseline["search"] = [str(self.original_session.keychain)]
        if role == "active":
            baseline["default"] = str(self.original_session.keychain)
        return baseline

    def observe_original_command(self, model, command_argv):
        super().observe_original_command(model, command_argv)
        ordinal, argv = self.command_ordinal, self.original_input
        assert ordinal == len(self.commands) + 1 and ordinal <= len(HEALTHY_COMMANDS)
        if ordinal <= 2:
            assert self.original_session.intent is None and self.intent_bytes is None
        elif ordinal == 3:
            self.observe_intent(self.original_session, initial=True)
        else:
            assert self.intent_bytes is not None, "setup intent was not observed before native effects"
        assert _call_signatures(model.state["calls"]) == HEALTHY_COMMANDS[:ordinal - 1]
        command = argv[1] if Path(argv[0]).name == "security" else Path(argv[0]).name
        signature = (command, "-s" in argv or command not in {"default-keychain", "list-keychains"}, model.recovery)
        assert signature == HEALTHY_COMMANDS[ordinal - 1], "healthy original command order differs"
        record = {"ordinal": ordinal, "command": command, "mutation": signature[1], "phase": self.phase}
        if command in {"openssl", "import"}:
            assert (command == "openssl" and 6 <= ordinal <= 8) or (command == "import" and 9 <= ordinal <= 11)
            name = EXTRACT_NAMES[ordinal - 6] if command == "openssl" else IMPORT_NAMES[ordinal - 9]
            if command == "openssl":
                assert argv.count("-out") == 1
                path = Path(argv[argv.index("-out") + 1])
            else:
                path = Path(argv[2])
            assert path == self.root / "private" / name, "healthy input file routing differs"
            record["inputPath"] = "<ROOT>/private/" + name
            if command == "import":
                facts = _read_expected_file(path, FICTIONAL_PEM)
                if ordinal == 9:
                    assert facts["mode"] == 0o600, "private key was not restricted before first import"
                extraction = next(row for row in self.effects if row.get("path") == record["inputPath"])
                assert all(facts[key] == extraction["file"][key] for key in ("device", "inode", "size", "sha256"))
                record["inputFile"] = facts
        self.commands.append(record)

    def observe_intent(self, session, *, initial=False):
        content, info = fixture.read_fixture_file(session.path / "intent.json", limit=signing.CONTROL_LIMIT)
        assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
        assert content == session._committed_controls["intent.json"]
        assert fixture.strict_json(content.decode("utf-8")) == session.intent
        if initial:
            assert self.command_ordinal == 3 and self.intent_bytes is None, "initial setup intent observation was delayed"
            self.intent_bytes = content  # Before the first original setup command acquires its target.
        else:
            assert self.intent_bytes is not None and content == self.intent_bytes, "initial setup intent changed"
        return content

    def begin(self, operation, slot, origin, details):
        event = super().begin(operation, slot, origin, details)
        if operation not in {"native-effect/extract", "native-effect/preference/search", "native-effect/preference/default"}:
            return event
        self.bound_session()
        assert self.effect_pending is None and len(self.effects) < len(HEALTHY_EFFECTS)
        expected = HEALTHY_EFFECTS[len(self.effects)]
        assert (operation.removeprefix("native-effect/"), event["phase"], event["occurrence"], self.command_ordinal) == expected
        assert event["slot"] == "native" and event["origin"] == "model" and not event["details"]
        context = self.observe_context(event)
        assert context["operationPhase"] == "ARMED" and not context["recoveryAttempt"]
        assert context["operationKind"] == ("extract" if expected[0] == "extract" else expected[0].split("/")[1])
        model = _model_state(self.root)
        # BEGIN precedes this first effect's save; persisted calls still end at
        # the previous original. END below requires the newly persisted call.
        assert _call_signatures(model["calls"]) == HEALTHY_COMMANDS[:self.command_ordinal - 1]
        record = {"eventIndex": event["index"], "operation": expected[0], "phase": event["phase"],
                  "occurrence": event["occurrence"], "commandOrdinal": self.command_ordinal,
                  "beforePreferences": model["preferences"]}
        if expected[0] == "extract":
            record["path"] = self.commands[-1]["inputPath"]
            path = self.root / "private" / EXTRACT_NAMES[len(self.effects)]
            assert not path.exists() and not path.is_symlink(), "healthy extraction destination already existed"
        self.effect_pending = record
        return event

    def end(self, event, *, succeeded, error=None):
        super().end(event, succeeded=succeeded, error=error)
        if self.effect_pending is None or self.effect_pending["eventIndex"] != event["index"]:
            return
        assert succeeded and error is None, "healthy effect did not actually return"
        record, self.effect_pending = self.effect_pending, None
        model = _model_state(self.root)
        assert _call_signatures(model["calls"]) == HEALTHY_COMMANDS[:self.command_ordinal]
        record["afterPreferences"] = model["preferences"]
        number = len(self.effects)
        before_role, after_role = (("baseline", "baseline") if number < 3 else (
            ("baseline", "search"), ("search", "active"), ("active", "search"), ("search", "baseline"))[number - 3])
        assert record["beforePreferences"] == self.preferences(before_role)
        assert record["afterPreferences"] == self.preferences(after_role)
        if number < 3:
            record["file"] = _read_expected_file(self.root / "private" / EXTRACT_NAMES[number], FICTIONAL_PEM)
        self.effects.append(record)

    def checkpoint_wrapper(self, original):
        callers = {getattr(signing.SigningSession, name).__code__: name for name in
                   ("activate", "remember_preferences", "cleanup_native", "cleanup_profile")}
        def checkpoint(session):
            frame = sys._getframe(1)
            try:
                caller = callers.get(frame.f_code)
                if caller is not None:
                    assert frame.f_locals.get("self") is session, "checkpoint caller/session differs"
            finally:
                del frame
            result = original(session)  # An exception can never become a completed checkpoint record.
            if caller is not None:
                self.checkpoint_return(session, caller)
            return result
        return checkpoint

    @contextmanager
    def installed(self):
        original = signing.SigningSession.checkpoint
        with super().installed(), patch.object(signing.SigningSession, "checkpoint", new=self.checkpoint_wrapper(original)):
            yield

    def checkpoint_return(self, session, caller):
        assert session is self.bound_session() and len(self.checkpoints) < len(HEALTHY_CHECKPOINTS)
        expected = HEALTHY_CHECKPOINTS[len(self.checkpoints)]
        completed = len(self.original_model.state["calls"])
        assert (caller, completed) == expected[:2], "healthy checkpoint caller/return order differs"
        assert _call_signatures(self.original_model.state["calls"]) == HEALTHY_COMMANDS[:completed]
        assert _model_state(self.root) == self.original_model.state, "checkpoint preceded actual original model return"
        content, info = fixture.read_fixture_file(session.path / "state.json", limit=signing.CONTROL_LIMIT)
        intent = self.observe_intent(session)
        assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
        assert content == session._committed_controls["state.json"]
        state = fixture.strict_json(content.decode("utf-8"))
        assert state == session.state
        assert not (session.path / "state.pending").exists() and not (session.path / "state.pending").is_symlink()
        assert not session.unresolved and not session.journal_failed and state["inflight"] is None and not state["conflict"]
        observed = fixture.snapshot(self.root)
        assert not observed["fences"] and state["native"] == _native_identities(observed)
        assert observed["preferences"] == state["preferences"] == self.preferences(expected[2])
        assert (state["searchAttempted"], state["defaultAttempted"], state["cleanupStarted"]) == expected[3:]
        if completed < 40:
            assert set(state["native"]) == {catalog.DB_NAME, catalog.LOCK_NAME} and state["profile"]["phase"] == "stage-removed"
        else:
            assert not state["native"] and state["profile"]["phase"] == "resolved"
            assert _profile(observed, ".mobile-release-profile-" + session.token) is None
            assert _profile(observed, fixture.UUID + ".mobileprovision") is None
        self.checkpoints.append({"ordinal": len(self.checkpoints) + 1, "caller": caller, "completedModelCalls": completed,
            "eventPosition": len(self.events), "stateIdentity": {"device": info.st_dev, "inode": info.st_ino},
            "stateSha256": hashlib.sha256(content).hexdigest(), "intentSha256": hashlib.sha256(intent).hexdigest(),
            "state": copy.deepcopy(state)})

    def result(self):
        value = super().result()
        assert self.effect_pending is None
        value["healthyContexts"] = {"commands": self.commands, "checkpoints": self.checkpoints, "effects": self.effects}
        assert_healthy_observation(self.root, value)
        return value


def assert_healthy_observation(root, value):
    contexts, observed = value["healthyContexts"], value["snapshot"]
    assert _call_signatures(observed["nativeCalls"]) == HEALTHY_COMMANDS and not observed["session"]
    commands, checkpoints, effects = (contexts[name] for name in ("commands", "checkpoints", "effects"))
    assert len(commands) == 50 and len(checkpoints) == 11 and len(effects) == 7
    assert tuple((row["command"], row["mutation"], False) for row in commands) == HEALTHY_COMMANDS
    assert [row["ordinal"] for row in commands] == list(range(1, 51))
    assert [row["phase"] for row in commands] == ["setup"] * 26 + ["build"] + ["cleanup"] * 23
    assert [row.get("inputPath") for row in commands[5:11]] == ["<ROOT>/private/" + name for name in (*EXTRACT_NAMES, *IMPORT_NAMES)]
    assert commands[8]["inputFile"]["mode"] == 0o600
    assert tuple((row["caller"], row["completedModelCalls"]) for row in checkpoints) == tuple(row[:2] for row in HEALTHY_CHECKPOINTS)
    assert [row["ordinal"] for row in checkpoints] == list(range(1, 12))
    assert len({row["intentSha256"] for row in checkpoints}) == 1
    assert observed["keychain"] == str(root / "home" / signing.LEASE_DIRECTORY / (
        "session-" + value["sessionToken"]) / "keychain" / catalog.DB_NAME)
    baseline = observed["original"]
    preferences = {"baseline": baseline,
        "search": {"default": baseline["default"], "search": [observed["keychain"]]},
        "active": {"default": observed["keychain"], "search": [observed["keychain"]]}}
    revisions = []
    for row, expected in zip(checkpoints, HEALTHY_CHECKPOINTS):
        state = row["state"]
        assert state["preferences"] == preferences[expected[2]] and state["inflight"] is None and not state["conflict"]
        assert (state["searchAttempted"], state["defaultAttempted"], state["cleanupStarted"]) == expected[3:]
        assert bool(state["native"]) is (expected[1] < 40)
        assert state["profile"]["phase"] == ("stage-removed" if expected[1] < 40 else "resolved")
        assert row["stateSha256"] == hashlib.sha256(signing._json(state)).hexdigest()
        revisions.append(state["revision"])
    assert revisions == sorted(set(revisions))
    assert tuple((row["operation"], row["phase"], row["occurrence"], row["commandOrdinal"]) for row in effects) == HEALTHY_EFFECTS
    positions = [row["eventPosition"] for row in checkpoints]
    assert positions == sorted(set(positions))
    for row in effects:
        event = value["events"][row["eventIndex"] - 1]
        assert event["index"] == row["eventIndex"] and event["operation"] == "native-effect/" + row["operation"]
        assert event["phase"] == row["phase"] and event["occurrence"] == row["occurrence"]
        assert event["origin"] == "model" and event["slot"] == "native" and event.get("succeeded") is True
        assert not event["details"] and "error" not in event
    # Actual returned checkpoints bracket their genuine four preference effects.
    for effect, before, after in ((effects[3], checkpoints[1], checkpoints[2]),
                                  (effects[4], checkpoints[3], checkpoints[4]),
                                  (effects[5], checkpoints[6], checkpoints[7]),
                                  (effects[6], checkpoints[7], checkpoints[8])):
        assert before["eventPosition"] < effect["eventIndex"] <= after["eventPosition"]
    for row, (before, after) in zip(effects, (("baseline", "baseline"),) * 3 + (
            ("baseline", "search"), ("search", "active"), ("active", "search"), ("search", "baseline"))):
        assert row["beforePreferences"] == preferences[before] and row["afterPreferences"] == preferences[after]
    for row, name in zip(effects[:3], EXTRACT_NAMES):
        assert row["path"] == "<ROOT>/private/" + name
        assert row["file"]["size"] == len(FICTIONAL_PEM) and row["file"]["sha256"] == hashlib.sha256(FICTIONAL_PEM).hexdigest()
        imported = next(command["inputFile"] for command in commands[8:11] if command["inputPath"] == row["path"])
        assert all(imported[key] == row["file"][key] for key in ("device", "inode", "size", "sha256"))
    publication = [event for event in value["events"] if event["operation"] == "replace"
                   and event["slot"] == catalog.SESSION + "/completed.pending"
                   and event["origin"] == catalog.LOCAL + "_write"]
    assert len(publication) == 1 and publication[0]["index"] > positions[-1]
    assert publication[0].get("succeeded") is True


def _state(observed):
    value = observed["controls"].get("state.json", {}).get("value")
    return value if type(value) is dict and "inflight" in value else None


def _phase(observed):
    state = _state(observed)
    return None if state is None or state["inflight"] is None else state["inflight"]["phase"]


def _native_identities(observed):
    return {Path(name).name: {key: value[key] for key in ("device", "inode")}
            for name, value in observed["native"].items()}


def _profile(observed, name):
    return observed["profile"].get("home/Library/MobileDevice/Provisioning Profiles/" + name)


def _fence_pair(observed, *, final_only=False):
    fences = observed["fences"]
    names = {"command-final.json"} if final_only else set(signing.FENCE_CONTROLS)
    assert set(fences) == names, "wrong original fence namespace"
    final = fences["command-final.json"]
    assert final["facts"]["mode"] == 0o600 and final["metadata"]["uid"] == os.getuid()
    assert final["metadata"]["links"] == (1 if final_only else 2)
    assert final["value"]["role"] == "command-custodian" and final["value"]["sessionToken"] == observed["session"]
    if not final_only:
        assert fences["command-final.pending"] == final, "fence names do not reference one original inode"
    state = _state(observed)
    operation = None if state is None else state["inflight"]
    if operation is not None:
        assert final["value"]["sequence"] == operation["sequence"] and final["value"]["nonce"] == operation["nonce"]
        assert final["value"]["kind"] == operation["kind"]
        if operation["phase"] == "SETTLED":
            assert operation["settlement"]["fence"] == {"identity": {
                key: final["facts"][key] for key in ("device", "inode")}, "sha256": final["facts"]["sha256"]}


def assert_seed_cut(root, name, cut):
    observed = cut["snapshot"]
    state, controls = _state(observed), observed["controls"]
    names = set(controls)
    token = cut["sessionToken"]
    assert observed["session"] == (None if name == "final-absent" else token)
    fixture.ResourceOracle(root).assert_sentinels()
    assert all(item["facts"]["mode"] == 0o600 for item in controls.values())
    native = _native_identities(observed)
    baseline = observed["original"]
    active = {"default": observed["keychain"], "search": [observed["keychain"]]}
    stage, destination = (_profile(observed, value) for value in
                          (".mobile-release-profile-" + token, fixture.UUID + ".mobileprovision"))
    if name in {"empty-session", "empty-native-directory"}:
        assert not names and not native and not observed["ownedRemaining"]
        assert observed["nativeDirectory"] == (name == "empty-native-directory")
        assert observed["preferences"] == baseline
    elif name in {"intent-pending-empty", "intent-pending-partial"}:
        assert names == {"intent.pending"} and not native and observed["nativeDirectory"]
        assert controls["intent.pending"]["facts"]["size"] == cut["physicalWrite"]["bytes"]
    elif name == "intent-committed":
        assert names == {"intent.json"} and not native and controls["intent.json"]["value"]["baseline"] == baseline
    elif name == "initial-state-pending":
        assert names == {"intent.json", "state.pending"} and not native and state is None
        assert cut["physicalWrite"]["properPrefix"] is True
    elif name == "profile-unrecorded-stage":
        assert state["profile"]["phase"] == "stage-intent" and state["profile"]["stageIdentity"] is None
        assert stage is not None and stage["size"] == 0 and destination is None and not native
    elif name == "profile-partial-bytes":
        assert state["profile"]["phase"] == "stage-created" and destination is None
        assert state["profile"]["stageIdentity"] == {key: stage[key] for key in ("device", "inode")}
        assert 0 < stage["size"] < len(fixture.PROFILE) and cut["physicalWrite"]["properPrefix"] is True
    elif name == "profile-complete-link":
        assert state["profile"]["phase"] == "link-intent" and state["profile"]["ownedIdentity"] is None
        assert stage == destination and stage["sha256"] == hashlib.sha256(fixture.PROFILE).hexdigest()
        assert state["profile"]["stageIdentity"] == {key: stage[key] for key in ("device", "inode")}
        for filename in (".mobile-release-profile-" + token, fixture.UUID + ".mobileprovision"):
            assert (root / "home/Library/MobileDevice/Provisioning Profiles" / filename).lstat().st_nlink == 2
    elif name == "native-unrecorded-create":
        assert _phase(observed) == "ARMED" and state["inflight"]["kind"] == "create" and not state["native"]
        assert set(native) == {signing.DB_NAME} and next(iter(observed["native"].values()))["size"] == 0
    elif name == "native-transaction-stage":
        assert _phase(observed) == "ARMED" and state["inflight"]["kind"] == "settings"
        assert set(native) == {signing.DB_NAME, signing.LOCK_NAME, "native-atomic-stage"}
        assert all(native[name] == value for name, value in state["native"].items())
        assert next(value for path, value in observed["native"].items() if path.endswith("/native-atomic-stage"))["size"] == 0
    elif name in {"native-unrecorded-inode", "active-build-result", "active-build-pending"}:
        assert _phase(observed) == "ARMED" and native[signing.DB_NAME] != state["native"][signing.DB_NAME]
        assert native[signing.LOCK_NAME] == state["native"][signing.LOCK_NAME] and len(native) == 2
        if name == "active-build-pending":
            assert cut["context"]["operationPhase"] == "SETTLED" and cut["physicalWrite"]["properPrefix"] is True
            _fence_pair(observed)
    elif name in {"active-before-build", "active-known-pending", "active-build-handed-off", "active-after-build"}:
        assert native == state["native"] and set(native) == {signing.DB_NAME, signing.LOCK_NAME}
        assert observed["preferences"] == state["preferences"] == active and state["cleanupStarted"] is False
        assert _phase(observed) == ("ARMED" if name == "active-build-handed-off" else None)
        if name == "active-known-pending":
            assert cut["physicalWrite"]["properPrefix"] is True
    elif name in {"default-restored", "search-restored"}:
        assert native == state["native"] and state["cleanupStarted"] and _phase(observed) == "ARMED"
        expected = {"default": baseline["default"], "search": active["search"] if name == "default-restored" else baseline["search"]}
        assert observed["preferences"] == expected and state["preferences"] != expected
    else:
        assert not native and not observed["ownedRemaining"] and observed["preferences"] == baseline
        expected_names = {
            "terminal-pending-empty": {"intent.json", "state.json", "completed.pending"},
            "terminal-pending-partial": {"intent.json", "state.json", "completed.pending"},
            "completed": {"intent.json", "state.json", "completed.json"},
            "completed-without-state": {"intent.json", "completed.json"},
            "completed-without-native-directory": {"intent.json", "completed.json"},
            "completed-only": {"completed.json"}, "final-empty": set(), "final-absent": set(),
        }
        assert name in expected_names and names == expected_names[name], "terminal cut authority differs"
        if "completed.json" in controls:
            terminal = controls["completed.json"]["value"]
            assert not terminal["state"]["native"] and terminal["state"]["inflight"] is None
            assert terminal["state"]["profile"]["phase"] == "resolved"
        assert observed["nativeDirectory"] == (name in {"terminal-pending-empty", "terminal-pending-partial", "completed", "completed-without-state"})
    assert bool(fixture.uncertainty(root, observed)) == (name in catalog.UNKNOWN_STATUS), "seed unknown-resource classification drift"


def _assert_settlement_cut(cut, stage):
    observed = cut["snapshot"]
    assert _phase(observed) == ("ARMED" if stage == 1 else None if stage == 6 else "SETTLED")
    if stage <= 2:
        _fence_pair(observed)
    elif stage == 3:
        _fence_pair(observed, final_only=True)
    else:
        assert not observed["fences"]
    if stage in {1, 5}:
        assert cut["physicalWrite"]["properPrefix"] is True


def assert_transition_cut(root, case, cut):
    selector, observed = case.selector, cut["snapshot"]
    assert cut["selector"] == selector.record() and selector.routes(cut["event"]) and cut["edge"] == selector.edge
    selector.check_context(cut["context"])
    fixture.ResourceOracle(root).assert_sentinels()
    identifier = case.identifier
    if identifier.startswith("C/fence/"):
        original = cut["originalCFenceObservation"]
        assert original["originalWorker"] is True and original["operation"] == selector.operation.removeprefix("command-fence/")
        assert original["edge"] == selector.edge.upper() and _phase(observed) == "ARMED"
        if selector.edge == "partial":
            from workflow.local_signing_matrix_contract import validate_original_c_prefix
            validate_original_c_prefix(original)
        if original["operation"] in {"FINAL_LINK", "DIRECTORY_FSYNC"} and not (
                original["operation"] == "FINAL_LINK" and selector.edge == "before"):
            _fence_pair(observed)
        else:
            assert "command-final.json" not in observed["fences"]
        return
    if identifier.startswith(("C/caller/", "R/new/")):
        number = int(identifier.rsplit("/", 1)[1])
        if number <= 2:
            assert _phase(observed) == ("PREPARED" if number == 1 else "ARMED") and not observed["fences"]
            assert cut["context"]["beforeBinding" if number == 1 else "beforeGrant"] is True
        else:
            _assert_settlement_cut(cut, number - (2 if identifier.startswith("R/new/") else 1))
        if identifier.startswith("R/new/"):
            state = _state(observed)
            active = {"default": observed["keychain"], "search": [observed["keychain"]]}
            assert state["cleanupStarted"] is True and state["preferences"] == active
            assert observed["preferences"] == (active if number <= 2 else {
                "default": observed["original"]["default"], "search": active["search"]})
        return
    if identifier.startswith("R/debt/"):
        _assert_settlement_cut(cut, int(identifier.rsplit("/", 1)[1]))
        assert not observed["native"] and observed["preferences"] == observed["original"]
        return
    if identifier.startswith("R/manual/"):
        before = cut["manualBefore"]
        assert before["controls"].get("intent.json") == observed["controls"].get("intent.json"), "manual action changed authority"
        unknown = fixture.uncertainty(root, observed)
        resolved = case.manual == "resolve" and cut["edge"] == "after"
        assert bool(unknown) is not resolved
        if resolved:
            assert not observed["ownedRemaining"] and observed["preferences"] == observed["original"]
        else:
            assert observed["native"] == before["native"] and observed["profile"] == before["profile"]
        return
    number, controls, native = int(identifier.split("/")[1]), observed["controls"], _native_identities(observed)
    if number in {1, 4, 7, 8}:
        assert {1: "intent.pending", 4: "state.pending", 7: "state.pending", 8: "completed.pending"}[number] not in controls
    elif number in {2, 17}:
        assert observed["nativeDirectory"] is False and observed["session"] is not None
    elif number in {3, 20}:
        assert observed["session"] is None and not controls and not native
    elif number == 5:
        assert "state.json" not in controls and cut["physicalWrite"]["properPrefix"] is True
    elif number == 6:
        assert _state(observed)["commandSequence"] == 0 and _phase(observed) is None and not native
    elif number in {9, 10}:
        assert _profile(observed, ".mobile-release-profile-" + cut["sessionToken"]) is None
        assert (_profile(observed, fixture.UUID + ".mobileprovision") is None) == (number == 10)
    elif number in {11, 12}:
        assert observed["preferences"]["default"] == observed["original"]["default"]
        assert observed["preferences"]["search"] == ([observed["keychain"]] if number == 11 else observed["original"]["search"])
        assert observed["preferences"] != _state(observed)["preferences"] and _phase(observed) == "ARMED"
    elif number in {13, 14}:
        assert set(native) == ({signing.LOCK_NAME} if number == 13 else set())
    elif number == 15:
        assert "completed.json" not in controls and cut["physicalWrite"]["properPrefix"] is True
    elif number == 16:
        assert "completed.json" in controls and not native and not observed["ownedRemaining"]
    elif number == 18:
        assert set(controls) == {"completed.json"}
    elif number == 19:
        assert not controls and observed["session"] is not None
    else:
        raise AssertionError("unmapped semantic transition")


def one_journalled_query(root, trace, *, phase):
    model = fixture.PersistentSigningModel(root)
    with trace.installed(), signing.local_signing_lease(home=root / "home") as lease:
        session = lease.session()
        session.bind_runner(model)
        session.open(create=True)
        session.prepare(fixture.PROFILE, fixture.UUID)  # Two genuine unjournalled observations.
        trace.phase = phase
        model.trace = trace
        session.run(["security", "default-keychain", "-d", "user"], kind="observe")
        assert trace.selector is None, "selected command cut was not reached"
        model.trace = None
        session.cleanup_native()
        session.cleanup_profile()
        session.finish()
    fixture.assert_positive_postconditions(root, expected_preferences=model.state["original"])
    return trace.result()


def _new_step(root, name):
    for suffix in (".json", "-cut.json", "-error.json", ".writing", "-cut.writing", "-error.writing"):
        path = root / (name + suffix)
        assert not path.exists() and not path.is_symlink(), "case step output already exists"


def seed(root, name, *, auto_add=False, after_effect=None, context=None, native_prefix=False):
    assert type(native_prefix) is bool
    selector = (catalog.NATIVE_PREFIXES[name] if native_prefix else
                catalog.QUERY_DEBT_SEED if name == "query-settled-partial" else catalog.SEEDS[name])
    if context is not None:
        fixture.check_case_context(root, context)
    _new_step(root, "seed")
    fixture.require_fresh_recovery(root)
    assert not native_prefix or (not auto_add and after_effect is None), "native prefix cannot alter its original model"
    trace = lambda: (NativePrefixTrace(root, "seed", name) if native_prefix else
                     SemanticTrace(root, "seed", selector, after_effect=after_effect))
    task = (lambda: one_journalled_query(root, trace(), phase="command")) if name == "query-settled-partial" else (
        lambda: fixture.original_flow(root, trace(), auto_add=auto_add))
    role = "minimal-query-seed" if name == "query-settled-partial" else "persistent-original"
    original = fixture.run_worker(root, "seed", task, timeout=worker_timeout(role), expect=fixture.CRASH)
    fixture.assert_original_return(original, expected=fixture.CRASH)
    cut = fixture.read_case_json(root, "seed-cut")
    if native_prefix:
        assert cut["physicalWrite"] == native_prefix_proof(root, name, cut)
    elif name == "query-settled-partial":
        _assert_settlement_cut(cut, 1)
        assert not cut["snapshot"]["native"] and cut["context"]["operationKind"] == "observe"
    else:
        assert_seed_cut(root, name, cut)
    if context is not None:
        fixture.check_case_context(root, context)
    return cut, original


def recovery_step(root, name, *, token, manual, expected, context, expected_preferences=None, final=False):
    fixture.check_case_context(root, context)
    _new_step(root, name)
    def task():
        return fixture.recovery_flow(root, fixture.Trace(root, name), original_token=token, manual=manual,
                                     expected_status=expected, expected_preferences=expected_preferences)
    original = fixture.run_worker(root, name, task, timeout=recovery_timeout(manual))
    fixture.assert_original_return(original)
    value = fixture.read_case_json(root, name)
    assert value["sessionToken"] == token and value["expectedStatus"] == expected
    assert (value["refused"] is not None) == (expected == catalog.REFUSED)
    assert value["idleAndRenewedAdmission"] is (expected != catalog.REFUSED)
    if expected != catalog.REFUSED:
        assert value["result"]["status"] == expected and value["result"]["session"] == token
    fixture.check_case_context(root, context)
    if final:
        assert expected != catalog.REFUSED
        identity = fixture._directory_identity(root)
        assert fixture._CASE_CUSTODY.get(str(root)) == identity == context[0]
        if str(root) in fixture._CASE_RECOVERY_DEBT:
            assert fixture._CASE_RECOVERY_DEBT[str(root)] == identity
            del fixture._CASE_RECOVERY_DEBT[str(root)]
    return {"name": name, "manual": manual, "expected": expected, "original": original, "observation": value}


def _persist_step(parent, identifier, name, value):
    # Preserve each negative BEFORE any successor; exclusive fixed name per ID.
    path = parent / ("semantic-" + digest(identifier) + "-" + name + ".json")
    assert not path.exists() and not path.is_symlink() and not path.with_suffix(".writing").exists()
    fixture.write_json(path, value)
    return path.name


def finish_semantic_case(parent, root, identifier, evidence, context):
    """Retain canonical observations before alias predicates or any removal."""
    from workflow.local_signing_regression_fixture import semantic_contributions

    fixture.check_case_context(root, context)
    evidence_name = _persist_step(parent, identifier, "complete", evidence)
    contributions = semantic_contributions(parent, identifier, evidence)
    if contributions:
        _persist_step(parent, identifier, "regression", {
            "schema": "mrk-signing-semantic-contribution-v1", "semantic": identifier,
            "contributions": list(contributions), "evidenceSha256": digest(evidence),
        })
    fixture.check_case_context(root, context)
    fixture.remove_case(root)
    assert not root.exists() and str(root) not in fixture._CASE_CUSTODY and str(root) not in fixture._CASE_RECOVERY_DEBT
    fixture.check_phase_context(context)
    return {"caseId": identifier, "status": "semantic-subset-case", "evidence": evidence_name,
            "caseRemoved": True, "originalWorkersSettled": True, "regressionContributions": list(contributions)}


def run_case(parent, identifier):
    """One source-defined case; inactive until the reviewed router calls it."""
    case = catalog.case(identifier)
    assert (catalog.DB_NAME, catalog.LOCK_NAME) == (signing.DB_NAME, signing.LOCK_NAME)
    if case.kind == "focused":
        from workflow.local_signing_semantic_focused import run_case as focused_case
        return focused_case(parent, identifier)
    root = parent / "case"
    root.mkdir(mode=0o700)  # Never overwrite a retained failed/UNKNOWN case.
    fixture.initialize(root)
    context = fixture.pin_case_context(root)
    evidence = {"schema": "mrk-signing-semantic-case-v1", "case": case.record(), "steps": [], "negativeEvidence": []}
    if case.kind == "healthy":
        _new_step(root, "healthy")
        original = fixture.run_worker(root, "healthy", lambda: fixture.original_flow(root, HealthyTrace(root, "healthy")),
                                      timeout=worker_timeout("persistent-original"))
        fixture.assert_original_return(original)
        value = fixture.read_case_json(root, "healthy")
        assert_healthy_observation(root, value)
        assert not fixture._CASE_RECOVERY_DEBT.get(str(root))
        evidence["steps"].append({"name": "healthy", "original": original, "observation": value})
    else:
        if case.kind == "command":
            fixture.require_fresh_recovery(root)
            _new_step(root, "seed")
            original = fixture.run_worker(root, "seed", lambda: one_journalled_query(root,
                SemanticTrace(root, "seed", case.selector, expected_sequence=1), phase=case.selector.phase),
                timeout=worker_timeout("minimal-query-seed"), expect=fixture.CRASH)
            fixture.assert_original_return(original, expected=fixture.CRASH)
            cut = fixture.read_case_json(root, "seed-cut")
            assert_transition_cut(root, case, cut)
        else:
            cut, original = seed(root, case.seed, context=context, native_prefix=case.kind == "native-prefix")
        token = cut["sessionToken"]
        evidence["steps"].append({"name": "seed", "original": original, "observation": cut})
        if case.kind == "recovery":
            fixture.check_case_context(root, context)
            fixture.require_fresh_recovery(root)
            _new_step(root, "recovery")
            sequence = None
            if identifier.startswith(("R/debt/", "R/new/")):
                sequence = _state(cut["snapshot"])["commandSequence"] + (1 if identifier.startswith("R/new/") else 0)
            original = fixture.run_worker(root, "recovery", lambda: fixture.recovery_flow(root,
                SemanticTrace(root, "recovery", case.selector, expected_sequence=sequence),
                original_token=token, manual=case.manual), timeout=recovery_timeout(case.manual), expect=fixture.CRASH)
            fixture.assert_original_return(original, expected=fixture.CRASH)
            selected = fixture.read_case_json(root, "recovery-cut")
            assert_transition_cut(root, case, selected)
            evidence["steps"].append({"name": "recovery-cut", "original": original, "observation": selected})
        # Only literal successors: an unexpected refusal fails, never invokes
        # adaptive automatic->observe->resolve work or a duplicate absent run.
        mode = case.manual if case.kind == "seed" else "none"
        main = recovery_step(root, "semantic-main", token=token, manual=mode, expected=case.expected,
                             context=context, final=case.resolution is None)
        if identifier == "R/13":
            assert any(event["operation"] == "unlink" and event["slot"].endswith("/keychain/" + signing.LOCK_NAME)
                       and event["origin"] == "mobile_release.local_signing:cleanup_native" and event.get("succeeded") is True
                       for event in main["observation"]["events"]), "real leftover-lock cleanup caller was not exercised"
        evidence["steps"].append(main)
        if case.resolution is not None:
            evidence["negativeEvidence"].append(_persist_step(parent, identifier, "negative", main))
            resolved = recovery_step(root, "semantic-resolution", token=token, manual="resolve", expected=case.resolution,
                                     context=context, final=True)
            evidence["steps"].append(resolved)
    return finish_semantic_case(parent, root, identifier, evidence, context)
