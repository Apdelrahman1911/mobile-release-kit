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
from pathlib import Path

from mobile_release import local_signing as signing
from workflow import local_signing_persistent_fixture as fixture
from workflow import local_signing_semantic_catalog as catalog
from workflow.local_signing_matrix_contract import digest
from workflow.local_signing_workload import recovery_timeout, worker_timeout


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
        frame, session, writing, callers = sys._getframe(1), None, None, []
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
            from mobile_release._command_process import OriginalCommandReservation
            reservation = binding._arming_reservation
            assert type(reservation) is OriginalCommandReservation
            binding.validate_reservation(reservation)  # Actual original engine checks; does not issue a permit.
            engine = reservation._engine
            assert engine is session._command_scope.outcome._engine and engine.prepared_reservation()
            assert not engine.create_route.attempted and not engine.run_route.attempted
            assert "_arm_original_command" in callers, "arming callback is not active"
            result.update(beforeGrant=True, originalArmingCallback=True,
                          originalReservationBound=True, createAttempted=False, runAttempted=False)
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
        assert not (self.root / (self.name + "-cut.json")).exists(), "selected cut output already exists"
        fixture.write_json(self.root / (self.name + "-cut.json"), record)
        os._exit(fixture.CRASH)  # Original O really exits; this does not kill/settle C.

    def result(self):
        assert self.selector is None, {"selectedSemanticCutNotReached": self.selector.record()}
        return super().result()


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


def seed(root, name, *, auto_add=False, after_effect=None, context=None):
    selector = catalog.QUERY_DEBT_SEED if name == "query-settled-partial" else catalog.SEEDS[name]
    if context is not None:
        fixture.check_case_context(root, context)
    _new_step(root, "seed")
    fixture.require_fresh_recovery(root)
    trace = lambda: SemanticTrace(root, "seed", selector, after_effect=after_effect)
    task = (lambda: one_journalled_query(root, trace(), phase="command")) if name == "query-settled-partial" else (
        lambda: fixture.original_flow(root, trace(), auto_add=auto_add))
    role = "minimal-query-seed" if name == "query-settled-partial" else "persistent-original"
    original = fixture.run_worker(root, "seed", task, timeout=worker_timeout(role), expect=fixture.CRASH)
    fixture.assert_original_return(original, expected=fixture.CRASH)
    cut = fixture.read_case_json(root, "seed-cut")
    if name == "query-settled-partial":
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
        original = fixture.run_worker(root, "healthy", lambda: fixture.original_flow(root, SemanticTrace(root, "healthy")),
                                      timeout=worker_timeout("persistent-original"))
        fixture.assert_original_return(original)
        value = fixture.read_case_json(root, "healthy")
        assert len(value["snapshot"]["nativeCalls"]) == 50 and not value["snapshot"]["session"]
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
            cut, original = seed(root, case.seed, context=context)
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
    fixture.check_case_context(root, context)
    evidence_name = _persist_step(parent, identifier, "complete", evidence)
    fixture.remove_case(root)
    assert not root.exists() and str(root) not in fixture._CASE_CUSTODY and str(root) not in fixture._CASE_RECOVERY_DEBT
    # Evidence/removal can consume the remaining original budget. Their safe
    # completion is not permission to publish an expired success case ID.
    fixture.check_phase_context(context)
    return {"caseId": identifier, "status": "semantic-subset-case", "evidence": evidence_name,
            "caseRemoved": True, "originalWorkersSettled": True}
