"""Three genuine account-command lifetimes, not replacement owner receipts."""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from unittest.mock import patch

from mobile_release import _command_process as command, local_signing as signing, owned_process
from unit.local_signing_persistent import PersistentSigningModel, PROFILE, UUID, ResourceOracle, initialize
from workflow import command_bootstrap_fixture as bootstrap
from workflow import command_fence_failure_fixture as fence
from workflow import local_signing_case_owner as case_owner  # Preload original case owner.
from workflow import local_signing_persistent_fixture as persistent


_RETAINED = []
NO_TARGET = "import pathlib,sys;pathlib.Path(sys.argv[1]).write_bytes(b'unexpected no-target execution')"


def copied(value):
    return json.loads(json.dumps(value))


def prepare(root, lease):
    model = PersistentSigningModel(root)
    session = lease.session()
    session.open(create=True)
    session.bind_runner(model)
    session.prepare(PROFILE, UUID)
    assert len(model.state["calls"]) == 2
    return model, session


def prepared_callback(root, session, case, captured, *, interruption=None, reciprocal=False):
    def started(group):
        assert not captured and case.engine is not None
        engine = case.engine
        assert engine.scope is session._command_scope and engine.binding is session._command_binding
        assert engine.phase == "PREPARED" and engine.prepared["group"] == group
        state = json.loads(signing._control(session.fd, "state.json", cancellation=session.cancellation))
        assert state == session.state and state["inflight"]["phase"] == "PREPARED"
        assert not engine.create_route.attempted and not engine.run_route.attempted
        assert fence.fences(session.fd) == dict.fromkeys(fence.NAMES)
        if reciprocal:
            # Same original O open description, not a separately acquired lease.
            fcntl.flock(session.lease.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        captured.update(state=state, binding=session._fence_binding(state["inflight"]),
                        owner=os.getpid(), custodian=engine.child.pid, group=group,
                        reciprocal=reciprocal)
        if interruption is not None:
            raise interruption
    return started


def no_target_runner(root, started):
    def runner(argv, **kwargs):
        assert argv == ["prepared-no-target"] and kwargs.get("on_start") is None
        options = dict(kwargs, on_start=started)
        return owned_process.run_owned(
            [sys.executable, "-I", "-S", "-B", "-c", NO_TARGET, str(root / "unexpected-target")], **options)
    return runner


def account_maps(rows, pids, binding, *, worker):
    expected = [binding["leaseIdentity"]["device"], binding["leaseIdentity"]["inode"], binding["uid"]]
    for role in (("C", "A", "W") if worker else ("C", "A")):
        mapping, fixed = rows[role]["account_map"], rows[role]["fixed_map"]
        assert fixed["original"] and mapping["nonce"]
        types = [stat.S_IFCHR] * 3 + [stat.S_IFIFO] * 2 + [
            stat.S_IFCHR if role == "W" else stat.S_IFDIR] + [stat.S_IFIFO] * 2
        assert fixed["types"] == types
        if role == "W":
            assert not mapping["bound"] and mapping["kind"] == "null"
        else:
            assert mapping["bound"] and mapping["kind"] == "account_hold" and mapping["identity"] == expected
    assert rows["A"]["boot"]["parent"] == pids["C"]
    if worker:
        assert rows["W"]["boot"]["parent"] == pids["A"]


def producer(rows, pids, *, worker):
    original = rows["C"]
    wait, io = original["fence_owner_wait"], original["fence_owner_io"]
    assert wait["exact"] and wait["child"] == pids["A"] and wait["kind"] == "exit"
    assert wait["code"] in (command.HELPER_OK, command.HELPER_FAILED)
    assert all(io[key] for key in ("joined", "eof", "closed")) and not io["unknown"]
    seal, grants, absent = original["fence_producer"], original["fence_grants"], original["group_absent"]
    assert all(seal[key] for key in ("exact", "nonce", "eof", "absent", "retired"))
    assert grants["create"] is worker and grants["run"] is worker
    assert grants["create_retired"] and grants["run_retired"] and grants["hold"] == "OPEN"
    assert absent["group"] == pids["A"] and absent["wait_owned"]
    assert not absent["retired"] and not absent["numeric_retired"]
    assert rows["A"]["owner_finish"]["code"] == wait["code"]
    result = rows["A"]["worker_result"]
    assert result["moved"] and result["result"] and result["armed"] is worker
    if worker:
        awaited, io = rows["A"]["owner_wait"], rows["A"]["owner_io"]
        assert awaited["exact"] and awaited["child"] == pids["W"]
        assert awaited["kind"] == "exit" and awaited["code"] == 0
        assert all(io[key] for key in ("joined", "eof", "closed")) and not io["unknown"]


def no_worker_result(case, session, captured, error, interruption, *, failed):
    assert error is interruption and captured
    pids = case.bind_no_worker_observations()
    outcome, engine, rows = case.outcome, case.outcome._engine, case.rows
    assert outcome.matches(session._command_scope, session._command_binding)
    assert captured["custodian"] == pids["C"] and rows["C"]["boot"]["parent"] == captured["owner"]
    assert engine.wait is engine.child.receipt and engine.wait.status_kind == "exit"
    assert engine.ctx.primary is interruption and engine.local_cleanup_complete and not engine.ctx.cleanup_unknown
    assert all(task.joined for task in engine.ctx.tasks)
    assert engine.wire.eof and engine.wire.reader.state == engine.wire.writer.state == "CLOSED"
    assert all(engine.output_eof) and all(reader.state == "CLOSED" for reader in engine.readers)
    assert not outcome.create_w.attempted and not outcome.run_tool.attempted
    assert outcome.create_w.retired and outcome.run_tool.retired and outcome.returncode is None
    assert not session.journal_failed
    account_maps(rows, pids, captured["binding"], worker=False)
    producer(rows, pids, worker=False)
    if failed:
        assert engine.wait.status_code == 73 and engine.terminal is None
        assert outcome.original_finality is None and outcome.no_target is None and outcome.result_integrity == "incomplete"
        assert session.unresolved and session.cancellation.lifetime_ledger.fatal and not session._command_finished
        assert session.state == captured["state"] and session.state["inflight"]["phase"] == "PREPARED"
        prefix = rows["C"]["prepared_prefix"]
        assert prefix["input_eof"] and prefix["parent_alive"] and not prefix["acknowledged"]
        assert prefix["pending"] == "OPEN" and prefix["sync"] == 0 and 0 < prefix["written"] < prefix["total"]
    else:
        assert engine.wait.status_code in (command.HELPER_OK, command.HELPER_FAILED)
        assert outcome.original_finality is not None and outcome.result_integrity == "complete"
        assert outcome.no_target is not None and outcome.no_target.kind == "NO_W_CREATION"
        assert engine.terminal["no_target"] == "NO_W_CREATION" and engine.terminal["wait"] is None
        assert engine.terminal["producer"] and engine.terminal["fence"] and not any(engine.outputs)
        assert not session.unresolved and not session.cancellation.lifetime_ledger.fatal
        assert session._command_finished and session.state["inflight"] is None
        assert rows["C"]["fence_terminal"]["hold"] == "CLOSED"
        case.release_no_worker()
    return {"schema": 1, "captured": captured, "pids": pids, "rows": rows,
            "failedOriginal": failed, "cExit": engine.wait.status_code,
            "resultIntegrity": outcome.result_integrity, "noTarget": None if outcome.no_target is None else outcome.no_target.kind}


@contextmanager
def original_pair_observer(session, observed):
    read_pair, retire = signing.SigningSession._read_fence_pair, signing.SigningSession._retire_fence

    def reading(actual, operation):
        result = read_pair(actual, operation)
        assert actual is session and not observed and actual._recovery_attempt is None
        state = json.loads(signing._control(actual.fd, "state.json", cancellation=actual.cancellation))
        pair = fence.fences(actual.fd)
        assert state["inflight"] == operation and operation["phase"] == "PREPARED"
        assert pair[fence.NAMES[0]] == pair[fence.NAMES[1]] and pair[fence.NAMES[0]] is not None
        expected = signing._fence_json({**actual._fence_binding(operation), "outcome": "never-dispatched"})
        assert bytes.fromhex(pair[fence.NAMES[0]]["hex"]) == expected and pair[fence.NAMES[0]]["state"][3] == 2
        observed.update(prepared=state, pair=pair, settlement=copied(result))
        return result

    def retiring(actual, operation):
        assert actual is session and observed and "settled" not in observed
        state = json.loads(signing._control(actual.fd, "state.json", cancellation=actual.cancellation))
        assert state["inflight"] == operation and operation["phase"] == "SETTLED"
        assert fence.fences(actual.fd) == observed["pair"]
        result = retire(actual, operation)
        assert fence.fences(actual.fd) == dict.fromkeys(fence.NAMES)
        observed["settled"] = state
        return result

    with patch.object(signing.SigningSession, "_read_fence_pair", new=reading), \
            patch.object(signing.SigningSession, "_retire_fence", new=retiring):
        yield


def positive_worker(root):
    captured, observed, interruption = {}, {}, KeyboardInterrupt("fixed original no-W callback")
    with signing.local_signing_lease(home=root / "home") as lease:
        model, session = prepare(root, lease)
        case = bootstrap.CommandCase(command, root / "command-observation", "prepared-no-target-off")
        started = prepared_callback(root, session, case, captured, interruption=interruption)
        session.bind_runner(no_target_runner(root, started))
        error = None
        with case, original_pair_observer(session, observed):
            try:
                session.run(["prepared-no-target"], kind="observe")
            except BaseException as caught:
                error = caught
        result = no_worker_result(case, session, captured, error, interruption, failed=False)
        assert observed["prepared"] == captured["state"]
        assert observed["settled"]["inflight"]["settlement"] == observed["settlement"]
        assert not (root / "unexpected-target").exists() and len(model.state["calls"]) == 2
        # The same original lease issues six genuine observation commands and
        # performs real minimal-session profile/control/native-dir teardown.
        session.bind_runner(model)
        assert session.finish() is False and session.closed and session._disposal_complete
        assert len(model.state["calls"]) == 8 and not lease._normal_execution_revoked
        lease.assert_owner()
    persistent.assert_positive_postconditions(root, expected_preferences=model.state["original"])
    result["originalSettlement"] = observed
    result["sameLeaseDisposed"] = True
    return result


def positive_result_worker(root):
    """No generic output acquisition after a failed original no-W lifetime."""
    code, sink = persistent.WORKER_ERROR, None
    try:
        sink = fence.ResultSink(root / "seed.json")
        sink.publish(positive_worker(root))
        code = 0
    except BaseException as error:
        fence.failure_report(sink, error)
    finally:
        os._exit(code)


def prefix_worker(root):
    code, sink, case = persistent.WORKER_ERROR, None, None
    try:
        sink = fence.ResultSink(root / "original-prepared.json")
        context = signing.local_signing_lease(home=root / "home")
        _RETAINED.append(context)
        lease = context.__enter__()
        model, session = prepare(root, lease)
        captured, interruption = {}, KeyboardInterrupt("fixed original no-W callback")
        case = bootstrap.CommandCase(command, root / "command-observation", "prepared-prefix-input-loss")
        session.bind_runner(no_target_runner(root, prepared_callback(
            root, session, case, captured, interruption=interruption)))
        error = None
        with case, patch.object(signing.SigningSession, "_fence_observation_policy",
                                new=lambda actual: command.FenceObservationPolicy.TRACE_V1):
            try:
                session.run(["prepared-no-target"], kind="observe")
            except BaseException as caught:
                error = caught
        result = no_worker_result(case, session, captured, error, interruption, failed=True)
        result["originalModelCalls"] = copied(model.state["calls"])
        sink.publish(result)
        code = persistent.CRASH
    except BaseException as error:
        fence.failure_report(sink, error, case=case)
    finally:
        os._exit(code)


def prefix_after_original(root, original):
    observed = persistent.snapshot(root)
    captured, rows = original["captured"], original["rows"]
    assert observed["controls"]["state.json"]["value"] == captured["state"]
    assert observed["nativeCalls"] == original["originalModelCalls"] and len(observed["nativeCalls"]) == 2
    assert not (root / "unexpected-target").exists() and not observed["native"] and not observed["ownedRemaining"]
    session = root / "home" / signing.LEASE_DIRECTORY / ("session-" + captured["binding"]["sessionToken"])
    directory = os.open(session, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        pair = fence.fences(directory)
    finally:
        closing, directory = directory, None
        os.close(closing)
    item, prefix = pair[fence.NAMES[0]], rows["C"]["prepared_prefix"]
    assert pair[fence.NAMES[1]] is None and item is not None and item["state"][3] == 1
    expected = signing._fence_json({**captured["binding"], "outcome": "never-dispatched"})
    content, state = bytes.fromhex(item["hex"]), item["state"]
    assert len(expected) == prefix["total"] and content == expected[:prefix["written"]]
    assert 0 < len(content) < len(expected)
    assert rows["C"]["prefix_identity"]["value"] == [state[0], state[1], state[4], state[5], state[2], state[3]]
    assert rows["C"]["prefix_digest"]["value"] == hashlib.sha256(content).hexdigest()
    ResourceOracle(root).assert_sentinels()
    return item


class PrefixRecoveryTrace(persistent.Trace):
    def __init__(self, *args, expected, **kwargs):
        super().__init__(*args, **kwargs)
        self.expected, self.disposal = expected, []

    @contextmanager
    def installed(self):
        original = signing.SigningSession._dispose_prepared_prefix

        def dispose(session, operation):
            assert not self.disposal and type(session._recovery_attempt) is signing._RecoveryAttempt
            assert session._recovery_attempt.pid == os.getpid() and operation["phase"] == "PREPARED"
            before = fence.fences(session.fd)
            assert before == {fence.NAMES[0]: self.expected, fence.NAMES[1]: None}
            result = original(session, operation)  # Genuine double-read/name checks and unlink/fsync.
            after = fence.fences(session.fd)
            assert after == dict.fromkeys(fence.NAMES)
            self.disposal.append({"before": before, "after": after, "returned_none": result is None})
            return result

        with patch.object(signing.SigningSession, "_dispose_prepared_prefix", new=dispose):
            yield

    def result(self):
        result = super().result()
        result["prefixDisposal"] = self.disposal
        return result


def fresh_recovery(root, trace_factory):
    original = persistent.run_worker

    def guarded_worker(actual_root, name, task, **kwargs):
        assert actual_root == root and name == "final-automatic"
        return original(actual_root, name, lambda: fence.result_worker(actual_root, name, task), **kwargs)

    with patch.object(persistent, "run_worker", new=guarded_worker):
        result = persistent.recover_final(root, trace_factory=trace_factory)
    assert result == {"automatic": "recovered", "manual": None}
    fresh = fence.read_report(root, "final-automatic.json")
    assert fresh["refused"] is None and str(root) not in persistent._CASE_RECOVERY_DEBT
    return fresh


class HoldTrace(persistent.Trace):
    def __init__(self, root, case, session, captured, sink):
        super().__init__(root, "original-hold")
        self.case, self.session, self.captured, self.sink = case, session, captured, sink
        self.phase = "fence"

    def _observe_fence(self, observation):
        super()._observe_fence(observation)
        if observation.operation is not command.FenceOperation.PENDING_WRITE or observation.edge is not command.FenceEdge.PARTIAL:
            return
        case, engine = self.case, self.case.engine
        assert engine.scope is self.session._command_scope and engine.binding is self.session._command_binding
        assert engine.child.wait_state == "OWNED" and engine.child.receipt is None
        assert engine.ctx.primary is None and not engine.ctx.cleanup_unknown
        assert engine.create_route.attempted and engine.run_route.attempted and engine.sealed
        case._snapshot()  # Preowned original readers, before deliberately ending O.
        assert not case.errors and all(slot["state"] == "CLOSED" for slot in case.slots)
        rows = {role: bootstrap.parse_trace(case.snapshots[role]) for role in bootstrap.ROLES}
        pids = {"C": engine.child.pid, "A": rows["C"]["child_published"]["child"],
                "W": rows["A"]["child_published"]["child"]}
        digest = hashlib.sha256(case.recipe.encode()).hexdigest()
        for role, records in rows.items():
            assert records and all(row["r"] == role and row["p"] == pids[role]
                                   and row["n"] == engine.nonce.hex() for row in records.values())
            assert records["boot"]["run"] == engine.ctx.run and records["boot"]["hard"] == engine.ctx.hard
        assert rows["C"]["recipe"]["digest"] == rows["A"]["recipe"]["digest"] == digest
        assert rows["C"]["recipe"]["child_role"] == "A" and rows["A"]["recipe"]["child_role"] == "W"
        assert rows["C"]["creator_joined"]["joined"] and rows["A"]["creator_joined"]["joined"]
        assert all(task.joined and task.spec.argv[5] == case.recipe for task in engine.ctx.tasks)
        assert self.captured["reciprocal"] and self.captured["custodian"] == pids["C"]
        assert rows["C"]["boot"]["parent"] == self.captured["owner"] == os.getpid()
        account_maps(rows, pids, self.captured["binding"], worker=True)
        producer(rows, pids, worker=True)
        initial = rows["C"]["hold_initial"]
        assert initial["blocked"] and initial["shared"] and initial["parent_alive"]
        assert initial["hold"] == initial["contender"] == "OPEN"
        state = json.loads(signing._control(self.session.fd, "state.json", cancellation=self.session.cancellation))
        assert state["inflight"]["phase"] == "ARMED" and state["inflight"]["nonce"] == observation.nonce.hex()
        self.sink.publish({"schema": 1, "captured": self.captured, "pids": pids, "rows": rows,
                           "state": state, "observation": dict(self._fence_evidence),
                           "traceIdentities": case.settings[3], "modelCalls": copied(persistent.snapshot(self.root)["nativeCalls"])})
        os._exit(persistent.CRASH)  # Actual O dies without the outstanding PARTIAL ACK.


def hold_worker(root):
    code, sink, case = persistent.WORKER_ERROR, None, None
    try:
        sink = fence.ResultSink(root / "original-hold.json")
        context = signing.local_signing_lease(home=root / "home")
        _RETAINED.append(context)
        lease = context.__enter__()
        model, session = prepare(root, lease)
        captured = {}
        case = bootstrap.CommandCase(command, root / "command-observation", bootstrap.HOLD_MODE)
        trace = HoldTrace(root, case, session, captured, sink)
        started = prepared_callback(root, session, case, captured, reciprocal=True)

        def runner(argv, **kwargs):
            assert kwargs.get("on_start") is None
            return model(argv, **dict(kwargs, on_start=started))

        session.bind_runner(runner)
        with case, patch.object(signing.SigningSession, "_fence_observation_policy",
                                new=lambda actual: trace._observe_fence_policy(actual)), \
                patch.object(command, "_fence_trace_checkpoint", new=trace._observe_fence):
            session.run(["security", "default-keychain", "-d", "user"], kind="observe")
        raise AssertionError("original O did not reach selected hold/loss checkpoint")
    except BaseException as error:
        fence.failure_report(sink, error, case=case)
    finally:
        os._exit(code)


def read_late_hold(root, original):
    directory = os.open(root / "command-observation", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        item = fence.read_named(directory, "C.trace", limit=bootstrap.MAX_TRACE_BYTES)
    finally:
        closing, directory = directory, None
        os.close(closing)
    assert item is not None and item["state"][3] == 1
    assert [item["state"][0], item["state"][1], item["state"][4]] == original["traceIdentities"][0]
    rows = bootstrap.parse_trace(bytes.fromhex(item["hex"]))
    assert all(row["r"] == "C" and row["p"] == original["pids"]["C"]
               and row["n"] == original["observation"]["nonce"] for row in rows.values())
    assert all(rows[name] == value for name, value in original["rows"]["C"].items())
    after, closed = rows["hold_after_parent_loss"], rows["hold_contender_closed"]
    assert after["blocked"] and after["parent_lost"] and after["producer"] and not after["acknowledged"]
    assert after["hold"] == closed["hold"] == "OPEN" and closed["state"] == "CLOSED"
    # Not a C wait or complete target-FD census. Fresh actual exclusion and the
    # pair's subsequent real publication establish the allowed continuation.
    return rows


def run_case(root, selected):
    root = Path(root)
    assert selected in {"prepared-positive", "prepared-prefix", "hold-parent-loss"}
    initialize(root)
    if selected == "prepared-positive":
        waited = persistent.run_worker(root, "seed", lambda: positive_result_worker(root))
        result = fence.read_report(root, "seed.json")
        assert result["captured"]["owner"] == waited["pid"] and result["sameLeaseDisposed"]
        return {"selected": selected, "originalWait": waited, "original": result}
    persistent.require_fresh_recovery(root)
    task = prefix_worker if selected == "prepared-prefix" else hold_worker
    waited = persistent.run_worker(root, "seed", lambda: task(root), expect=persistent.CRASH)
    original = fence.read_report(root, "original-prepared.json" if selected == "prepared-prefix" else "original-hold.json")
    assert original["captured"]["owner"] == waited["pid"]
    if selected == "prepared-prefix":
        pending = prefix_after_original(root, original)
        fresh = fresh_recovery(root, lambda *args, **kwargs: PrefixRecoveryTrace(*args, expected=pending, **kwargs))
        assert len(fresh["prefixDisposal"]) == 1 and fresh["prefixDisposal"][0]["returned_none"]
    else:
        assert len(original["modelCalls"]) == 3 and original["observation"]["originalReadClosed"]
        fresh = fresh_recovery(root, fence.RecoveryTrace)
        assert len(fresh["retirement"]) == 1 and fresh["retirement"][0]["returned_none"]
        assert fresh["before"]["controls"]["state.json"]["value"] == original["state"]
        original["lateCustodianRows"] = read_late_hold(root, original)
    assert fresh["result"] == {"status": "recovered", "session": original["captured"]["binding"]["sessionToken"]}
    return {"selected": selected, "originalWait": waited, "original": original, "fresh": fresh}
