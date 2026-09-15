"""Finite original-C failures; fresh recovery never repairs the original O.

Native entry is only through literal disposable singleton captures. Real C/A/W,
the model target and original case owner supply custody, never these records.
"""
from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path
import stat
from unittest.mock import patch

from mobile_release import _command_process as command, local_signing as signing
from mobile_release.errors import CredentialError
from unit.local_signing_persistent import PersistentSigningModel, PROFILE, UUID, ResourceOracle, initialize
from workflow import command_bootstrap_fixture as bootstrap
from workflow import local_signing_case_owner as case_owner  # Preload before original workers.
from workflow import local_signing_persistent_fixture as persistent

CASES = bootstrap.FENCE_CASES
NAMES = ("command-final.pending", "command-final.json")
FOREIGN = b"fixture-owned foreign pending name; not a command fence\n"
MAX_REPORT = 65536
_RETAINED_ORIGINALS = []
# These C deaths do NOT execute. Only successful read-only namespace checks
# and diagnostic progression separate them from the actual representatives.
EQUIVALENT_C_EDGES = {
    ("PENDING_WRITE", "BEFORE"): ("PENDING_CREATE", "AFTER"),
    ("DATA_FSYNC", "BEFORE"): ("PENDING_WRITE", "AFTER"),
    ("PENDING_CLOSE", "BEFORE"): ("DATA_FSYNC", "AFTER"),
    ("FINAL_LINK", "BEFORE"): ("PENDING_CLOSE", "AFTER"),
    ("DIRECTORY_FSYNC", "BEFORE"): ("FINAL_LINK", "AFTER"),
}


def file_state(value):
    return [value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def read_named(directory, name, *, limit=signing.FENCE_LIMIT):
    """Bounded original-dir read; retire the actual fd before its one close."""
    try:
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None
    assert (stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o600
            and before.st_uid == os.getuid() and before.st_nlink in (1, 2)
            and 0 <= before.st_size <= limit)
    descriptor, primary, close_error, data = None, None, None, bytearray()
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=directory)
        assert file_state(os.fstat(descriptor)) == file_state(before)
        while len(data) <= before.st_size:
            chunk = os.read(descriptor, before.st_size + 1 - len(data))
            if not chunk:
                break
            data.extend(chunk)
        assert len(data) == before.st_size
        assert file_state(os.fstat(descriptor)) == file_state(before)
        assert file_state(os.stat(name, dir_fd=directory, follow_symlinks=False)) == file_state(before)
    except BaseException as error:
        primary = error
    finally:
        closing, descriptor = descriptor, None
        if closing is not None:
            try:
                os.close(closing)
            except BaseException as error:
                close_error = error
    if primary is not None and close_error is not None:
        raise BaseExceptionGroup("original fence observation and close failed", [primary, close_error])
    if primary is not None:
        raise primary
    if close_error is not None:
        raise close_error
    return {"state": file_state(before), "hex": bytes(data).hex()}


def fences(directory):
    return {name: read_named(directory, name) for name in NAMES}


class ResultSink:
    """One original O output descriptor, acquired before possible UNKNOWN."""
    def __init__(self, path):
        self.fd, self.state = None, "OPENING"
        _RETAINED_ORIGINALS.append(self)
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        self.state = "OPEN"
        details = os.fstat(self.fd)
        assert stat.S_ISREG(details.st_mode) and stat.S_IMODE(details.st_mode) == 0o600 and details.st_nlink == 1
        self.identity = details.st_dev, details.st_ino, details.st_uid

    def publish(self, value):
        assert self.state == "OPEN"
        self.state = "PUBLISHING"  # An interrupted/partial attempt is never retried.
        data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
        assert 0 < len(data) <= MAX_REPORT
        details = os.fstat(self.fd)
        assert (details.st_dev, details.st_ino, details.st_uid) == self.identity
        assert os.write(self.fd, data) == len(data)  # No retry on partial/failed publication.
        descriptor, self.fd, self.state = self.fd, None, "UNKNOWN"
        os.close(descriptor)
        self.state = "CLOSED"


def failure_report(sink, error, *, case=None):
    """Bounded failure location, never a new output owner or a success receipt."""
    try:
        frames, trace = [], BaseException.__dict__["__traceback__"].__get__(error, BaseException)
        while trace is not None and len(frames) < 12:
            frames.append([Path(trace.tb_frame.f_code.co_filename).name, trace.tb_lineno])
            trace = trace.tb_next
        failure = {"category": type(error).__name__, "frames": frames}
        if sink is not None and sink.state == "OPEN":
            report = {"schema": 1, "failure": failure}
            if case is not None and case.closed:
                report["captured"] = {role: data.hex() for role, data in case.snapshots.items()
                                      if type(data) is bytes and len(data) <= bootstrap.MAX_TRACE_BYTES}
            sink.publish(report)
        marker = b"\nMRK_C_FENCE_FIXTURE_FAILURE=" + json.dumps(failure, separators=(",", ":")).encode("ascii") + b"\n"
        if len(marker) <= 2048:
            os.write(2, marker)  # Existing original captured stderr; no reopen/retry.
    except BaseException:
        pass  # The original error exit remains WORKER_ERROR.


class FenceTrace(persistent.Trace):
    def __init__(self, root, selected):
        super().__init__(root, "original-c")
        self.selected, self.held, self.collision = selected, None, None
        self.observations = []
        self.phase = "fence"

    def _observe_fence(self, observation):
        super()._observe_fence(observation)
        assert len(self.observations) < 13
        self.observations.append({"op": observation.operation.name, "edge": observation.edge.name,
                                  "outcome": observation.outcome.name, "ordinal": observation.ordinal})
        operation, edge, kind, _recover = CASES[self.selected]
        if observation.operation.name != operation or observation.edge.name != edge:
            return
        assert self.held is None
        session, directory = self._fence_namespace()
        if kind == "collision":
            assert fences(directory) == dict.fromkeys(NAMES)
            descriptor = os.open(NAMES[0], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 0o600, dir_fd=directory)
            try:
                assert os.write(descriptor, FOREIGN) == len(FOREIGN)
            finally:
                closing, descriptor = descriptor, None
                os.close(closing)
            self.collision = read_named(directory, NAMES[0])
        original = dict(self._fence_evidence)
        state = persistent.snapshot(self.root)["controls"]["state.json"]["value"]
        assert state["inflight"]["phase"] == "ARMED" and state["inflight"]["nonce"] == observation.nonce.hex()
        self.held = {"observation": original, "state": state, "fences": fences(directory),
                     "binding": session._fence_binding(state["inflight"])}
        assert self._fence_namespace() == (session, directory)


def validate_held(selected, held, collision=None):
    """Only captured bytes/scalars; no post-UNKNOWN file or owner acquisition."""
    operation, edge, kind, recover = CASES[selected]
    observation, state, pair = held["observation"], held["state"], held["fences"]
    assert (observation["operation"], observation["edge"]) == (operation, edge)
    assert observation["outcome"] == ("UNKNOWN" if kind in {"close-loss", "link-loss"} else
                                      "PENDING" if edge == "BEFORE" else "OK")
    assert state["inflight"]["phase"] == "ARMED"
    assert (state["inflight"]["sequence"], state["inflight"]["nonce"]) == (
        observation["commandSequence"], observation["nonce"])
    pending, final = pair[NAMES[0]], pair[NAMES[1]]
    expected = json.dumps({**held["binding"], "outcome": "producer-settled"},
                          sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    assert len(expected) == observation["total"] and set(pair) == set(NAMES)
    if kind == "collision":
        assert pending == collision and bytes.fromhex(pending["hex"]) == FOREIGN and final is None
        assert observation["creationIdentity"] is None
        return
    if selected == "pending-create-before":
        assert pending is final is None and observation["creationIdentity"] is None
        assert observation["written"] == observation["syncFlags"] == 0
        return
    assert pending is not None
    details, data = pending["state"], bytes.fromhex(pending["hex"])
    assert [details[index] for index in (0, 1, 4, 5, 2)] + [1] == observation["creationIdentity"]
    assert details[6] == len(data) == observation["written"]
    if selected == "pending-create-after":
        assert data == b"" and observation["syncFlags"] == 0
    elif selected == "pending-write-partial":
        assert 0 < len(data) < len(expected) and expected.startswith(data)
        assert data == bytes.fromhex(observation["operandHex"])[:observation["written"]]
        assert data == bytes.fromhex(observation["actualReadHex"])
        assert observation["originalReadClosed"] and observation["finalAbsentBeforeAndAfter"]
    else:
        assert data == expected
    expected_sync = 3 if selected == "directory-fsync-after" else 0 if operation in {
        "PENDING_CREATE", "PENDING_WRITE"} else 1
    assert observation["syncFlags"] == expected_sync
    if recover:
        assert final == pending and details[3] == 2
    else:
        assert final is None and details[3] == 1


def original_result(selected, case, session, trace, error):
    pids = case.bind_observations()
    outcome, engine, rows = case.outcome, case.outcome._engine, case.rows
    kind = CASES[selected][2]
    assert error is not None and outcome.matches(session._command_scope, session._command_binding)
    assert engine.wait is engine.child.receipt and engine.wait.status_kind == "exit"
    assert engine.wait.status_code == (73 if kind == "loss" else
                                      command.HELPER_FAILED if kind == "collision" else command.HELPER_UNKNOWN)
    assert engine.local_cleanup_complete and not engine.ctx.cleanup_unknown
    assert all(task.joined for task in engine.ctx.tasks)
    assert engine.wire.eof and engine.wire.reader.state == engine.wire.writer.state == "CLOSED"
    assert all(engine.output_eof) and all(reader.state == "CLOSED" for reader in engine.readers)
    assert outcome.create_w.attempted and outcome.run_tool.attempted
    assert outcome.create_w.retired and outcome.run_tool.retired and outcome.no_target is None
    assert outcome.result_integrity == "incomplete"
    assert (outcome.original_finality is not None) == (kind == "collision")
    assert session.unresolved and session.cancellation.lifetime_ledger.fatal and not session._command_finished
    assert session.state["inflight"]["phase"] == "ARMED" and not session.journal_failed
    for role, wait_name, io_name in (("C", "fence_owner_wait", "fence_owner_io"),
                                    ("A", "owner_wait", "owner_io")):
        wait, io = rows[role][wait_name], rows[role][io_name]
        assert wait["exact"] and wait["kind"] == "exit" and wait["code"] == command.HELPER_OK
        assert wait["child"] == pids["A" if role == "C" else "W"]
        assert io["joined"] and io["eof"] and io["closed"] and not io["unknown"]
    producer, grants, absent = rows["C"]["fence_producer"], rows["C"]["fence_grants"], rows["C"]["group_absent"]
    assert all(producer[key] for key in ("exact", "nonce", "eof", "absent", "retired"))
    assert all(grants[key] for key in ("create", "run", "create_retired", "run_retired"))
    assert grants["hold"] == "OPEN" and grants["sequence"] == session.state["inflight"]["sequence"]
    assert absent["group"] == pids["A"] and absent["wait_owned"] and not absent["numeric_retired"] and not absent["retired"]
    assert rows["A"]["worker_result"]["armed"] and rows["A"]["worker_result"]["result"]
    validate_held(selected, trace.held, trace.collision)
    if kind == "loss":
        cut = rows["C"]["fence_cut"]
        assert engine.terminal is None and "fence_publish_end" not in rows["C"]
        assert (cut["op"], cut["edge"], cut["ordinal"]) == (
            trace.held["observation"]["operation"], trace.held["observation"]["edge"],
            trace.held["observation"]["ordinal"])
        assert cut["acknowledged"] and cut["sync"] == trace.held["observation"]["syncFlags"]
        expected_pending = "NEW" if selected == "pending-create-before" else "CLOSED" if selected in {
            "pending-close-after", "final-link-after", "directory-fsync-after"} else "OPEN"
        assert cut["pending"] == expected_pending
    else:
        terminal, cleanup, publication = rows["C"]["fence_terminal"], rows["C"]["fence_cleanup"], rows["C"]["fence_publish_end"]
        assert not publication["complete"] and publication["attempted"] and publication["primary"]
        assert not engine.terminal["fence"] and not engine.terminal["result"] and engine.terminal["producer"]
        assert terminal["code"] == engine.wait.status_code and not terminal["complete"]
        assert cleanup["retired"] and cleanup["other_closed"] and cleanup["pending_fd"] is None
        assert trace.observations[-1]["outcome"] == "UNKNOWN"
        if kind == "collision":
            assert not terminal["unknown"] and terminal["hold"] == "CLOSED"
            assert cleanup["settled"] and cleanup["pending"] == "NEW" and cleanup["close_calls"] == 0
        else:
            actual, effect = rows["C"]["fence_effect_return"], rows["C"]["fence_effect_end"]
            assert actual["attempt"] == effect["attempt"] == 1 and actual["returned_none"] and actual["inflight"]
            assert effect["returned"] and effect["state"] == "UNKNOWN" and effect["primary"] and effect["unknown"]
            assert terminal["unknown"] and terminal["hold"] == "OPEN" and cleanup["close_calls"] == 1
            assert cleanup["pending"] == ("UNKNOWN" if kind == "close-loss" else "CLOSED")
            assert cleanup["settled"] == (kind == "link-loss")
    return {"schema": 1, "selected": selected, "owner": os.getpid(), "pids": pids,
            "cExit": engine.wait.status_code, "originalFinality": outcome.original_finality is not None,
            "resultIntegrity": outcome.result_integrity, "unresolved": session.unresolved,
            "fatal": session.cancellation.lifetime_ledger.fatal, "held": trace.held,
            "collision": trace.collision, "observations": trace.observations, "rows": rows}


def original_worker(root, selected):
    """Intentionally ends O; never falls into generic worker JSON reporting."""
    code, sink, case = persistent.WORKER_ERROR, None, None
    try:
        assert selected in CASES
        sink = ResultSink(root / "original-c.json")
        context = signing.local_signing_lease(home=root / "home")
        _RETAINED_ORIGINALS.append(context)  # Keep generator/lease until actual O exit.
        lease = context.__enter__()
        session = lease.session()
        session.bind_runner(PersistentSigningModel(root))
        session.open(create=True)
        session.prepare(PROFILE, UUID)
        trace = FenceTrace(root, selected)
        case = bootstrap.CommandCase(command, root / "command-observation", "fence-" + selected)
        failure = None
        with case, patch.object(signing.SigningSession, "_fence_observation_policy",
                                new=lambda actual: trace._observe_fence_policy(actual)), \
                patch.object(command, "_fence_trace_checkpoint", new=trace._observe_fence):
            try:
                session.run(["security", "default-keychain", "-d", "user"], kind="observe")
            except BaseException as error:
                failure = error
        # Original command cleanup ran, but this failed O cannot create a new
        # session or observer. Only preowned/captured objects and sink follow.
        sink.publish(original_result(selected, case, session, trace, failure))
        assert sink.state == "CLOSED"
        code = persistent.CRASH
    except BaseException as error:
        failure_report(sink, error, case=case)
    finally:
        os._exit(code)  # Includes setup/assertion/encoding/close failures; no fallthrough.


def read_report(root, name):
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        result = read_named(directory, name, limit=MAX_REPORT)
        assert result is not None and result["state"][3] == 1
        return json.loads(bytes.fromhex(result["hex"]))
    finally:
        closing, directory = directory, None
        os.close(closing)


def refusal_worker(root, selected, original):
    assert not CASES[selected][3]
    initial = signing.signing_status(home=root / "home")
    assert initial["status"] == "pending" and initial["session"] == original["held"]["binding"]["sessionToken"]
    before = persistent.snapshot(root)
    controls = persistent._focused_controls(root, initial["session"])
    calls, sessions = [], []
    model = PersistentSigningModel(root, recovery=True)
    gate, inventory = signing.SigningSession._recover_command_gate, signing.SigningSession.inventory

    def observed_gate(session):
        sessions.append(session)
        assert type(session._recovery_attempt) is signing._RecoveryAttempt
        assert session._recovery_attempt.pid == os.getpid() and session.pid != original["owner"]
        return gate(session)

    def observed_inventory(session):
        calls.append("inventory")
        return inventory(session)

    def observed_runner(*args, **kwargs):
        calls.append("native-query")
        return model(*args, **kwargs)

    refused = None
    with patch.object(signing.SigningSession, "_recover_command_gate", new=observed_gate), \
            patch.object(signing.SigningSession, "inventory", new=observed_inventory):
        try:
            signing.recover_signing(initial["session"], signing.CONFIRMATION, home=root / "home", runner=observed_runner)
        except CredentialError as error:
            refused = str(error)
    expected = "complete original custodian fence is missing" if selected == "pending-create-before" else "command fence metadata differs"
    assert refused == "local signing: " + expected and calls == [] and len(sessions) == 1
    recovered_session = sessions[0]
    assert recovered_session.closed and not recovered_session.cancellation.lifetime_ledger.fatal
    assert recovered_session._recovery_attempt.active_query is None
    assert persistent.snapshot(root) == before and persistent._focused_controls(root, initial["session"]) == controls
    assert before["controls"]["state.json"]["value"] == original["held"]["state"]
    ResourceOracle(root).assert_sentinels()
    persistent.assert_pending(root)
    return {"schema": 1, "selected": selected, "refused": refused, "newNativeCalls": 0,
            "preserved": True, "owner": os.getpid(), "originalOwner": original["owner"]}


def result_worker(root, name, task):
    """Fresh worker errors also cannot fall into a newly acquired JSON output."""
    code, sink = persistent.WORKER_ERROR, None
    try:
        assert name in {"refusal", "final-automatic"}
        sink = ResultSink(root / (name + ".json"))
        sink.publish(task())
        code = 0
    except BaseException as error:
        failure_report(sink, error)
    finally:
        os._exit(code)


class RecoveryTrace(persistent.Trace):
    """Only genuine retirement plus existing target events, not all setup IO."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.retirement = []

    @contextmanager
    def installed(self):
        actual = signing.SigningSession._retire_fence

        def retired(session, operation):
            assert not self.retirement and operation is session.state["inflight"]
            assert type(session._recovery_attempt) is signing._RecoveryAttempt
            # Observe the actual committed state, not just its mutable object.
            committed = json.loads(signing._control(session.fd, "state.json", cancellation=session.cancellation))
            assert committed["inflight"] == operation and operation["phase"] == "SETTLED"
            before = fences(session.fd)
            assert before[NAMES[0]] == before[NAMES[1]] and before[NAMES[0]] is not None
            assert before[NAMES[0]]["state"][3] == 2
            result = actual(session, operation)
            after = fences(session.fd)
            assert after == dict.fromkeys(NAMES)
            self.retirement.append({"committed": committed, "before": before, "after": after,
                                    "returned_none": result is None})
            return result

        with patch.object(signing.SigningSession, "_retire_fence", new=retired):
            yield

    def result(self):
        result = super().result()
        result["retirement"] = self.retirement
        return result


def run_case(root, selected):
    """One literal case under its already-admitted external disposable owner."""
    assert selected in CASES
    root = Path(root)
    initialize(root)
    persistent.require_fresh_recovery(root)
    original_wait = persistent.run_worker(root, "seed", lambda: original_worker(root, selected), expect=persistent.CRASH)
    original = read_report(root, "original-c.json")
    assert original["selected"] == selected and original["owner"] == original_wait["pid"]
    assert original["owner"] != original["pids"]["C"] and original["unresolved"] and original["fatal"]
    assert original["resultIntegrity"] == "incomplete"
    validate_held(selected, original["held"], original["collision"])
    if CASES[selected][3]:
        original_worker_owner = persistent.run_worker

        def guarded_worker(actual_root, name, task, **kwargs):
            assert actual_root == root and name == "final-automatic"
            return original_worker_owner(actual_root, name, lambda: result_worker(actual_root, name, task), **kwargs)

        with patch.object(persistent, "run_worker", guarded_worker):
            result = persistent.recover_final(root, trace_factory=RecoveryTrace)
        assert result == {"automatic": "recovered", "manual": None}
        fresh = read_report(root, "final-automatic.json")
        assert fresh["refused"] is None and fresh["before"]["controls"]["state.json"]["value"] == original["held"]["state"]
        assert len(fresh["retirement"]) == 1
        retire = fresh["retirement"][0]
        assert retire["returned_none"] and retire["after"] == dict.fromkeys(NAMES)
        assert retire["before"] == original["held"]["fences"]
        assert retire["committed"]["inflight"]["phase"] == "SETTLED"
        assert str(root) not in persistent._CASE_RECOVERY_DEBT
        disposition = "recovered"
    else:
        fresh_wait = persistent.run_worker(root, "refusal", lambda: result_worker(
            root, "refusal", lambda: refusal_worker(root, selected, original)))
        fresh = read_report(root, "refusal.json")
        assert fresh["owner"] == fresh_wait["pid"] != original["owner"]
        assert fresh["preserved"] and fresh["newNativeCalls"] == 0
        assert str(root) in persistent._CASE_RECOVERY_DEBT
        disposition = "refused"
    # No deletion or next fault. The literal singleton's existing Session owns
    # final test-domain disposal, including original O's retained bridge files.
    return {"selected": selected, "disposition": disposition, "original": original,
            "originalWait": original_wait, "fresh": fresh}
