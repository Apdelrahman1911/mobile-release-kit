"""Finite test-only observations/cuts in the live original command bootstrap.

No project import at module scope: fresh C snapshots inherited signal policy
before loading this file. Native execution belongs to the reviewed disposable
owner, never the shared host. Diagnostic records are not lifetime capabilities.
"""
from __future__ import annotations

import ast
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time

ROLES = ("C", "A", "W")
FENCE_CASES = {
    "pending-create-before": ("PENDING_CREATE", "BEFORE", "loss", False),
    "pending-create-after": ("PENDING_CREATE", "AFTER", "loss", False),
    "pending-write-partial": ("PENDING_WRITE", "PARTIAL", "loss", False),
    "pending-write-after": ("PENDING_WRITE", "AFTER", "loss", False),
    "data-fsync-after": ("DATA_FSYNC", "AFTER", "loss", False),
    "pending-close-after": ("PENDING_CLOSE", "AFTER", "loss", False),
    "final-link-after": ("FINAL_LINK", "AFTER", "loss", True),
    "directory-fsync-after": ("DIRECTORY_FSYNC", "AFTER", "loss", True),
    "pending-close-lost-return": ("PENDING_CLOSE", "AFTER", "close-loss", False),
    "final-link-lost-return": ("FINAL_LINK", "AFTER", "link-loss", True),
    "foreign-pending-collision": ("PENDING_CREATE", "BEFORE", "collision", False),
}
FENCE_MODES = {"fence-" + name: value for name, value in FENCE_CASES.items()}
NO_WORKER_MODES = frozenset({"prepared-no-target-off", "prepared-prefix-input-loss"})
HOLD_MODE = "account-hold-parent-loss"
ACCOUNT_MODES = NO_WORKER_MODES | {HOLD_MODE}
MODES = frozenset({
    "observe", "body-return", "body-systemexit", "report-format-error", "reject-full",
    "reject-zero", "reject-eagain", "reject-error", "reject-partial", "arm-missing",
    "arm-partial", "post-map-pre-ready", "first-self-stop", "both-self-stop",
    "preguard-127", "guarded-import",
}) | frozenset(FENCE_MODES) | ACCOUNT_MODES
MAX_RECORDS, MAX_RECORD_BYTES = 32, 256
MAX_TRACE_BYTES = MAX_RECORDS * MAX_RECORD_BYTES
_RETAINED_CASES = []
_MARKER = "_mrk_fir03"


def build_bootstrap(original, settings):
    """Instrument original text before its original whole-recipe permit exists."""
    mode, fixture, root, identities = settings
    if (type(original) is not str or _MARKER in original or mode not in MODES
            or not Path(fixture).is_absolute() or not Path(root).is_absolute()
            or len(identities) != 3):
        raise AssertionError("unexpected fixed command fixture recipe")
    anchors = (
        'if _role == "W":\n',
        '                from mobile_release._command_process import helper_main\n',
        '    from mobile_release._command_process import helper_main\n',
    )
    # Include leading newline for the C/A import so it cannot match W's indent.
    anchors = (anchors[0], anchors[1], "\n" + anchors[2])
    if any(original.count(anchor) != 1 for anchor in anchors):
        raise AssertionError("original loader anchors changed")
    ast.parse(original)
    load = f'{_MARKER} = __import__("runpy").run_path({fixture!r})'
    arguments = repr(settings)
    result = original.replace(anchors[0], anchors[0] +
        f'    if {mode!r} == "preguard-127":\n'
        f'        {load}\n'
        f'        {_MARKER}["preguard"](globals(), {arguments})\n')
    result = result.replace(anchors[1],
        f'                {load}\n'
        f'                {_MARKER}["before_import"](globals(), {arguments})\n'
        + anchors[1] +
        f'                {_MARKER}["install"](sys.modules["mobile_release._command_process"], globals(), {arguments})\n')
    result = result.replace(anchors[2], anchors[2] +
        f'    {load}\n'
        f'    {_MARKER}["install"](sys.modules["mobile_release._command_process"], globals(), {arguments})\n')
    ast.parse(result)
    if len(os.fsencode(result)) > 8192:
        raise AssertionError("fixture exceeded original native argument limit")
    return result


class _Record:
    def __init__(self, loader, settings):
        self.mode, _fixture, root, identities = settings
        self.role, self.pid, self.nonce = loader["_role"], os.getpid(), sys.argv[8]
        self.path = os.path.join(root, self.role + ".trace")
        self.identity = identities[ROLES.index(self.role)]
        self.seen, self.broken, self.sealed = set(), False, False
        self.write, self.open, self.close, self.fstat = os.write, os.open, os.close, os.fstat
        self.held = self.role == "C" and self.mode in (FENCE_MODES.keys() | ACCOUNT_MODES)
        self.descriptor, self.descriptor_state = None, "NEW"
        self.contender = None
        if self.held:
            # Before any original command work. UNKNOWN effects may not open
            # a new diagnostic owner, even when reporting only optional DATA.
            self.descriptor_state = "OPENING"
            self.descriptor = self.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW)
            self.descriptor_state = "OPEN"

    def close_owned(self):
        if not self.held or self.descriptor_state != "OPEN":
            return
        descriptor, self.descriptor = self.descriptor, None
        self.descriptor_state = "UNKNOWN"  # No retry after a lost close return.
        try:
            self.close(descriptor)
            self.descriptor_state = "CLOSED"
        except BaseException:
            self.broken = True

    def emit(self, event, **fields):
        # Unique events saturate even if signal.pause repeatedly returns/raises.
        # IO failure never selects a command cut or skips the original operation.
        if self.broken or self.sealed or event in self.seen:
            return
        self.seen.add(event)
        descriptor = None
        try:
            row = {"r": self.role, "p": self.pid, "n": self.nonce, "e": event, **fields}
            data = (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            if len(self.seen) > MAX_RECORDS or len(data) > MAX_RECORD_BYTES:
                raise AssertionError("fixture diagnostic bound")
            if self.held:
                if self.descriptor_state != "OPEN":
                    raise AssertionError("fixture diagnostic writer already retired")
                descriptor = self.descriptor
            else:
                descriptor = self.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW)
            details = self.fstat(descriptor)
            if (not stat.S_ISREG(details.st_mode) or stat.S_IMODE(details.st_mode) != 0o600
                    or (details.st_dev, details.st_ino, details.st_uid) != self.identity
                    or details.st_nlink != 1):
                raise AssertionError("fixture diagnostic identity")
            if self.write(descriptor, data) != len(data):
                raise AssertionError("partial fixture diagnostic")
        except BaseException:
            self.broken = True
        finally:
            if descriptor is not None and not self.held:
                try:
                    self.close(descriptor)  # One attempt; never retry this number.
                except BaseException:
                    self.broken = True
        # A complete row is an entered-operation observation, not a close receipt.
        # Only original child/group finality settles an uncertain child-local FD.


def _record(loader, settings):
    record = loader.get("_mrk_fir03_record")
    if record is None:
        record = loader["_mrk_fir03_record"] = _Record(loader, settings)
        record.emit("boot", parent=os.getppid(), run=int(sys.argv[6]), hard=int(sys.argv[7]))
    return record


def preguard(loader, settings):
    record = _record(loader, settings)
    record.emit("preguard", code=127)
    raise SystemExit(127)


def before_import(loader, settings):
    record = _record(loader, settings)
    if record.mode == "guarded-import":
        record.emit("guarded_import")
        raise ImportError("fixed command fixture import cut")


class _BodyReturn(BaseException):
    pass


def install(command, loader, settings):
    record = _record(loader, settings)
    # Each fresh exec imports pristine module bytes. Its original _command_spec
    # issues a new permit for the same complete selected recipe before creation.
    command._BOOTSTRAP = build_bootstrap(command._BOOTSTRAP, settings)
    if record.mode in ACCOUNT_MODES:
        _install_account_map(command, record)
    if record.role != "W":
        _install_owner(command, record)
        if record.role == "C" and record.mode in FENCE_MODES:
            _install_fence(command, record)
        elif record.role == "C" and record.mode in ACCOUNT_MODES:
            _install_account_fence(command, record)
        return
    mode = record.mode
    send, run, reject, scalar = command._send, command._Worker.run, command._Worker._reject, command._scalar
    actual_os, active = command.os, {"send": None, "worker": None, "writes": 0}

    class ObservedOS:
        def __getattr__(self, name):
            return getattr(actual_os, name)

        def write(self, descriptor, data):
            worker = active["worker"]
            if (worker is not None and worker.reject_attempted
                    and descriptor == worker.mapping[4].fileno()):
                active["writes"] += 1
                facts = {"attempt": active["writes"], "retired": worker.exec_retired,
                         "size": len(data), "nonblocking": not actual_os.get_blocking(descriptor)}
                if mode in {"reject-zero", "reject-eagain", "reject-error"}:
                    record.emit("reject_write", **facts, count=0, kind=mode)
                    if mode == "reject-zero":
                        return 0
                    if mode == "reject-eagain":
                        raise BlockingIOError(errno.EAGAIN, "fixed report cut")
                    raise OSError(errno.EIO, "fixed report cut")
                payload = data[:3] if mode == "reject-partial" else data
                count = actual_os.write(descriptor, payload)
                record.emit("reject_write", **facts, count=count, kind=mode)
                return count
            if mode == "arm-partial" and active["send"] is command.Tag.EXEC_ARMED:
                count = actual_os.write(descriptor, data[:3])
                record.emit("arm_partial", count=count, size=len(data))
                # _send normally retries suffix progress. This definitive body
                # abort, not the short write itself, prevents that next suffix.
                raise _BodyReturn
            return actual_os.write(descriptor, data)

    def observed_send(wire, tag, body, pump, **kwargs):
        if mode == "post-map-pre-ready" and tag is command.Tag.READY:
            record.emit("pre_ready")
            raise _BodyReturn
        if mode == "arm-missing" and tag is command.Tag.EXEC_ARMED:
            record.emit("arm_missing")
            raise _BodyReturn
        active["send"] = tag
        try:
            result = send(wire, tag, body, pump, **kwargs)
        finally:
            active["send"] = None
        if tag in (command.Tag.HELLO, command.Tag.READY, command.Tag.EXEC_ARMED):
            record.emit(tag.name.lower())
        if tag is command.Tag.EXEC_ARMED and mode in {
                "body-return", "body-systemexit", "first-self-stop", "both-self-stop"}:
            raise _BodyReturn
        return result

    def observed_run(worker):
        try:
            return run(worker)
        except _BodyReturn:
            record.emit("body_return")
            return None

    def observed_reject(worker, stage, number):
        active["worker"] = worker
        record.emit("reject_enter", stage=stage, errno=number)
        try:
            result = reject(worker, stage, number)
            record.emit("reject_done", attempts=active["writes"])
            return result
        finally:
            active["worker"] = None

    def observed_scalar(nonce, **fields):
        worker = active["worker"]
        if mode == "report-format-error" and worker is not None and fields.get("stage") == "exec":
            record.emit("format_error", retired=worker.exec_retired)
            raise ValueError("fixed rejection formatting cut")
        return scalar(nonce, **fields)

    original_raise, original_kill, original_park = loader["_raise"], loader["_kill"], loader["_park"]

    def self_raise(number):
        record.emit("self_raise", signal=int(number))
        if mode in {"first-self-stop", "both-self-stop"}:
            raise RuntimeError("fixed first self-stop cut")
        return original_raise(number)

    def self_kill(pid, number):
        record.emit("self_kill", self_pid=pid, signal=int(number))
        if mode == "both-self-stop":
            raise RuntimeError("fixed second self-stop cut")
        return original_kill(pid, number)

    def park():
        record.emit("park")
        return original_park()

    command.os, command._send, command._scalar = ObservedOS(), observed_send, observed_scalar
    command._Worker.run, command._Worker._reject = observed_run, observed_reject
    loader["_raise"], loader["_kill"], loader["_park"] = self_raise, self_kill, park
    if mode == "body-systemexit":
        original_helper = loader["helper_main"]

        def system_exit(*args, **kwargs):
            returned = original_helper(*args, **kwargs)
            record.emit("system_exit", returned=returned, code=127)
            raise SystemExit(127)

        # Replace the already imported loader alias, not an unused module name.
        loader["helper_main"] = system_exit


def _install_owner(command, record):
    event, spec = command._command_event, command._command_spec

    def observed_event(role, name, **facts):
        result = event(role, name, **facts)
        if name == "child_published":
            record.emit(name, child=facts["child"].pid)
        elif name == "creator_joined":
            record.emit(name, joined=facts["task"].joined)
        elif name == "anchor_moved":
            record.emit(name, group=os.getpgrp(), session=os.getsid(0))
        return result

    def observed_spec(*args, **kwargs):
        result = spec(*args, **kwargs)
        record.emit("recipe", child_role=result.argv[7],
                    digest=hashlib.sha256(result.argv[5].encode()).hexdigest())
        return result

    owner_type = command._Custodian if record.role == "C" else command._Anchor
    finish = owner_type.finish

    def observed_finish(owner):
        result = finish(owner)
        wait, child, wire = owner.wait, owner.child, owner.downstream
        record.emit("owner_wait", child=None if child is None else child.pid,
                    exact=wait is not None and child is not None and wait is child.receipt,
                    kind=None if wait is None else wait.status_kind,
                    code=None if wait is None else wait.status_code)
        record.emit("owner_io", joined=all(task.joined for task in owner.ctx.tasks),
                    eof=wire is not None and wire.eof,
                    closed=wire is not None and wire.reader.state == wire.writer.state == "CLOSED",
                    unknown=owner.ctx.cleanup_unknown)
        if record.role == "C":
            record.emit("producer", sealed=owner.seal is not None, eof=all(owner.source_eof),
                        absent=owner.group is not None and owner.group.absent,
                        retired=owner.group is not None and owner.group.retired)
        else:
            record.emit("worker_result", armed=owner.armed, rejected=owner.rejection is not None,
                        moved=owner.moved, result=None if owner.work_done is None else
                        command._settlement_fields(owner.work_done, owner.ctx)["result"])
            if record.mode in NO_WORKER_MODES:
                record.emit("no_worker", no_child=owner.no_child, child=owner.child is None,
                            wait=owner.wait is None, downstream=owner.downstream is None,
                            attempted=owner.ctx.child_acquisition.attempted,
                            unknown=owner.ctx.child_acquisition.cleanup_unknown, tasks=len(owner.ctx.tasks))
                record.emit("no_worker_producers", moved=owner.moved, group_done=owner.group_done,
                            settled=owner._local_producers(), hold=owner.mapping[5].state,
                            create=owner.create_route.attempted, run=owner.run_route.attempted,
                            retired=owner.create_route.retired and owner.run_route.retired)
        record.emit("owner_finish", code=result)
        return result

    group_type = command._AnchorGroup if record.role == "C" else command._SelfGroup
    terminate = group_type.terminate

    def observed_terminate(group):
        record.emit("group_kill", group=group.group, retired=group.retired,
                    before_cutoff=time.monotonic_ns() < group.context.cutoff())
        return terminate(group)

    if record.role == "C":
        probe = command._AnchorGroup.probe

        def observed_probe(group):
            result = probe(group)
            if result:
                record.emit("group_absent", group=group.group, retired=group.retired,
                            wait_owned=group.anchor.wait_state == "OWNED",
                            numeric_retired=group.anchor.numeric_retired)
            return result

        command._AnchorGroup.probe = observed_probe
    command._command_event, command._command_spec = observed_event, observed_spec
    owner_type.finish, group_type.terminate = observed_finish, observed_terminate


class _AccountContender:
    """C-local independent open description, preregistered before any loss."""
    def __init__(self, hold, context):
        self.hold, self.context = hold, context
        self.fd, self.state = None, "NEW"
        self.identity = None

    def acquire(self):
        assert self.state == "NEW" and not self.context.parent_lost()
        hold = self.hold.fileno()
        before = os.stat(".", dir_fd=hold, follow_symlinks=False)
        binding = self.hold.account_binding
        assert (binding is not None and stat.S_ISDIR(before.st_mode)
                and stat.S_IMODE(before.st_mode) == 0o700 and before.st_uid == binding.uid == os.getuid()
                and (before.st_dev, before.st_ino) == binding.identity)
        self.identity = before.st_dev, before.st_ino, before.st_uid, before.st_mode
        self.state = "OPENING"
        self.fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=hold)
        self.state = "OPEN"
        self.check()

    def check(self):
        assert self.state == "OPEN" and self.hold.state == "OPEN"
        for fd in (self.fd, self.hold.fileno()):
            value = os.fstat(fd)
            assert (value.st_dev, value.st_ino, value.st_uid, value.st_mode) == self.identity

    def challenge(self, *, shared=False):
        self.check()
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            assert error.errno in {errno.EAGAIN, errno.EWOULDBLOCK}
        else:
            raise AssertionError("independent contender unexpectedly acquired the account")
        if shared:
            fcntl.flock(self.hold.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.check()

    def close(self):
        if self.state != "OPEN":
            return
        descriptor, self.fd, self.state = self.fd, None, "UNKNOWN"
        os.close(descriptor)
        self.state = "CLOSED"


def _install_account_map(command, record):
    original = command._bootstrap_map

    def mapped(context, bootstrap, relay, account):
        result = original(context, bootstrap, relay, account)
        try:
            assert context.role == record.role and context.nonce.hex() == record.nonce
            hold, binding = result[5], result[5].account_binding
            assert hold.account_binding is bootstrap.account_binding
            details = os.fstat(hold.fileno())
            record.emit("account_map", bound=binding is not None, kind=hold._kind,
                        identity=[details.st_dev, details.st_ino, details.st_uid],
                        nonce=binding is None or binding.command_nonce == context.nonce)
            record.emit("fixed_map", types=[stat.S_IFMT(os.fstat(fd).st_mode) for fd in range(8)],
                        original=all(value._original_fd == fd and value._validated
                                     for fd, value in result.items()))
            if record.role == "C" and record.mode == HOLD_MODE:
                contender = record.contender = _AccountContender(hold, context)
                contender.acquire()
                contender.challenge(shared=True)
                assert not context.parent_lost()
                record.emit("hold_initial", blocked=True, shared=True, hold=hold.state,
                            contender=contender.state, parent_alive=True)
        except BaseException:
            record.broken = True
            if record.contender is not None:
                try:
                    record.contender.close()
                except BaseException:
                    pass  # Failed witness; never retry a number or skip original map cleanup.
        return result

    command._bootstrap_map = mapped


def _install_account_fence(command, record):
    """Separate no-W/input-withdrawal and true-parent-loss witnesses."""
    publish, checkpoint = command.FenceWriter.publish, command.FenceWriter._checkpoint
    finish, actual_exit = command._Custodian.finish, os._exit
    active = {"writer": None}

    def observed_publish(writer, seal):
        assert active["writer"] is None and writer.ctx.role == "C"
        active["writer"] = writer
        owner, wait, wire = writer.custodian, writer.custodian.wait, writer.custodian.downstream
        record.emit("fence_owner_wait", child=owner.child.pid, exact=wait is owner.child.receipt,
                    kind=wait.status_kind, code=wait.status_code)
        record.emit("fence_owner_io", joined=all(task.joined for task in owner.ctx.tasks),
                    eof=wire.eof, closed=wire.reader.state == wire.writer.state == "CLOSED",
                    unknown=owner.ctx.cleanup_unknown)
        record.emit("fence_producer", exact=seal is owner.seal and seal._custodian is owner,
                    nonce=seal._nonce == owner.ctx.nonce, eof=all(owner.source_eof),
                    absent=owner.group.absent, retired=owner.group.retired)
        record.emit("fence_grants", create=owner.create_route.attempted, run=owner.run_route.attempted,
                    create_retired=owner.create_route.retired, run_retired=owner.run_route.retired,
                    hold=writer.hold.state, sequence=writer.fields["sequence"])
        return publish(writer, seal)

    def observed_checkpoint(writer, operation, edge, outcome, operand=b""):
        result = checkpoint(writer, operation, edge, outcome, operand)
        if (writer is not active["writer"] or operation is not command.FenceOperation.PENDING_WRITE
                or edge is not command.FenceEdge.PARTIAL or record.mode == "prepared-no-target-off"):
            return result
        observer, ctx, owner = writer.observer, writer.ctx, writer.custodian
        assert (observer is not None and observer.owner_loss and observer.retired and not observer.acknowledged
                and outcome is command.FenceEventOutcome.OK and writer.pending.state == "OPEN"
                and 0 < writer.written < len(writer.content) and writer.sync_flags == 0
                and owner._producer_settled() and owner.seal._custodian is owner
                and owner.seal._nonce == ctx.nonce and writer.hold.state == "OPEN")
        if record.mode == "prepared-prefix-input-loss":
            assert observer.wire.eof and not ctx.parent_lost()
            assert not owner.create_route.attempted and not owner.run_route.attempted
            assert owner.anchor_work["no_child"] and owner.anchor_work["wait"] is None
            record.emit("prepared_prefix", written=writer.written, total=len(writer.content),
                        pending=writer.pending.state, sync=writer.sync_flags, input_eof=True,
                        parent_alive=True, acknowledged=False)
            record.emit("prefix_identity", value=list(writer.creation_identity))
            record.emit("prefix_digest", value=hashlib.sha256(writer.content[:writer.written]).hexdigest())
            record.close_owned()
            assert not record.broken and record.descriptor_state == "CLOSED"
            actual_exit(73)
        assert record.mode == HOLD_MODE and owner.create_route.attempted and owner.run_route.attempted
        # O's descriptor withdrawal can precede actual reparenting. Use only
        # this original relation and its immutable cutoff, never a stored PID.
        while not ctx.parent_lost():
            ctx.check_tail()
            time.sleep(min(.002, max(0, (ctx.cutoff() - time.monotonic_ns()) / 1e9)))
        ctx.check_tail()
        contender = record.contender
        assert contender is not None and contender.hold is writer.hold
        contender.challenge()
        assert ctx.parent_lost() and owner._producer_settled() and writer.hold.state == "OPEN"
        record.emit("hold_after_parent_loss", blocked=True, parent_lost=True, hold=writer.hold.state,
                    producer=True, acknowledged=False, input_eof=observer.wire.eof)
        try:
            contender.close()
        finally:
            record.emit("hold_contender_closed", state=contender.state, hold=writer.hold.state)
            record.close_owned()
            record.sealed = True  # Both close attempts precede any failure unwind.
        assert contender.state == "CLOSED"
        assert not record.broken and record.descriptor_state == "CLOSED"
        # A failed diagnostic close aborts this original publication, leaving
        # an ARMED prefix which fresh recovery cannot accept. Successful close
        # precedes the real final link; later optional records are intentionally
        # absent, not inferred post-loss C waits or close receipts.
        return result

    def observed_finish(owner):
        try:
            result = finish(owner)
            if record.mode in NO_WORKER_MODES:
                record.emit("fence_terminal", code=result, hold=owner.mapping[5].state,
                            complete=owner.writer is not None and owner.writer.complete,
                            unknown=owner.ctx.cleanup_unknown)
            return result
        finally:
            if record.contender is not None:
                try:
                    record.contender.close()
                except BaseException:
                    record.broken = True
            record.close_owned()
            if (record.broken or record.descriptor_state != "CLOSED"
                    or record.contender is not None and record.contender.state != "CLOSED"):
                actual_exit(91)

    command.FenceWriter.publish, command.FenceWriter._checkpoint = observed_publish, observed_checkpoint
    command._Custodian.finish = observed_finish


def _install_fence(command, record):
    """Closed faults in the actual original C writer, not replacement proof."""
    operation_name, edge_name, kind, _recovery = FENCE_MODES[record.mode]
    publish, checkpoint = command.FenceWriter.publish, command.FenceWriter._checkpoint
    effect, close = command.FenceWriter.effect, command.FenceWriter.close
    finish = command._Custodian.finish
    actual_close, actual_link, actual_exit = command.os.close, command.os.link, os._exit
    active = {"writer": None, "pending_fd": None, "attempts": 0, "close_calls": 0, "returned": False}

    def observed_publish(writer, seal):
        assert active["writer"] is None and writer.ctx.role == "C"
        active["writer"] = writer
        owner, wait, wire = writer.custodian, writer.custodian.wait, writer.custodian.downstream
        record.emit("fence_owner_wait", child=owner.child.pid,
                    exact=wait is owner.child.receipt, kind=wait.status_kind, code=wait.status_code)
        record.emit("fence_owner_io", joined=all(task.joined for task in owner.ctx.tasks),
                    eof=wire.eof, closed=wire.reader.state == wire.writer.state == "CLOSED",
                    unknown=owner.ctx.cleanup_unknown)
        record.emit("fence_producer", exact=seal is owner.seal and seal._custodian is owner,
                    nonce=seal._nonce == owner.ctx.nonce, eof=all(owner.source_eof),
                    absent=owner.group.absent, retired=owner.group.retired)
        record.emit("fence_grants", create=owner.create_route.attempted, run=owner.run_route.attempted,
                    create_retired=owner.create_route.retired, run_retired=owner.run_route.retired,
                    hold=writer.hold.state, sequence=writer.fields["sequence"])
        try:
            return publish(writer, seal)
        finally:
            record.emit("fence_publish_end", complete=writer.complete, attempted=writer.attempted,
                        unknown=writer.ctx.cleanup_unknown, primary=writer.ctx.primary is not None)

    def observed_checkpoint(writer, operation, edge, outcome, operand=b""):
        if (writer is active["writer"] and operation is command.FenceOperation.PENDING_CREATE
                and edge is command.FenceEdge.AFTER and outcome is command.FenceEventOutcome.OK):
            assert active["pending_fd"] is None
            active["pending_fd"] = writer.pending.fileno()
        result = checkpoint(writer, operation, edge, outcome, operand)
        if (writer is active["writer"] and operation.name == operation_name
                and edge.name == edge_name and kind == "loss"):
            observer = writer.observer
            assert (observer is not None and observer.acknowledged and not observer.retired
                    and not observer.owner_loss and observer.outstanding.operation is operation
                    and observer.outstanding.edge is edge and observer.outstanding.nonce == writer.ctx.nonce
                    and time.monotonic_ns() < writer.ctx.cutoff())
            record.emit("fence_cut", op=operation.name, edge=edge.name, ordinal=observer.ordinal,
                        written=writer.written, total=len(writer.content), sync=writer.sync_flags,
                        pending=writer.pending.state, acknowledged=observer.acknowledged)
            record.close_owned()
            assert not record.broken and record.descriptor_state == "CLOSED"
            actual_exit(73)  # Original C, never O or a caller-supplied numeric target.
        return result

    def observed_effect(writer, name, function, *args, **kwargs):
        if writer is active["writer"] and name == "close" and args == (active["pending_fd"],):
            active["close_calls"] += 1
        selected = (writer is active["writer"] and (
            kind == "close-loss" and name == "close" and function is actual_close
            and args == (active["pending_fd"],) and writer.pending.state == "CLOSING"
            and writer.pending.fd is None
            or kind == "link-loss" and name == "final_link" and function is actual_link
            and args == ("command-final.pending", "command-final.json")
            and kwargs == {"src_dir_fd": writer.session.fileno(), "dst_dir_fd": writer.session.fileno(),
                           "follow_symlinks": False}))
        if not selected:
            return effect(writer, name, function, *args, **kwargs)
        active["attempts"] += 1
        assert active["attempts"] == 1
        error = OSError(errno.EIO, "fixed original fence lost return")

        def lose_return(*actual_args, **actual_kwargs):
            original = writer.effects[-1]
            assert original.operation == name and original.state == "IN_FLIGHT"
            returned = function(*actual_args, **actual_kwargs)
            active["returned"] = True
            record.emit("fence_effect_return", op=name, attempt=active["attempts"],
                        returned_none=returned is None, inflight=original.state == "IN_FLIGHT")
            raise error  # INSIDE unchanged effect, which alone records UNKNOWN.

        try:
            return effect(writer, name, lose_return, *args, **kwargs)
        finally:
            record.emit("fence_effect_end", op=name, attempt=active["attempts"],
                        returned=active["returned"], state=writer.effects[-1].state,
                        primary=writer.ctx.primary is error, unknown=writer.ctx.cleanup_unknown)

    def observed_close(writer):
        result = close(writer)
        if writer is active["writer"]:
            record.emit("fence_cleanup", settled=result, retired=writer.retired,
                        pending=writer.pending.state, pending_fd=writer.pending.fd,
                        close_calls=active["close_calls"], unknown=writer.ctx.cleanup_unknown,
                        other_closed=all(slot.state in ("NEW", "CLOSED") for slot in writer.files
                                         if slot is not writer.pending))
        return result

    def observed_finish(owner):
        try:
            result = finish(owner)
            if owner.writer is active["writer"]:
                record.emit("fence_terminal", code=result, hold=owner.writer.hold.state,
                            complete=owner.writer.complete, unknown=owner.ctx.cleanup_unknown)
            return result
        finally:
            record.close_owned()
            if record.broken or record.descriptor_state != "CLOSED":
                # The actual original C receipt must reject failed diagnostics,
                # even when its prior terminal row was completely written.
                actual_exit(91)

    command.FenceWriter.publish, command.FenceWriter._checkpoint = observed_publish, observed_checkpoint
    command.FenceWriter.effect, command.FenceWriter.close = observed_effect, observed_close
    command._Custodian.finish = observed_finish


def parse_trace(raw, *, partial=False):
    """Finite observation parser; never supplies process/cleanup authority."""
    if type(raw) is not bytes or len(raw) > MAX_TRACE_BYTES:
        raise AssertionError("fixture trace byte bound")
    if raw and not raw.endswith(b"\n"):
        if not partial:
            raise AssertionError("partial fixture trace")
        raw = raw[:raw.rfind(b"\n") + 1]
    lines, result = raw.splitlines(), {}
    if len(lines) > MAX_RECORDS:
        raise AssertionError("fixture trace record bound")
    for line in lines:
        if len(line) + 1 > MAX_RECORD_BYTES:
            raise AssertionError("fixture trace row bound")
        row = json.loads(line)
        if (type(row) is not dict or not {"r", "p", "n", "e"} <= row.keys()
                or row["r"] not in ROLES or type(row["p"]) is not int
                or type(row["n"]) is not str or len(row["n"]) != 32
                or type(row["e"]) is not str or row["e"] in result
                or json.dumps(row, sort_keys=True, separators=(",", ":")).encode() != line):
            raise AssertionError("fixture trace shape/replay")
        result[row["e"]] = row
    return result


class CommandCase:
    """Original O observation with preowned readers, not a new process owner."""
    def __init__(self, command, root, mode, *, interruption=None):
        self.command, self.root, self.mode = command, Path(root), mode
        self.interruption, self.interrupted = interruption, False
        self.outcome, self.rows, self.snapshots, self.errors = None, {}, {}, []
        self.slots, self.readers, self.settings = [], {}, None
        self.closed, self.released, self.pump_reads = False, False, 0
        self.engine = None
        _RETAINED_CASES.append(self)  # Before any path/descriptor acquisition.

    def _open(self, path, flags, mode=0o600):
        slot = {"fd": None, "state": "ACQUIRING"}
        self.slots.append(slot)
        slot["fd"] = os.open(path, flags | os.O_CLOEXEC | os.O_NOFOLLOW, mode)
        slot["state"] = "OPEN"
        return slot

    def _close(self, slot):
        if slot["state"] != "OPEN":
            return
        slot["state"] = "UNKNOWN"  # Retirement precedes a possibly lost return.
        try:
            os.close(slot["fd"])
            slot["state"] = "CLOSED"
        except BaseException as error:
            self.errors.append(error)

    def __enter__(self):
        if self.mode not in MODES:
            raise AssertionError("unknown fixture mode")
        self.root.mkdir(mode=0o700)
        details = self.root.lstat()
        if not stat.S_ISDIR(details.st_mode) or stat.S_IMODE(details.st_mode) != 0o700:
            raise AssertionError("fixture root mode/type")
        identities = []
        for role in ROLES:
            path = self.root / (role + ".trace")
            slot = self._open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            details = os.fstat(slot["fd"])
            identity = details.st_dev, details.st_ino, details.st_uid
            identities.append(identity)
            self._close(slot)
            if slot["state"] != "CLOSED":
                raise AssertionError("fixture creation close unknown")
            reader = self._open(path, os.O_RDONLY)
            details = os.fstat(reader["fd"])
            if (details.st_dev, details.st_ino, details.st_uid) != identity:
                raise AssertionError("fixture reader identity")
            self.readers[role] = reader
        self.settings = self.mode, str(Path(__file__).resolve()), str(self.root.resolve()), tuple(identities)
        command = self.command
        self.original = command._BOOTSTRAP, command._Outer.publish, command._Outer._pump
        self.recipe = build_bootstrap(self.original[0], self.settings)
        command._BOOTSTRAP = self.recipe

        def published(engine):
            try:
                self._snapshot()
            finally:
                # A failed observation can never prevent the original publication.
                outcome = self.original[1](engine)
                self.outcome = outcome
            return outcome

        def pumped(engine):
            if self.mode in ACCOUNT_MODES:
                self.engine = engine  # Original object, never a recreated outcome.
            result = self.original[2](engine)
            if self.interruption is not None and not self.interrupted:
                try:
                    self.pump_reads += 1
                    if self.pump_reads > 4096:
                        raise AssertionError("fixture park observation bound")
                    data = os.pread(self.readers["W"]["fd"], MAX_TRACE_BYTES + 1, 0)
                    rows = parse_trace(data, partial=True)
                    parked = rows.get("park")
                    if parked is not None and parked["n"] == engine.nonce.hex():
                        self.interrupted = True
                except BaseException as error:
                    self.errors.append(error)
                if self.interrupted:
                    raise self.interruption
            return result

        self.published, self.pumped = published, pumped
        command._Outer.publish, command._Outer._pump = published, pumped
        return self

    def _snapshot(self):
        if self.closed:
            self.errors.append(AssertionError("fixture publication repeated"))
            return
        self.closed = True
        for role, slot in self.readers.items():
            try:
                self.snapshots[role] = os.pread(slot["fd"], MAX_TRACE_BYTES + 1, 0)
            except BaseException as error:
                self.errors.append(error)
            finally:
                self._close(slot)

    def __exit__(self, kind, value, traceback):
        command = self.command
        if (command._BOOTSTRAP != self.recipe or command._Outer.publish is not self.published
                or command._Outer._pump is not self.pumped):
            self.errors.append(AssertionError("fixture patch custody changed"))
        command._BOOTSTRAP, command._Outer.publish, command._Outer._pump = self.original
        # No post-UNKNOWN path lookup/import/reader reopen or disposal operation.
        return False

    def bind_observations(self):
        assert not self.errors and self.closed
        assert self.outcome is not None and self.outcome._engine.slot.read() is self.outcome
        assert all(slot["state"] == "CLOSED" for slot in self.slots)
        engine = self.outcome._engine
        self.rows = {role: parse_trace(self.snapshots[role]) for role in ROLES}
        pids = {"C": engine.child.pid, "A": self.rows["C"]["child_published"]["child"],
                "W": self.rows["A"]["child_published"]["child"]}
        for role, rows in self.rows.items():
            assert rows and all(row["r"] == role and row["p"] == pids[role]
                                and row["n"] == engine.nonce.hex() for row in rows.values())
            assert rows["boot"]["run"] == engine.ctx.run and rows["boot"]["hard"] == engine.ctx.hard
        digest = hashlib.sha256(self.recipe.encode()).hexdigest()
        assert self.rows["C"]["recipe"]["digest"] == self.rows["A"]["recipe"]["digest"] == digest
        assert self.rows["C"]["recipe"]["child_role"] == "A"
        assert self.rows["A"]["recipe"]["child_role"] == "W"
        assert self.rows["C"]["creator_joined"]["joined"] is True
        assert self.rows["A"]["creator_joined"]["joined"] is True
        assert all(task.spec.argv[5] == self.recipe for task in engine.ctx.tasks)
        return pids

    def bind_no_worker_observations(self):
        """Explicit no-W case; missing W still fails the three-role validator."""
        assert self.mode in NO_WORKER_MODES and not self.errors and self.closed
        assert self.outcome is not None and self.outcome._engine.slot.read() is self.outcome
        assert all(slot["state"] == "CLOSED" for slot in self.slots)
        engine = self.outcome._engine
        self.rows = {role: parse_trace(self.snapshots[role]) for role in ROLES}
        assert self.rows["W"] == {}
        pids = {"C": engine.child.pid, "A": self.rows["C"]["child_published"]["child"]}
        digest = hashlib.sha256(self.recipe.encode()).hexdigest()
        for role in ("C", "A"):
            rows = self.rows[role]
            assert rows and all(row["r"] == role and row["p"] == pids[role]
                                and row["n"] == engine.nonce.hex() for row in rows.values())
            assert rows["boot"]["run"] == engine.ctx.run and rows["boot"]["hard"] == engine.ctx.hard
        assert self.rows["C"]["recipe"]["digest"] == digest
        assert self.rows["C"]["recipe"]["child_role"] == "A"
        assert self.rows["C"]["creator_joined"]["joined"]
        assert all(task.spec.argv[5] == self.recipe for task in engine.ctx.tasks)
        anchor = self.rows["A"]
        assert not {"recipe", "child_published", "creator_joined"} & anchor.keys()
        no_worker, producer = anchor["no_worker"], anchor["no_worker_producers"]
        assert all(no_worker[key] for key in ("no_child", "child", "wait", "downstream"))
        assert not no_worker["attempted"] and not no_worker["unknown"] and no_worker["tasks"] == 0
        assert producer["moved"] and producer["group_done"] and producer["settled"] and producer["retired"]
        assert not producer["create"] and not producer["run"] and producer["hold"] == "CLOSED"
        assert anchor["owner_wait"]["child"] is None and anchor["owner_wait"]["kind"] is None
        assert anchor["owner_wait"]["code"] is None and not anchor["owner_wait"]["exact"]
        assert anchor["owner_io"]["joined"] and not anchor["owner_io"]["unknown"]
        assert not anchor["owner_io"]["eof"] and not anchor["owner_io"]["closed"]
        return pids

    def require_finality(self):
        pids = self.bind_observations()
        outcome, engine = self.outcome, self.outcome._engine
        assert outcome.original_finality is not None and outcome.original_finality._engine is engine
        assert engine.wait is engine.child.receipt and engine.wait.status_kind == "exit"
        assert all(task.joined for task in engine.ctx.tasks) and not engine.ctx.cleanup_unknown
        assert engine.wire.eof and engine.wire.reader.state == engine.wire.writer.state == "CLOSED"
        assert all(engine.output_eof) and all(reader.state == "CLOSED" for reader in engine.readers)
        for role in ("C", "A"):
            rows = self.rows[role]
            assert rows["owner_wait"]["exact"] is True
            assert rows["owner_io"]["joined"] and rows["owner_io"]["eof"] and rows["owner_io"]["closed"]
            assert not rows["owner_io"]["unknown"]
        assert self.rows["C"]["owner_wait"]["child"] == pids["A"]
        assert self.rows["A"]["owner_wait"]["child"] == pids["W"]
        assert self.rows["C"]["owner_finish"]["code"] == engine.wait.status_code
        assert self.rows["A"]["owner_finish"]["code"] == self.rows["C"]["owner_wait"]["code"]
        assert self.rows["A"]["owner_wait"]["kind"] == engine.terminal["wait"]["kind"]
        assert self.rows["A"]["owner_wait"]["code"] == engine.terminal["wait"]["code"]
        producer, absent = self.rows["C"]["producer"], self.rows["C"]["group_absent"]
        assert producer["sealed"] and producer["eof"] and producer["absent"] and producer["retired"]
        assert absent["group"] == pids["A"] and absent["wait_owned"]
        assert not absent["retired"] and not absent["numeric_retired"]
        return pids

    def release(self):
        self.require_finality()
        assert not self.released
        self.released = True
        _RETAINED_CASES.remove(self)

    def release_no_worker(self):
        pids = self.bind_no_worker_observations()
        outcome, engine = self.outcome, self.outcome._engine
        assert outcome.original_finality is not None and outcome.original_finality._engine is engine
        assert outcome.no_target is not None and outcome.no_target._engine is engine
        assert outcome.no_target.kind == "NO_W_CREATION" and outcome.returncode is None
        assert outcome.result_integrity == "complete"
        assert not outcome.create_w.attempted and not outcome.run_tool.attempted
        assert outcome.create_w.retired and outcome.run_tool.retired
        assert engine.wait is engine.child.receipt and engine.wait.status_kind == "exit"
        assert engine.local_cleanup_complete and not engine.ctx.cleanup_unknown
        assert all(task.joined for task in engine.ctx.tasks)
        assert engine.wire.eof and engine.wire.reader.state == engine.wire.writer.state == "CLOSED"
        assert all(engine.output_eof) and all(reader.state == "CLOSED" for reader in engine.readers)
        custodian = self.rows["C"]
        assert custodian["owner_wait"]["exact"] and custodian["owner_wait"]["child"] == pids["A"]
        assert all(custodian["owner_io"][key] for key in ("joined", "eof", "closed"))
        assert not custodian["owner_io"]["unknown"]
        assert custodian["owner_finish"]["code"] == engine.wait.status_code
        assert self.rows["A"]["owner_finish"]["code"] == custodian["owner_wait"]["code"]
        assert not self.released
        self.released = True
        _RETAINED_CASES.remove(self)
