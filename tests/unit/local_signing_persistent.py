"""Persisted fictional native state and independent resource oracle, not credentials.

Production never reads these files. A new adapter must reload the last observed
effects after process death; it cannot manufacture a fresh baseline on recovery.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from mobile_release.local_signing import DB_NAME, LOCK_NAME

PROFILE = b"fictional-authenticated-profile"
UUID = "12345678-1234-1234-1234-1234567890AB"
_RETAINED_MODEL_LIFETIMES = []  # Original unknown thread/namespace custody; process retirement required.


class OwnerResolutionRefused(RuntimeError):
    """Independent fictional owner lacks authority; not a production exception."""


def _materializer_directory(original, private, created, *args, **kwargs):
    """Route only this fixture's materializer into its real model input root."""
    if kwargs.get('prefix') != 'mobile-release-build-inputs-':
        return original(*args, **kwargs)
    assert not args and set(kwargs) == {'prefix'}, 'materializer allocation contract changed'
    owner = original(dir=private, **kwargs)
    created.append(Path(owner.name))
    return owner


def write_json(path: Path, value: object) -> None:
    pending = path.with_suffix(".writing")
    with pending.open("wb") as stream:
        stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
        stream.flush()
        os.fsync(stream.fileno())
    pending.chmod(0o600)
    pending.replace(path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def facts(path: Path) -> dict | None:
    try:
        details = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(details.st_mode):
        return {"kind": "non-regular", "device": details.st_dev, "inode": details.st_ino}
    return {"device": details.st_dev, "inode": details.st_ino,
            "mode": stat.S_IMODE(details.st_mode), "size": details.st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


class ResourceOracle:
    def __init__(self, root: Path):
        self.root = root
        self.path = root / "independent-owner.json"
        assert self.path.is_file(), "oracle must be initialized outside the worker"

    def read(self):
        return json.loads(self.path.read_bytes())

    def record(self, path: Path, kind: str) -> None:
        relative = str(path.relative_to(self.root))
        state = self.read()
        if relative in state["sentinels"]:
            return  # Borrowed/preexisting resources never become owned.
        observed = facts(path)
        assert observed is not None and "sha256" in observed
        state[kind][relative] = observed
        write_json(self.path, state)

    def assert_sentinels(self):
        state = self.read()
        expected = dict(state["sentinels"])
        expected.update({path: change["after"] for path, change in state["foreignChanges"].items()})
        archive = state.get("fixtureForeignDbArchive")
        if archive is not None:
            assert set(archive) == {"source", "destination", "identity", "directoryIdentity"}
            source, destination = archive["source"], archive["destination"]
            assert destination == "fixture-owner-archive/foreign-native.keychain-db"
            assert source in state["native"] and source in state["foreignChanges"]
            assert Path(source).name == DB_NAME and source not in state["sentinels"]
            assert facts(self.root / source) is None, "archived fixture DB reappeared"
            for path, identity in ((self.root / destination, archive["identity"]),
                                   ((self.root / destination).parent, archive["directoryIdentity"])):
                observed = path.lstat()
                assert [observed.st_dev, observed.st_ino, observed.st_mode, observed.st_uid,
                        observed.st_gid, observed.st_nlink] == identity, "fixture archive identity changed"
            expected[destination] = expected.pop(source)
        for path, original in expected.items():
            assert facts(self.root / path) == original, "unrelated fixture state was changed: " + path

    def record_fixture_foreign_db_archive(self, source: Path, destination: Path) -> None:
        """One fixed fixture-owner transition; never adoption/production authority.

        The independent foreign edit history remains immutable. Only the exact
        replacement DB can be preserved at this exclusive case-owned archive.
        """
        state = self.read()
        relative = source.relative_to(self.root).as_posix()
        assert destination == self.root / "fixture-owner-archive/foreign-native.keychain-db"
        assert state.get("fixtureForeignDbArchive") is None, "repeated fixture archive transition"
        assert relative in state["native"] and relative in state["foreignChanges"]
        assert source.name == DB_NAME and relative not in state["sentinels"]
        assert facts(source) is None and facts(destination) == state["foreignChanges"][relative]["after"], \
            "unbound fixture archive transition"
        identities = []
        for path in (destination, destination.parent):
            value = path.lstat()
            assert value.st_uid == os.getuid()
            identities.append([value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid, value.st_nlink])
        assert stat.S_ISREG(identities[0][2]) and identities[0][-1] == 1
        assert stat.S_ISDIR(identities[1][2]) and stat.S_IMODE(identities[1][2]) == 0o700
        state["fixtureForeignDbArchive"] = {"source": relative,
            "destination": destination.relative_to(self.root).as_posix(),
            "identity": identities[0], "directoryIdentity": identities[1]}
        write_json(self.path, state)
        self.assert_sentinels()

    def record_foreign(self, path: Path, before: dict | None) -> None:
        """Explicit independently performed external edit, not a new owned file."""
        state = self.read()
        relative = str(path.relative_to(self.root))
        assert relative not in state["foreignChanges"]
        state["foreignChanges"][relative] = {"before": before, "after": facts(path)}
        write_json(self.path, state)

    def owned_remaining(self):
        state = self.read()
        return {name: facts(self.root / name) for kind in ("native", "profile") for name in state[kind]
                if (self.root / name).exists() and name not in state["foreignChanges"]}

    def resolve_owned(self, model):
        """Fictional owner work during locked TTY recheck, never journal editing."""
        state = self.read()
        keychain = model.state["keychain"]
        removable = []
        # Establish COMPLETE current ownership before changing even one
        # preference. The pathname alone cannot authorize detaching a replaced
        # DB. Prevalidation also prevents an edited profile from causing partial
        # fictional owner cleanup that could conceal a production refusal.
        for kind in ("native", "profile"):
            for relative, original in state[kind].items():
                path = self.root / relative
                observed = facts(path)
                if observed is None:
                    continue
                if relative in state["foreignChanges"] and kind == "profile":
                    continue  # A foreign profile is never owner cleanup work.
                if relative in state["foreignChanges"] or observed != original:
                    raise OwnerResolutionRefused("owner cannot identify an intervening replacement/edit")
                removable.append(path)
        preferences = copy.deepcopy(model.state["preferences"])
        if keychain in [preferences["default"], *preferences["search"]]:
            if keychain is None or Path(keychain) not in removable:
                raise OwnerResolutionRefused("owner cannot identify the currently referenced keychain")
        if preferences["default"] == keychain:
            preferences["default"] = model.state["original"]["default"]
        if keychain in preferences["search"]:
            preferences["search"] = (copy.deepcopy(model.state["original"]["search"])
                                     if preferences["search"] == [keychain] else
                                     [item for item in preferences["search"] if item != keychain])
        # These are owner actions, not allowed native API calls or CLI overrides.
        model.state["preferences"] = preferences
        model.save()
        removed = []
        for path in removable:
            path.unlink()
            removed.append(str(path.relative_to(self.root)))
        self.assert_sentinels()
        return removed


def initialize(root: Path, *, borrowed=False):
    home, private = root / "home", root / "private"
    home.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    original = {"default": str(home / "fictional login.keychain-db"),
                "search": [str(home / "fictional login.keychain-db"), str(home / "f\\ictional أرشيف.keychain-db")]}
    sentinels = []
    for index, name in enumerate(original["search"]):
        path = Path(name)
        path.write_bytes(b"fictional unrelated keychain " + str(index).encode())
        path.chmod(0o600)
        sentinels.append(path)
    directory = home / "Library/MobileDevice/Provisioning Profiles"
    directory.mkdir(parents=True, mode=0o700)
    foreign = directory / "99999999-9999-9999-9999-999999999999.mobileprovision"
    foreign.write_bytes(b"fictional unrelated profile")
    foreign.chmod(0o600)
    sentinels.append(foreign)
    if borrowed:
        existing = directory / (UUID + ".mobileprovision")
        existing.write_bytes(PROFILE)
        existing.chmod(0o600)
        sentinels.append(existing)
    for filename, content in (("p12", b"fictional-p12"), ("profile", PROFILE)):
        path = private / filename
        path.write_bytes(content)
        path.chmod(0o600)
        sentinels.append(path)
    write_json(root / "observed-native.json", {"original": original, "preferences": copy.deepcopy(original),
                                               "keychain": None, "revisions": 0, "calls": []})
    write_json(root / "independent-owner.json", {"sentinels": {str(path.relative_to(root)): facts(path) for path in sentinels},
                                                 "native": {}, "profile": {}, "foreignChanges": {}})


class PersistentSigningModel:
    def __init__(self, root: Path, *, trace=None, recovery=False, auto_add=False):
        self.root, self.trace, self.recovery, self.auto_add = root, trace, recovery, auto_add
        self.path = root / "observed-native.json"
        self.state = json.loads(self.path.read_bytes())  # Never reset on missing/corrupt state.
        self.oracle = ResourceOracle(root)

    def save(self):
        write_json(self.path, self.state)

    def effect(self, name, action, *, partial=None):
        event = self.trace.begin("native-effect/" + name, "native", "model", {}) if self.trace else None
        if event is not None and self.trace.partial(event):
            assert partial is not None, "partial cut selected for a non-write effect"
            partial()
            self.save()
            self.trace.cut(event, "partial")
        result = action()
        self.save()  # Persist the effect BEFORE the after-effect crash edge.
        if event is not None:
            self.trace.end(event, succeeded=True)
        return result

    def file_create(self, path):
        def create():
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
            self.oracle.record(path, "native")
        self.effect("create/" + path.name, create)

    def file_write(self, path, content):
        def write(data):
            with path.open("wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            self.oracle.record(path, "native")
        self.effect("write/" + path.name, lambda: write(content), partial=lambda: write(content[:max(1, len(content) // 2)]))

    def transaction(self):
        self.state["revisions"] += 1
        database = Path(self.state["keychain"])
        previous = facts(database)
        staging = database.parent / "native-atomic-stage"
        self.file_create(staging)
        self.file_write(staging, b"fictional-db-revision-" + str(self.state["revisions"]).encode())

        def replace():
            staging.replace(database)
            self.oracle.record(database, "native")
            assert facts(database)["inode"] != previous["inode"]
        self.effect("replace/" + DB_NAME, replace)

    def __call__(self, argv, *, result_policy=None, **kwargs):
        """Real command custody surrounds every independently persisted effect.

        This original worker services only Trace requests; the executed target
        performs the model IO. A selected Trace cut exits this worker73 without
        ACK, leaving real target/C lifetimes for their original owners to settle.
        """
        from mobile_release import owned_process
        from workflow import local_signing_case_owner as case_owner
        from workflow.local_signing_bridge import Channel, Namespace, VERSION, require, remaining, result_policy as policy_contract
        import mobile_release

        policy = policy_contract(result_policy)
        require(not _RETAINED_MODEL_LIFETIMES, "prior original model lifecycle is unresolved")
        timeout = kwargs.get("timeout", 30)
        require(type(timeout) is int and timeout > 0, "finite model timeout required")
        deadline = time.monotonic() + timeout
        require(type(argv) in (list, tuple) and 0 < len(argv) <= 64, "bounded fictional command required")
        command_argv = tuple(argv)
        require(0 < len(command_argv) <= 64
                and all(type(item) is str and 0 < len(item) <= 8192 for item in command_argv)
                and sum(len(item.encode("utf-8")) for item in command_argv) <= 32768,
                "bounded fictional command required")
        observer = getattr(self.trace, "observe_original_command", None)
        if observer is not None:
            # O observes its actual immutable input, not frames in separate W.
            # This work consumes the original endpoint before any acquisition.
            observer(self, command_argv)
            remaining(deadline)
        token = uuid.uuid4().hex
        stop = threading.Event()
        service_finished = threading.Event()
        original_target_returned = threading.Event()
        state = {"error": None, "done": False, "eof": False}
        service = None
        start_attempted = start_confirmed = join_confirmed = False
        complete = False
        primary = None
        cleanup_errors = []
        result = None
        target_result = None
        progress_command = None
        namespace = Namespace(self.root / ("model-bridge-" + token), create=True)
        try:
            progress_command = case_owner.adapter_progress("begin")
            # Open before any target creation. Only this original service owns
            # the descriptor once its actual thread starts.
            reader = namespace.open("events.fifo", os.O_RDONLY, deadline)

            def serve():
                try:
                    incoming = Channel(reader, deadline, stop=stop, peer_finished=original_target_returned)
                    case_owner.adapter_progress("HELLO", command=progress_command)  # Existing receive entry, not authentication.
                    hello = incoming.receive()
                    require(type(hello) is dict and type(hello.get("version")) is int
                            and hello == {"version": VERSION, "kind": "HELLO", "token": token}, "wrong target HELLO")
                    outgoing = Channel(namespace.open("acks.fifo", os.O_WRONLY, deadline), deadline, stop=stop)
                    outgoing.send({"version": VERSION, "kind": "HELLO-ACK", "token": token,
                                   "argv": list(command_argv), "recovery": self.recovery, "auto_add": self.auto_add,
                                   "trace": self.trace is not None, "result_policy": policy})
                    incoming.established = outgoing.established = True
                    sequence = 0
                    active = {}
                    while True:
                        record = incoming.receive()
                        sequence += 1
                        require(type(record) is dict and set(record) == {"version", "sequence", "kind", "value"}
                                and type(record["sequence"]) is int and record["sequence"] == sequence
                                and type(record["version"]) is int and record["version"] == VERSION
                                and record["kind"] in {"BEGIN", "PARTIAL", "END", "CUT", "DONE"},
                                "invalid target event")
                        kind, value = record["kind"], record["value"]
                        answer = None
                        if kind == "BEGIN":
                            require(type(value) is dict and set(value) == {"operation", "slot", "origin", "details"}
                                    and type(value["operation"]) is str and value["operation"].startswith(("native/", "native-effect/"))
                                    and value["slot"] == "native" and value["origin"] == "model"
                                    and value["details"] == {}, "unmodeled Trace request")
                            require(self.trace is not None, "original Trace is required")
                            require(len(active) < 2, "nested model effect bound")
                            case_owner.adapter_progress("BEGIN", command=progress_command)
                            answer = self.trace.begin(value["operation"], "native", "model", {})
                            active[answer["index"]] = answer
                        elif kind in {"PARTIAL", "END", "CUT"}:
                            event = value["event"] if kind != "PARTIAL" else value
                            require(type(event) is dict and type(event.get("index")) is int
                                    and event["index"] in active and event == active[event["index"]], "replayed or changed Trace event")
                            event = active[event["index"]]
                            if kind == "PARTIAL":
                                case_owner.adapter_progress("EFFECT", command=progress_command)
                                answer = self.trace.partial(event)
                            elif kind == "CUT":
                                require(set(value) == {"event", "edge"} and value["edge"] == "partial"
                                        and self.trace.partial(event), "unselected target cut")
                                case_owner.adapter_progress("EFFECT", command=progress_command)
                                self.trace.cut(event, "partial")  # Never returns or sends an ACK.
                            else:
                                require(set(value) == {"event", "succeeded", "error"}
                                        and type(value["succeeded"]) is bool
                                        and (value["error"] is None or type(value["error"]) is str), "invalid effect outcome")
                                case_owner.adapter_progress("END", command=progress_command)
                                self.trace.end(event, succeeded=value["succeeded"], error=value["error"])
                                active.pop(event["index"])
                        else:
                            require(value is None and not active, "model ended with incomplete effects")
                            case_owner.adapter_progress("DONE", command=progress_command)
                        outgoing.send({"version": VERSION, "sequence": sequence, "kind": kind + "-ACK", "value": answer})
                        if kind == "DONE":
                            namespace.close_node("acks.fifo")
                            # EOF is entry into the existing wait, not proof it completed.
                            case_owner.adapter_progress("EOF", command=progress_command)
                            incoming.require_eof()
                            state["eof"] = state["done"] = True
                            return
                except BaseException as error:
                    state["error"] = error
                finally:
                    namespace.close_node("acks.fifo")
                    namespace.close_node("events.fifo")
                    service_finished.set()  # No namespace/FD access may follow this original signal.

            service = threading.Thread(target=serve, name="mrk-model-trace", daemon=False)
            case_owner.adapter_progress("bind-service", command=progress_command, service=service)
            start_attempted = True  # Prearm before native thread creation can be attempted.
            service.start()
            start_confirmed = True
            target = Path(__file__).resolve().parents[1] / "workflow/local_signing_model_target.py"
            command = [sys.executable, "-I", "-S", "-B", str(target),
                       str(Path(mobile_release.__file__).resolve().parent.parent), str(namespace.path),
                       json.dumps(namespace.binding, sort_keys=True, separators=(",", ":")),
                       str(self.root), repr(deadline), token]
            options = dict(kwargs)
            source = options.pop("execution_source", None)
            if source is not None:
                require(options.get("execution_scope") is None and options.get("journal_binding") is None,
                        "source and selected scope are mutually exclusive")
                options["execution_scope"] = source.new_scope()
            case_owner.adapter_progress("run-owned", command=progress_command)
            target_result = owned_process.run_owned(command, **options)
            case_owner.adapter_progress("target-return", command=progress_command)  # Normal return, not success.
            result = target_result
            # A failed target cannot supply a future HELLO. Latch its actual
            # result before joining a service still awaiting its first writer;
            # the existing stop/join cleanup below retains that first failure.
            require(result.returncode == policy["returncode"]
                    and result.stderr == (policy["stderr"] if kwargs.get("capture", True) else ""),
                    "fixed model target result differs from actual selected behavior")
            # This hint permits a real nonblocking FIFO observation, not an
            # inferred EOF or service settlement. Buffered DONE/EOF work may
            # still belong to the original service after the target returns.
            original_target_returned.set()
            service.join(timeout=remaining(deadline))
            require(service_finished.is_set() and not service.is_alive(), "original model service join unresolved")
            join_confirmed = True
            case_owner.adapter_progress("service-joined", command=progress_command, service=service)
            if state["error"] is not None:
                raise AssertionError("original model observation failed") from state["error"]
            require(not service.is_alive() and state["done"] and state["eof"]
                    and not namespace.close_errors, "original model service not settled")
            namespace.remove()
            complete = True
            self.state = json.loads(self.path.read_bytes())
            # Only args are projected; return/status/streams and the selected
            # scope's original outcome are never manufactured or replaced.
            result = subprocess.CompletedProcess(argv, result.returncode, result.stdout, result.stderr)
        except BaseException as error:
            primary = error
            if target_result is not None:
                try:
                    case_owner.observe_adapter_target_result(target_result)
                except BaseException:
                    pass  # Optional data only, after the original failure latch.
        finally:
            try:
                stop.set()
            except BaseException as error:
                cleanup_errors.append(error)
            if start_confirmed and not join_confirmed:
                try:
                    service.join(timeout=max(0, deadline - time.monotonic()))
                    require(service_finished.is_set() and not service.is_alive(), "model service original join unresolved")
                    join_confirmed = True
                    case_owner.adapter_progress("service-joined", command=progress_command, service=service)
                except BaseException as error:
                    cleanup_errors.append(error)
            if start_attempted and not join_confirmed:
                # Missing ident/is_aliveFalse is not original no-creation or
                # join evidence when Thread.start itself was interrupted.
                # The stop barrier makes any delayed service fail before IO;
                # only that service may retire its preregistered FIFO slots.
                _RETAINED_MODEL_LIFETIMES.append((namespace, service, service_finished, stop, state,
                                                original_target_returned))
                cleanup_errors.append(AssertionError("original model thread startup/join custody remains unknown"))
            elif not complete:
                # Preserve the identity-bound namespace on command/bridge
                # uncertainty. Later case cleanup cannot normalize this failure.
                if not namespace.close():
                    cleanup_errors.extend(namespace.close_errors)
            observation_error = state["error"]
            if (observation_error is not None and observation_error is not primary
                    and (primary is None or BaseException.__dict__["__cause__"].__get__(primary, BaseException)
                         is not observation_error)
                    and not any(error is observation_error for error in cleanup_errors)):
                # Early target/command failure must not erase the independently
                # observed service failure, nor replace the original primary.
                cleanup_errors.append(observation_error)
        if primary is not None:
            if cleanup_errors:
                primary._model_cleanup_errors = tuple(cleanup_errors)
                primary.add_note("model cleanup failures: " + ",".join(type(error).__name__ for error in cleanup_errors))
            raise primary
        require(not cleanup_errors and complete and result is not None, "model cleanup unresolved")
        case_owner.adapter_progress("model-return", command=progress_command)
        return result

    def execute_model(self, argv):
        """Only the fixed target invokes the retained model's actual effects."""
        command = argv[1] if Path(argv[0]).name == "security" else Path(argv[0]).name
        if self.recovery:
            assert command in {"default-keychain", "list-keychains", "delete-keychain"}, "recovery repeated setup/build"
        event = self.trace.begin("native/" + command, "native", "model", {}) if self.trace else None
        self.state["calls"].append({"command": command, "recovery": self.recovery,
                                     "mutation": "-s" in argv or command not in {"default-keychain", "list-keychains"}})
        stdout = ""
        if command in {"default-keychain", "list-keychains"}:
            field = "default" if command == "default-keychain" else "search"
            if "-s" in argv:
                value = argv[argv.index("-s") + 1:]
                def set_preference():
                    self.state["preferences"][field] = value[0] if field == "default" else value
                self.effect("preference/" + field, set_preference)
            else:
                value = self.state["preferences"][field]
                values = [value] if field == "default" else value
                stdout = "".join('    "' + item + '"\n' for item in values)
        elif command == "create-keychain":
            self.state["keychain"] = argv[-1]
            keychain = Path(argv[-1])
            self.file_create(keychain)
            self.file_write(keychain, b"fictional-db")
            self.file_create(keychain.parent / LOCK_NAME)
            self.file_write(keychain.parent / LOCK_NAME, b"fictional-lock")
            if self.auto_add:
                self.effect("create-search-add", lambda: self.state["preferences"]["search"].append(str(keychain)))
        elif command in {"set-keychain-settings", "unlock-keychain", "import", "set-key-partition-list", "build"}:
            self.transaction()
        elif command == "openssl":
            assert "-out" in argv
            destination = Path(argv[argv.index("-out") + 1])
            destination.relative_to(self.root / "private")
            # Exercise all three production imports, including the chain branch.
            self.effect("extract", lambda: destination.write_bytes(
                b"-----BEGIN CERTIFICATE-----\nfictional-not-a-certificate\n"))
        elif command == "delete-keychain":
            keychain = Path(self.state["keychain"])
            assert str(keychain) not in [self.state["preferences"]["default"], *self.state["preferences"]["search"]]
            for name in (DB_NAME, LOCK_NAME):
                path = keychain.parent / name
                if path.exists():
                    assert facts(path) == self.oracle.read()["native"][str(path.relative_to(self.root))]
                    self.effect("delete/" + name, path.unlink)
        else:
            raise AssertionError("unmodeled native command: " + command)
        self.save()
        if event is not None:
            self.trace.end(event, succeeded=True)
        return stdout
