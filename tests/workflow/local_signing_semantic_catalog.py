"""Finite, source-defined signing lifecycle cases; not an execution receipt.

This is the independently reviewed semantic SUBSET.  It deliberately does not
replace the global matrix inventory until the remaining native/caller and
delegated-regression obligations have an accepted exact-union mapping.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from types import MappingProxyType


SESSION = "<ROOT>/home/.mobile-release-signing/session-<TOKEN>"
KEYCHAIN = SESSION + "/keychain"
PROFILES = "<ROOT>/home/Library/MobileDevice/Provisioning Profiles"
PROFILE_STAGE = PROFILES + "/.mobile-release-profile-<TOKEN>"
PROFILE_DESTINATION = PROFILES + "/12345678-1234-1234-1234-1234567890AB.mobileprovision"
LOCAL = "mobile_release.local_signing:"
PROFILE_INSTALLER = "mobile_release.credentials:_temporary_profile_installation"
# Source-defined name, not a pathname/selector supplied by a worker report.
DB_NAME = "signing.keychain-db"
LOCK_NAME = ".flD3051040"
REFUSED = "refused-unknown-resource"
RECOVERED = "recovered"
CONFLICT = "recovered-with-conflict"
ABSENT = "absent"


@dataclass(frozen=True)
class Selector:
    operation: str
    slot: str
    origin: str
    phase: str
    occurrence: int = 1
    edge: str = "after"
    destination: str | None = None
    context: tuple[tuple[str, object], ...] = ()

    def __post_init__(self):
        assert type(self.occurrence) is int and self.occurrence > 0
        assert self.edge in {"before", "partial", "after"}
        assert self.phase in {"setup", "build", "cleanup", "command", "recovery"}
        assert self.context == tuple(sorted(self.context)) and len(dict(self.context)) == len(self.context)
        assert all(type(key) is str and (value is None or type(value) in {str, int, bool})
                   for key, value in self.context)
        assert (self.operation in {"replace", "link"}) == (self.destination is not None)

    def routes(self, event):
        """Count the original trace tuple BEFORE context filtering.

        A matching tuple/ordinal with the wrong live context must fail; it may
        not search for a later convenient match.  Global event index, inode,
        worker PID and a previous inventory have no role in selection.
        """
        return all(event.get(key) == getattr(self, key) for key in
                   ("operation", "slot", "origin", "phase", "occurrence")) and (
                   event.get("details", {}).get("destination") == self.destination)

    def check_context(self, context):
        for key, value in self.context:
            assert key in context and type(context[key]) is type(value) and context[key] == value, {
                "semanticContextMismatch": key, "expected": value, "actual": context.get(key)}

    def record(self):
        value = asdict(self)
        value["context"] = dict(self.context)
        return value


def io(operation, name, function, *, phase="setup", edge="after", occurrence=1,
       destination=None, **context):
    slot = name if name.startswith("<ROOT>") else SESSION + "/" + name
    return Selector(operation, slot, LOCAL + function, phase, occurrence, edge,
                    destination, tuple(sorted(context.items())))


def write(name="state", *, phase="setup", edge="partial", occurrence=1, **context):
    return io("write", name + ".pending", "_write", phase=phase, edge=edge, occurrence=occurrence,
              writeName=name + ".json", **context)


def commit(name="state", *, phase="setup", occurrence=1, **context):
    return io("replace", name + ".pending", "_write", phase=phase, occurrence=occurrence,
              destination=SESSION + "/" + name + ".json", writeName=name + ".json", **context)


def native(operation, *, phase="setup", edge="after", occurrence=1, **context):
    return Selector(operation, "native", "model", phase, occurrence, edge, None, tuple(sorted(context.items())))


_seeds = {
    "empty-session": io("mkdir", SESSION, "open", statePresent=False),
    "empty-native-directory": io("mkdir", KEYCHAIN, "open", statePresent=False),
    "intent-pending-empty": write("intent", edge="before", statePresent=False),
    "intent-pending-partial": write("intent", statePresent=False),
    "intent-committed": commit("intent", statePresent=False),
    "initial-state-pending": write(commandSequence=0, operationPhase=None),
    "profile-unrecorded-stage": Selector("open", PROFILE_STAGE, PROFILE_INSTALLER, "setup",
        context=(("profilePhase", "stage-intent"),)),
    "profile-partial-bytes": Selector("buffer.write", PROFILE_STAGE, PROFILE_INSTALLER, "setup", edge="partial",
        context=(("profilePhase", "stage-created"),)),
    "profile-complete-link": Selector("link", PROFILE_STAGE, PROFILE_INSTALLER, "setup",
        destination=PROFILE_DESTINATION, context=(("profilePhase", "link-intent"),)),
    "native-unrecorded-create": native("native-effect/create/" + DB_NAME, operationKind="create", operationPhase="ARMED"),
    "native-transaction-stage": native("native-effect/create/native-atomic-stage", operationKind="settings", operationPhase="ARMED"),
    "native-unrecorded-inode": native("native-effect/replace/" + DB_NAME, operationKind="settings", operationPhase="ARMED"),
    "active-before-build": io("open", "state.json", "_read_regular", phase="build", edge="before",
        operationKind="build", operationPhase="PREPARED"),
    "active-build-handed-off": native("native/build", phase="build", edge="before", operationKind="build", operationPhase="ARMED"),
    "active-build-result": native("native/build", phase="build", operationKind="build", operationPhase="ARMED"),
    "active-known-pending": write(phase="build", operationKind="build", operationPhase="PREPARED"),
    "active-build-pending": write(phase="build", occurrence=3, operationKind="build", operationPhase="SETTLED"),
    "active-after-build": io("open", "state.json", "_read_regular", phase="cleanup", edge="before", operationPhase=None),
    "default-restored": native("native-effect/preference/default", phase="cleanup", operationKind="default",
        operationPhase="ARMED", cleanupStarted=True),
    "search-restored": native("native-effect/preference/search", phase="cleanup", operationKind="search",
        operationPhase="ARMED", cleanupStarted=True),
    "terminal-pending-empty": write("completed", phase="cleanup", edge="before", operationPhase=None),
    "terminal-pending-partial": write("completed", phase="cleanup", operationPhase=None),
    "completed": commit("completed", phase="cleanup", operationPhase=None),
    "completed-without-state": io("unlink", "state.json", "_remove_control", phase="cleanup"),
    "completed-without-native-directory": io("rmdir", KEYCHAIN, "finish_terminal", phase="cleanup"),
    "completed-only": io("unlink", "intent.json", "_remove_control", phase="cleanup"),
    "final-empty": io("unlink", "completed.json", "_remove_control", phase="cleanup"),
    "final-absent": io("rmdir", SESSION, "_remove_empty_session", phase="cleanup"),
}
SEEDS = MappingProxyType(_seeds)
UNKNOWN_STATUS = MappingProxyType({
    "profile-unrecorded-stage": RECOVERED, "profile-partial-bytes": RECOVERED,
    "native-unrecorded-create": RECOVERED, "native-transaction-stage": CONFLICT,
    "native-unrecorded-inode": CONFLICT, "active-build-result": CONFLICT, "active-build-pending": CONFLICT,
})


@dataclass(frozen=True)
class Case:
    identifier: str
    kind: str
    seed: str | None
    selector: Selector | None
    manual: str
    expected: str
    resolution: str | None = None
    variant: str | None = None

    def __post_init__(self):
        assert self.kind in {"seed", "recovery", "command", "focused", "healthy"}
        assert self.manual in {"none", "observe", "resolve"}
        assert self.expected in {RECOVERED, CONFLICT, ABSENT, REFUSED, "focused"}
        assert self.resolution in {None, RECOVERED, CONFLICT}

    def record(self):
        result = asdict(self)
        result["selector"] = self.selector.record() if self.selector is not None else None
        return result


_cases = []
for _name, _selector in SEEDS.items():
    for _mode in (("none", "observe", "resolve") if _name in UNKNOWN_STATUS else ("none",)):
        _status = (UNKNOWN_STATUS[_name] if _mode == "resolve" else REFUSED) if _name in UNKNOWN_STATUS else (
            ABSENT if _name == "final-absent" else CONFLICT if _name in {"default-restored", "search-restored"} else RECOVERED)
        _cases.append(Case("S/" + _name + "/" + _mode, "seed", _name, _selector, _mode, _status,
                           UNKNOWN_STATUS[_name] if _status == REFUSED else None))


_recovery = (
    ("intent-pending-partial", io("unlink", "intent.pending", "_remove_control", phase="recovery"), RECOVERED),
    ("empty-native-directory", io("rmdir", KEYCHAIN, "cleanup_preparation", phase="recovery"), RECOVERED),
    ("empty-session", io("rmdir", SESSION, "_remove_empty_session", phase="recovery"), ABSENT),
    ("initial-state-pending", io("unlink", "state.pending", "_remove_control", phase="recovery"), RECOVERED),
    ("intent-committed", write(phase="recovery", commandSequence=0, operationPhase=None), RECOVERED),
    ("intent-committed", commit(phase="recovery", commandSequence=0, operationPhase=None), RECOVERED),
    ("active-known-pending", io("unlink", "state.pending", "_remove_control", phase="recovery"), RECOVERED),
    ("terminal-pending-partial", io("unlink", "completed.pending", "_remove_control", phase="recovery"), RECOVERED),
    ("profile-complete-link", io("unlink", PROFILE_STAGE, "cleanup_profile", phase="recovery"), RECOVERED),
    ("profile-complete-link", io("unlink", PROFILE_DESTINATION, "cleanup_profile", phase="recovery"), RECOVERED),
    ("active-before-build", native("native-effect/preference/default", phase="recovery", operationKind="default", operationPhase="ARMED"), CONFLICT),
    ("active-before-build", native("native-effect/preference/search", phase="recovery", operationKind="search", operationPhase="ARMED"), CONFLICT),
    ("active-before-build", native("native-effect/delete/" + DB_NAME, phase="recovery", operationKind="delete", operationPhase="ARMED"), RECOVERED),
    ("active-before-build", native("native-effect/delete/" + LOCK_NAME, phase="recovery", operationKind="delete", operationPhase="ARMED"), RECOVERED),
    ("active-before-build", write("completed", phase="recovery", operationPhase=None), RECOVERED),
    ("active-before-build", commit("completed", phase="recovery", operationPhase=None), RECOVERED),
    ("completed", io("rmdir", KEYCHAIN, "finish_terminal", phase="recovery"), RECOVERED),
    ("completed-without-native-directory", io("unlink", "intent.json", "_remove_control", phase="recovery"), RECOVERED),
    ("completed-only", io("unlink", "completed.json", "_remove_control", phase="recovery"), RECOVERED),
    ("final-empty", io("rmdir", SESSION, "_remove_empty_session", phase="recovery"), ABSENT),
)
for _number, (_seed, _selector, _status) in enumerate(_recovery, 1):
    _cases.append(Case(f"R/{_number:02}", "recovery", _seed, _selector, "none", _status))
for _seed, _status in UNKNOWN_STATUS.items():
    for _mode in ("observe", "resolve"):
        _selector = Selector("manual/input", "tty", "owner", "recovery", context=(("manualAction", _mode),))
        _cases.append(Case(f"R/manual/{_seed}/{_mode}-after", "recovery", _seed, _selector, _mode,
                           REFUSED if _mode == "observe" else _status, _status if _mode == "observe" else None))
for _seed in ("profile-unrecorded-stage", "native-unrecorded-create"):
    _cases.append(Case("R/manual/" + _seed + "/before", "recovery", _seed,
        Selector("manual/input", "tty", "owner", "recovery", edge="before", context=(("manualAction", "resolve"),)),
        "resolve", REFUSED, UNKNOWN_STATUS[_seed]))


def settlement_selectors(*, phase, kind, settled_occurrence):
    common = {"phase": phase, "operationKind": kind, "operationPhase": "SETTLED"}
    return (
        write(occurrence=settled_occurrence, **common),
        commit(occurrence=settled_occurrence, **common),
        io("unlink", "command-final.pending", "_retire_fence", **common),
        io("unlink", "command-final.json", "_retire_fence", **common),
        write(phase=phase, occurrence=settled_occurrence + 1, operationPhase=None),
        commit(phase=phase, occurrence=settled_occurrence + 1, operationPhase=None),
    )


QUERY_DEBT_SEED = write(phase="command", occurrence=3, operationKind="observe", operationPhase="SETTLED")
for _number, _selector in enumerate(settlement_selectors(phase="recovery", kind="observe", settled_occurrence=1), 1):
    _cases.append(Case(f"R/debt/{_number:02}", "recovery", "query-settled-partial", _selector, "none", RECOVERED))
# These are GLOBAL tuple occurrences, not context-filtered counts.  Recovery
# checkpoints its adopted empty-inflight state (1), then cleanupStarted (2),
# before the first default PREPARED (3), ARMED (4), SETTLED (5) and clear (6).
_new = (
    commit(phase="recovery", occurrence=3, operationKind="default", operationPhase="PREPARED"),
    commit(phase="recovery", occurrence=4, operationKind="default", operationPhase="ARMED", beforeGrant=True),
    *settlement_selectors(phase="recovery", kind="default", settled_occurrence=5),
)
for _number, _selector in enumerate(_new, 1):
    _cases.append(Case(f"R/new/{_number:02}", "recovery", "active-before-build", _selector, "none",
                       RECOVERED if _number <= 2 else CONFLICT))


_fence = (("PENDING_CREATE", "before"), ("PENDING_CREATE", "after"),
          ("PENDING_WRITE", "before"), ("PENDING_WRITE", "partial"), ("PENDING_WRITE", "after"),
          ("DATA_FSYNC", "before"), ("DATA_FSYNC", "after"),
          ("PENDING_CLOSE", "before"), ("PENDING_CLOSE", "after"),
          ("FINAL_LINK", "before"), ("FINAL_LINK", "after"),
          ("DIRECTORY_FSYNC", "before"), ("DIRECTORY_FSYNC", "after"))
for _number, (_operation, _edge) in enumerate(_fence, 1):
    _slot = SESSION if _operation == "DIRECTORY_FSYNC" else SESSION + (
        "/command-final.json" if _operation == "FINAL_LINK" else "/command-final.pending")
    _selector = Selector("command-fence/" + _operation, _slot, "original-custodian", "setup", edge=_edge,
                         context=(("operationKind", "observe"), ("operationPhase", "ARMED")))
    _cases.append(Case(f"C/fence/{_number:02}", "command", None, _selector, "none", RECOVERED))
_caller = (
    commit(phase="command", occurrence=1, operationKind="observe", operationPhase="PREPARED"),
    commit(phase="command", occurrence=2, operationKind="observe", operationPhase="ARMED", beforeGrant=True),
    *settlement_selectors(phase="command", kind="observe", settled_occurrence=3)[1:],
)
for _number, _selector in enumerate(_caller, 1):
    _cases.append(Case(f"C/caller/{_number:02}", "command", None, _selector, "none", RECOVERED))

FOCUSED_VARIANTS = (
    "foreign-default", "reordered-search", "deleted-search", "foreign-profile", "profile-inplace-edit",
    "native-unknown-stage", "foreign-native-db", "terminal-profile-reappeared", "terminal-native-reappeared",
    "manual-wrong", "manual-eof", "manual-cancel", "auto-add-active", "borrowed-profile", "auto-add-ambiguous-create",
)
for _number, _variant in enumerate(FOCUSED_VARIANTS, 1):
    _cases.append(Case(f"F/{_number:02}", "focused", None, None, "none", "focused", variant=_variant))
_cases.append(Case("H/full-context", "healthy", None, None, "none", RECOVERED))

assert len(SEEDS) == 28 and len(_cases) == 128 and len({item.identifier for item in _cases}) == 128
CASES = MappingProxyType({item.identifier: item for item in sorted(_cases, key=lambda item: item.identifier)})


def case(identifier):
    assert type(identifier) is str and identifier in CASES, "unknown semantic case"
    return CASES[identifier]


def definition():
    return {"schema": "mrk-signing-semantic-subset-v1", "completeRequiredUnion": False,
            "cases": [item.record() for item in CASES.values()]}
