"""One source-defined signing coverage union; no native/product imports.

Logical IDs describe reviewed obligations, not historical crash executions.
Scheduling units are explicit source estimates, never measured time or a timer.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from types import MappingProxyType

OPERATING_SYSTEMS = ("ubuntu-24.04", "macos-26")
SHARDS = 16
SCHEMA = "mrk-signing-layered-catalog-v2"


def _require(value, message):
    if not value:
        raise ValueError("signing catalog: " + message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


_PEER_BINDINGS = {}


def _peer(name):
    # Exact adjacent pure source, including the outside-controller load path.
    # Do not insert tests into sys.path or import an ambient workflow package.
    _require(name in {"local_signing_semantic_catalog", "local_signing_regression_catalog"}, "unknown pure dependency")
    path = Path(__file__).resolve().with_name(name + ".py")
    _require(path.is_file() and not path.is_symlink(), "pure dependency missing")
    identity = "_mrk_signing_data_" + hashlib.sha256(str(path).encode()).hexdigest()
    _require(identity not in sys.modules, "pure dependency alias occupied")
    if name in _PEER_BINDINGS:
        module = _PEER_BINDINGS[name]
        _require(Path(module.__file__) == path, "pure dependency origin changed")
        return module
    spec = importlib.util.spec_from_file_location(identity, path)
    _require(spec is not None and spec.loader is not None, "pure dependency loader missing")
    module = importlib.util.module_from_spec(spec)
    sys.modules[identity] = module
    try:
        spec.loader.exec_module(module)
        _require(sys.modules.get(identity) is module, "pure dependency binding changed")
    finally:
        if sys.modules.get(identity) is module:
            del sys.modules[identity]
    _PEER_BINDINGS[name] = module
    return module


SEMANTIC = _peer("local_signing_semantic_catalog")
REGRESSION = _peer("local_signing_regression_catalog")
PRIMITIVE_NAMES = (
    "writer-intent-first", "writer-state-first", "writer-state-replace", "writer-completed-first",
    "remover-intent-json", "remover-state-json", "remover-completed-json",
    "remover-intent-pending", "remover-state-pending", "remover-completed-pending",
    "reader-private", "reader-profile", "installer-owned", "installer-borrowed",
    "writer-failures", "reader-failures", "remover-failures",
)
PRIMITIVE_FAILURES = MappingProxyType({
    "writer-failures": (
        "short-write", "zero-write", "oversized-write", "partial-write-error",
        "pending-intent", "pending-state", "pending-completed", "immutable-intent", "immutable-completed",
        "stage-replaced", "target-replaced", "file-sync-before", "file-sync-after",
        "directory-sync-before", "directory-sync-after", "close-after",
    ),
    "reader-failures": ("read-before", "read-after", "reader-name-changed", "reader-close-after"),
    "remover-failures": ("unlink-before", "unlink-after", "remove-sync-before", "remove-sync-after"),
})
# Complete source-planning table is mandatory before catalog admission.
# A missing row is an error, not zero-cost permission to dispatch a full matrix.
PRIMITIVE_PLANNING = MappingProxyType({
    "installer-borrowed": (0, 83, "Unchanged primitive algorithm; 41 normal-path events, before+after each, 0 write/buffer.write partial; 1+2*41+0=83 original invocations. Existing Linux direct-algorithm data supports event count only, NOT native/cut/platform capacity."),
    "installer-owned": (0, 98, "Unchanged primitive algorithm; 48 normal-path events, before+after each, 1 write/buffer.write partial; 1+2*48+1=98 original invocations. Existing Linux direct-algorithm data supports event count only, NOT native/cut/platform capacity."),
    "reader-failures": (0, 4, "Literal _READER_FAILURES: 4 fixed variants; one original run_worker each, no preliminary inventory or cut workers."),
    "reader-private": (0, 17, "Unchanged primitive algorithm; 8 normal-path events, before+after each, 0 write/buffer.write partial; 1+2*8+0=17 original invocations. Existing Linux direct-algorithm data supports event count only, NOT native/cut/platform capacity."),
    "reader-profile": (0, 17, "Unchanged primitive algorithm; 8 normal-path events, before+after each, 0 write/buffer.write partial; 1+2*8+0=17 original invocations. Existing Linux direct-algorithm data supports event count only, NOT native/cut/platform capacity."),
    "remover-completed-json": (0, 51, "Unchanged primitive algorithm; 25 normal-path events, before+after each, 0 write/buffer.write partial; 1+2*25+0=51 original invocations. Existing Linux direct-algorithm data supports event count only, NOT native/cut/platform capacity."),
    "remover-completed-pending": (0, 51, "Unchanged primitive algorithm; 25 normal-path events, before+after each, 0 write/buffer.write partial; 1+2*25+0=51 original invocations. Existing Linux direct-algorithm data supports event count only, NOT native/cut/platform capacity."),
    "remover-failures": (0, 4, "Literal _REMOVER_FAILURES: 4 fixed variants; one original run_worker each, no preliminary inventory or cut workers."),
    "remover-intent-json": (0, 51, "Unchanged primitive algorithm; 25 normal-path events, before+after each, 0 write/buffer.write partial; 1+2*25+0=51 original invocations. Existing Linux direct-algorithm data supports event count only, NOT native/cut/platform capacity."),
    "remover-intent-pending": (0, 51, "Unchanged primitive algorithm; 25 normal-path events, before+after each, 0 write/buffer.write partial; 1+2*25+0=51 original invocations. Existing Linux direct-algorithm data supports event count only, NOT native/cut/platform capacity."),
    "remover-state-json": (0, 51, "Unchanged primitive algorithm; 25 normal-path events, before+after each, 0 write/buffer.write partial; 1+2*25+0=51 original invocations. Existing Linux direct-algorithm data supports event count only, NOT native/cut/platform capacity."),
    "remover-state-pending": (0, 51, "Unchanged primitive algorithm; 25 normal-path events, before+after each, 0 write/buffer.write partial; 1+2*25+0=51 original invocations. Existing Linux direct-algorithm data supports event count only, NOT native/cut/platform capacity."),
    "writer-completed-first": (0, 72, "Unchanged primitive algorithm; 35 normal-path events, before+after each, 1 write/buffer.write partial; 1+2*35+1=72 original invocations. Existing Linux direct-algorithm data supports event count only, NOT native/cut/platform capacity."),
    "writer-failures": (0, 16, "Literal _WRITER_FAILURES: 16 fixed variants; one original run_worker each, no preliminary inventory or cut workers."),
    "writer-intent-first": (0, 72, "Unchanged primitive algorithm; 35 normal-path events, before+after each, 1 write/buffer.write partial; 1+2*35+1=72 original invocations. Existing Linux direct-algorithm data supports event count only, NOT native/cut/platform capacity."),
    "writer-state-first": (0, 72, "Unchanged primitive algorithm; 35 normal-path events, before+after each, 1 write/buffer.write partial; 1+2*35+1=72 original invocations. Existing Linux direct-algorithm data supports event count only, NOT native/cut/platform capacity."),
    "writer-state-replace": (0, 84, "Unchanged primitive algorithm; 41 normal-path events, before+after each, 1 write/buffer.write partial; 1+2*41+1=84 original invocations. Existing Linux direct-algorithm data supports event count only, NOT native/cut/platform capacity."),
})
SEMANTIC_PLANNING = MappingProxyType({
    "C/caller/01": (18, 2, "Catalog proposal §4; minimal caller seed2 + fresh genuine recovery16"),
    "C/caller/02": (19, 2, "Catalog proposal §4; minimal caller seed3 + fresh genuine recovery16; conservative entered-model attempt includes pre-grant path without claiming target execution"),
    "C/caller/03": (19, 2, "Catalog proposal §4; minimal caller seed3 + fresh genuine recovery16"),
    "C/caller/04": (19, 2, "Catalog proposal §4; minimal caller seed3 + fresh genuine recovery16"),
    "C/caller/05": (19, 2, "Catalog proposal §4; minimal caller seed3 + fresh genuine recovery16"),
    "C/caller/06": (19, 2, "Catalog proposal §4; minimal caller seed3 + fresh genuine recovery16"),
    "C/caller/07": (19, 2, "Catalog proposal §4; minimal caller seed3 + fresh genuine recovery16"),
    "C/fence/01": (19, 2, "Catalog proposal §4; minimal actual query seed3 + fresh genuine recovery16"),
    "C/fence/02": (19, 2, "Catalog proposal §4; minimal actual query seed3 + fresh genuine recovery16"),
    "C/fence/03": (19, 2, "Catalog proposal §4; minimal actual query seed3 + fresh genuine recovery16"),
    "C/fence/04": (19, 2, "Catalog proposal §4; minimal actual query seed3 + fresh genuine recovery16"),
    "C/fence/05": (19, 2, "Catalog proposal §4; minimal actual query seed3 + fresh genuine recovery16"),
    "C/fence/06": (19, 2, "Catalog proposal §4; minimal actual query seed3 + fresh genuine recovery16"),
    "C/fence/07": (19, 2, "Catalog proposal §4; minimal actual query seed3 + fresh genuine recovery16"),
    "C/fence/08": (19, 2, "Catalog proposal §4; minimal actual query seed3 + fresh genuine recovery16"),
    "C/fence/09": (19, 2, "Catalog proposal §4; minimal actual query seed3 + fresh genuine recovery16"),
    "C/fence/10": (19, 2, "Catalog proposal §4; minimal actual query seed3 + fresh genuine recovery16"),
    "C/fence/11": (19, 2, "Catalog proposal §4; minimal actual query seed3 + fresh genuine recovery16"),
    "C/fence/12": (19, 2, "Catalog proposal §4; minimal actual query seed3 + fresh genuine recovery16"),
    "C/fence/13": (19, 2, "Catalog proposal §4; minimal actual query seed3 + fresh genuine recovery16"),
    "F/01": (47, 2, "Catalog proposal §5 foreign-default; seed + one genuine final recovery; no post-success absent worker"),
    "F/02": (50, 2, "Catalog proposal §5 reordered-search; seed + one genuine final recovery; no post-success absent worker"),
    "F/03": (47, 2, "Catalog proposal §5 deleted-search; seed + one genuine final recovery; no post-success absent worker"),
    "F/04": (50, 2, "Catalog proposal §5 foreign-profile; seed + one genuine final recovery; no post-success absent worker"),
    "F/05": (70, 3, "Catalog proposal §5 profile-inplace-edit; seed + actual refusal + final locked recovery/fixture-owner; no post-success absent worker"),
    "F/06": (43, 3, "Catalog proposal §5 native-unknown-stage; seed + actual refusal + final locked recovery/fixture-owner; no post-success absent worker"),
    "F/07": (43, 4, "Catalog proposal §5 foreign-native-db; seed + automatic refusal + ordinary owner refusal + one reviewed fixture-owner final recovery; no post-success absent worker"),
    "F/08": (54, 3, "Catalog proposal §5 terminal-profile-reappeared; seed + actual refusal + final locked recovery/fixture-owner; no post-success absent worker"),
    "F/09": (50, 3, "Catalog proposal §5 terminal-native-reappeared; seed + actual refusal + final locked recovery/fixture-owner; no post-success absent worker"),
    "F/10": (38, 3, "Catalog proposal §5 manual-wrong; seed + actual refusal + final locked recovery/fixture-owner; no post-success absent worker"),
    "F/11": (38, 3, "Catalog proposal §5 manual-eof; seed + actual refusal + final locked recovery/fixture-owner; no post-success absent worker"),
    "F/12": (38, 3, "Catalog proposal §5 manual-cancel; seed + actual refusal + final locked recovery/fixture-owner; no post-success absent worker"),
    "F/13": (50, 2, "Catalog proposal §5 auto-add-active; seed + one genuine final recovery; no post-success absent worker"),
    "F/14": (50, 2, "Catalog proposal §5 borrowed-profile; seed + one genuine final recovery; no post-success absent worker"),
    "F/15": (19, 3, "Catalog proposal §5 auto-add-ambiguous-create; seed + actual refusal + final locked recovery/fixture-owner; no post-success absent worker"),
    "H/full-context": (50, 1, "PB2 accepted H50/H11/H7; one original full credential/setup/build/cleanup flow; observation adds no model command"),
    "N/native-prefix/database": (19, 3, "PB2 N3 supplement; original3 + fresh automatic refusal0 + actual locked resolution16"),
    "N/native-prefix/lock": (19, 3, "PB2 N3 supplement; original3 + fresh automatic refusal0 + actual locked resolution16"),
    "N/native-prefix/transaction-stage": (20, 3, "PB2 N3 supplement; original4 + fresh automatic refusal0 + actual locked resolution16"),
    "R/01": (6, 3, "Catalog proposal §3; original seed + interrupted original recovery + fresh declared final recovery"),
    "R/02": (4, 3, "Catalog proposal §3; original seed + interrupted original recovery + fresh declared final recovery"),
    "R/03": (2, 3, "Catalog proposal §3; original seed + interrupted original recovery + fresh declared final recovery"),
    "R/04": (22, 3, "Catalog proposal §3; original seed + interrupted original recovery + fresh declared final recovery; retain conservative22 although current direct no-resource arithmetic appears20, pending measured reconciliation"),
    "R/05": (22, 3, "Catalog proposal §3; original seed + interrupted original recovery + fresh declared final recovery; retain conservative22 although current direct no-resource arithmetic appears20, pending measured reconciliation"),
    "R/06": (20, 3, "Catalog proposal §3; original seed + interrupted original recovery + fresh declared final recovery"),
    "R/07": (49, 3, "Catalog proposal §3; original seed + interrupted original recovery + fresh declared final recovery"),
    "R/08": (64, 3, "Catalog proposal §3; original seed + interrupted original recovery + fresh declared final recovery"),
    "R/09": (28, 3, "Catalog proposal §3; original seed + interrupted original recovery + fresh declared final recovery"),
    "R/10": (28, 3, "Catalog proposal §3; original seed + interrupted original recovery + fresh declared final recovery"),
    "R/11": (51, 3, "Catalog proposal §3; original seed + interrupted original recovery + fresh declared final recovery"),
    "R/12": (53, 3, "Catalog proposal §3; original seed + interrupted original recovery + fresh declared final recovery"),
    "R/13": (55, 3, "Catalog proposal §3; original seed + interrupted original recovery + fresh declared final recovery"),
    "R/14": (55, 3, "Catalog proposal §3; original seed + interrupted original recovery + fresh declared final recovery"),
    "R/15": (61, 3, "Catalog proposal §3; original seed + interrupted original recovery + fresh declared final recovery"),
    "R/16": (49, 3, "Catalog proposal §3; original seed + interrupted original recovery + fresh declared final recovery"),
    "R/17": (52, 3, "Catalog proposal §3; original seed + interrupted original recovery + fresh declared final recovery"),
    "R/18": (54, 3, "Catalog proposal §3; original seed + interrupted original recovery + fresh declared final recovery"),
    "R/19": (54, 3, "Catalog proposal §3; original seed + interrupted original recovery + fresh declared final recovery"),
    "R/20": (52, 3, "Catalog proposal §3; original seed + interrupted original recovery + fresh declared final recovery"),
    "R/debt/01": (21, 3, "Finalizer supplement B1; actual query seed3 + interrupted recovery2 + fresh recovery16"),
    "R/debt/02": (21, 3, "Finalizer supplement B1; actual query seed3 + interrupted recovery2 + fresh recovery16"),
    "R/debt/03": (21, 3, "Finalizer supplement B1; actual query seed3 + interrupted recovery2 + fresh recovery16"),
    "R/debt/04": (21, 3, "Finalizer supplement B1; actual query seed3 + interrupted recovery2 + fresh recovery16"),
    "R/debt/05": (21, 3, "Finalizer supplement B1; actual query seed3 + interrupted recovery2 + fresh recovery16"),
    "R/debt/06": (21, 3, "Finalizer supplement B1; actual query seed3 + interrupted recovery2 + fresh recovery16"),
    "R/manual/active-build-pending/observe-after": (43, 4, "Catalog proposal §3; seed + manual original cut + fresh automatic refusal + locked resolution"),
    "R/manual/active-build-pending/resolve-after": (43, 3, "Catalog proposal §3; seed + manual original cut + fresh automatic final recovery"),
    "R/manual/active-build-result/observe-after": (43, 4, "Catalog proposal §3; seed + manual original cut + fresh automatic refusal + locked resolution"),
    "R/manual/active-build-result/resolve-after": (43, 3, "Catalog proposal §3; seed + manual original cut + fresh automatic final recovery"),
    "R/manual/native-transaction-stage/observe-after": (20, 4, "Catalog proposal §3; seed + manual original cut + fresh automatic refusal + locked resolution"),
    "R/manual/native-transaction-stage/resolve-after": (20, 3, "Catalog proposal §3; seed + manual original cut + fresh automatic final recovery"),
    "R/manual/native-unrecorded-create/before": (19, 4, "Catalog proposal §3; seed + original manual-before-input cut + fresh automatic refusal + locked resolution"),
    "R/manual/native-unrecorded-create/observe-after": (19, 4, "Catalog proposal §3; seed + manual original cut + fresh automatic refusal + locked resolution"),
    "R/manual/native-unrecorded-create/resolve-after": (19, 3, "Catalog proposal §3; seed + manual original cut + fresh automatic final recovery"),
    "R/manual/native-unrecorded-inode/observe-after": (20, 4, "Catalog proposal §3; seed + manual original cut + fresh automatic refusal + locked resolution"),
    "R/manual/native-unrecorded-inode/resolve-after": (20, 3, "Catalog proposal §3; seed + manual original cut + fresh automatic final recovery"),
    "R/manual/profile-partial-bytes/observe-after": (48, 4, "Catalog proposal §3; seed + manual original cut + fresh automatic refusal + locked resolution; CORRECTED old38 to48: seed2 + initial manual10 + fresh automatic refusal10 + manual resolution26"),
    "R/manual/profile-partial-bytes/resolve-after": (28, 3, "Catalog proposal §3; seed + manual original cut + fresh automatic final recovery"),
    "R/manual/profile-unrecorded-stage/before": (48, 4, "Catalog proposal §3; seed + original manual-before-input cut + fresh automatic refusal + locked resolution; CORRECTED old38 to48: 2+10+10+26"),
    "R/manual/profile-unrecorded-stage/observe-after": (48, 4, "Catalog proposal §3; seed + manual original cut + fresh automatic refusal + locked resolution; CORRECTED old38 to48: seed2 + initial manual10 + fresh automatic refusal10 + manual resolution26"),
    "R/manual/profile-unrecorded-stage/resolve-after": (28, 3, "Catalog proposal §3; seed + manual original cut + fresh automatic final recovery"),
    "R/new/01": (53, 3, "Finalizer supplement B2; seed26 + initial restoration prelude4 + fresh recovery23"),
    "R/new/02": (54, 3, "Finalizer supplement B2; seed26 + initial restoration prelude4 + entered before-grant command1 + fresh recovery23"),
    "R/new/03": (51, 3, "Finalizer supplement B2; seed26 + initial restoration prelude4 + actual restoration1 + fresh recovery20"),
    "R/new/04": (51, 3, "Finalizer supplement B2; seed26 + initial restoration prelude4 + actual restoration1 + fresh recovery20"),
    "R/new/05": (51, 3, "Finalizer supplement B2; seed26 + initial restoration prelude4 + actual restoration1 + fresh recovery20"),
    "R/new/06": (51, 3, "Finalizer supplement B2; seed26 + initial restoration prelude4 + actual restoration1 + fresh recovery20"),
    "R/new/07": (51, 3, "Finalizer supplement B2; seed26 + initial restoration prelude4 + actual restoration1 + fresh recovery20"),
    "R/new/08": (51, 3, "Finalizer supplement B2; seed26 + initial restoration prelude4 + actual restoration1 + fresh recovery20"),
    "S/active-after-build/none": (50, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode active-after-build/none"),
    "S/active-before-build/none": (49, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode active-before-build/none"),
    "S/active-build-handed-off/none": (50, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode active-build-handed-off/none"),
    "S/active-build-pending/none": (43, 3, "Catalog proposal §2; original seed + declared refusal + actual locked resolution; source/mode active-build-pending/none"),
    "S/active-build-pending/observe": (43, 3, "Catalog proposal §2; original seed + declared refusal + actual locked resolution; source/mode active-build-pending/observe"),
    "S/active-build-pending/resolve": (43, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode active-build-pending/resolve"),
    "S/active-build-result/none": (43, 3, "Catalog proposal §2; original seed + declared refusal + actual locked resolution; source/mode active-build-result/none"),
    "S/active-build-result/observe": (43, 3, "Catalog proposal §2; original seed + declared refusal + actual locked resolution; source/mode active-build-result/observe"),
    "S/active-build-result/resolve": (43, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode active-build-result/resolve"),
    "S/active-known-pending/none": (49, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode active-known-pending/none"),
    "S/completed-only/none": (52, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode completed-only/none"),
    "S/completed-without-native-directory/none": (52, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode completed-without-native-directory/none"),
    "S/completed-without-state/none": (52, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode completed-without-state/none"),
    "S/completed/none": (50, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode completed/none"),
    "S/default-restored/none": (52, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode default-restored/none"),
    "S/empty-native-directory/none": (2, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode empty-native-directory/none"),
    "S/empty-session/none": (2, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode empty-session/none"),
    "S/final-absent/none": (50, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode final-absent/none"),
    "S/final-empty/none": (52, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode final-empty/none"),
    "S/initial-state-pending/none": (18, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode initial-state-pending/none"),
    "S/intent-committed/none": (18, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode intent-committed/none"),
    "S/intent-pending-empty/none": (4, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode intent-pending-empty/none"),
    "S/intent-pending-partial/none": (4, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode intent-pending-partial/none"),
    "S/native-transaction-stage/none": (20, 3, "Catalog proposal §2; original seed + declared refusal + actual locked resolution; source/mode native-transaction-stage/none"),
    "S/native-transaction-stage/observe": (20, 3, "Catalog proposal §2; original seed + declared refusal + actual locked resolution; source/mode native-transaction-stage/observe"),
    "S/native-transaction-stage/resolve": (20, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode native-transaction-stage/resolve"),
    "S/native-unrecorded-create/none": (19, 3, "Catalog proposal §2; original seed + declared refusal + actual locked resolution; source/mode native-unrecorded-create/none"),
    "S/native-unrecorded-create/observe": (19, 3, "Catalog proposal §2; original seed + declared refusal + actual locked resolution; source/mode native-unrecorded-create/observe"),
    "S/native-unrecorded-create/resolve": (19, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode native-unrecorded-create/resolve"),
    "S/native-unrecorded-inode/none": (20, 3, "Catalog proposal §2; original seed + declared refusal + actual locked resolution; source/mode native-unrecorded-inode/none"),
    "S/native-unrecorded-inode/observe": (20, 3, "Catalog proposal §2; original seed + declared refusal + actual locked resolution; source/mode native-unrecorded-inode/observe"),
    "S/native-unrecorded-inode/resolve": (20, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode native-unrecorded-inode/resolve"),
    "S/profile-complete-link/none": (18, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode profile-complete-link/none"),
    "S/profile-partial-bytes/none": (38, 3, "Catalog proposal §2; original seed + declared refusal + actual locked resolution; source/mode profile-partial-bytes/none"),
    "S/profile-partial-bytes/observe": (48, 3, "Catalog proposal §2; original seed + declared refusal + actual locked resolution; source/mode profile-partial-bytes/observe"),
    "S/profile-partial-bytes/resolve": (28, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode profile-partial-bytes/resolve"),
    "S/profile-unrecorded-stage/none": (38, 3, "Catalog proposal §2; original seed + declared refusal + actual locked resolution; source/mode profile-unrecorded-stage/none"),
    "S/profile-unrecorded-stage/observe": (48, 3, "Catalog proposal §2; original seed + declared refusal + actual locked resolution; source/mode profile-unrecorded-stage/observe"),
    "S/profile-unrecorded-stage/resolve": (28, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode profile-unrecorded-stage/resolve"),
    "S/search-restored/none": (54, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode search-restored/none"),
    "S/terminal-pending-empty/none": (62, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode terminal-pending-empty/none"),
    "S/terminal-pending-partial/none": (62, 2, "Catalog proposal §2; original seed + declared final recovery; source/mode terminal-pending-partial/none"),
})


@dataclass(frozen=True)
class Case:
    kind: str
    name: str
    specification: str
    estimated_commands: int
    owned_workers: int
    planning_basis: str

    def __post_init__(self):
        _require(self.kind in {"primitive", "semantic", "regression"}, "unknown case kind")
        _require(type(self.name) is str and bool(self.name), "missing canonical name")
        _require(type(self.estimated_commands) is int and 0 <= self.estimated_commands <= 10000
                 and type(self.owned_workers) is int and 0 <= self.owned_workers <= 10000
                 and type(self.planning_basis) is str and bool(self.planning_basis), "unknown planning cost")

    @property
    def identifier(self):
        return digest({"schema": SCHEMA, "kind": self.kind, "name": self.name,
                       "specification": json.loads(self.specification)})

    @property
    def scheduling_units(self):
        return self.estimated_commands + 4 * self.owned_workers + 1

    def record(self):
        return {"caseId": self.identifier, "kind": self.kind, "name": self.name,
                "specification": json.loads(self.specification),
                "estimatedCommands": self.estimated_commands, "ownedWorkers": self.owned_workers,
                "planningBasis": self.planning_basis, "schedulingUnits": self.scheduling_units}


@cache
def cases_for(operating_system):
    _require(type(operating_system) is str and operating_system in OPERATING_SYSTEMS, "unknown operating system")
    _require(set(PRIMITIVE_PLANNING) == set(PRIMITIVE_NAMES) and len(PRIMITIVE_NAMES) == 17,
             "incomplete primitive planning table")
    _require(set(SEMANTIC_PLANNING) == set(SEMANTIC.CASES) and len(SEMANTIC.CASES) == 131,
             "incomplete semantic planning table")
    result = []
    for name in PRIMITIVE_NAMES:
        commands, workers, basis = PRIMITIVE_PLANNING[name]
        _require(commands == 0 and workers > 0, "primitive native or worker plan changed")
        specification = {"component": name, "failureVariants": list(PRIMITIVE_FAILURES.get(name, ()))}
        result.append(Case("primitive", "A/" + name, canonical(specification).decode(),
                           commands, workers, basis))
    for name, item in SEMANTIC.CASES.items():
        commands, workers, basis = SEMANTIC_PLANNING[name]
        result.append(Case("semantic", name, canonical(item.record()).decode(), commands, workers, basis))
    for item in REGRESSION.cases_for(operating_system):
        if item.kind == "execution":
            result.append(Case("regression", item.identifier, canonical(item.record()).decode(),
                               item.estimated_commands, item.owned_workers, item.planning_basis))
    _require(len({item.identifier for item in result}) == len(result)
             and len({item.name for item in result}) == len(result), "duplicate layered case")
    return tuple(sorted(result, key=lambda item: item.identifier))


@cache
def assignment(operating_system):
    cases = cases_for(operating_system)
    groups, weights = [[] for _ in range(SHARDS)], [0] * SHARDS
    for item in sorted(cases, key=lambda item: (-item.scheduling_units, item.identifier)):
        shard = min(range(SHARDS), key=lambda index: (weights[index], index))
        groups[shard].append(item.identifier)
        weights[shard] += item.scheduling_units
    _require(all(groups), "empty source-defined shard")
    return tuple(tuple(sorted(group)) for group in groups), tuple(weights)


def case(identifier, operating_system):
    _require(type(identifier) is str, "invalid case identifier")
    selected = [item for item in cases_for(operating_system) if item.identifier == identifier]
    _require(len(selected) == 1, "unknown case identifier")
    return selected[0]


def expected_ids(operating_system):
    return tuple(item.identifier for item in cases_for(operating_system))


def shard_ids(operating_system, shard):
    _require(type(shard) is int and 0 <= shard < SHARDS, "invalid shard")
    return assignment(operating_system)[0][shard]


def regression_parts(item, operating_system):
    _require(type(item) is Case, "expected original layered descriptor")
    if item.kind == "regression":
        return (item.name,)
    if item.kind == "semantic":
        return tuple(identifier for identifier in REGRESSION.semantic_contributions(item.name)
                     if operating_system in REGRESSION.case(identifier).platforms)
    return ()


def coverage(operating_system, identifiers):
    _require(type(identifiers) in {tuple, list} and list(identifiers) == sorted(set(identifiers)),
             "noncanonical coverage IDs")
    by_id = {item.identifier: item for item in cases_for(operating_system)}
    _require(all(identifier in by_id for identifier in identifiers), "unknown coverage ID")
    kinds = {"primitive": 0, "semantic": 0, "regression": 0}
    parts = []
    for identifier in identifiers:
        item = by_id[identifier]
        kinds[item.kind] += 1
        parts.extend(regression_parts(item, operating_system))
    _require(len(parts) == len(set(parts)), "duplicate original-regression contribution")
    return {"kinds": kinds, "regressionParts": sorted(parts)}


def definition(operating_system):
    groups, weights = assignment(operating_system)
    return {"schema": SCHEMA, "operatingSystem": operating_system, "shards": SHARDS,
            "cases": [item.record() for item in cases_for(operating_system)],
            "assignment": [list(group) for group in groups], "schedulingUnits": list(weights),
            "regressionObligations": {name: list(parts) for name, parts in REGRESSION.obligations(operating_system).items()},
            "semanticContributions": {name: list(REGRESSION.semantic_contributions(name))
                                      for name in SEMANTIC.CASES if REGRESSION.semantic_contributions(name)}}
