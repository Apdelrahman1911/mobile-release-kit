"""Finite test-only workload bounds; never a production or phase override.

These source-derived candidate budgets are not measured capacity guarantees.
Actual enclosing original-owner/phase deadlines always remain authoritative.
"""
from __future__ import annotations

from types import MappingProxyType


WORKER_SECONDS = MappingProxyType({
    "minimal-query-seed": 20,
    "persistent-original": 120,
    "automatic-recovery": 60,
    "manual-recovery": 60,
    "focused-refusal": 60,
    "focused-owner": 60,
    "bare-home-original": 60,
    "bare-home-recovery": 60,
    "fresh-cli-recovery": 60,
    "account-native-flow": 120,
})

# All fifty actual ProfileInstallationSignalTests variants, not a permissive
# string prefix. The seventeen zero-model paths retain their original15s.
PROFILE_SIGNAL_SECONDS = MappingProxyType({
    "standalone-cleanup-entry:INT": 15,
    "standalone-cleanup-entry:TERM": 15,
    "standalone-cleanup-dispatch:INT": 15,
    "standalone-cleanup-dispatch:TERM": 15,
    "standalone-restore-entry:INT": 15,
    "standalone-restore-entry:TERM": 15,
    "standalone-restore-active:INT": 15,
    "standalone-restore-active:TERM": 15,
    "standalone-restore-term": 15,
    "standalone-restore-int": 15,
    "standalone-partial-install": 15,
    "standalone-pre-yield:INT": 15,
    "standalone-pre-yield:TERM": 15,
    "standalone-body:INT": 15,
    "standalone-body:TERM": 15,
    "open-home": 15,
    "partial-install": 15,
    "open-child": 60,
    "open-stage": 60,
    "fstat": 60,
    "fdopen": 60,
    "close": 60,
    "assigned-open": 60,
    "before-fstat": 60,
    "handoff": 60,
    "body-repeat": 120,
    "unexpected-cleanup": 120,
    "mutation-create": 120,
    "mutation-search": 120,
    "mutation-default": 120,
    "cleanup-entry:INT": 120,
    "cleanup-entry:TERM": 120,
    "cleanup-dispatch:INT": 120,
    "cleanup-dispatch:TERM": 120,
    "restore-entry:INT": 120,
    "restore-entry:TERM": 120,
    "restore-active:INT": 120,
    "restore-active:TERM": 120,
    "restore-term": 120,
    "restore-int": 120,
    "pre-yield:INT": 120,
    "pre-yield:TERM": 120,
    "body:INT": 120,
    "body:TERM": 120,
    "material-pre-yield:INT": 120,
    "material-pre-yield:TERM": 120,
    "material-body:INT": 120,
    "material-body:TERM": 120,
    "cleanup-error-signal:INT": 120,
    "cleanup-error-signal:TERM": 120,
})


def worker_timeout(role):
    assert type(role) is str and role in WORKER_SECONDS, "unknown signing workload role"
    return WORKER_SECONDS[role]


def recovery_timeout(manual):
    assert type(manual) is str and manual in {"none", "observe", "resolve"}, "unknown signing recovery workload"
    return worker_timeout("automatic-recovery" if manual == "none" else "manual-recovery")


def profile_signal_timeout(mode):
    assert type(mode) is str and mode in PROFILE_SIGNAL_SECONDS, "unknown signing profile signal workload"
    return PROFILE_SIGNAL_SECONDS[mode]
