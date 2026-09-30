"""Finite compile DATA for the reviewed retained-shell integration fixture.

No staging, build, native action, process launch or qualification occurs here.
The caller supplies five independently hash-bound DATA3 controls produced using
the existing stage() tool with the genuine pinned runtime47. This module only
reuses the existing profile renderer and constrains the compatible five-case set.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "_mrk_retained_shell_fixture_profile", Path(__file__).with_name("windows_installer_profile.py")
)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("Fixed installer profile renderer is unavailable")
profile = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(profile)
FixtureDataError = profile.ProfileError
require = profile.require

CASES = ("fresh", "reuse", "stop-copy", "wrong-caller", "bad-manifest")
PROFILE_HEADER = b"MRK_WINDOWS_RETAINED_SHELL_FIXTURE_PROFILE_SET_V1\n"
ROSTER_HEADER = "MRK_WINDOWS_RETAINED_SHELL_FIXTURE_ROSTER_V1"
OUTPUTS = ("fixture-profiles.ndjson", "fixture-roster.txt")
MAX_INPUT_BYTES = 128 * 1024 * 1024
MAX_PROFILE_SET_BYTES = len(PROFILE_HEADER) + len(CASES) * (profile.MAX_PROFILE_BYTES + 1)
MAX_ROSTER_BYTES = 32 * 1024
_ARGUMENTS = {"inventory", "admission", "expected_inventory", "expected_admission"}
_COMMON = (*profile.staging.COMMON_BINDINGS, "publisherSha256")


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def render_fixture_data(cases: list[dict] | tuple[dict, ...]) -> dict[str, bytes]:
    """Return two finite compile-input byte strings; no filesystem operation.

    Case order is fixed. Only shell row48 and its consequent control hashes may
    vary. A is the real embedded profile arm; B-E are test-only compatible
    profiles, never a runtime/production profile override.
    """
    require(type(cases) in (list, tuple) and len(cases) == len(CASES),
            "Exactly five fixed fixture profiles are required")
    encoded: list[bytes] = []
    values: list[dict] = []
    for case in cases:
        require(type(case) is dict and set(case) == _ARGUMENTS,
                "Fixture control arguments differ from the fixed renderer")
        require(type(case["inventory"]) is bytes and type(case["admission"]) is bytes,
                "Fixture controls must be original DATA byte strings")
        raw = profile.render_profile(**case)
        value = json.loads(raw)  # canonical output of the existing validator
        require(sum(row["size"] for row in value["inputs"]) <= MAX_INPUT_BYTES,
                "Fixture inputs exceed the fixed 128-MiB resource bound")
        encoded.append(raw)
        values.append(value)
    first = values[0]
    for value in values[1:]:
        require(all(value[key] == first[key] for key in _COMMON),
                "Fixture cases must share source, runtime, protocol and publisher")
        require(all(row == first["inputs"][index] for index, row in enumerate(value["inputs"])
                    if index not in (48, 52, 53)),
                "Only finalized shell and consequent controls may vary between cases")
    require(len({_digest(raw) for raw in encoded}) == len(CASES)
            and len({value["inputs"][48]["sha256"] for value in values}) == len(CASES),
            "Each fixture must have a distinct finalized shell and retained image")

    profiles = PROFILE_HEADER + b"".join(raw + b"\n" for raw in encoded)
    require(len(profiles) <= MAX_PROFILE_SET_BYTES, "Fixture profile table is oversized")
    lines = [
        ROSTER_HEADER,
        "profilesSha256=" + _digest(profiles),
        *[key + "=" + str(first[key]) for key in _COMMON],
    ]
    for name, raw, value in zip(CASES, encoded, values):
        lines.extend(("case=" + name, "image=" + _digest(raw)))
        lines.extend(f"{index}\t{row['size']}\t{row['sha256']}"
                     for index, row in enumerate(value["inputs"]))
    roster = ("\n".join(lines) + "\n").encode("ascii")
    require(len(roster) <= MAX_ROSTER_BYTES, "Fixture roster is oversized")
    return dict(zip(OUTPUTS, (profiles, roster)))
