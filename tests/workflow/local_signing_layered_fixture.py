"""Thin exact-union router inside the existing admitted matrix owner.

No standalone launcher, alternate deadline or filesystem/process custody scheme.
Only successful original helper lifecycles may produce typed coverage records.
"""
from __future__ import annotations

import gzip
import os
import shutil
import stat
import time
from itertools import islice

from workflow import local_signing_matrix_contract as contract
from workflow import local_signing_persistent_fixture as fixture
from unit.local_signing_workspace import assert_native_cases_idle


def _identity(path):
    value = path.lstat()
    contract.require(stat.S_ISDIR(value.st_mode) and stat.S_IMODE(value.st_mode) == 0o700
                     and value.st_uid == os.getuid(), "layered case directory state")
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid


def _file_identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _evidence(parent, deadline):
    contract.before_deadline(deadline)
    with os.scandir(parent) as entries:
        names = sorted(entry.name for entry in islice(entries, 6))
    contract.require(0 < len(names) <= 5, "layered evidence inventory")
    records, identities, total = {}, {}, 0
    for name in names:
        contract.before_deadline(deadline)
        path = parent / name
        info = path.lstat()
        contract.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                         and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid(),
                         "layered evidence file state")
        data, original = fixture.read_fixture_file(path, limit=2 * 1024**2)
        contract.require(_file_identity(original) == _file_identity(info),
                         "layered evidence changed before original read")
        total += len(data)
        contract.require(total <= 2 * 1024**2, "layered case evidence bound")
        records[name] = contract.strict_json(data)
        identities[name] = _file_identity(original)
    contract.before_deadline(deadline)
    return records, identities


def _dispose_parent(parent, identity, files, deadline):
    # Original helper returns and already-loaded ledgers establish finality;
    # neither a JSON boolean nor mere path absence authorizes this removal.
    assert_native_cases_idle()
    contract.before_deadline(deadline)
    contract.require(_identity(parent) == identity, "layered case parent changed")
    with os.scandir(parent) as entries:
        names = sorted(entry.name for entry in islice(entries, 6))
    contract.require(names == sorted(files), "layered retained evidence changed")
    for name, expected in files.items():
        contract.require(_file_identity((parent / name).lstat()) == expected, "layered evidence inode changed")
    contract.require(shutil.rmtree.avoids_symlink_attacks, "descriptor-relative layered removal unavailable")
    shutil.rmtree(parent)
    try:
        parent.lstat()
    except FileNotFoundError:
        pass
    else:
        raise ValueError("signing matrix: layered case path remains")
    contract.before_deadline(deadline)


def _private_opener(path, flags):
    return os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)


def _write_record(path, value, deadline):
    contract.before_deadline(deadline)
    data = contract.canonical(value) + b"\n"
    with open(path, "xb", opener=_private_opener) as stream:
        contract.require(stream.write(data) == len(data), "layered record short write")
        stream.flush()
        os.fsync(stream.fileno())
    contract.before_deadline(deadline)


def run_phase(output, shard, scope, package, package_files, definitions, *, deadline):
    """Execute only the source-defined shard; no native discovery prefix."""
    contract.before_deadline(deadline)
    contract.require(type(deadline) is float and fixture.PHASE_DEADLINE == deadline,
                     "layered original deadline not bound")
    catalog = contract.layered_catalog()
    operating_system = scope["os"]
    expected = list(catalog.expected_ids(operating_system))
    selected = list(catalog.shard_ids(operating_system, shard))
    definition = catalog.definition(operating_system)
    _identity(output)
    contract.require(not list(output.iterdir()), "layered phase output is not fresh")
    assert_native_cases_idle()
    from workflow import local_signing_primitive_fixture as primitive
    from workflow import local_signing_semantic_fixture as semantic
    from workflow import local_signing_regression_fixture as regression
    contract.require(tuple(primitive.COMPONENT_NAMES) == catalog.PRIMITIVE_NAMES, "primitive source API differs")
    contract.require({name: tuple(values) for name, values in (
        ("writer-failures", primitive._WRITER_FAILURES), ("reader-failures", primitive._READER_FAILURES),
        ("remover-failures", primitive._REMOVER_FAILURES))} == dict(catalog.PRIMITIVE_FAILURES),
        "primitive failure variants differ")
    _write_record(output / "catalog.json", definition, deadline)
    started, expanded, completed = time.monotonic(), 0, []
    destination = output / "results.jsonl.gz"
    with open(destination, "xb", opener=_private_opener) as raw:
        with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as compressed:
            for identifier in selected:
                contract.before_deadline(deadline)
                assert_native_cases_idle()
                item = catalog.case(identifier, operating_system)
                parent = output / ("case-" + identifier)
                parent.mkdir(mode=0o700)
                identity = _identity(parent)
                if item.kind == "primitive":
                    observed = primitive.run_component(parent, item.name.removeprefix("A/"))
                elif item.kind == "semantic":
                    observed = semantic.run_case(parent, item.name)
                else:
                    observed = regression.run_case(parent, item.name)
                assert_native_cases_idle()
                evidence, files = _evidence(parent, deadline)
                row = {"schemaVersion": 2, "caseId": identifier, "kind": item.kind, "name": item.name,
                       "observation": observed, "evidence": evidence,
                       "regressionParts": list(catalog.regression_parts(item, operating_system))}
                contract.require(contract.validate_layered_record(row, operating_system) == identifier,
                                 "layered original result differs")
                data = contract.canonical(row) + b"\n"
                expanded += len(data)
                contract.require(len(data) <= 2 * 1024**2 and expanded <= contract.MAX_EXPANDED_RESULTS,
                                 "layered result expanded bound")
                contract.before_deadline(deadline)
                contract.require(compressed.write(data) == len(data), "layered result short write")
                compressed.flush()
                raw.flush()
                os.fsync(raw.fileno())
                contract.require(raw.tell() <= contract.MAX_RESULTS_BYTES, "layered result compressed bound")
                # Complete original evidence is now durable in results before
                # deleting its task-owned parent. A late error withholds the
                # final phase result and retains the already-written evidence.
                _dispose_parent(parent, identity, files, deadline)
                completed.append(identifier)
        raw.flush()
        os.fsync(raw.fileno())
        contract.require(raw.tell() <= contract.MAX_RESULTS_BYTES, "layered final compressed bound")
    assert_native_cases_idle()
    contract.before_deadline(deadline)
    contract.require(completed == selected and contract.package_manifest(package, deadline=deadline) == package_files
                     and contract.definitions_manifest(fixture.ROOT, deadline=deadline) == definitions,
                     "layered final source or coverage differs")
    _write_record(output / "matrix-result.json", {
        "schemaVersion": 2, "shard": shard, "scope": scope, "expectedCaseIds": expected,
        "executedCaseIds": completed, "catalogSha256": contract.digest(definition),
        "packageSha256": contract.digest(package_files), "definitionsSha256": contract.digest(definitions),
        "coverage": catalog.coverage(operating_system, completed), "productionRoot": str(package),
        "elapsed": time.monotonic() - started,
        "allExactChildrenReapedAndGroupsAbsent": True, "allCasePathsRemoved": True,
    }, deadline)


if __name__ == "__main__":
    raise SystemExit("Use the fixed verify_ci matrix phase; raw layered execution is not admitted.")
