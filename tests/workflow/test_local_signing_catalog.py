"""Pure source-loader custody contracts, not native execution evidence."""
from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from . import local_signing_matrix_contract as contract


class SigningCatalogAdmissionTests(unittest.TestCase):
    def test_capacity_canary_covers_command_worker_peaks_and_original_failed_cases(self):
        catalog = contract.layered_catalog()
        self.assertEqual((contract.SHARDS, catalog.SHARDS), (48, 48))
        for operating_system, heavy_shard, command_max in (("ubuntu-24.04", 20, 361), ("macos-26", 1, 363)):
            with self.subTest(operating_system=operating_system):
                cases = {item.identifier: item for item in catalog.cases_for(operating_system)}
                groups, _weights = catalog.assignment(operating_system)
                estimates = [sum(cases[identifier].estimated_commands for identifier in group)
                             for group in groups]
                workers = [sum(cases[identifier].owned_workers for identifier in group) for group in groups]
                self.assertEqual((estimates[heavy_shard], max(estimates)), (command_max, command_max))
                self.assertEqual((workers[0], max(workers)), (99, 99))
                self.assertIn("A/installer-owned", {cases[identifier].name for identifier in groups[0]})
                # Planning arithmetic selects useful probes; it is not measured
                # capacity or permission to omit any of the forty-eight shards.
        for operating_system, shard, identifier, name in (
            ("ubuntu-24.04", 28, "626776edad3a2c9ba7ef48a7d457e9dcbe556e51fe8082dcea814208280472d7",
             "G/unit.test_ios_profile_installation.ProfileInstallationSignalTests."
             "test_late_setup_and_actual_materialized_body_cancellation_never_execute_following_build_code/variant/material-body:TERM"),
            ("macos-26", 12, "b67561fee0d342c81aadbd88dee9d48aacf5653274556ba4c814f6b141a920eb",
             "G/unit.test_local_signing_recovery.SigningRecoveryTests."
             "test_prepared_without_any_command_dispatch_needs_a_fresh_attempt_before_cleanup/whole"),
            ("macos-26", 37, "224b4cdf58e40ff3b8e9b008b7ba5ebfa9fb856cf9850613515e7350e6b2c75a",
             "S/native-unrecorded-create/resolve"),
        ):
            with self.subTest(original_failure=(operating_system, shard)):
                self.assertIn(identifier, catalog.shard_ids(operating_system, shard))
                self.assertEqual(catalog.case(identifier, operating_system).name, name)

    def loaders(self):
        catalog = contract.layered_catalog()
        yield contract, contract.layered_catalog, "_LAYERED_CATALOG", None, catalog, "_mrk_layered_"
        for name in ("local_signing_semantic_catalog", "local_signing_regression_catalog"):
            yield (catalog, lambda name=name: catalog._peer(name), "_PEER_BINDINGS", {},
                   catalog._peer(name), "_mrk_signing_data_")

    def test_original_objects_are_reused_without_leaving_aliases_or_accepting_filename_lookalikes(self):
        for module, load, _cache, _empty, original, prefix in self.loaders():
            with self.subTest(source=original.__file__):
                path = Path(original.__file__).resolve()
                alias = prefix + hashlib.sha256(str(path).encode()).hexdigest()
                self.assertNotIn(alias, sys.modules)
                self.assertIs(load(), original)
                foreign = SimpleNamespace(__file__=str(path))
                with patch.dict(sys.modules, {alias: foreign}):
                    with self.assertRaisesRegex(ValueError, "alias occupied"):
                        load()
                    self.assertIs(sys.modules[alias], foreign)
                self.assertIs(load(), original)
                self.assertNotIn(alias, sys.modules)

    def test_failed_original_load_never_caches_or_removes_a_replacement_binding(self):
        for module, load, cache, empty, original, prefix in self.loaders():
            path = Path(original.__file__).resolve()
            alias = prefix + hashlib.sha256(str(path).encode()).hexdigest()
            for replacement, raise_original in ((False, True), (True, False), (True, True)):
                with self.subTest(source=path.name, replacement=replacement, raise_original=raise_original):
                    candidate = SimpleNamespace(__file__=str(path))
                    foreign = SimpleNamespace(__file__=str(path))
                    failure = RuntimeError("inert original loader failure")

                    def execute(value):
                        self.assertIs(value, candidate)
                        self.assertIs(sys.modules[alias], candidate)
                        if replacement:
                            sys.modules[alias] = foreign
                        if raise_original:
                            raise failure

                    spec = SimpleNamespace(loader=SimpleNamespace(exec_module=execute))
                    with patch.object(module, cache, empty), patch.dict(sys.modules), \
                            patch.object(module.importlib.util, "spec_from_file_location", return_value=spec), \
                            patch.object(module.importlib.util, "module_from_spec", return_value=candidate):
                        with self.assertRaises(RuntimeError if raise_original else ValueError) as raised:
                            load()
                        if raise_original:
                            self.assertIs(raised.exception, failure)
                        else:
                            self.assertIn("binding changed", str(raised.exception))
                        if replacement:
                            self.assertIs(sys.modules[alias], foreign)
                        else:
                            self.assertNotIn(alias, sys.modules)
                        self.assertEqual(getattr(module, cache), empty)
                self.assertIs(load(), original)
