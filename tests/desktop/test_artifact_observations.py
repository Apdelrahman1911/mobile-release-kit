"""Inert record/ABI DATA tests; no files, archives, native tools or custody.

CLI IO behavior is represented by narrow mocks, not replayed on the filesystem.
ZIP metadata fixtures are deliberately constructible DATA, not integrity results
or original-artifact receipts. Source was authored without importing/running it.
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from mobile_release import android_zip as zip_policy
from mobile_release import provenance
from mobile_release.errors import ValidationError


DIGEST = "a" * 64
KEYS = {"logicalName", "platform", "kind", "fileName", "size", "sha256", "architectures"}


def observation(**changes):
    value = provenance.ArtifactObservation("android-aab", "app.aab", 17, DIGEST, ("arm64-v8a",))
    return replace(value, **changes)


def entry(name, **changes):
    value = zip_policy.AndroidZipEntry(name, name.encode("utf-8"), 0x0800, 0, 0, 0, 0, 0, 0, 3, 10)
    return replace(value, **changes)


def metadata(*entries):
    # Shape-only fixture: these invented extents are intentionally NOT proof of
    # admitted ZIP bytes. The pure ABI helper cannot confer original custody.
    plan = zip_policy.ZipDirectoryPlan(1000, 978, len(entries), zip_policy.ZipReadRange(900, 78))
    return zip_policy.AndroidZipMetadata(plan, tuple(entries), 0)


def abis(value, checkpoint=lambda: None):
    return provenance.android_abis_from_zip_metadata(value, checkpoint=checkpoint)


class PathData:
    """No actual Path or file operations; exposes the legacy call sequence."""

    def __init__(self, name="app.aab", *, sizes=(17, 17), symlink=False, regular=True):
        self.basename, self.sizes, self.symlink, self.regular = name, iter(sizes), symlink, regular
        self.events = []

    def is_symlink(self):
        self.events.append("is_symlink")
        return self.symlink

    def is_file(self):
        self.events.append("is_file")
        return self.regular

    def stat(self):
        self.events.append("stat")
        return SimpleNamespace(st_size=next(self.sizes))

    @property
    def name(self):
        self.events.append("name")
        return self.basename


class ArtifactObservationTests(unittest.TestCase):
    def refused(self, reason, function, *args, **kwargs):
        with self.assertRaises(provenance.ArtifactObservationError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.reason, reason)
        self.assertNotIn("PRIVATE", str(caught.exception))
        return caught.exception

    def test_pure_constructor_preserves_every_existing_logical_name_platform_kind_and_schema(self):
        expected = {
            "android-aab": ("android", "aab"), "android-apk": ("android", "apk"),
            "android-mapping": ("android", "r8-mapping"), "android-native-symbols": ("android", "native-symbols"),
            "ios-ipa": ("ios", "ipa"), "ios-archive": ("ios", "xcarchive"), "ios-dsyms": ("ios", "dsym"),
            "store-metadata": ("shared", "metadata"), "validation-report": ("shared", "validation-report"),
        }
        self.assertEqual(provenance.ARTIFACT_TYPES, expected)
        for name, (platform, kind) in expected.items():
            value = provenance._artifact_record(name, file_name="legacy:name", size=17,
                                                 sha256=DIGEST, architectures=[])
            self.assertEqual(value, {"logicalName": name, "platform": platform, "kind": kind,
                                     "fileName": "legacy:name", "size": 17, "sha256": DIGEST, "architectures": []})
            self.assertEqual(set(value), KEYS)
        with self.assertRaisesRegex(ValidationError, "unsupported artifact logical name: other"):
            provenance._artifact_record("other", file_name="app.aab", size=17, sha256=DIGEST, architectures=[])

    def test_cli_and_data_call_the_same_constructor_without_changing_cli_reads_or_field_values(self):
        path = PathData()

        def digest(original):
            self.assertIs(original, path)
            path.events.append("sha256")
            return DIGEST

        def architectures(name, original):
            self.assertEqual(name, "android-aab")
            self.assertIs(original, path)
            path.events.append("architectures")
            return ["arm64-v8a"]

        with patch.object(provenance, "sha256_file", side_effect=digest), \
                patch.object(provenance, "_artifact_architectures", side_effect=architectures), \
                patch.object(provenance, "_artifact_record", wraps=provenance._artifact_record) as constructor:
            old = provenance.artifact_records(iter((("android-aab", path),)))
            new = provenance.artifact_records_from_observations((observation(),))
            self.assertEqual(constructor.call_count, 2)
        self.assertEqual(old, new)
        self.assertEqual(path.events, ["is_symlink", "is_file", "stat", "name", "stat", "sha256", "architectures"])

    def test_cli_still_accepts_its_iterable_and_all_logical_types_and_sorts_records(self):
        names = tuple(reversed(tuple(provenance.ARTIFACT_TYPES)))
        values = ((name, PathData(f"{name}.data")) for name in names)
        with patch.object(provenance, "sha256_file", return_value=DIGEST), \
                patch.object(provenance, "_artifact_architectures", return_value=[]):
            records = provenance.artifact_records(values)
        self.assertEqual([value["logicalName"] for value in records], sorted(names))
        self.assertTrue(all(set(value) == KEYS for value in records))
        self.assertEqual(provenance.artifact_records(iter(())), [])

    def test_cli_refusal_order_and_duplicate_short_circuit_are_unchanged(self):
        for path, expected, calls in (
            (PathData(symlink=True), "regular non-symlink", ["is_symlink"]),
            (PathData(regular=False), "regular non-symlink", ["is_symlink", "is_file"]),
            (PathData(), "unsupported artifact logical name", ["is_symlink", "is_file"]),
        ):
            with self.assertRaisesRegex(ValidationError, expected):
                provenance.artifact_records((("unsupported", path),))
            self.assertEqual(path.events, calls)
        empty = PathData(sizes=(0,))
        with self.assertRaisesRegex(ValidationError, "artifact is empty: android-aab"):
            provenance.artifact_records((("android-aab", empty),))
        self.assertEqual(empty.events, ["is_symlink", "is_file", "stat"])
        first, duplicate = PathData(), PathData()
        with patch.object(provenance, "sha256_file", return_value=DIGEST), \
                patch.object(provenance, "_artifact_architectures", return_value=[]):
            with self.assertRaisesRegex(ValidationError, "duplicate artifact name: android-aab"):
                provenance.artifact_records((("android-aab", first), ("android-aab", duplicate)))
        self.assertEqual(duplicate.events, [])

    def test_cli_keeps_its_second_size_observation_and_propagates_read_failures(self):
        path = PathData(sizes=(17, 23))
        with patch.object(provenance, "sha256_file", return_value=DIGEST), \
                patch.object(provenance, "_artifact_architectures", return_value=[]):
            self.assertEqual(provenance.artifact_records((("android-aab", path),))[0]["size"], 23)
        for function in ("sha256_file", "_artifact_architectures"):
            original = OSError("PRIVATE original file failure")
            with patch.object(provenance, "sha256_file", return_value=DIGEST), \
                    patch.object(provenance, "_artifact_architectures", return_value=[]), \
                    patch.object(provenance, function, side_effect=original):
                with self.assertRaises(OSError) as caught:
                    provenance.artifact_records((("android-aab", PathData()),))
            self.assertIs(caught.exception, original)

    def test_legacy_aab_architecture_read_preserves_all_labels_and_prefix_semantics(self):
        path = object()
        archive = MagicMock()
        archive.__enter__.return_value.namelist.return_value = [
            "base/lib/x86/", "base/lib/arm64-v8a/libx.so", "base/lib/x86/nested/file",
            "base/lib/PRIVATE-legacy-abi/file", "base/lib//file", "feature/lib/x86_64/libx.so",
            "base/lib/x86", "other/file", "base/lib/arm64-v8a/second.so",
        ]
        with patch.object(provenance.zipfile, "ZipFile", return_value=archive) as constructor:
            self.assertEqual(provenance._artifact_architectures("android-aab", path),
                             ["", "PRIVATE-legacy-abi", "arm64-v8a", "x86"])
            constructor.assert_called_once_with(path)
            archive.__enter__.return_value.namelist.assert_called_once_with()
        with patch.object(provenance.zipfile, "ZipFile", side_effect=AssertionError("not Android AAB")):
            for name in provenance.ARTIFACT_TYPES.keys() - {"android-aab"}:
                self.assertEqual(provenance._artifact_architectures(name, path), [])

    def test_legacy_bad_zip_returns_empty_but_other_zip_failures_propagate(self):
        with patch.object(provenance.zipfile, "ZipFile", side_effect=provenance.zipfile.BadZipFile("bad")):
            self.assertEqual(provenance._artifact_architectures("android-aab", object()), [])
        original = RuntimeError("PRIVATE unexpected original failure")
        with patch.object(provenance.zipfile, "ZipFile", side_effect=original):
            with self.assertRaises(RuntimeError) as caught:
                provenance._artifact_architectures("android-aab", object())
        self.assertIs(caught.exception, original)

    def test_observation_scope_is_one_aab_not_a_generic_artifact_or_iterator_admission(self):
        class PoisonIterable:
            def __iter__(self):
                raise AssertionError("must reject before iteration")

        for value in (None, [], {}, iter(()), PoisonIterable()):
            self.refused("input", provenance.artifact_records_from_observations, value)
        for value in ((), (observation(), observation())):
            self.refused("scope", provenance.artifact_records_from_observations, value)
        for value in (None, {}, ("android-aab", "app.aab")):
            self.refused("input", provenance.artifact_records_from_observations, (value,))
        for name in (*(provenance.ARTIFACT_TYPES.keys() - {"android-aab"}), "PRIVATE-other", None):
            self.refused("scope", provenance.artifact_records_from_observations, (observation(logical_name=name),))

    def test_observed_basename_is_bounded_exact_unicode_without_path_or_control_bytes(self):
        for name in (None, "", ".", "..", "/PRIVATE/app.aab", "dir/app.aab", "dir\\app.aab", "C:app.aab",
                     "app\0.aab", "app\n.aab", "app\x7f.aab", "app\ud800.aab", "x" * 256, "\u00e9" * 128):
            self.refused("name", provenance.artifact_records_from_observations, (observation(file_name=name),))
        name = "\u00e9" * 127 + "x"
        self.assertEqual(provenance.artifact_records_from_observations((observation(file_name=name),))[0]["fileName"], name)

    def test_observed_size_is_positive_exact_integer_with_the_unchanged_aab_ceiling(self):
        for size in (True, 17.0, "17", None, 0, -1, zip_policy.MAX_AAB_BYTES + 1):
            self.refused("size", provenance.artifact_records_from_observations, (observation(size=size),))
        for size in (1, zip_policy.MAX_AAB_BYTES):
            self.assertEqual(provenance.artifact_records_from_observations((observation(size=size),))[0]["size"], size)

    def test_observed_digest_is_copied_not_recomputed_and_requires_exact_lowercase_sha256(self):
        for digest in (None, b"a" * 64, "a" * 63, "a" * 65, "A" * 64, "g" * 64, "PRIVATE/hash"):
            self.refused("digest", provenance.artifact_records_from_observations, (observation(sha256=digest),))
        with patch.object(provenance, "sha256_file", side_effect=AssertionError("no new hash read")):
            record = provenance.artifact_records_from_observations((observation(sha256="b" * 64),))[0]
        self.assertEqual(record["sha256"], "b" * 64)

    def test_observed_architectures_are_bounded_unique_fixed_labels_and_canonicalized(self):
        for value in (None, [], ("PRIVATE-abi",), ("unknown",), ([],), ("x86", "x86"), ("x86",) * 5):
            self.refused("architectures", provenance.artifact_records_from_observations, (observation(architectures=value),))
        labels = tuple(reversed(provenance.ANDROID_ABI_LABELS))
        record = provenance.artifact_records_from_observations((observation(architectures=labels),))[0]
        self.assertEqual(record["architectures"], list(provenance.ANDROID_ABI_LABELS))
        self.assertEqual(provenance.artifact_records_from_observations((observation(architectures=()),))[0]["architectures"], [])

    def test_observation_inputs_are_immutable_and_each_record_has_fresh_mutable_schema_containers(self):
        original = observation()
        with self.assertRaises(FrozenInstanceError):
            original.size = 99
        first = provenance.artifact_records_from_observations((original,))
        first[0]["architectures"].append("changed")
        first[0]["size"] = 99
        second = provenance.artifact_records_from_observations((original,))
        self.assertEqual(original.architectures, ("arm64-v8a",))
        self.assertEqual(second[0]["architectures"], ["arm64-v8a"])
        self.assertEqual(second[0]["size"], 17)

    def test_data_construction_never_opens_hashes_seals_publishes_or_adds_authority_fields(self):
        with patch("builtins.open", side_effect=AssertionError("no file open")), \
                patch.object(Path, "open", side_effect=AssertionError("no path open")), \
                patch.object(Path, "stat", side_effect=AssertionError("no path stat")), \
                patch.object(provenance.os, "open", side_effect=AssertionError("no descriptor open")), \
                patch.object(provenance.zipfile, "ZipFile", side_effect=AssertionError("no archive reopen")), \
                patch.object(provenance, "sha256_file", side_effect=AssertionError("no payload hash")), \
                patch.object(provenance, "_artifact_architectures", side_effect=AssertionError("no path ABI read")), \
                patch.object(provenance, "seal", side_effect=AssertionError("no evidence seal")), \
                patch.object(provenance, "write_evidence", side_effect=AssertionError("no evidence publication")), \
                patch.object(provenance, "timestamp", side_effect=AssertionError("no observation time invention")):
            record = provenance.artifact_records_from_observations((observation(),))[0]
        self.assertEqual(set(record), KEYS)
        self.assertEqual({field.name for field in fields(provenance.ArtifactObservation)},
                         {"logical_name", "file_name", "size", "sha256", "architectures"})
        self.assertTrue(all(field not in record for field in
                            ("integrity", "receipt", "owner", "freshness", "sourceBinding", "signer", "unknownAbi")))

    def test_same_metadata_abi_labels_are_canonical_bounded_and_unknown_strings_do_not_escape(self):
        value = metadata(entry("base/lib/x86/libx.so"), entry("base/lib/arm64-v8a/libx.so"),
                         entry("base/lib/PRIVATE-unknown/libPRIVATE.so"), entry("base/lib/x86/another.so"),
                         entry("base/lib/armeabi-v7a/libx.so"), entry("base/lib/x86_64/libx.so"))
        result = abis(value)
        self.assertEqual(result.architectures, provenance.ANDROID_ABI_LABELS)
        self.assertIs(result.unknown_abi, True)
        self.assertNotIn("PRIVATE", repr(result))
        with self.assertRaises(FrozenInstanceError):
            result.unknown_abi = False
        record = provenance.artifact_records_from_observations((observation(architectures=result.architectures),))[0]
        self.assertEqual(record["architectures"], list(result.architectures))
        self.assertNotIn("unknownAbi", record)  # Operation must carry the separate observation boolean.

    def test_base_prefix_semantics_are_shared_without_claiming_dynamic_module_or_elf_completeness(self):
        names = ("base/lib/x86/", "base/lib/arm64-v8a/nested/not-an-elf", "feature/lib/x86_64/libx.so",
                 "BASE/lib/armeabi-v7a/libx.so", "lib/x86_64/libx.so", "base/lib/x86_64", "other/file")
        result = abis(metadata(*(entry(name) for name in names)))
        self.assertEqual(result, provenance.AndroidAbiObservation(("arm64-v8a", "x86"), False))
        self.assertEqual(abis(metadata(entry("ordinary-file"))), provenance.AndroidAbiObservation((), False))

    def test_abi_metadata_checks_shared_unsafe_name_type_and_encryption_rules(self):
        base = entry("file")
        for name in ("", "/PRIVATE", "base/lib/x86/../PRIVATE", "base\\lib\\x86\\PRIVATE", "C:/PRIVATE", "PRIVATE\0file", "\ud800"):
            self.refused("metadata", abis, metadata(replace(base, name=name)))
        for changes in ({"flag_bits": 1}, {"external_attr": 0xA000 << 16}, {"file_size": zip_policy.MAX_ENTRY_SIZE + 1}):
            self.refused("metadata", abis, metadata(replace(base, **changes)))
        self.refused("metadata", abis, metadata(replace(base, name=None)))
        self.refused("metadata", abis, metadata(object()))
        self.refused("metadata", abis, replace(metadata(base), entries=[base]))
        self.refused("metadata", abis, object())

    def test_abi_work_limits_precede_name_splitting_and_unbounded_retention(self):
        base = entry("file")
        for value in (metadata(), replace(metadata(base), entries=(base,) * 0xFFFF)):
            with patch.object(provenance, "_android_aab_abi", side_effect=AssertionError("reject count first")):
                self.refused("limit", abis, value)
        with patch.object(provenance, "_android_aab_abi", side_effect=AssertionError("reject name bound first")):
            self.refused("limit", abis, metadata(replace(base, name="x" * (zip_policy.MAX_ENTRY_NAME_BYTES + 1))))
        first, second = entry("first"), entry("second")
        budget = 2 * zip_policy.CENTRAL_HEADER_BYTES + len(first.name) + len(second.name) - 1
        with patch.object(zip_policy, "MAX_CENTRAL_DIRECTORY_BYTES", budget), \
                patch.object(provenance, "_android_aab_abi", wraps=provenance._android_aab_abi) as select:
            self.refused("limit", abis, metadata(first, second))
        self.assertEqual(select.call_count, 1)

    def test_original_checkpoint_failures_before_during_and_after_abi_work_propagate_unchanged(self):
        value = metadata(entry("base/lib/x86/libx.so"), entry("other/file"))
        baseline = []
        abis(value, checkpoint=lambda: baseline.append(None))

        class OriginalLifetimeFailure(ValidationError):
            pass

        for failure in (OriginalLifetimeFailure("PRIVATE original lifetime"),
                        zip_policy.AndroidZipError("layout"), KeyboardInterrupt("PRIVATE original cancel")):
            for stop_at in (1, 3, len(baseline)):
                calls = []

                def check():
                    calls.append(None)
                    if len(calls) == stop_at:
                        raise failure

                with self.assertRaises(type(failure)) as caught:
                    abis(value, checkpoint=check)
                self.assertIs(caught.exception, failure)
                self.assertEqual(len(calls), stop_at)
        self.refused("input", abis, value, checkpoint=lambda: False)
        self.refused("input", abis, value, checkpoint=42)

    def test_abi_data_helper_never_reopens_artifacts_and_does_not_mint_validation_or_custody(self):
        # Directly constructed metadata can describe a label without any bytes
        # ever being inspected. The operation, not this DATA helper, establishes
        # origin and integrity and must retain its actual original artifact.
        value = metadata(entry("base/lib/arm64-v8a/not-an-elf"))
        with patch.object(provenance.zipfile, "ZipFile", side_effect=AssertionError("no second archive view")), \
                patch.object(provenance, "_artifact_architectures", side_effect=AssertionError("no path reader")), \
                patch.object(Path, "open", side_effect=AssertionError("no file open")), \
                patch.object(Path, "stat", side_effect=AssertionError("no stat")), \
                patch.object(provenance, "sha256_file", side_effect=AssertionError("no file hash")):
            result = abis(value)
        self.assertEqual(result, provenance.AndroidAbiObservation(("arm64-v8a",), False))
        self.assertEqual({field.name for field in fields(result)}, {"architectures", "unknown_abi"})


if __name__ == "__main__":
    unittest.main()
