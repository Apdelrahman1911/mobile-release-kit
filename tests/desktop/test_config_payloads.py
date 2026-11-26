"""Bounded pure byte/equality cases; no CLI import, fixtures, native work or IO.

These are source-authored prospective checks. They do not qualify transactions,
platforms, original-child finality or production mutation capability.
"""
from __future__ import annotations

import json
import unittest

from mobile_release.config import configuration_data_equal
from mobile_release.config_payloads import (IGNORE_LINES, MAX_IGNORE_BYTES,
                                            IgnoreRuleConflict, append_ignore_lines,
                                            prepare_edit_ignore, serialize_config_data,
                                            sufficient_ignore_rules)
from mobile_release.errors import ValidationError


def legacy_ignore_bytes(before: bytes, lines: tuple[str, ...] = IGNORE_LINES) -> bytes:
    """Literal old CLI byte expression, not an import or CLI invocation."""
    before.decode("utf-8")
    result = before
    for line in lines:
        if line.encode() not in result.splitlines():
            if result and not result.endswith(b"\n"):
                result += b"\n"
            result += line.encode() + b"\n"
    if len(result) > 1024 * 1024:
        raise ValidationError("root .gitignore including required ignore lines must fit within 1 MiB")
    return result


def legacy_private_proof(content: bytes) -> bool:
    """Literal pre-extraction one-directory proof, without importing its owner."""
    try:
        lines = content.decode("utf-8").split("\n")
    except UnicodeError:
        return False
    excluded = False
    for raw in lines:
        line = raw[:-1] if raw.endswith("\r") else raw
        if line in (".mobile-release/", "/.mobile-release/"):
            excluded = True
        elif line.startswith("!"):
            excluded = False
    return excluded


class ConfigPayloadTests(unittest.TestCase):
    def test_cli_json_bytes_are_the_exact_legacy_expression(self):
        values = ({"schemaVersion": 1, "text": "日本語 – café", "flag": False},
                  {"second": [], "first": {"value": [None, 1, 1.0, True]}}, {})
        for value in values:
            with self.subTest(value_type=type(value).__name__):
                self.assertEqual(serialize_config_data(value),
                                 (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
        self.assertTrue(serialize_config_data(values[0]).endswith(b"\n"))
        self.assertNotIn(b"\\u", serialize_config_data(values[0]))

    def test_cli_ignore_bytes_match_all_frozen_legacy_inputs(self):
        full = ("\n".join(IGNORE_LINES) + "\n").encode()
        cases = (b"", b"# original", b"# original\r\n", full, full.rstrip(b"\n"),
                 b"/.mobile-release/\n", b"!.mobile-release/\n",
                 b".mobile-release/\n!.mobile-release/\n", b"!keep.txt\n",
                 b"\\!literal\n", b" !not-a-negation\r\n",
                 ".mobile-release/\u2028!not-a-separate-line\n".encode(),
                 b".mobile-release/\r# original\r\n")
        for before in cases:
            with self.subTest(length=len(before)):
                self.assertEqual(append_ignore_lines(before), legacy_ignore_bytes(before))
        # Editor sufficient coverage must not silently change the CLI default.
        rooted = ("\n".join("/" + line for line in IGNORE_LINES) + "\n").encode()
        self.assertEqual(append_ignore_lines(rooted), rooted + full)

    def test_editor_preserves_complete_plain_rooted_and_post_negation_suffixes(self):
        for prefix, rooted, newline, terminal in ((b"", False, "\n", True),
                                                  (b"# keep\r\n", True, "\r\n", False),
                                                  (b"!keep.txt\n", False, "\n", True),
                                                  (b"!.mobile-release/\n", True, "\r\n", True)):
            rules = ["/" + line if rooted else line for line in IGNORE_LINES]
            before = prefix + (newline.join(rules) + (newline if terminal else "")).encode()
            with self.subTest(rooted=rooted, terminal=terminal):
                self.assertTrue(sufficient_ignore_rules(before))
                self.assertEqual(prepare_edit_ignore(before), (before, ()))

    def test_editor_adds_only_uncovered_rules_and_preserves_original_bytes(self):
        before = b"# comment retained\r\n/.mobile-release/\r\n.mobile-release-init/"
        missing = tuple(line for line in IGNORE_LINES if line not in {".mobile-release/", ".mobile-release-init/"})
        after, additions = prepare_edit_ignore(before)
        self.assertEqual(additions, missing)
        self.assertEqual(after, legacy_ignore_bytes(before, missing))
        self.assertTrue(after.startswith(before + b"\n"))
        self.assertTrue(sufficient_ignore_rules(after))
        for harmless in (b"\\!escaped\n", b" !space-prefixed\n", b"# !comment\n"):
            result, additions = prepare_edit_ignore(harmless)
            self.assertEqual(additions, IGNORE_LINES)
            self.assertEqual(result, legacy_ignore_bytes(harmless))

    def test_editor_refuses_incomplete_coverage_with_any_syntactic_negation(self):
        cases = (b"!.mobile-release/\n", b".mobile-release/\n!.mobile-release/\n",
                 b"!keep.txt\n", b"!unrelated\r\n/.mobile-release/\r\n",
                 b".mobile-release/\n!\n")
        for before in cases:
            with self.subTest(length=len(before)), self.assertRaises(IgnoreRuleConflict):
                prepare_edit_ignore(before)
            self.assertEqual(append_ignore_lines(before), legacy_ignore_bytes(before))

    def test_single_private_rule_proof_matches_the_existing_algorithm(self):
        cases = (b"", b"\xff", b".mobile-release/", b"/.mobile-release/\r\n",
                 b" .mobile-release/\n", b".mobile-release/ \n", b"\r.mobile-release/\n",
                 b".mobile-release/\n!later\n", b"!earlier\n.mobile-release/\n",
                 b".mobile-release/\n !not-negation\n", b".mobile-release/\n\\!literal\n",
                 ".mobile-release/\u2028!later".encode(), b".mobile-release/\r!later\n",
                 b".mobile-release/\r\n!later\r\n/.mobile-release/\r\n",
                 b".mobile-release/\v!later\n", b".mobile-release/\n\xff")
        for content in cases:
            with self.subTest(length=len(content)):
                self.assertEqual(sufficient_ignore_rules(content, (".mobile-release/",)),
                                 legacy_private_proof(content))

    def test_fixed_rule_admission_and_ignore_byte_limits_are_closed(self):
        for rules in ([IGNORE_LINES[0]], ("private/custom/",), (IGNORE_LINES[0],) * 2,
                      IGNORE_LINES + (IGNORE_LINES[0],)):
            with self.subTest(kind=type(rules).__name__), self.assertRaises(ValidationError):
                append_ignore_lines(b"", rules)
        for invalid in (b"\xff", bytearray(b"value"), "text"):
            with self.subTest(kind=type(invalid).__name__), self.assertRaises(ValidationError):
                append_ignore_lines(invalid)
        covered = ("\n".join(IGNORE_LINES) + "\n").encode()
        exactly = covered + b"#" * (MAX_IGNORE_BYTES - len(covered))
        self.assertEqual(prepare_edit_ignore(exactly), (exactly, ()))
        with self.assertRaises(ValidationError):
            append_ignore_lines(exactly + b"#")
        with self.assertRaises(ValidationError):
            prepare_edit_ignore(b"#" * MAX_IGNORE_BYTES)
        self.assertEqual(append_ignore_lines(b"# retained", ()), b"# retained")
        self.assertFalse(sufficient_ignore_rules(b"\xff", ()))
        self.assertFalse(sufficient_ignore_rules(bytearray(b""), ()))

    def test_semantic_equality_is_type_exact_and_order_aware(self):
        self.assertTrue(configuration_data_equal({"a": 1, "b": [False, {"c": "x"}]},
                                                 {"b": [False, {"c": "x"}], "a": 1}))
        for first, second in ((False, 0), (True, 1), (1, 1.0), (None, ""),
                              ({"a": [1, 2]}, {"a": [2, 1]}), ({}, {"absent": None})):
            with self.subTest(first_type=type(first).__name__, second_type=type(second).__name__):
                self.assertFalse(configuration_data_equal(first, second))


if __name__ == "__main__":
    unittest.main()
