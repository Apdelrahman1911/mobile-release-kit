from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mobile_release.config import VERSION_RE, parse_key_value_file
from mobile_release.errors import ConfigurationError


ROOT = Path(__file__).resolve().parents[2]
CORPUS = json.loads(
    (ROOT / "tests/fixtures/version-parser-corpus.json").read_text(encoding="utf-8")
)


def python_release_version(path: Path) -> tuple[str, int]:
    values = parse_key_value_file(path)
    marketing = values["VERSION_NAME"]
    build_text = values["BUILD_NUMBER"]
    if not VERSION_RE.fullmatch(marketing):
        raise ConfigurationError("invalid marketing version")
    if not build_text.isascii() or not build_text.isdigit() or build_text.startswith("0"):
        raise ConfigurationError("invalid build number")
    build = int(build_text, 10)
    if not 1 <= build <= 2_100_000_000:
        raise ConfigurationError("invalid build number")
    return marketing, build


class VersionParserCorpusTests(unittest.TestCase):
    def test_python_accepts_shared_valid_corpus(self) -> None:
        for case in CORPUS["valid"]:
            with self.subTest(case=case["name"]), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "version.properties"
                path.write_text(case["text"], encoding="utf-8")
                self.assertEqual(
                    (case["marketing"], case["build"]),
                    python_release_version(path),
                )

    def test_python_rejects_shared_invalid_corpus(self) -> None:
        for case in CORPUS["invalid"]:
            with self.subTest(case=case["name"]), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "version.properties"
                path.write_text(case["text"], encoding="utf-8")
                with self.assertRaises((ConfigurationError, KeyError, ValueError)):
                    python_release_version(path)


if __name__ == "__main__":
    unittest.main()
