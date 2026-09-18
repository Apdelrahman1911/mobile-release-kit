"""Compile-only peer warning regression; never import or execute the peer.

The full source becomes an unused code object; the negative canary must be rejected.
Qualification requires a separately admitted CPython3.14.7 run with zero skips;
an older interpreter's canary skip is not evidence for this regression.
"""
from pathlib import Path
import sys
import unittest
import warnings


PEER = Path(__file__).resolve().parents[2] / "desktop/src-tauri/tests/fixtures/github_tls_peer.py"


class PeerCompileWarningTests(unittest.TestCase):
    def test_complete_peer_has_no_syntax_warning(self):
        source = PEER.read_bytes()
        with warnings.catch_warnings():
            warnings.simplefilter("error", SyntaxWarning)
            compile(source, str(PEER), "exec", flags=0, dont_inherit=True, optimize=0)

    @unittest.skipUnless(sys.implementation.name == "cpython" and sys.version_info >= (3, 14),
                         "PEP765 compiler canary requires CPython3.14+")
    def test_compiler_rejects_return_from_finally(self):
        source = ("def canary():\n"
                  "    try:\n"
                  "        pass\n"
                  "    finally:\n"
                  "        return 74\n")
        with warnings.catch_warnings():
            warnings.simplefilter("error", SyntaxWarning)
            with self.assertRaisesRegex(SyntaxError, "'return' in a 'finally' block"):
                compile(source, "<peer-pep765-canary>", "exec", flags=0,
                        dont_inherit=True, optimize=0)


if __name__ == "__main__":
    unittest.main()
