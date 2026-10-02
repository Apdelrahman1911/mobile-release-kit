"""Active Mac shell assertion regression: source DATA, not native execution."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]


class MacWorkflowGuardTests(unittest.TestCase):
    def test_active_mac_assertions_have_explicit_failure_exits(self):
        # Deliberately checks the known single-line assertion syntax. This is
        # not a general Bash parser. Continued if clauses end in '; then' and
        # must retain their ordinary false branch, not terminate the workflow.
        bare = re.compile(r"\s*\[\[ .+ \]\]\s*")
        for name in ("desktop-macos-aqua.yml", "desktop-macos-installed.yml"):
            lines = (ROOT / ".github/workflows" / name).read_text().splitlines()
            with self.subTest(workflow=name):
                self.assertFalse([(i + 1, line) for i, line in enumerate(lines) if bare.fullmatch(line)])
                self.assertTrue(any("]] || exit " in line for line in lines))

    def test_original_command_status_is_not_replaced_by_a_later_assertion(self):
        result = re.compile(r'\s*\[\[ "?\$([a-z_]+)"? == 0 \]\](.*)')
        for name in ("desktop-macos-aqua.yml", "desktop-macos-installed.yml"):
            for line in (ROOT / ".github/workflows" / name).read_text().splitlines():
                match = result.fullmatch(line)
                if match:
                    with self.subTest(workflow=name, status=match[1]):
                        self.assertEqual(match[2].strip(), '|| exit "$' + match[1] + '"')
        installed = (ROOT / ".github/workflows/desktop-macos-installed.yml").read_text()
        self.assertIn("(( statuses[1] == 0 && statuses[2] == 0 )) || return 1", installed)
        self.assertIn('if (( statuses[0] != 0 )); then return "${statuses[0]}"; fi', installed)


if __name__ == "__main__":
    unittest.main()
