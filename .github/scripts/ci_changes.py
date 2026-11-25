"""Select affected CI checks by paths, not source hashes or test receipts."""
from __future__ import annotations

import os
import re
import subprocess


def affects_core(path: bytes) -> bool:
    if path.startswith((b"src/", b"fastlane/", b"schemas/", b"templates/",
                        b".github/scripts/", b"examples/")):
        return True
    if path.startswith(b"tests/"):
        return not path.startswith((b"tests/desktop/", b"tests/native_desktop"))
    if path.startswith(b".github/workflows/reusable-"):
        return True
    return path in {b".github/workflows/ci.yml", b".github/verification-tools.json",
                    b"README.md", b"LICENSE", b"pyproject.toml", b"MANIFEST.in",
                    b"Gemfile", b"Gemfile.lock", b".python-version", b".ruby-version"}


def affects_desktop_native(path: bytes) -> bool:
    """Skip compilation only for known non-product inputs; unknowns build."""
    # Shared JSON fixtures and tests/native_desktop* are compiled into Rust.
    # Only the standalone JS cases and ordinary Python suites can skip native.
    if path.startswith(b"desktop/tests/") and path.endswith(b".test.mjs"):
        return False
    if path.startswith((b"docs/", b"tests/desktop/", b"tests/unit/", b"tests/workflow/",
                        b"desktop/native/macos-normal-ui/")):
        return False
    if path in {b"README.md", b"CONTRIBUTING.md", b"SECURITY.md", b"AGENTS.md"}:
        return False
    return True


def main() -> None:
    event, base, head = (os.environ[key] for key in ("CI_EVENT", "CI_BASE", "CI_HEAD"))
    scope = os.environ.get("CI_SCOPE", "core")
    if scope not in {"core", "desktop"}:
        raise ValueError("Unsupported CI scope")
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("Invalid event commit")
    if event not in {"pull_request", "push", "workflow_dispatch"}:
        raise ValueError("Unsupported CI event")
    if event == "workflow_dispatch" or base in {"", "0" * 40}:
        changed = True
    else:
        if not re.fullmatch(r"[0-9a-f]{40}", base):
            raise ValueError("Invalid comparison commit")
        # Checkout depth two includes both parents of the ordinary PR merge.
        # A multi-commit push may need its exact previous commit fetched once.
        if subprocess.run(["git", "cat-file", "-e", base + "^{commit}"],
                          stderr=subprocess.DEVNULL, check=False).returncode:
            subprocess.run(["git", "fetch", "--no-tags", "--depth=1", "origin", base],
                           check=True, timeout=120)
        paths = subprocess.check_output([
            "git", "-c", "core.fsmonitor=false", "diff", "--no-ext-diff",
            "--no-textconv", "--no-renames", "--name-only", "-z", base, head,
        ], timeout=30).split(b"\0")
        selector = affects_desktop_native if scope == "desktop" else affects_core
        changed = any(selector(path) for path in paths if path)
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"{'native' if scope == 'desktop' else 'core'}={'true' if changed else 'false'}\n")
    if scope == "desktop":
        print("Product or unknown inputs changed; running native checks." if changed else
              "Only known test/documentation inputs changed; fast tests still run, native builds are not repeated.")
    else:
        print("Core inputs changed; running core verification." if changed else
              "No core input changes; retaining the required status without rerunning core verification.")


if __name__ == "__main__":
    main()
