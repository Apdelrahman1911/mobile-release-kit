# Clone-ready continuation record

## What this branch is

The user requested an immediate push so another agent can clone and continue
without losing the analysis or unfinished code. This **handoff-only exception**
does not change the original requirement to fully review and verify each issue
before its separate protected delivery to `main`.

Only continuation documentation, inert source references, and two unapplied
patches are added. No application, CLI, Fastlane, workflow, schema, dependency,
or test implementation on this branch is changed from the base commit.

The public repository must not receive secrets, signing material, private Store
data, raw `.mobile-release/` evidence, local caches, or live execution grants.
See [exclusions and authority](DECISIONS.md). This is a portable **knowledge and
source** handoff, not a portable running environment or authenticated test result.

## Baseline actually observed for the handoff

| Item | Value |
| --- | --- |
| Version | `0.3.0` |
| Main/base commit | `2beb37336fa8002b69f598fe431082606368310d` |
| Main product tree | `00f3acee00c994e6e81470cc76e42f1f2108fcdb` |
| Main product files | 150 |
| Original audit version/commit | `0.1.3`, `c3a5a0fedce2695f9e5ff520bc15c48aa0af268c` |
| Original audit tree / tracked files | `6ebb3eddaeeb3c714d6a6ebf49568d8da255791b`, 67 |
| Original local root branch | `fix/qa-003-local-signing-lease` |
| Separate local fixture branch | `fix/qa-006-upload-process-fixtures` |
| Source ownership | Original worktrees and their indexes preserved; user-owned untracked `AGENTS.md` neither changed nor exported |
| Remote | Public; current `main` SHA matched the base during this handoff |
| Protection observed | PR required, strict `test`, administrators enforced, force pushes/deletions disabled |
| Main CI observed | [33996725809](https://github.com/Apdelrahman1911/mobile-release-kit/actions/runs/33996725809), completed/success for this exact main SHA |

Remote facts are observations at handoff time, not permanent guarantees. Recheck
before later delivery. Native Git for this handoff ran only in a fresh owned
clone and copied source trees, never against the original worktrees.

## Honest progress

| Scope | Verified protected-main deliveries | Remaining | Percentage |
| --- | ---: | ---: | ---: |
| Original findings | 7/9 | 2 | 77.8% |
| Additional findings | 2/7 | 5 | 28.6% |
| All currently confirmed findings | 9/16 | 7 | **56.25%** |

Supporting verification-infrastructure repairs do not increase that percentage.
The fresh complete audit and final feature report remain additional work; there
is no evidence-based total-effort percentage. **Overall verdict: NOT READY.**

## Preserved implementation snapshots

| Issue | Base | Expected complete product tree | Files / changed paths | State |
| --- | --- | --- | --- | --- |
| QA-003 | main above | `387856e314cb3475c20509fb70f5a8c3708a87af` | 173 / 55 | Implementation-only approval; full verification failed/incomplete; not delivered |
| QA-006 R6 | main above | `6009247f3627c9825e9ad9c790a57876e09f3726` | 152 / 7 | Partial independent review supports correction; acceptance withheld pending required entered/native/full tests |

- [QA-003 patch](patches/qa003.patch) and [complete file manifest](manifests/qa003.json).
- [QA-006 patch](patches/qa006.patch) and [complete file manifest](manifests/qa006.json).

Both patches were produced from copied, hash-verified source. Separate Git indexes
reconstructed **exactly** the expected trees, with 55 and 7 changed paths.
Neither includes `AGENTS.md`, ignored evidence, or private working files. The
patches are product source, not test-output records. They intentionally remain
unapplied so an unverified combined implementation is not published as working code.
They use Git full-index, **zero-context** text format to avoid whitespace-only
context lines in a committed transport file. This requires the explicit exact-base
guards below; it is not permission to apply at approximate or guessed locations.

## Resume without losing or mixing work

Read the safety/verification records first. Retain this clone as a read-only
handoff reference. For QA-006, create a separate disposable worktree from the
exact base, then apply only its patch:

```bash
(
set -eu
handoff="$PWD"
base=2beb37336fa8002b69f598fe431082606368310d
worktree="$handoff/../mobile-release-kit-qa006"
check_snapshot() {
  python3 -I -S - "$1" "$2" <<'PY'
import hashlib, json, os, stat, sys
from pathlib import Path, PurePosixPath

manifest, root = Path(sys.argv[1]), Path(sys.argv[2])
if root.is_symlink() or not root.is_dir():
    raise SystemExit("Snapshot root must be an actual directory")
records = json.loads(manifest.read_text())["files"]
expected = {}
for item in records:
    name = item["path"]
    path = PurePosixPath(name)
    if (path.is_absolute() or path.as_posix() != name or ".." in path.parts
            or ".git" in path.parts or "\\" in name or name in expected):
        raise SystemExit("Unsafe or duplicate manifest path")
    expected[name] = item
actual = set()
for directory, dirs, files in os.walk(root, followlinks=False):
    if Path(directory) == root:
        dirs[:] = [name for name in dirs if name != ".git"]
        files = [name for name in files if name != ".git"]
    for name in dirs + files:
        if (Path(directory) / name).is_symlink():
            raise SystemExit("Unexpected symlink in snapshot")
    actual.update((Path(directory) / name).relative_to(root).as_posix()
                  for name in files)
if actual != set(expected):
    raise SystemExit("Snapshot file inventory differs")
for name, item in expected.items():
    if not stat.S_ISREG((root / name).lstat().st_mode):
        raise SystemExit("Snapshot entry is not a regular file: " + name)
    fd = os.open(root / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_size != item["bytes"]
                or bool(before.st_mode & 0o111) != (item["gitMode"] == "100755")):
            raise SystemExit("Snapshot type, size, or Git mode differs: " + name)
        digest = hashlib.sha256()
        left = before.st_size
        while left:
            chunk = os.read(fd, min(left, 65536))
            if not chunk:
                raise SystemExit("Unexpected EOF: " + name)
            digest.update(chunk)
            left -= len(chunk)
        after = os.fstat(fd)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode,
                                  value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(after) or digest.hexdigest() != item["sha256"]:
            raise SystemExit("Snapshot changed or hash differs: " + name)
    finally:
        os.close(fd)
print("Verified snapshot files:", len(expected))
PY
}
git worktree add -b resume/qa-006 "$worktree" "$base"
head=$(git -C "$worktree" rev-parse HEAD)
status=$(git -C "$worktree" status --porcelain=v1)
tree=$(git -C "$worktree" write-tree)
test "$head" = "$base"
test -z "$status"
test "$tree" = 00f3acee00c994e6e81470cc76e42f1f2108fcdb
check_snapshot "$handoff/docs/continuation/manifests/base.json" "$worktree"
git -C "$worktree" apply --check --index --unidiff-zero \
  "$handoff/docs/continuation/patches/qa006.patch"
git -C "$worktree" apply --index --unidiff-zero \
  "$handoff/docs/continuation/patches/qa006.patch"
tree=$(git -C "$worktree" write-tree)
test "$tree" = 6009247f3627c9825e9ad9c790a57876e09f3726
check_snapshot "$handoff/docs/continuation/manifests/qa006.json" "$worktree"
)
```

These Git commands do not run product tests or authorize native execution.
Use the complete [baseline manifest](manifests/base.json) before applying, and
check every resulting source hash/mode against the issue manifest before reviewing
or running anything. `--index` checks worktree/index agreement, not a general
full-preimage guarantee; the exact baseline and full resulting checks are mandatory.
No `--3way`, reject/partial, or fuzzy recovery is allowed. The application stages
the issue changes in its **new** worktree; it does not create an approved commit.
The patch hash and expected tree are in the issue manifest;
an adjacent hash is an integrity aid, not independent authenticity.
The subshell stops on the first failed guard. Investigate rather than manually
continuing later lines after failure. Keep the new worktree private and unused by
other tasks during reconstruction; these drift checks are not a hostile concurrent
same-user filesystem isolation mechanism.

Reconstruct QA-003 separately in the same manner when needed for inspection.
After QA-006 and QA-007 are delivered, reconcile QA-003 deliberately with the
new main, review the changed combined contracts, and run **fresh complete**
verification. In particular both old patches touch `.github/workflows/ci.yml`
and `tests/workflow/test_native_profile_ci.py`; do not overwrite either issue's
requirements by blindly replaying an old whole file. All protected delivery
commits must contain only the relevant finished issue, not this historical export.

## Where the retained knowledge lives

- `original-findings/`: the original nine short findings, with historical line
  numbers. They describe the audit baseline, not necessarily current locations.
- `FINDINGS.md`: canonical current disposition of all 16, including later issues.
- `plans/qa-003/`, `plans/qa-006/`: preserved plan/review chronology. A filename
  beginning `PLAN` is not approval. Superseded/rejected drafts remain historical.
- `plans/qa006-verifier/`: active fixture-base amendment and inherited contract.
- `reviews/`: sanitized relevant independent reviews, not executable grants.
- `drafts/verifier/`: 24 baseline helper sources, two paused draft overrides,
  nine proof drivers, and two original comparison oracles.
- `drafts/clock-original/`: original nine runtime sources, both pure drivers,
  test matrix/obligations, and sanitized inherited fixture reference shapes.
- `drafts/qa003-verification/`: old final controller and supporting scripts for
  understanding the failed run; not a command to resume that consumed namespace.
- `EXPORT-MANIFEST.json`: original-vs-export hashes and explicit transformations.
- `SHA256SUMS`: static integrity inventory of the handoff files, excluding itself.

Reference copies have local path placeholders and sometimes normalized whitespace.
Two selector fixtures have identity/status fields removed. They **cannot** satisfy
old exact-byte approvals. Do not restore them over old evidence, import them, or
execute them. Any adapted helper requires new bindings and independent review.

## First actions for the successor

1. Read this entire handoff and `SECURITY.md`; inspect any local instructions.
2. Record the clone's actual commit, branch, tree, tools, and user changes.
3. Verify the handoff inventory and reconstruct the relevant patch separately.
4. Resume QA-006 from its actual review stage, not from zero or from an assumed
   pass. Resolve a safe verification path while keeping QA-007 separate.
5. Complete the remaining issues in order under [the required workflow](WORKFLOW.md).
6. Perform the new all-file/all-release-path audit, fix further confirmed blockers,
   repeat until READY is justified, and only then write the detailed feature report.

Do not promise zero repeated verification: changed hosts, source, toolchains, or
execution bindings require fresh proof. Preserve earlier useful analysis and every
known failed/unexecuted case instead of silently skipping or relabeling them.
