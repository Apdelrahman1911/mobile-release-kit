# Initialization and local recovery

`mobile-release init` is a read-only discovery preview. `init --apply` installs configuration,
thin workflow callers, empty metadata prompts and ignore lines; it never builds an application
or contacts a Store. Git discovery remains a separate read-only subprocess. This filesystem
recovery protocol is unrelated to [Store-operation recovery](recovery.md).

## Applying an integration

Supply the reviewed toolkit repository and full commit SHA:

```bash
mobile-release init --root /path/to/application --apply \
  --tooling-repository OWNER/REPOSITORY --tooling-sha FULL_40_CHARACTER_COMMIT_SHA
```

All paths, templates and original inputs are checked before destination writes. Apply holds a
nonblocking project-directory lock across discovery, input snapshots, staging, installation and
cleanup. A second apply/recovery reports that the first command must finish; preview does not
take this mutation lock. Complete generated files, missing directory inodes and a recovery plan
are staged privately before installation. Exclusive native renames cannot overwrite a newly
appearing target. Whole-set readback precedes the commit marker and success report.

Without `--force`, an existing config/caller is an error. With it, replacements preserve regular
permission bits, but use new inodes: original ownership, ACLs and extended attributes are not
promised on successful replacement. Identical outputs are not replaced. Existing metadata is
always preserved, and ignore lines are appended without normalizing existing bytes or CRLF.
Precommit rollback restores the actual original inodes, bytes and modes, including their inode
metadata. Directory timestamps may change. Review `created`/`updated` and the generated policy;
successful installation is not approval to release.

## After failure or termination

Ordinary precommit failures and catchable interrupts attempt complete rollback. An interrupt
returns exit 130; a validation/filesystem failure returns exit 2. No success JSON is emitted on
either. A successful rename followed by an I/O error is classified by the observed journal state,
not by the error alone: an observed commit is never rolled back.

After SIGTERM/SIGKILL, cancellation, an incomplete cleanup or a failed automatic rollback:

```bash
mobile-release init --root /path/to/application --recover
```

Recovery needs no config, project discovery, original templates, credentials or toolkit pin
arguments. `--recover` and `--apply` are mutually exclusive. Keep the original toolkit version
available for its journal format. Normal apply refuses any pending state. Repeated recovery is
safe, including after recovery itself was interrupted.

| State / reported result | Behavior |
| --- | --- |
| No pending transaction / `no-op` | Nothing changes. |
| Preparation / `preparing-cleanup` | Remove recognized private staging only; installation never began. |
| Installed or partially installed, not committed / `rolled-back` | Restore the complete original logical file/directory set. |
| Committed / `committed-cleanup` | Keep the new integration and later user edits; remove private backups/staging only. |
| Rollback already complete / `rolled-back-cleanup` | Finish private cleanup without touching destinations. |
| Cleanup already begun / `cleanup-only` | Finish irreversible private cleanup, even if some control files were already removed. |

An error after commit still reports failure and explains that integration may already be committed;
inspect it rather than assuming the old config is active. Durable phase markers prevent cleanup
failure from reversing a completed integration.

## Conflicts and privacy

**Never commit, upload, or blindly delete** these three private directories:

```text
.mobile-release-init-prepare/
.mobile-release-init/
.mobile-release-init-cleanup/
```

They are mode 0700 and may retain original configuration. Apply adds their exact `.gitignore`
lines and `.mobile-release/`, but interruption may precede that append. A private permission bit
does not stop the owner from running `git add`. Inspect `git status` before staging anything.

If a user edited a destination, wrote through an old descriptor/hardlink, replaced an ancestor,
or added content to a newly created directory, recovery stops rather than overwriting the edit
or recursively deleting it. Corrupt/truncated/extra journal data and missing original backups
also stop recovery. Save intervening work **outside the transaction**, preserve the journal and
all original backups, and inspect the reported conflict rule. Restore a displaced original ancestor
only after verifying its identity; never replace a journal with a checked-in copy or fabricate
marker/hash values. Some conflicts (such as a removed recorded inode) require manual restoration
from the retained original backups, not merely removing the changed file and rerunning. Seek
maintainer help with a sanitized description, not private config/journal contents. Do not rerun
apply until the conflict is resolved and recovery state is cleared safely.

## Supported environment and bounds

Mutation/recovery requires local Linux or macOS filesystems honoring directory `flock`, directory
`fsync` and exclusive atomic rename (`renameat2` / `renameatx_np`). Unsupported primitives and
detected nested mounts fail closed; an undetectable cross-mount rename error never falls back to
copying or overwriting. Preview and unrelated portable commands do not import POSIX capabilities.
Network filesystems and Windows mutation are outside this contract.

Paths must stay inside the canonical project root without symlinked descendants, case/Unicode
aliases, reserved Git/transaction paths or file/ancestor collisions. Limits: 64 templates at
1 MiB each, 256 file destinations and 256 ancestor directories, 8 MiB per original/generated file,
64 MiB combined originals/staged content, 1 MiB root ignore file, 512 KiB control files, path depth
64 and UTF-8 path length 4096 bytes. The 1 MiB ignore bound applies both before and after appending
required lines. Special permission bits (setuid, setgid and sticky) on files, the project root or
any destination ancestor are rejected before staging; use a project with ordinary directory modes.

The lock serializes cooperating toolkit commands, not arbitrary editors or malicious same-user
namespace changes. Descriptor anchoring and repeated identity/hash checks detect ordinary
conflicts but are not a filesystem compare-and-swap security boundary. This is recoverable
multi-file installation, not simultaneous atomic visibility to other readers. Forced termination
can expose a pending partial integration until recovery; persistent I/O failures may require
repair before recovery succeeds. Durability depends on the filesystem honoring `fsync`, not a
universal hardware power-loss guarantee.
