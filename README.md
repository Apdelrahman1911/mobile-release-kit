# Historical branches archive

This branch preserves the full original Git histories of 198 historical named tips. Its file tree contains this guide and the branch index. Original source trees remain available at their recorded commit SHAs.

Current application work continues on `release/desktop-production`. `main` and the three platform baseline branches remain separately maintained.

## Browse a historical version

Open [BRANCHES.md](BRANCHES.md) for a clickable branch-to-commit index, or read [branch-heads.json](branch-heads.json) for the full names, commits, trees and snapshot metadata. Every recorded tip is an ancestor of this archive branch.

## Restore a historical branch

Fetch the archive and select the original SHA from the index:

```sh
git fetch origin archive/legacy-branches
git show <original-commit-sha>:<repository-relative-file>
git branch recovered/example <original-commit-sha>
```

To recreate an original branch name on GitHub, use its exact saved name and SHA:

```sh
git push origin <original-commit-sha>:refs/heads/<original-branch-name>
```

## Preservation method

The archive links the independent historical tips through ordinary two-parent history-retention commits. The archive index tree stays identical across these commits. All original commits and their source trees retain their original identities. The historical implementations remain separate versions in Git history.

The index includes the branches consolidated during this operation and the branches removed in the earlier verified cleanup. Branch names are retired only after remote archive reachability is verified. Original workflows, tags and release artifacts are preserved in their source histories.
