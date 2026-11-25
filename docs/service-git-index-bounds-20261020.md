# Git-index v60 test-bound correction

The real v60 library and TypeScript graphs compiled. Two Git-index-related
tests failed; this successor changes tests only, not production limits or
the capabilities JSON shape.

Apply `service-git-index-bounds-hooks-20261020.patch` to the shared CLI test.
Its obsolete 8 KiB assertion now matches `capabilities`' existing enforced
12 KiB output ceiling (also already used by the Git-index catalogue test).
Descriptions and all command/permission fields remain unchanged.

The existing escaped-selection test now retains the accepted near-bound
case: 64 paths with four 250-quote components serialize to 128,868 bytes.
The adjacent 251-quote case has valid path/component lengths but serializes
to 129,380 bytes, exceeding the unchanged 129,024-byte selection ceiling.
The test uses real `serde_json`, checks both sides, verifies the counting
writer's exact-size boundary, and includes the near-bound selection in the
existing complete response envelope check.

Root rerun selectors (no author Cargo/test execution):

- `installed_cli::tests::capabilities_keep_read_grants_separate_from_desktop_reviewed_proposals`
- `service_git_protocol::tests::capacity_and_escaped_reply_bounds_apply_before_output_allocation`

Author source-format and current-Root patch checks are separate from the
pending actual Rust test results. The failed v60 evidence remains retained.
