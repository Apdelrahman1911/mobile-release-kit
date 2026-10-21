# Canonical candidate caller and exact predecessor update

Base: `420db551a18925d759994548ef747fdff995e139`. This is a source/generator
integration, not a GitHub or native execution qualification.

## What changes

The fixed `api/data/github-setup-v1.json` candidate caller now equals the
already-supported `templates/workflows/mobile-candidate.yml`. The actual
`github.setup.propose` and saved-source Setup publication generators therefore
produce the same two-job caller:

- `candidate` remains the default and uses only the candidate job.
- `reserve-version` and `recover-play-edit` select the existing protected
  version job, with the exact operation, platform and confirmation inputs.
- Both reusable-workflow invocations retain the selected full toolkit SHA in
  `uses` and `tooling_sha`, and bind `source_sha` to `${{ github.sha }}`.
- The version caller passes only the existing GitHub App secret references.
  The separate protected Play recovery key remains an external setup
  requirement in the reusable workflow. No key, edit ID, token or new recovery
  correlation input is added to the caller or proposal.

The other three callers, schema, bounds, selected toolkit coordinate and
workflow permissions are unchanged. Generation/preview does not check that
an arbitrary user-selected older toolkit SHA supports the new operations;
the selected pinned tooling must contain the updated reusable workflow.
No branch or SHA is silently substituted.

## One predecessor, before-image only

`github_workflow_candidate_compat.py` contains the immediately prior shipped
candidate literal. Its pure helper first uses the existing exact current
matcher, then permits this **one candidate-only predecessor**, after the same
supported repository/SHA rendering. It does not parse or normalize YAML.
Comments, line-ending changes, inconsistent repeated pins, other-family
aliases and any other user changes remain conflicts.

The helper is used only at these existing before-image checks:

1. Workflow editor `_derive` produces the existing explicit update preview.
2. `InitWorkspace._admit_workflow_updates` rechecks the real original before
   image; its AFTER matcher remains current-only.
3. Setup publication Prepare validates each original remote caller blob.
4. `Prepared.parse` revalidates the same complete original bytes.

Resource digest, original `RootedRevision`, full before bytes and physical
identity, one-use consent, filesystem transaction/rollback, remote base/tree
CAS, and all original retirement/unknown guards remain unchanged. The old
literal is **not** added to the Release dispatch/current caller matcher.
Uncertain prior work does not become retryable. An older binary will still
refuse an unfamiliar newer caller; this is not a backwards migration or an
automatic YAML merge.

## Cleanup source after the branch advances

The supported dispatch input is the configured **branch**, with actual
current dispatch HEAD B. It is not an arbitrary historical SHA or tag. The
existing protected version job validates `inputs.source_sha == github.sha`
and checks out B with `fetch-depth: 0`, without persisted Git credentials.

The already-implemented cleanup then independently reads the retained
candidate's original commit A, tree, configuration and version blobs and
checks their full binding. B is not substituted into that request. Missing
original objects refuse before the no-network verifier, one-use cleanup
claim or DELETE. There is no fetch/reset/checkout fallback inside cleanup.
The new tests exercise advanced B versus original A and unavailable A with
explicit fake Git/HTTP/child boundaries; no GitHub dispatch was executed.

This packet makes the generated caller usable for the supported workflow
inputs after separately reviewed setup. It does **not** add a Desktop or
installed-agent `recover-play-edit` action. That explicit dispatch/consent
integration is a separate Service-owned slice; source generation alone is
not full Desktop cleanup parity.

## Delivery

Owned files:

- `src/mobile_release/api/data/github-setup-v1.json`
- `src/mobile_release/github_workflow_candidate_compat.py`
- `tests/workflow/test_github_setup_candidate_yaml.rb`
- this guide
- `docs/github-canonical-candidate-hooks-20261021.patch`

Apply the patch once to these **eight** existing targets (they were not edited
in the author worktree):

1. `src/mobile_release/github_workflow_edit.py`
2. `src/mobile_release/init_transaction.py`
3. `src/mobile_release/github_setup_publication.py`
4. `tests/desktop/test_github_setup.py`
5. `tests/desktop/test_github_workflow_edit.py`
6. `tests/desktop/test_workflow_transaction_profile.py`
7. `tests/desktop/test_github_setup_publication.py`
8. `tests/unit/test_version_hosted_play_recovery.py`

## Actual bounded author checks

The existing unittest runner used a task-owned public source projection,
UID/GID 65534, no supplementary groups/capabilities, no-new-privs, empty
environment except fixed PATH/HOME/TMP/locale/PYTHONPATH, and a 120s outer
bound. No dependency install, live Git, provider, Ruby SDK or native process
ran. Original filesystem fixtures did use real held files/directories and
the existing InitWorkspace transaction/rollback owner. Remote publication
and hosted recovery used their explicit existing transport/child doubles.

- **98 distinct Python tests passed across bounded runs**: first 93 passed;
  four corrected cases then passed; the final corrected platform-matrix case
  passed. Unchanged passing cases were not rerun. The new actual filesystem
  Apply/rollback/stale tests and advanced-HEAD tests passed in the first run.
- Corrections were test/preparation-only: a prior caller's sole repository
  marker may be any supported coordinate; the inert workspace needed the
  actual fixed resource digest; one existing helper import was missing from
  the projection; the real private journal correctly refused `/tmp` ancestry,
  so the next task root used an existing safe `/home` parent. Its guards were
  not changed. The old inert platform expectation now explicitly includes
  the already-admitted `PROJECT_INITIALIZATION` and `PROJECT_IDENTITY` enum
  arms on Darwin, with no production admission changes.
- **3 YAML tests / 70 assertions passed**, parsing the actual JSON caller and
  reusable workflow as data. They check both pin/source invocations, closed
  dispatch choices, permissions, exact secret references, current HEAD and
  original-history checkout prerequisites.
- Own/helper and all eight projected Python sources parsed. Patch replay,
  own-base/current-Root apply checks and whitespace checks passed.

Evidence is retained in `.task-github-canonical/`: `python-v1.log` (including
the initial failures), `python-v2.log`, `python-v3.log`, `yaml-v1.log`, matching
exit files, source manifests and `cleanup-v3.json`. All actual callers
returned. The passing 399-file projection and empty HOME/TMP were retired by
exact inventory; the initial failure evidence is preserved. No installed
app, live workflow/provider, protected-key provisioning or dispatch success
is claimed.
