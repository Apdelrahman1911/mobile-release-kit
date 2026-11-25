# Desktop-reviewed CLI identity requests

Scope: enter an app-ID proposal once in the installed CLI, then explicitly read,
preview and approve it in the running Desktop's **original** identity editor.
This is not CLI Apply, configuration JSON mutation, autonomous editing or native
qualification. Existing static `mrk capabilities` is unchanged.

## Exact ownership / integration

Four new Rust modules:

* `agent_identity_requests.rs`: closed DATA, per-launch bounded proposal inbox.
  No Desktop import; also compiled into the existing client-only binary.
* `installed_cli_identity.rs`: two fixed commands in the existing installed CLI.
* `asset_session_agent_identity.rs`: child of the actual DocumentBinding, seven
  closed main-Webview commands; no new process or filesystem owner.
* `edit_owner_agent_identity.rs`: child of the actual EditOwner. Memory-only
  request-to-original-Session linkage and common Prepare/Apply guards.

The companion patch is **Root-only**, against the current integration sources.
It changes 16 central files: service protocol/service/Host, AssetSession and its
two existing identity/service children, EditOwner, lib/client entry/CLI, shell,
and frontend `projectIdentityNative.ts`, `types.ts`, `bridge.ts`,
`ProjectIdentityEditor.tsx`, `App.tsx`. It does not change the state store,
accepted history mapper/relay, qualification flags or any existing peer gate.
All source bytes were read from integration; no integration file was edited.

## User flow

1. In Desktop Settings, enable the existing project read access. Separately
   enable **Allow identity proposals · 15 minutes** for the selected project.
2. Obtain the stable project ID and current saved observation revision from
   the existing read commands. Send one closed stdin object:

   ```text
   mrk identity-request PROJECT_ID OBSERVATION_REVISION --stdin --json
   {"selection":{"platform":"android","target":":app","project":null},"desiredIdentity":"com.example.separate","identityIntent":"new-application"}
   ```

3. The CLI prints an exact nonsecret instance/intent query receipt **before**
   sending. It never automatically retries or puts the desired identity in
   argv. On a lost response, query that receipt; do not resubmit the edit.
4. In Desktop Settings, **Check requests**, select its already registered
   project, and **Open request review**. This only binds the immutable editor;
   it does not auto-open a native session. Click **Read App ID**, acknowledge a
   separate new app when required, **Preview**, review/acknowledge the exact
   native preview, then **Apply**. Original local drafts are kept separately.
5. `mrk identity-request-status PROJECT_ID SERVICE_INSTANCE INTENT_ID --json`
   returns the original SID if one was actually installed. Query the existing
   operation-history route separately. History capture is optional and a
   captured link is not a durable history acknowledgement or native finality.

No renderer field supplies a root, continuity decision, executable, window,
Session or desired-identity replacement to the native review wrappers.
Original Status, Close and explicit original GUI recovery remain available.

## Admission, races and no replay

* Same existing UID/capability Unix transport and complete 4096-byte frame
  bound. Read grant alone cannot submit. The separate lease is default-off,
  project-scoped, monotonic and at most 15 minutes.
* At most 32 non-evicted per-launch intent records and one queued/admitting
  proposal. An identical instance/intent/body from a new authenticated
  connection only observes the first entry. Changed bodies conflict. Neither
  disconnect nor restart causes replay/adoption. A lost old instance remains
  unavailable/conflicting, not "not started".
* Service grant validation stays held through the **memory-only** inbox put.
  Doc/Edit never calls into Service/store while holding its original guards:
  real saved-point lookup is off-lock, followed by the same native root,
  registration, document identity and SavedEditStamp recheck.
* First-Allow captures the original Document revoke epoch before off-lock IO.
  Revoke advances that epoch under the same Document mutex **even before a
  service link exists**; late Allow rechecks it before installing a lease.
  Revoke always requests the original EditOwner STOP, including error paths.
* The original ticket carries an opaque link. Immediately after the permanent
  original `claimed = true`, the entry records that claim. After installing the
  **same** ActiveOwner, its actual SID/generation/Session weak link is bound
  once, **before** the original bump/history/queue/GO. No status-shaped object
  or optional history getter mints that link.
* A genuinely returned preclaim refusal is distinct from claimed/unreturned
  uncertainty. The latter never invites replay. Proposal occupancy releases
  only on the actual original ownership handoff, not on native finality.
  Weak disappearance, replaced status or absent history never means settled.
* Common original Prepare and Apply check the retained immutable proposal and
  current review/permission, including calls via the ordinary GUI endpoints.
  Invalid new wrapper requests retire the original review just like the
  existing wrappers. New-app and exact-preview acknowledgements are never
  restored from proposal data. No new Apply is authorized after revocation.
* Frontend permission calls use two finite retained slots (normal + Revoke),
  latched before invocation. A UI epoch suppresses a late Allow result after
  Revoke, and status/proposal data is pinned to the original API instance.
  The existing retained CLI service preserves Revoke on failed reconnect.
  Revoke also runs at a saturated display epoch and supersedes the retained
  normal result. Proposal seeding requires the same pair and UI snapshot.
* Original fixed document census reserves 491,520 bytes for inbox/transient
  DATA. No daemon, worker, generic RPC, polling framework or second writer.

## Focused evidence / limits

* Eight new Node DATA/RAW/controller tests passed, original process exit 0,
  0.162 s. Test input was a task-owned mirror of four **complete actual** TS
  modules (including the exact patched native adapter), not extracted/stubbed
  code. Its closed inventory was removed after the joined command.
* 21 Rust tests are authored **not run/compiled in this lane**: 13 inbox/actual
  UDS tests, two EditOwner matching/unqualified-gate tests, three Document
  tests and three installed-CLI tests. The revoke regression calls the actual
  Document Revoke before a service link exists, then the exact original
  lock-held late-Allow epoch guard. It is not a fake positive native admission.
* Root should batch `agent_identity` and `installed_cli::identity::tests`
  filters in the actual graph; the existing strict socket bound requires the
  existing short private HOME fixture convention. Also build the actual thin
  CLI binary and run the integrated frontend typecheck/affected tests.
* Rust syntax parsing and patch applicability are separate from compilation.
  No actual Mac/native edit, renderer automation, credential, Store, provider,
  release or installed delivery was tested. Existing native qualification
  gates remain authoritative and disabled where previously disabled.
