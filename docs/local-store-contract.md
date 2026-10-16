# Local Store draft contract (not execution)

`mobile_release.local_release_intent` introduces **DATA preparation only** for the
separate local-desktop release route. Nothing calls a Store, unlocks credentials,
creates a journal, launches a tool, enables a UI action or changes CI policy.

`decode_local_draft(bytes)` validates a bounded, closed JSON draft and returns an
immutable `LocalReleaseDraft`. `prepare_local_draft` additionally requires an
explicit `LocalStorePolicy(enabled=True)` and a matching clean local Git
observation. The policy defaults off; candidate/external and production branches
are checked separately. A local Git repository is required, not GitHub hosting.
The original owner must supply the observation; constructing a `GitContext` or
replaying a serialized `dirty:false` claim does not establish actual cleanliness.

The optional saved project setting `source.localStoreEnabled` is strictly a
boolean and defaults to false. It is exposed by the existing guided settings
editor with contextual help and the ordinary preview/save path.
`LocalStorePolicy.from_config` derives the draft policy and both branch names
from core-validated configuration; it does not read a file or prove that a
constructed `ReleaseConfig` is an original saved observation. The native owner
must supply that observation. Turning this setting on does not enable an
unfinished UI action, grant consent, change CI authorization or execute a Store
operation. Existing projects that omit it remain local-preparation disabled.

`prepare_local_release` additionally binds the draft to supplied captured bytes
of `release/mobile-release.json` and its exact configured version file. It uses
the shared configuration/version parsers and checks the original-byte digests,
configured release keys and values, enabled platform, approved application/Store
identity and stage-specific branch. The existing original file readers must
capture and retain those bytes; this pure function does not establish custody.
The lower-level decoder remains suitable for inspecting historical draft DATA,
not admitting a release. Draft assignment references use the actual Desktop
asset kinds `operation-commitment`, `apple-review-contact` and
`apple-review-demo`; old speculative aliases are rejected. `google-adc` remains
reserved for the unfinished local credential route, not the GitHub WIF input.

The draft binds local operation/project UUIDs, source commit/tree/branch, approved
application identity, release/confirmation, configuration/version/metadata
content digests, existing seven-field artifact records, and credential assignment
revision references. No credential values, absolute private paths, POSIX custody
claims, workflow IDs or GitHub authorization objects belong in this contract.
Metadata and validation artifacts plus the platform's release binaries are
required. Promotion drafts additionally require local candidate manifest/receipt
digests; production requires an external-testing receipt digest. These are
references, **not authentication or proof of actual Store state**. Artifact rows
for promotion must later be compared with the authenticated original candidate;
a draft cannot establish build-once provenance by itself.

Existing CI schemas and guards are unchanged and do not accept these documents.
There is no automatic cross-origin migration. This draft is intentionally distinct
from a future authenticated local operation intent; it does not add a generic
`execute` switch or present local evidence as a GitHub attestation.

## Still required before local release execution

- Original native ownership, actual input/artifact validation and credential
  assignment resolution/rechecking (the reference roster does not prove access).
- Durable authenticated local journal, fresh bounded consent, and independently
  observed Store preconditions/readback, including replay/partial-success recovery.
- Shared Python/Ruby local authority admission and unchanged CI guard regression
  coverage; never fabricated `GITHUB_ACTIONS`, workflow IDs or OIDC credentials.
- Bundled pinned Ruby/Fastlane runtime, real macOS qualification, and UI integration.
- No automatic public release: existing production draft/manual-release semantics
  must remain in force.

The unit tests exercise only pure parsing/preparation/refusal/immutability. They
are not native, credential, Store, signing or release-readiness evidence.
