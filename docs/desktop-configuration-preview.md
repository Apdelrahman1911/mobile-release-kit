# Pure desktop configuration preparation (API/protocol 1 additive methods)

These methods only process supplied, bounded JSON. They do not read a project,
fetch `$schema`, execute argv, discover files, save, initialize, register assets,
or issue revisions/plan tokens. All existing mutation capabilities stay disabled;
pure methods remain available on Windows while filesystem snapshots remain gated.
The authoritative shape is `mobile_release.api.contracts` plus closed parameter
admission in `api.__init__` and `api._preview`.

## `config.suggest`

Exactly `{hints}`. `hints` is a closed object with optional:

- `platforms`: unique array of `android` and/or `ios`, at most two; absent means `[]`;
- `androidApplicationId`, `iosBundleId`: string, only for a listed platform;
- `versionSource`, `versionNameKey`, `versionBuildKey`: string hints, not read paths.

Strings are nonempty, at most 512 UTF-8 bytes, with no ASCII controls/DEL. Hints
fit 8 KiB, 64 nodes including keys, and depth 4. Other keys/types reject without
echoing input. Configuration policy is still checked by the shared validator.

Result exactly:

```text
{schemaVersion:1, draft:object, platformSelectionRequired:boolean,
 provenance:[{path, source:"hint"|"default"|"example", reason}],
 validation:ValidateResult, assurance:Assurance}
```

No hinted platform produces a draft with both platforms disabled, explicit
selection required and invalid validation, not fictitious detected support.
Listed platforms without an identifier get the existing example identifier,
labelled `example`; identity status stays `unverified`. Branches/locales are
labelled defaults, never observed project facts. The caller explicitly adopts a
suggestion; it never replaces an in-progress draft automatically.

### Exact projection from M1 snapshot discovery hints

For `snapshot.discovery.hints`, a present **nonempty object** at `android` or
`ios` supplies that unverified platform entry; absent, empty or non-object values
do not. Copy only singular string `android.applicationId` to
`androidApplicationId` and `ios.bundleId` to `iosBundleId`. When Android
`ambiguous === true`, omit its identity even if a singular member is present.
Never pick from `candidates`/`bundleIds`, use `namespace` as identity, or infer a
platform from a default. Copy only the three singular version hint strings.
Omit a string that violates the scalar bound; do not truncate it. The UI must
keep a visible partial/omitted-hint notice when applicable. No root, Git,
project/workspace, source build-file path, branch or other key is projected.
This is transport projection, not new discovery or validation policy.

## `config.preview`

Exactly `{base:object|null, draft:object}`. Each document fits 512 KiB, 8,000
nodes including keys and depth 28; the joined parameter object fits 768 KiB and
16,000 nodes. Root depth is zero: scalars may reach the depth limit, but containers
must remain strictly below it, including empty containers. Existing transport
framing/depth/byte bounds independently apply.
Non-JSON, cyclic, nonfinite, non-object or oversized input is a constant
`invalid_params` error. Malformed values inside admitted objects remain intact.

Result exactly:

```text
{schemaVersion:1, validation:ValidateResult,
 comparison:{baseProvided:boolean, kind:"proposed-create"|"compare",
   state:"complete"|"partial", semanticallyChanged:boolean,
   counts:{added,changed,removed},
   changes:[{path,operation:"add"|"change"|"remove",before:Summary,after:Summary}],
   unreviewedCount:number},
 fields:[{path,state:"required"|"optional"|"forbidden"|"unknown",present,reason}],
 assurance:Assurance}
Summary = {present:false} | {present:true,type:"null"|"boolean"|"number"|
          "string"|"array"|"object",count?:number}
```

`count` appears only for arrays (immediate item count) and objects (own key count).
No value, argv token, string length, raw unknown key or absolute source path is
returned in a diff. Paths are known core leaves or known structural containers
when their presence/type changes. A container is not rebuilt from visible leaves.
Changes and contexts use deterministic sorted known paths.

Object key order is insignificant; array order matters. Values are compared
without type coercion: boolean/number, null/absent and Python integer/float differ.
JavaScript cannot preserve the lexical `1`/`1.0` distinction; no client equality
or server comparison grants raw-byte serialization or filesystem no-op authority.
`base=null` is a proposed creation only, **not observed filesystem absence**.

`semanticallyChanged` covers the entire supplied objects, not just displayed
paths. Changed unknown locations are counted once at each unsupported key,
never named, and force `state=partial`; they are excluded from known-path counts.
Thus unknown-only edits cannot appear unchanged. Known malformed leaf/container
values are summarized by presence/type without exposing their contents.

Context covers every known leaf, using shared core structural/conditional facts,
not help-prose interpretation. Missing/malformed controllers produce `unknown`;
`forbidden` never deletes a value. Field `present` reports an actual own property
reachable through object parents, distinct from null/false/empty. UI-only explicit
cleanup and undo must preserve dependent/unrecognized data.

Validation uses the same core policy and returns its first failure with a
constant safe diagnostic; it does not echo arbitrary invalid key names/values.
The untouched caller draft remains the editing source. Requirements remain
unknown. Both complete result objects fit 128 KiB; contexts/provenance <=64,
changes <=64. Output overflow refuses with `preview_output_limit`, never silently
truncates a supposedly complete review.

The renderer correlates replies to project, draft revision and local baseline
generation. None of those client counters is sent back as filesystem authority.
Late replies must not overwrite newer edits or make stale context current.
Existing assurance flags stay read-only with release readiness `unknown`.
