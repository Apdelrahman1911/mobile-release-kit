# Fresh macOS CPython source supplier

This is a **verification-only supplier build**, not a Desktop installer or a
public release. It replaces neither installed-app qualification nor the CLI/core.
The initial target is **ordinary-GIL CPython 3.14.7, ARM64, macOS 26**. Intel is not
activated by this workflow.

## When to use it

After the producer, probe, source recipe and workflow have passed independent
review and focused local DATA checks, the reviewed commit can be tested on the
fixed `verify/desktop-macos-cpython-source-build` branch. The workflow is
`.github/workflows/desktop-macos-cpython-source-build.yml`; it has one `producer`
job on a disposable GitHub-hosted `macos-26` ARM runner. There are no arbitrary
inputs, manual dispatch, matrix, automatic retries or consumer activation.
Do not run this native producer on a shared development machine.

The checked-out commit, workflow commit, push event and fixed repository/branch
must agree. The workflow checks source cleanliness before and after the producer,
including a failed build. Checkout does not retain Git credentials. No Store,
signing, release or user credentials are passed to the producer.

## What runs

`actions/setup-python` selects an absolute **orchestration** interpreter. It is
not copied into the supplier. With an empty inherited environment plus the fixed
host/run identity allowlist, the workflow invokes only:

```text
<selected Python 3.14.7> -I -S -B desktop/tools/macos_cpython_source_build.py
```

The entry takes no arguments. It alone creates its exclusive directory under
`RUNNER_TEMP`, acquires the four hash/length-pinned public source archives from
the source lock, and uses the existing command owner for serial native phases.
No historical supplier artifact, downloaded run evidence, system Python or
alternate build route is a fallback.

The source recipe builds fresh static OpenSSL and zlib and uses Apple's SDK/system
libffi for the supported Darwin calling convention. The nominated private-libffi
source notice is retained but does not imply its code was incorporated. Generated
configuration, builtins, loader dependencies, actual C calls/callbacks, local TLS,
relocation and cancellation are checked together by the native producer. A green
Linux DATA test cannot replace those Mac results.

The owner has one 45-minute work budget and a 120-second cleanup allowance; the
job has 55 minutes including setup and transport. Build parallelism is limited to
`make -j2`; no shared cache or other task's process is cleaned. Scratch is removed
only after its own processes, descriptors and handlers are genuinely settled.
The workflow does not retry commands or add shell cleanup that could hide the
original failure.

## Outputs and failure semantics

The unique task root is:

```text
${RUNNER_TEMP}/mrk-macos-cpython-${GITHUB_SHA}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}
```

During native work there is **no `public/` directory**. Diagnostics remain private
to the task until original child/descriptor/handler finality and the cleanup
attempt are known. Unknown finality publishes nothing. A settled failed attempt
can publish bounded evidence, but never a successful supplier receipt or tar.
A missing artifact on a failed run is not a pass or a reusable supplier.

After the entry returns, Actions retains only these outputs, for 14 days:

| Artifact | Exact public content | Gate |
| --- | --- | --- |
| `desktop-macos-cpython-evidence-<sha>-<run>-<attempt>` | `public/evidence/` | Closed export after a real attempt; at most 128 regular files / 32 MiB; missing evidence fails a nominally successful build. |
| `desktop-macos-cpython-supplier-<sha>-<run>-<attempt>` | `public/supplier.tar` and `public/supplier-receipt.json` | Actual producer exit 0, unchanged source and successful evidence transport. |

The producer caps each retained phase capture at 2 MiB and the receipt at 1 MiB.
No downloaded archive, source/build scratch or arbitrary task-directory glob is
uploaded. Raw directories are not used for supplier transport because Actions
changes file modes. The tar contains only `python/`, no links, directories0555,
`python/bin/python3`0555 and other files0444. Its normalized uid/gid metadata is
not evidence of installed ownership. Consumers must extract through their own
reviewed bounded path and admit the actual resulting owner, tree, modes and
bytes. Do not invoke an unreviewed general extraction command on the payload.

## Accepting an actual supplier

Record the exact source commit, workflow, run/attempt, native platform and actual
job/step outcomes. A queued, skipped, cancelled or unavailable job is unexecuted,
not a pass. A tar/receipt produced before a later workflow failure is not delivery.

After the actual successful run, independently hash the downloaded receipt and
bind that SHA256 separately from the receipt's own claims. Reconcile its exact
13-key schema, source/recipe/toolchain/inventory bindings and seven native evidence
references (`build`, `relocation`, `modules`, `loader`, `tls`, `cancellation`,
`notices`) against the corresponding closed evidence and payload. The consumer
limits remain 2035 supplier files / 464 MiB with its own output reserve.
Hashes and self-reported JSON are references, not independent native approval.

Only that separate acceptance can authorize a fresh installed-runtime consumer
pin. This workflow does not set one, mutate source locks, edit another workflow,
publish a release or upload to any Store. Installed launch, UI, Keychain,
Android/iOS operations, Intel support, Developer ID and notarization remain their
own obligations; this supplier build does not claim them.

## Small local regression scope

`tests/desktop/test_macos_cpython_source_workflow.py` reads this one workflow as
SOURCE DATA. Its three grouped contracts cover the fixed host/source route and
pinned actions, the clean environment/original exit status, and the separate
closed-evidence/successful-supplier upload gates. It does not import the producer,
run Bash, invoke Git, use the network or execute a native process. Batch it with
the producer's focused DATA cases under the reviewed local owner before using
the native runner; no full application build is needed for this YAML-only check.
