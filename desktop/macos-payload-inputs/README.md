# macOS ARM64 payload inputs

These are public, source-reviewed inputs for `../tools/macos_payload.py`, not a
runtime, source-authentication service, publisher signature or distribution
approval. The driver fetches only the three exact HTTPS archives in
`sources.json`, checks their complete size/SHA-256, and stages them before the
offline build recipe. It never installs packages or searches a user's Python.

CPython/zlib authority is the retained official-HTTPS pin and source
correspondence, **not signature verification**. The OpenSSL pin additionally
has retained successful official-key GPG verification. The CA is the exact
previously reviewed certifi/upstream-corresponding public body. Notice hashes
identify the retained upstream texts; they do not approve Apple's toolchain.

The native driver records actual selected Apple CLT/SDK/tool/compiler-resource
identities and any present vendor documents. Applicable Apple/LLVM
incorporation/redistribution obligations still require independent review.
GNU/Linux/glibc/GCC notices are not transplanted into this Darwin profile;
Apple OS `libffi` is not the separately built Linux `libffi3.4.8`.

## What one future successful job will prove

- One conventional ordinary-GIL/non-framework CPython 3.14.7 on **macOS 26
  ARM64**, deployment target26.0; no Intel or older-macOS qualification.
- Private OpenSSL3.5.8 dylibs, builtin extensions, static zlib1.3.2 and internal
  HACL/Expat; copied bytecode-free stdlib and actual generated configuration.
  CPython's actual `BUILDPYTHON`/`BUILDEXE` selects `python.exe` on
  case-insensitive APFS (to avoid `Python/`); either admitted native spelling
  is copied to the same final `python/bin/python3`, never guessed from PATH.
- Closed Mach-O load paths, original→relocated→ad-hoc-signed correspondence,
  and the unchanged runtime preparer's six bootstraps/core ZIP/CA manifest.
- Copied-interpreter native imports, actual generated builtin roster,
  relocated load origins, and exact passive capabilities/catalog frames under
  the existing Darwin ordinary command owner.

The one work deadline is1800s, with30s reserved for final records and settled
cleanup; each command reserves the ordinary owner's original3s cleanup tail.
Captures are16MiB summed per command, retained evidence≤256MiB; payload bounds
remain the unchanged preparer's bounds. Builds use `make -j2`, private home/tmp
and a clean fixed environment. There is no aggregate RSS or OS network-sandbox
claim. The only network phase is fixed-source acquisition. Workflow timeout is
VM disposal, **not proof of original wait/EOF/handle/handler settlement**.

Only after original settlement does the driver delete its original task-owned
build/source/dependency roots. It retains the actual payload, compact evidence
and a mode-preserving `payload.tar`; the upload includes only evidence and tar,
never a failed build tree. An unknown owner causes no follow-up native work or
recursive cleanup. The dedicated VM is the final infrastructure boundary; such
a run remains failed, not "clean by disposal".

**Acceptance requires both the original workflow step's successful conclusion
and its final `evidence/result.json` with cleanup/accounting established.**
`work-result.json` is provisional; a partial artifact/upload is not a pass.
Final output inventory explicitly excludes itself and `result.json` to avoid
self-reference. Native result review must reconcile final manifest and copy/
signing correspondence; preparing hashes is not independent acceptance.

This SOURCE slice is unexecuted until independent SOURCE/COMMAND acceptance.
It does not enable production launch, installed runtime custody, UI/Save/Quit,
TLS/Store operations, installers, Developer-ID signing or notarization. A
physical Mac/signing account is not required for this bounded hosted payload
slice; distribution signing and installation remain separate obligations.
