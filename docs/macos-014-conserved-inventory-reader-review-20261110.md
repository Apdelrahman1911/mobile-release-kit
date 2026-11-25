# Conserved inventory collection role

Recovery run 42765816408 reached the copying frontier, then ordinary Installer refused `read-bound`. That reason does not identify the exact native read object. The saved inventory is 1,402,721 bytes. Both `fresh_conservation::read_attempt` and `ConservationAttemptOriginal::resume` used the generic metadata reader for the fixed alias `inventory.json`; the generic collector allowed only 1 MiB for that alias. This is a deterministic mismatch, independent of the missing per-object trace.

The two conservation slots now explicitly request the inventory role, bounded by the existing 12 MiB inventory limit and the caller's smaller exact limit. The only accepted inventory names are `install-inventory.json` and `inventory.json`. The ordinary control role remains capped at 1 MiB even when its caller supplies a larger limit. Canonical inventory callers preserve their existing behavior. All native open/protection/attribute/stat/read/identity/POST/snapshot checks and consuming closes remain shared and unchanged.

Audit: canonical installed inventory readers in maintenance and restore already select `install-inventory.json`; source inventory uses its dedicated bounded collector; conservation copy/POST uses streaming verification and held_inventory; producer/receipt/intent/state/removal records retain their smaller explicit limits. No other saved inventory collection alias was found. No persisted names/schema or global resource/deadline limits change.

The changed ordinary-user regression uses real native originals and an inventory larger than 1 MiB. It checks ordinary-control refusal, wrong-name refusal, exact inventory bounds, unchanged original offset on pre-dispatch refusals, actual collected bytes/hash/capacity, held-name POST, replacement-name refusal and consuming original closes. It does not claim root protection or Installer execution.

Before another signed candidate, validate the corrected full recovery path through an explicitly nonshipping diagnostic with the retained signed package. That diagnostic cannot qualify ordinary installation or the final package's recovery gates. Owner installation remains disabled.
