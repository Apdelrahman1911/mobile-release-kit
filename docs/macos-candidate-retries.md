# Retry one Mac candidate part

Use **Re-run failed jobs** on the existing candidate run. Successful jobs keep their immutable outputs for 14 days. A signing or packaging failure reuses the completed compiler outputs from that exact source and run. Do not choose **Re-run all jobs**: multiple successful originals for one part are deliberately refused.

Tool26 and Git27 have separate job chains. Each has 14 parts: preparation, resident image, vault helper, frontend, observer and its DATA checks, remover, command-line app, remover signing, command-line signing, app assembly/signing, payload notarization, installer compilation, scripts/package creation, and final package signing/notarization/export. The final native owner and its receipt/export stay together; its original invocation is never resumed halfway or given a new deadline.

Every transfer checks the actual successful GitHub job, source/tree, original attempt, artifact digest, complete dependency chain, archive spans/CRC, file hashes and modes. The receiving runner creates fresh files and repeats the original source and native admission checks. Compiler caches, signing stores and credentials are excluded. These intermediate files do not qualify an installation or a functional check.

A new source commit starts a new candidate. Completed outputs from another source or run cannot qualify it. Diagnose a failed part before retrying it. The automatic Git check starts only after both complete signed candidates pass; local service/reboot verification and the other independent groups retain their existing prerequisites.
