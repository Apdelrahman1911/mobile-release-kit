# macOS Python public-source inputs

This is an input nomination, **not a usable Python runtime or an approved build
recipe**. The ARM64 target is CPython 3.14.10 with the ordinary GIL on macOS 26
ARM64 (`aarch64-apple-darwin`).

`source-lock.json` records the exact four public upstream archives and their
inventory hashes. The ARM64 producer checks CPython and OpenSSL against pinned
decoded TAR digests, file inventories and directory rosters. Libffi and zlib
retain their existing upstream inventories. Intel retains its separate source
lock and requires its own qualification.

The six notice rows identify required public source inputs, not complete license
or distribution clearance. Actual incorporated CPython, dependency, compiler and
SDK components still need corresponding notices.

Every approval flag intentionally remains false. Nothing in this directory
downloads, builds, selects or activates a supplier. The historical project
supplier artifact is not an allowed fallback.

Next: inspect the authenticated upstream configure/Setup/Makefile sources, freeze
and independently review the concrete macOS recipe and native execution bounds,
then build on GitHub-hosted macOS. Genuine output, module/loader closure, notices
and the installed application must be verified before supplier activation.
Intel and other macOS targets require their own applicable native evidence.
