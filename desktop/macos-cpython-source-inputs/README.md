# macOS Python public-source inputs

This is an input nomination, **not a usable Python runtime or an approved build
recipe**. The first target is CPython 3.14.7 with the ordinary GIL on macOS 26
ARM64 (`aarch64-apple-darwin`).

`source-lock.json` records the exact four public upstream archives, their hashes
and source inventories. Only upstream source facts are shared with the existing
Linux input lock; its compiler, dependency packages, execution permissions,
runtime layout and ELF configuration do not apply to macOS.

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
