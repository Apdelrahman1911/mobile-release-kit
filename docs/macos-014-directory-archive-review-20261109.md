# macOS 0.1.4 directory and archive review

Reviewed runtime source: `1e8671a274027ddf9b6aa3e3d71563af0dd5e877`,
tree `0a7880eb71079d1f88d57c5305d6321c986c20b5`.

The interrupted-write inspection exposed an installer directory buffer smaller
than the native API's required 64 KiB. Review covered all 31 callers and corrected
the installer and two GitHub source readers. The source working reservation now
includes its actual buffer. Existing roster, filename and parser bounds remain.

The archive census's optional conservation span is separately allocated, with
its complete pointee and fact-vector bytes charged by the existing accounting.
The actual empty 64-slot table occupies 123,504 bytes within its unchanged
131,072-byte limit. The 2 MiB archive work reservation and wire format remain.

The actual unchanged native API refused 4 KiB and 16 KiB buffers and completed a
64 KiB directory read, EOF and known close on an owned temporary fixture. Full
installer regression passed 27 tests under the 3 GiB compiler limit; its peak was
844,021,760 bytes. One pre-existing ordinary-user disposable-DMG test was ignored.
A stale test-only snapshot initializer was completed with `conservation: None`.

This candidate uses the existing Desktop26 build-only route. It authorizes no
release publication. A newly signed package must independently pass artifact
admission, ordinary disposable installation and both first-install recovery
scenarios. Previous-package successes do not qualify these new package bytes.
Owner-machine installation remains pending those checks and final live bindings.
