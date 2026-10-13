# Mobile Release Kit maintained source

Origin: `secret-service` 5.2.0, upstream
https://github.com/hwchen/secret-service-rs . The published crate archive SHA256 is
`5107b24b91445dd2aa449a258a1807b63240942157292354dc5bfdbeb8bc6db8`.
The complete upstream source and both `LICENSE-APACHE` and `LICENSE-MIT` are
retained. This local copy is not an upstream release or endorsement.

Baseline: MRK checked-reply-routing SOURCE02, complete result inventory SHA256
`e6c20e176e73c7a8d8e77db8b4f078f40c8751bd9333aeb5d73f40f1fb371d39`.
That baseline adds bounded borrowed reply support and preserves raw asynchronous
method/prompt errors; it does not qualify transport allocation or task finality.

Consumer01 adds only `checked_lookup`: raw, uniquely routed SearchItems and
Attributes calls, plus borrowed bus-owner/empty-reply views. Shared envelope
admission preserves absent signatures for genuinely empty bus replies only.
Legacy lookup/session/blocking APIs are unchanged by Consumer01. Inline tests
are synthetic DATA tests; never run the default legacy suite against a user's
keyring. Persistent credentials remain disabled in the Desktop application.

Original-task finality adds two concrete owned-path checked_lookup starters.
They reuse the same bounded route validation and Query/Attributes bodies while
storing owned arguments in maintained zbus's fixed original RPC slot. Ordinary
Connection-based APIs remain unchanged; no connection trait, codec duplication,
proxy/cache task or native/public activation is added. The standalone SDK root
patch selects the same maintained zbus5.19.0 as the application root.
