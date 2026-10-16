# Applications launcher component

This is a nonprivileged convenience launcher for the protected installed app,
not an installer, signing authority or replacement runtime entry. Integrated
placement in `/Applications`, update/removal and actual launch verification
remain required before it is delivered to users.

`build.sh ABSENT_OUTPUT.app arm64|x86_64` builds only this unsigned component
using the native macOS SDK. It refuses an occupied output and removes its own
temporary compiler cache. It does not install anything, use credentials or run
the protected app. The focused component workflow compiles both architectures.

The launcher checks the fixed installed URL against the Developer ID, team and
entry identifier; uses public strict, nested-code and all-architecture signature
checks; and refuses substitution by a running app at a different URL. It forwards
no arguments or environment overrides. The actual entry retains responsibility
for its own clean environment, installed-file admission and maintenance lock.
A fifteen-second deadline bounds initiation/completion; late results never retry
or terminate the target application.

## SDK correction

Run `38833403703/1` failed compilation on both architectures because
`kSecCSNoNetworkAccess` is not a public imported SDK constant. The correction
removes that flag, not signature validation. It does **not** set the public
`kSecCSAllowNetworkAccess` flag or substitute a private numeric constant.
Ordinary Security certificate-trust evaluation and NSWorkspace/Gatekeeper may
contact Apple under OS policy. Omitting the explicit opt-in does not itself prove
network access is disabled: Apple's implementation has a separate default-policy
setting. This component does not claim that signature evaluation or launching an
app is wholly offline. Core offline preflight and Store authorization are unchanged.

References: Apple's public
[SecStaticCode.h](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_codesigning/lib/SecStaticCode.h),
[StaticCode.cpp](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_codesigning/lib/StaticCode.cpp)
(`validationCannotUseNetwork`),
[SecStaticCodeCheckValidity](https://developer.apple.com/documentation/security/secstaticcodecheckvalidity(_:_:_:)),
and [NSWorkspace application launch](https://developer.apple.com/documentation/appkit/nsworkspace/openapplication(at:configuration:completionhandler:)).

Compilation, signature precheck and Launch Services confirmation are distinct
from successful application initialization or complete feature readiness.
