//! Setup-only same-executing-image signer. Not a package or provisioning grant.
//! Caller retains original source custody, protected ancestors and W/F/H owner.
pub(crate) use mrk_macos_installed_native::xcode_self::{SelfSigner, CF_REFERENCES, OWNED_BYTES};
