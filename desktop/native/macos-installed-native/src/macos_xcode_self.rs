//! Setup-only same-executing-image signer. Not a package or provisioning grant.
//! Caller retains original source custody, protected ancestors and W/F/H owner.
pub(crate) use crate::xcode_self::{SelfSigner, CF_REFERENCES, OWNED_BYTES};
