//! Compile the whole production client and its tests, without the application.
//! Every unused admission/launch adapter below panics on entry. No stub can
//! manufacture a grant, native receipt, helper process, successful settlement
//! or key. Transport and wire decoding use the actual production modules.
#![cfg(target_os = "macos")]
#![allow(dead_code, unexpected_cfgs)]

#[path = "../../../../desktop/src-tauri/src/vault_keyring_macos.rs"]
mod vault_keyring_macos;

mod asset_session {
    use mrk_macos_installed_native::{local_keychain_wire as local, local_project_lease::ProjectLease};
    use std::sync::Arc;
    use zeroize::Zeroizing;

    pub(crate) enum KeyringMemoryAdmission {}
    impl KeyringMemoryAdmission {
        pub(crate) fn data(_: usize, _: usize) -> Result<Self, ()> { Err(()) }
    }
    pub(crate) enum KeyringInitializationAdmission {}
    impl KeyringInitializationAdmission {
        pub(crate) fn into_identity(self) -> crate::vault_format::Identity { match self {} }
    }
    pub(crate) enum LocalHistoryKeyGrant {}
    impl LocalHistoryKeyGrant {
        pub(crate) fn into_parts(self) -> (local::Context, local::Operation, Zeroizing<[u8; 32]>, Arc<ProjectLease>) { match self {} }
    }
}

mod vault_format {
    // Type-check unused public entry points only. None of these adapters is
    // used by the pipe tests, and none accepts or constructs an input identity.
    #[derive(Clone, Copy)]
    pub(crate) enum Id {}
    impl Id { pub(crate) fn bytes(&self) -> &[u8; 16] { match *self {} } }
    #[derive(Clone, Copy)]
    pub(crate) struct Identity { pub(crate) vault: Id, pub(crate) generation: Id }
    impl Identity {
        pub(crate) fn new(vault: Id, _: Id) -> Result<Self, ()> { match vault {} }
    }
    pub(crate) enum Header {}
    impl Header {
        pub(crate) fn parse(_: &[u8], _: Identity) -> Result<Self, ()> { panic!("no fixture header admission") }
    }
}

mod vault_crypto {
    pub(crate) enum InitializationKey {}
    impl InitializationKey {
        pub(crate) fn header(&self) -> &[u8; 104] { match *self {} }
        pub(crate) fn consume_for_transport<R>(self, _: impl FnOnce(&[u8; 32]) -> R) -> ([u8; 104], R) { match self {} }
    }
}

mod installed_runtime {
    use mrk_macos_installed_native::local_project_lease::ProjectLease;
    use std::{process::Child, sync::Arc, time::Instant};

    pub(crate) enum VaultHelperSlots {}
    impl VaultHelperSlots {
        pub(crate) fn new() -> Self { panic!("no fixture native admission or launch") }
        pub(crate) fn command_ready(&self) -> bool { match *self {} }
        pub(crate) fn first_failure(&self) -> Option<((), Instant)> { match *self {} }
        pub(crate) fn inspect_once(&mut self, _: &mut dyn FnMut() -> bool) -> Result<(), ()> { match *self {} }
        pub(crate) fn prepare_command(&mut self) -> Result<(), ()> { match *self {} }
        pub(crate) fn prepare_local_command(&mut self, _: Arc<ProjectLease>) -> Result<(), ()> { match *self {} }
        pub(crate) fn claim_once(&mut self) -> Result<(), ()> { match *self {} }
        pub(crate) fn spawn_original(&mut self) -> std::io::Result<Child> { match *self {} }
        pub(crate) fn check_after_use(&mut self, _: &mut dyn FnMut() -> bool) -> Result<(), ()> { match *self {} }
        pub(crate) fn check_gate_after_exit(&mut self, _: &mut dyn FnMut() -> bool) -> Result<(), ()> { match *self {} }
        pub(crate) fn settle_originals(&mut self, _: &mut dyn FnMut(Option<((), Instant)>) -> bool) -> bool { match *self {} }
        pub(crate) fn retire_command_storage(&mut self) { match *self {} }
        pub(crate) fn settle_gate(&mut self, _: &mut dyn FnMut(Option<((), Instant)>) -> bool) -> bool { match *self {} }
        pub(crate) fn code_settled(&self) -> bool { match *self {} }
        pub(crate) fn settled(&self) -> bool { match *self {} }
        pub(crate) fn retained_bytes(&self) -> Option<usize> { match *self {} }
    }
}
