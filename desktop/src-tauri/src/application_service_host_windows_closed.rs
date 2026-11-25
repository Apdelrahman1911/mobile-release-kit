//! Windows has no native application-state host. No Ready/use token can exist.
use std::{path::PathBuf,sync::Arc};
use crate::{application_service::ProjectBinding,application_state_store::{PrivateStateDirectory,NativeUse,StateError},service_protocol::Error};
#[derive(Clone)]
pub(crate) struct NativeProject {
    pub(crate) runtime_id: String,
    pub(crate) canonical_root: PathBuf,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) registration_generation: u32,
    pub(crate) document_identity: Arc<()>,
    pub(crate) input_revision: u64,
}
pub(crate) enum NativeStateReady {}
pub(crate) enum NativeStateLease {}
pub(crate) enum NativeStateTicket {}
impl NativeStateReady {
    pub(crate) fn store(&self)->&Arc<PrivateStateDirectory> {match *self {}}
    pub(crate) fn project_binding(&self)->&ProjectBinding {match *self {}}
    pub(crate) fn begin_use(self:&Arc<Self>)->Result<NativeStateLease,StateError> {Err(Error::UnsupportedPlatform.into())}
}
impl NativeStateLease {
    pub(crate) fn context(&self)->&NativeStateReady {match *self {}}
    pub(crate) fn store(&self)->&Arc<PrivateStateDirectory> {match *self {}}
    pub(crate) fn project_binding(&self)->&ProjectBinding {match *self {}}
    pub(crate) fn native_use(&self)->&Arc<NativeUse> {match *self {}}
}
