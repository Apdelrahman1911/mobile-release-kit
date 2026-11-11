//! Unsupported-platform DATA surface; no persistence or successful native acquisition.
use crate::service_protocol::Error;
include!("application_state_data.rs");
pub(crate) enum NativeUse {}
pub(crate) enum PrivateStateDirectory {}
impl NativeUse {
    pub(crate) fn same(&self,_:&Self)->bool {match *self {}}
}
impl PrivateStateDirectory {
    pub(crate) fn begin_native_use(&self)->Result<NativeUse> {Err(Error::UnsupportedPlatform.into())}
}
