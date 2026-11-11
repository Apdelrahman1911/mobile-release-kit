//! Project reference DATA only. No Windows service/store implementation is linked.
use crate::service_protocol::Id;
use serde::{Deserialize,Serialize};
include!("application_project_binding_data.rs");
pub(crate) enum ApplicationService {}
