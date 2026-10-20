//! Unsupported-platform compile cut. No Store, source, process or native
//! owner is constructed; closed public status remains explicitly unavailable.
use super::*;
use crate::{git_local_protocol as wire,git_read_protocol as read};
use std::path::Path;
pub(super) enum Entry {}
pub(super) enum ReadyReview {}
#[derive(Clone)]
pub(crate) struct GitLocalGate {context:wire::Context}
impl GitLocalGate {
    pub(crate) fn context(&self)->wire::Context {self.context.clone()}
    pub(crate) fn check_current(&self,_:&str)->Result<asset_source::RegisteredRoot,BridgeError> {Err(BridgeError::unavailable("Local Git writes are unavailable on this platform."))}
    pub(crate) fn claim<T>(&self,_:&str,_:impl FnOnce()->Result<T,BridgeError>)->Result<T,BridgeError> {Err(BridgeError::unavailable("Local Git writes are unavailable on this platform."))}
}
pub(super) fn pending(_: &DocumentState)->bool {false}
pub(super) fn stop(_: &DocumentState) {}
pub(super) fn invalidate(_: &mut DocumentState) {}
pub(super) fn reconcile(_: &Arc<Inner>,_: &mut DocumentState) {}
pub(super) fn retained_bytes(_: &DocumentState)->Option<usize> {Some(0)}
impl DocumentBinding {
    pub(crate) fn git_local_status(&self)->wire::Status {wire::Status {schema_version:1,document_revision:self.lock().revision,available:false,review:None,operation:None}}
    pub(crate) fn git_local_prepare(&self,args:wire::Prepare)->Result<wire::StartResult,BridgeError> {
        self.git_local_unavailable(wire::StartRequest {phase:wire::Phase::Prepare,project_id:args.project_id,expected_document_revision:args.expected_document_revision,action:Some(args.action.public()),review_id:None})
    }
    pub(crate) fn git_local_apply(&self,args:wire::Apply,_:&Path)->Result<wire::StartResult,BridgeError> {
        self.git_local_unavailable(wire::StartRequest {phase:wire::Phase::Apply,project_id:args.project_id,expected_document_revision:args.expected_document_revision,action:None,review_id:Some(args.review_id)})
    }
    fn git_local_unavailable(&self,request:wire::StartRequest)->Result<wire::StartResult,BridgeError> {Ok(wire::StartResult {schema_version:1,admission:read::Admission::Refused,request,status:self.git_local_status(),reason:Some(read::StartRefusal::Unavailable)})}
    pub(crate) fn git_local_cancel(&self,_:&str)->Result<wire::Status,BridgeError> {Err(BridgeError::invalid())}
    pub(crate) fn git_local_discard(&self,_:&str)->Result<wire::Status,BridgeError> {Err(BridgeError::invalid())}
}
