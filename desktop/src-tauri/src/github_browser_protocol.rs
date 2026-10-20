//! Fixed GitHub browser destinations selected from ORIGINAL native-held data.
//! Request IDs only correlate that data; this is not an arbitrary URL opener.
use crate::{error::BridgeError, github_connection_protocol::bounds,
    github_preflight_protocol::hex, github_repository_create_protocol::coordinate,
    protocol::{strict_json, valid_id}};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all="kebab-case")]
pub(crate) enum Page { Conversation, Files }
#[derive(Clone, Debug, Deserialize)]
#[serde(tag="kind", rename_all="kebab-case", rename_all_fields="camelCase", deny_unknown_fields)]
pub(crate) enum Request {
    ActivityPullRequest { session_id:String, expected_revision:u32, expected_connection_revision:u32, operation_id:String, page:Page },
    CreatedPullRequest { session_id:String, expected_revision:u32, expected_connection_revision:u32, operation_id:String, page:Page },
    Comparison { session_id:String, expected_revision:u32, expected_connection_revision:u32, consent_id:String },
}
impl Request {
    pub(crate) fn session(&self)->&str {match self {Self::ActivityPullRequest{session_id,..}|Self::CreatedPullRequest{session_id,..}|Self::Comparison{session_id,..}=>session_id}}
    pub(crate) fn revision(&self)->u32 {match self {Self::ActivityPullRequest{expected_revision,..}|Self::CreatedPullRequest{expected_revision,..}|Self::Comparison{expected_revision,..}=>*expected_revision}}
    pub(crate) fn connection_revision(&self)->u32 {match self {Self::ActivityPullRequest{expected_connection_revision,..}|Self::CreatedPullRequest{expected_connection_revision,..}|Self::Comparison{expected_connection_revision,..}=>*expected_connection_revision}}
}
pub(crate) fn decode(raw:&[u8])->Result<Request,BridgeError> {
    if raw.is_empty()||raw.len()>1024 {return Err(refused());}
    let v=strict_json(raw).map_err(|_|refused())?;
    if !v.is_object()||!bounds(&v,1024,16,2){return Err(refused());}
    let r:Request=serde_json::from_value(v).map_err(|_|refused())?;
    if !valid_id(r.session())||![r.revision(),r.connection_revision()].iter().all(|n|*n>0&&*n<=u32::MAX-1)
        || !match &r {Request::Comparison{consent_id,..}=>hex(consent_id,32),Request::ActivityPullRequest{operation_id,..}|Request::CreatedPullRequest{operation_id,..}=>valid_id(operation_id)} {return Err(refused());}
    Ok(r)
}
// No Deserialize or public wire form. Only the same native owner produces one
// after validating original session, project/root and completed result/review.
pub(crate) enum Destination {
    PullRequest {repository:String,number:String,page:Page},
    Comparison {repository:String,base_sha:String,head_sha:String},
}
impl Destination {
    pub(crate) fn valid(&self)->bool {match self {
        Self::PullRequest{repository,number,..}=>coordinate(repository)&&crate::github_connection_protocol::numeric_id(number),
        Self::Comparison{repository,base_sha,head_sha}=>coordinate(repository)&&hex(base_sha,40)&&hex(head_sha,40)&&base_sha!=head_sha,
    }}
}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
pub(crate) struct RequestSent {state:&'static str,browser_visibility:&'static str}
pub(crate) fn request_sent()->RequestSent {RequestSent{state:"request-sent",browser_visibility:"unconfirmed"}}
pub(crate) fn refused()->BridgeError {BridgeError::new("github_browser_refused","Read the current pull request or review this comparison again before opening it.")}
pub(crate) fn unavailable()->BridgeError {BridgeError::new("github_browser_unavailable","Browser handoff requires the normal installed Mac app. Copy the shown GitHub address into your browser.")}
pub(crate) fn unconfirmed()->BridgeError {BridgeError::new("github_browser_unconfirmed","The browser request is unconfirmed. Check your browser; no automatic retry was made.")}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_wire_accepts_only_original_selectors_not_urls_or_accounts() {
        let good=serde_json::json!({"kind":"activity-pull-request","sessionId":"session-a","expectedRevision":2,"expectedConnectionRevision":3,"operationId":"read-a","page":"files"});
        assert!(decode(&serde_json::to_vec(&good).unwrap()).is_ok());
        for k in ["url","repository","number","token","argv","path"]{let mut v=good.clone();v[k]=serde_json::json!("inert");assert!(decode(&serde_json::to_vec(&v).unwrap()).is_err());}
        let mut v=good;v["page"]=serde_json::json!("merge");assert!(decode(&serde_json::to_vec(&v).unwrap()).is_err());
        assert!(decode(br#"{"kind":"comparison","kind":"comparison"}"#).is_err());
        assert!(decode(&vec![b' ';1025]).is_err());
        assert_eq!(serde_json::to_value(request_sent()).unwrap(),serde_json::json!({"state":"request-sent","browserVisibility":"unconfirmed"}));
    }
}
