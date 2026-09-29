//! Credential-free protocol DATA shared by focused unit tests. No native owner,
//! platform witness, installed grant, network request or crypto qualification.
use super::*;
use serde_json::json;
pub(crate) fn prepared() -> Prepared {
    serde_json::from_value(json!({
        "target":{"projectBinding":"1".repeat(64),"repository":"fixture/project","accountId":"123",
            "repositoryId":"456","branch":"main","toolingRepository":TOOLING_REPOSITORY,"toolingSha":"2".repeat(40),
            "scope":{"platform":"android","stage":"candidate","purpose":"signing"},"kind":"android-keystore",
            "marker":"a".repeat(32),"nativeConfigSha256":"3".repeat(64)},
        "sourceSha":"4".repeat(40),"callerSha256":"5".repeat(64),"configSha256":"6".repeat(64),"environmentId":"789",
        "environmentPolicy":{"canAdminsBypass":false,"branchPolicy":{"protectedBranches":true,"customBranchPolicies":false},
            "rules":[{"type":"required_reviewers","id":"11","preventSelfReview":true,"reviewers":[{"type":"User","id":"123"}]}]},
        "publicKey":{"keyId":"fixture-key","key":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="},
        "metadata":{"state":"present","createdAt":"2026-09-01T00:00:00Z","updatedAt":"2026-09-02T00:00:00Z","observedAt":"2026-09-28T12:00:00Z"},
        "observedAt":"2026-09-28T12:00:00Z"
    })).unwrap()
}
pub(crate) fn request(kind:Kind) -> Request {
    let prepared=prepared();
    if kind==Kind::Pending {return Request {action:None,pending_scope:Some(PendingScope {
        project_binding:prepared.target.project_binding,repository:prepared.target.repository,
        account_id:prepared.target.account_id,repository_id:prepared.target.repository_id}),home:Some("/inert/home".into())};}
    Request {action:Some(Action {kind,target:prepared.target.clone(),prepared:if kind==Kind::Prepare {None} else {Some(prepared)}}),
        pending_scope:None,home:if kind==Kind::Prepare {None} else {Some("/inert/home".into())}}
}
pub(crate) fn record(marker:&str,write:RemoteWrite) -> PrivateRecord {
    let mut prepared=prepared();prepared.target.marker=marker.into();
    PrivateRecord {intent_sha256:prepared.intent_digest().unwrap(),prepared,write}
}
pub(crate) fn frame(value:Value) -> Vec<u8> {let mut out=serde_json::to_vec(&value).unwrap();out.push(b'\n');out}
pub(crate) fn control(reason:crate::github_connection_protocol::Reason) -> Value {
    json!({"reason":reason,"credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false})
}
pub(crate) fn ready(id:&str,digest:&str,kind:Kind) -> Vec<u8> {
    frame(json!({"protocol":PROTOCOL,"id":id,"ready":{"requestSha256":digest,"phase":"observe","journal":kind.journal()}}))
}
pub(crate) fn rechecked(digest:&str,original:&Prepared) -> Rechecked {
    Rechecked {request_sha256:digest.into(),snapshot_sha256:original.snapshot_digest().unwrap(),
        intent_sha256:original.intent_digest().unwrap(),snapshot:original.clone()}
}
pub(crate) fn rechecked_frame(id:&str,value:&Rechecked) -> Vec<u8> {
    frame(json!({"protocol":PROTOCOL,"id":id,"rechecked":{"requestSha256":value.request_sha256,
        "snapshotSha256":value.snapshot_sha256,"intentSha256":value.intent_sha256,"snapshot":value.snapshot}}))
}
pub(crate) fn remote(id:&str,value:&Rechecked,write:RemoteWrite,control:Value) -> Vec<u8> {
    frame(json!({"protocol":PROTOCOL,"id":id,"outcome":{"requestSha256":value.request_sha256,
        "snapshotSha256":value.snapshot_sha256,"intentSha256":value.intent_sha256,"write":write,"control":control}}))
}
pub(crate) fn terminal(id:&str,request:&Request,reason:Reason,write:Option<RemoteWrite>,network:Settlement,journal:Settlement) -> Vec<u8> {
    let action=request.action.as_ref().unwrap();
    let record=write.map(|write| {let prepared=action.prepared.as_ref().unwrap().clone();
        PrivateRecord {intent_sha256:prepared.intent_digest().unwrap(),prepared,write}});
    frame(json!({"protocol":PROTOCOL,"id":id,"pending":null,"result":{"schemaVersion":1,"action":action.kind,
        "reason":reason,"prepared":if action.kind==Kind::Prepare && reason==Reason::None {Some(prepared())} else {None},
        "record":record,"observation":null,"control":control(crate::github_connection_protocol::Reason::None),
        "networkCleanup":network,"journal":journal}}))
}
