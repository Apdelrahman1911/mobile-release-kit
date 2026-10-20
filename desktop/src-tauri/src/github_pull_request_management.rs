//! Optional historical closure DATA; it never restores the old claim or a native join.
use super::Acknowledgement;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Closed {
    id: String,
    number: String,
    closed_at: String,
    merged: bool,
}
impl Closed {
    pub(super) fn valid(&self, ack: &Acknowledgement) -> bool {
        self.id == ack.id && self.number == ack.number
            && crate::github_connection_protocol::utc(&self.closed_at)
    }
    pub(super) fn heap(&self) -> Option<usize> {
        self.id.capacity().checked_add(self.number.capacity())?.checked_add(self.closed_at.capacity())
    }
}
// Backward-compatible absence only. Explicit null is not a saved closure.
pub(super) fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Closed>, D::Error> {
    Closed::deserialize(d).map(Some)
}

#[cfg(test)]
mod tests {
    use super::super::*;
    fn prepared() -> Value {
        let target = serde_json::json!({"scope":{"projectBinding":"a".repeat(64),"repository":"owner/app","accountId":"11","repositoryId":"22"},
            "intent":{"base":"main","head":"feature","marker":"b".repeat(32),"titleSha256":"c".repeat(64),"bodySha256":"d".repeat(64)}});
        let typed:Target=serde_json::from_value(target.clone()).unwrap();
        serde_json::json!({"target":target,"baseSha":"c".repeat(40),"headSha":"d".repeat(40),"comparison":{
            "aheadBy":1,"behindBy":0,"totalCommits":1,"reportedFiles":0,"coverage":"windowed","files":[]},
            "draft":true,"creationPermission":"not-proven","confirmation":typed.confirmation()})
    }
    #[test]
    fn closed_history_requires_exact_ack_and_does_not_restore_claim() {
        let ack=serde_json::json!({"id":"44","number":"3","url":"https://github.com/owner/app/pull/3"});
        let mut row=serde_json::json!({"prepared":prepared(),"claimed":true,"acknowledged":ack});
        let old:Pending=serde_json::from_value(row.clone()).unwrap();
        assert!(old.valid() && old.closed.is_none());
        assert!(serde_json::to_value(&old).unwrap().get("closed").is_none());
        row["closed"]=serde_json::json!({"id":"44","number":"3","closedAt":"2026-10-20T12:00:00Z","merged":true});
        let parsed:Pending=serde_json::from_value(row.clone()).unwrap();
        assert!(parsed.valid() && parsed.heap().unwrap() > old.heap().unwrap());
        for field in ["id","number","acknowledged","claimed","closed","resumeWrite"] {
            let mut bad=row.clone();
            match field {
                "id"|"number" => bad["closed"][field]=Value::String("99".into()),
                "acknowledged"|"closed" => bad[field]=Value::Null,
                "claimed"=>bad[field]=Value::Bool(false),
                _=>bad[field]=Value::Bool(true),
            }
            assert!(!serde_json::from_value::<Pending>(bad).is_ok_and(|v|v.valid()));
        }
    }
    #[test]
    fn closed_effect_is_reconcile_only_and_original_201_required() {
        let p:Prepared=serde_json::from_value(prepared()).unwrap();
        let mut request=Request{kind:Kind::Reconcile,target:p.target.clone(),home:Some("/inert-home".into()),prepared:Some(p),draft:None};
        let ack=serde_json::json!({"id":"44","number":"3","url":"https://github.com/owner/app/pull/3"});
        let raw=serde_json::json!({"effect":"closed-confirmed","reason":"none","claimed":true,"acknowledged":ack,"observed":ack,
            "control":{"reason":"none","credentialExpiresAt":null,"cooldownSeconds":null,"cooldownBlocked":false}});
        let c:Creation=serde_json::from_value(raw.clone()).unwrap();
        assert!(request.valid() && c.valid(&request));
        request.kind=Kind::Create;assert!(!c.valid(&request));request.kind=Kind::Reconcile;
        for field in ["acknowledged","observed","claimed"] {
            let mut bad=raw.clone();bad[field]=if field=="claimed"{Value::Bool(false)}else{Value::Null};
            assert!(!serde_json::from_value::<Creation>(bad).unwrap().valid(&request));
        }
    }
}
