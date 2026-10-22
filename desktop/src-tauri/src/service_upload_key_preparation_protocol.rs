//! MAIN-only comparison of an actually returned stored-key Prepare. This is
//! never an IPC input, permission, assessment or replacement native receipt.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Prepared {
    // Absent preserves the old Android wire exactly; general read requires it.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "kind_present")]
    pub credential_kind: Option<CredentialKind>,
    pub asset_operation_id: u32,
    pub status_revision: u32,
    pub context_revision: u32,
    pub record_id: Id,
    pub expected_revision: u32,
    pub preview_token: Id,
    pub remaining_ms: u64,
}
impl Prepared {
    pub(crate) fn valid(&self) -> bool {
        [self.asset_operation_id, self.status_revision, self.context_revision, self.expected_revision]
            .into_iter().all(|v| (1..u32::MAX).contains(&v))
            && (1..=ALLOW_SECONDS * 1000).contains(&self.remaining_ms)
    }
}
fn kind_present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<CredentialKind>, D::Error> {
    CredentialKind::deserialize(d).map(Some)
}
// Optional means omitted, not an explicitly null/partial prepared object.
pub(super) fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Prepared>, D::Error> {
    Prepared::deserialize(d).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prepared_comparison_is_bounded_and_never_a_grant_for_other_actions() {
        let value = Prepared { credential_kind: None, asset_operation_id: 7, status_revision: 9, context_revision: 1,
            record_id: Id::parse(&"a".repeat(32)).unwrap(), expected_revision: 1,
            preview_token: Id::parse(&"b".repeat(32)).unwrap(), remaining_ms: 300_000 };
        assert!(value.valid());
        let mut a = Access::empty();
        a.prepared = Some(value.clone());
        assert!(a.validate().is_err());
        a.service_instance = Some(Id::parse(&"c".repeat(32)).unwrap());
        a.project_id = Some(Id::parse(&"d".repeat(32)).unwrap());
        a.grant_id = Some(Id::parse(&"e".repeat(32)).unwrap());
        a.request_id = Some(Id::parse(&"f".repeat(32)).unwrap());
        a.consumed = true;
        a.kind = Some(Kind::PrepareExisting);
        assert!(a.validate().is_ok());
        assert!(serde_json::to_vec(&a).unwrap().len() < VIEW_LIMIT);
        for kind in [Kind::GenerateNew, Kind::BindReviewed, Kind::BackupEncrypted, Kind::RestoreEncrypted] {
            a.kind = Some(kind); assert!(a.validate().is_err());
        }
        a.kind = Some(Kind::CredentialAssessExisting);
        assert!(a.validate().is_err()); // New read cannot reinterpret the old seven fields.
        a.prepared.as_mut().unwrap().credential_kind=Some(CredentialKind::AscP8);
        assert!(a.validate().is_ok());
        assert!(serde_json::to_vec(&a).unwrap().len()<VIEW_LIMIT);
        let mut malformed=serde_json::to_value(&a).unwrap();malformed["prepared"]["credentialKind"]=serde_json::Value::Null;
        assert!(serde_json::from_value::<Access>(malformed).is_err());
        a.kind=Some(Kind::PrepareExisting);assert!(a.validate().is_err());
        a.prepared.as_mut().unwrap().credential_kind=None;
        for end in [0, 300_001, u64::MAX] {
            a.prepared.as_mut().unwrap().remaining_ms = end; assert!(a.validate().is_err());
        }
        let mut raw = serde_json::to_value(Access::empty()).unwrap();
        assert!(raw.get("prepared").is_none());
        raw["prepared"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<Access>(raw).is_err());
    }
}
