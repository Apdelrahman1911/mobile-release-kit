//! Ready is explicit in private text input AND retained intent. Legacy absence
//! serializes exactly as before; a bare Prepared.draft=false is never sufficient.
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CreationMode {
    #[default]
    Draft,
    ReadyForReview,
}
impl CreationMode {
    pub(super) fn is_draft(&self) -> bool {
        *self == Self::Draft
    }
}
pub(super) fn present<'de, D: Deserializer<'de>>(d: D) -> Result<CreationMode, D::Error> {
    let value = String::deserialize(d)?;
    if value == "ready-for-review" {
        Ok(CreationMode::ReadyForReview)
    } else {
        Err(serde::de::Error::custom("Invalid PR creation mode"))
    }
}
impl super::Prepared {
    pub(crate) fn agent_kind_matches(
        &self,
        kind: crate::service_github_action_protocol::Kind,
    ) -> bool {
        use crate::service_github_action_protocol::Kind;
        self.valid()
            && matches!(
                (self.target.intent.as_ref().map(|i| i.creation_mode), kind),
                (Some(CreationMode::Draft), Kind::DraftPrCreate)
                    | (Some(CreationMode::ReadyForReview), Kind::PrCreate)
            )
    }
}

#[cfg(test)]
#[path = "github_pull_request_mode_tests.rs"]
mod tests;
