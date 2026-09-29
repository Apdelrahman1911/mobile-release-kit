//! Public metadata only. This is not a credential, configuration receipt or
//! permission to mutate an environment. The existing connection owns execution.
use serde::{Deserialize, Serialize};
use crate::github_connection_protocol::{Fact, FactState, GitHubReadControl, Reason, Repository, numeric_id, utc};

pub(crate) const PROTOCOL: &str = "mrk-github-input-metadata/1";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Selection { pub stage: String, pub name: String }
impl Selection {
    pub(crate) fn environment(&self) -> Option<&'static str> {
        match self.stage.as_str() {
            "candidate" => Some("mobile-candidate"),
            "external-testing" => Some("mobile-external-testing"),
            "production" => Some("mobile-production"), _ => None,
        }
    }
    pub(crate) fn valid(&self) -> bool {
        self.environment().is_some() && self.name.starts_with("MOBILE_RELEASE_")
            && self.name.len() > "MOBILE_RELEASE_".len() && self.name.len() <= 96 && self.name.bytes().all(|v| v.is_ascii_uppercase() || v.is_ascii_digit() || v == b'_')
        // Exact allowed names/classifications are independently derived by core,
        // before it creates the fixed reader. No renderer supplies a URL/type.
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Environment { pub id: String, pub name: String }
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FieldKind { Secret, Variable }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Field { pub name: String, pub kind: FieldKind, pub created_at: String, pub updated_at: String }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Observation { pub selection: Selection, pub environment: Fact<Environment>, pub field: Fact<Field> }

impl Observation {
    pub(crate) fn valid(&self, repository: &Fact<Repository>) -> bool {
        self.selection.valid()
            && self.environment.state != FactState::NotObserved && self.field.state != FactState::NotObserved
            && self.environment.valid(|v| numeric_id(&v.id) && Some(v.name.as_str()) == self.selection.environment())
            && self.field.valid(|v| v.name == self.selection.name && utc(&v.created_at) && utc(&v.updated_at))
            && (self.environment.value.is_none() || repository.value.is_some())
            && (self.field.value.is_none() || self.environment.value.is_some())
            && (self.environment.state != FactState::Observed || repository.state == FactState::Observed)
            && (self.field.state != FactState::Observed || self.environment.state == FactState::Observed)
    }
    pub(crate) fn private_valid(&self, repository: &Fact<Repository>, control: &GitHubReadControl) -> bool {
        self.valid(repository)
            && [(&self.environment.state, self.environment.reason), (&self.field.state, self.field.reason)].into_iter()
                .all(|(state, reason)| matches!(*state, FactState::Observed | FactState::Unavailable)
                    && crate::github_connection_protocol::coherent_fact_reason(reason, control))
            && (control.reason != Reason::None
                || self.environment.state == FactState::Observed && self.field.state == FactState::Observed)
    }
    pub(crate) fn stale(&mut self, reason: Reason) {
        fn mark<T>(fact: &mut Fact<T>, reason: Reason) {
            if fact.value.is_some() { fact.state = FactState::Stale; fact.reason = reason; }
            else { fact.state = FactState::Unavailable; fact.observed_at = None; fact.reason = reason; }
        }
        mark(&mut self.environment, reason); mark(&mut self.field, reason);
    }
    pub(crate) fn flags(&self) -> (&'static str, &'static str, &'static str) {
        let environment = if self.environment.value.is_some() { "metadata-only" } else { "not-run" };
        let secret = if self.field.value.as_ref().is_some_and(|f| f.kind == FieldKind::Secret) { "metadata-only" } else { "not-run" };
        let variable = if self.field.value.as_ref().is_some_and(|f| f.kind == FieldKind::Variable) { "metadata-only" } else { "not-run" };
        (environment, secret, variable)
    }
}
