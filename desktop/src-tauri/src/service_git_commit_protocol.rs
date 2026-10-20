//! Closed whole-index Commit DATA. The CLI receives no commit message or
//! author. Native approval retains that draft separately on the SAME inbox.
use crate::{service_git_protocol as p, service_protocol::Error};
use serde::{Deserialize, Serialize};

pub const CONSENT: &str = "agent-local-git-commit-once-v1";
pub(crate) const DRAFT_BACKING: usize = 4096 + 128 + 254 + 3 * std::mem::size_of::<String>();

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    Index,
    Commit,
    Repository,
}
impl Family {
    pub(crate) fn matches(self, action: p::Action) -> bool {
        match self {
            Self::Index => matches!(action, p::Action::Stage | p::Action::Unstage),
            Self::Commit => action == p::Action::Commit,
            Self::Repository => false,
        }
    }
}

// Private approved data, not a native receipt. No Debug/serde: it must never
// enter the public request/history/CLI projection. The actual Action validator
// independently checks this again before the original native admission.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Draft {
    message: String,
    author_name: String,
    author_email: String,
}
impl Draft {
    pub(crate) fn new(
        message: String,
        author_name: String,
        author_email: String,
    ) -> Result<Self, Error> {
        let value = Self {
            message: message.into_boxed_str().into_string(),
            author_name: author_name.into_boxed_str().into_string(),
            author_email: author_email.into_boxed_str().into_string(),
        };
        if value.valid() {
            Ok(value)
        } else {
            Err(Error::InvalidRequest)
        }
    }
    pub(crate) fn valid(&self) -> bool {
        fn text(v: &str, limit: usize, multiline: bool) -> bool {
            v.len() <= limit
                && !v
                    .chars()
                    .any(|c| c == '\u{7f}' || (c < ' ' && !(multiline && matches!(c, '\n' | '\t'))))
        }
        !self.message.trim().is_empty()
            && text(&self.message, 4096, true)
            && !self.author_name.is_empty()
            && text(&self.author_name, 128, false)
            && !self.author_name.contains(['<', '>'])
            && !self.author_email.is_empty()
            && text(&self.author_email, 254, false)
            && !self
                .author_email
                .chars()
                .any(|c| c.is_whitespace() || matches!(c, '<' | '>'))
            && self.author_email.split('@').count() == 2
            && self.author_email.split('@').all(|p| !p.is_empty())
    }
    pub(crate) fn parts(&self) -> (&str, &str, &str) {
        (&self.message, &self.author_name, &self.author_email)
    }
}

pub type Query = p::Query;
pub type Prepare = p::Prepare;
pub type Start = p::Start;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Access(pub p::Access);
impl Access {
    pub(crate) fn empty() -> Self {
        Self(p::Access::empty())
    }
    pub fn validate(&self) -> Result<(), Error> {
        Self::validate_value(&self.0)
    }
    fn validate_value(value: &p::Access) -> Result<(), Error> {
        value.validate_shared()?;
        if value
            .selection
            .as_ref()
            .is_none_or(|s| s.summary.action == p::Action::Commit)
        {
            Ok(())
        } else {
            Err(Error::InvalidRequest)
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Scope(pub p::Scope);
impl Scope {
    pub fn validate(&self) -> Result<(), Error> {
        self.0.validate_shared()?;
        Access::validate_value(&self.0.access)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Status(pub p::Status);
impl Status {
    pub fn validate(&self) -> Result<(), Error> {
        self.0.validate_shared()?;
        if self.0.selection.action == p::Action::Commit {
            Ok(())
        } else {
            Err(Error::InvalidRequest)
        }
    }
}

#[cfg(test)]
#[path = "service_git_commit_protocol_tests.rs"]
mod tests;
