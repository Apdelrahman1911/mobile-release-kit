//! The fixed union carried by the existing Git inbox, not another inbox or
//! state machine. Public old-family DTOs are projected without new fields;
//! repository actions never manufacture paths, an index, or a Git observation.
use super::*;
use crate::service_git_commit_protocol::Family;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub(crate) enum Selected {
    Files(p::Selection),
    Repository(Selection),
    Remote(crate::service_git_remote_protocol::Selection),
}
impl From<p::Selection> for Selected {
    fn from(value: p::Selection) -> Self {
        Self::Files(value)
    }
}
impl From<Selection> for Selected {
    fn from(value: Selection) -> Self {
        Self::Repository(value)
    }
}
impl From<crate::service_git_remote_protocol::Selection> for Selected { fn from(v: crate::service_git_remote_protocol::Selection) -> Self { Self::Remote(v) } }
impl Selected {
    pub(crate) fn family(&self) -> Family {
        match self {
            Self::Files(v) if v.summary.action == p::Action::Commit => Family::Commit,
            Self::Files(_) => Family::Index,
            Self::Repository(_) => Family::Repository,
            Self::Remote(_) => Family::Remote,
        }
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Files(v) => v.validate_shared(),
            Self::Repository(v) => v.validate(),
            Self::Remote(v) => v.validate(),
        }
    }
    pub(crate) fn files(&self) -> Result<&p::Selection, Error> {
        match self {
            Self::Files(v) => Ok(v),
            _ => Err(Error::InvalidRequest),
        }
    }
    pub(crate) fn repository(&self) -> Result<&Selection, Error> {
        match self {
            Self::Repository(v) => Ok(v),
            _ => Err(Error::InvalidRequest),
        }
    }
    pub(crate) fn summary(&self) -> Summary {
        match self {
            Self::Files(v) => Summary::Files(v.summary.clone()),
            Self::Repository(v) => Summary::Repository(v.clone()),
            Self::Remote(v) => Summary::Remote(v.clone()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub(crate) enum Summary {
    Files(p::Summary),
    Repository(Selection),
    Remote(crate::service_git_remote_protocol::Selection),
}
impl Summary {
    fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Files(v) => v.validate(),
            Self::Repository(v) => v.validate(),
            Self::Remote(v) => v.validate(),
        }
    }
    pub(crate) fn history_action(&self) -> crate::service_protocol::Action {
        use crate::service_protocol::Action as A;
        match self {
            Self::Files(v) => match v.action {
                p::Action::Stage => A::GitStage,
                p::Action::Unstage => A::GitUnstage,
                p::Action::Commit => A::GitCommit,
            },
            Self::Repository(v) => v.action.history_action(),
            Self::Remote(v) => v.action.history_action(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub(crate) enum Reviewed {
    Files(p::Review),
    Repository(Review),
    Remote(crate::service_git_remote_protocol::Review),
}
impl From<p::Review> for Reviewed {
    fn from(value: p::Review) -> Self {
        Self::Files(value)
    }
}
impl From<Review> for Reviewed {
    fn from(value: Review) -> Self {
        Self::Repository(value)
    }
}
impl From<crate::service_git_remote_protocol::Review> for Reviewed { fn from(v: crate::service_git_remote_protocol::Review) -> Self { Self::Remote(v) } }
impl Reviewed {
    pub(crate) fn can_apply(&self) -> bool { match self { Self::Remote(r) => r.can_apply(), _ => true } }
    pub(crate) fn id(&self) -> &str {
        match self {
            Self::Files(v) => &v.review_id,
            Self::Repository(v) => &v.review_id,
            Self::Remote(v) => &v.review_id,
        }
    }
    pub(crate) fn matches(&self, selection: &Summary) -> bool {
        match (self, selection) {
            (Self::Files(r), Summary::Files(_)) => r.validate().is_ok(),
            (Self::Repository(r), Summary::Repository(s)) => r.matches(s),
            (Self::Remote(r), Summary::Remote(s)) => r.matches(s),
            _ => false,
        }
    }
}
pub(crate) type Access = p::Access<Selected>;
impl Access {
    pub(crate) fn validate_shared(&self) -> Result<(), Error> {
        p::access_shape(
            self.enabled,
            self.remaining_ms,
            self.consumed,
            self.project_id.is_some(),
            self.grant_id.is_some(),
            self.selection.is_some(),
        )?;
        if let Some(v) = &self.selection {
            v.validate()?;
        }
        p::encoded_bound(self, p::SCOPE_BYTES - 1024)
    }
    pub(crate) fn files(self) -> Result<p::Access, Error> {
        let selection = self
            .selection
            .as_ref()
            .map(|s| s.files().cloned())
            .transpose()?;
        let out = self.with_selection(selection);
        out.validate_shared()?;
        Ok(out)
    }
    pub(crate) fn remote(self) -> Result<crate::service_git_remote_protocol::Access, Error> {
        let selection=self.selection.as_ref().map(|s| match s {Selected::Remote(v)=>Ok(v.clone()),_=>Err(Error::InvalidRequest)}).transpose()?;
        let out=crate::service_git_remote_protocol::Access::from_parts(self.with_selection(selection));out.validate()?;Ok(out)
    }
    pub(crate) fn repository(self) -> Result<super::Access, Error> {
        let selection = self
            .selection
            .as_ref()
            .map(|s| s.repository().cloned())
            .transpose()?;
        let out = super::Access::from_parts(self.with_selection(selection));
        out.validate()?;
        Ok(out)
    }
}
pub(crate) type Status = p::Status<Summary, Reviewed>;
impl Status {
    pub(crate) fn validate_shared(&self) -> Result<(), Error> {
        self.selection.validate()?;
        if self
            .review
            .as_ref()
            .is_some_and(|r| !r.matches(&self.selection))
        {
            return Err(Error::InvalidRequest);
        }
        self.validate_progress()?;
        p::encoded_bound(self, p::STATUS_BYTES - 512)
    }
    pub(crate) fn files(self) -> Result<p::Status, Error> {
        let Summary::Files(selection) = &self.selection else {
            return Err(Error::InvalidRequest);
        };
        let selection = selection.clone();
        let review = self
            .review
            .as_ref()
            .map(|v| match v {
                Reviewed::Files(r) => Ok(r.clone()),
                _ => Err(Error::InvalidRequest),
            })
            .transpose()?;
        let out = self.with_data(selection, review);
        out.validate_shared()?;
        Ok(out)
    }
    pub(crate) fn remote(self, result:Option<crate::service_git_remote_protocol::Outcome>) -> Result<crate::service_git_remote_protocol::Status, Error> {
        let Summary::Remote(selection)=&self.selection else {return Err(Error::InvalidRequest);};let selection=selection.clone();
        let review=self.review.as_ref().map(|r| match r {Reviewed::Remote(v)=>Ok(v.clone()),_=>Err(Error::InvalidRequest)}).transpose()?;
        let out=crate::service_git_remote_protocol::Status {progress:self.with_data(selection,review),result};out.validate()?;Ok(out)
    }
    pub(crate) fn repository(self) -> Result<super::Status, Error> {
        let Summary::Repository(selection) = &self.selection else {
            return Err(Error::InvalidRequest);
        };
        let selection = selection.clone();
        let review = self
            .review
            .as_ref()
            .map(|v| match v {
                Reviewed::Repository(r) => Ok(r.clone()),
                _ => Err(Error::InvalidRequest),
            })
            .transpose()?;
        let out = self.with_data(selection, review);
        out.validate()?;
        Ok(out)
    }
}
