//! Child of the existing GitLocal protocol. This is a closed DATA constructor,
//! not a review, publisher, execution permit or new Git engine.
use super::*;

impl Action {
    pub(crate) fn approved_commit(
        revision: String,
        draft: &crate::service_git_commit_protocol::Draft,
    ) -> Result<Self, BridgeError> {
        if !draft.valid() {
            return Err(BridgeError::invalid());
        }
        let (message, name, email) = draft.parts();
        let action = Self::Files(FileAction {
            kind: Kind::Commit,
            expected_revision: revision,
            paths: Vec::new(),
            message: Some(message.into()),
            identity: Some(Identity {
                name: name.into(),
                email: email.into(),
            }),
        });
        if action.valid() {
            Ok(action)
        } else {
            Err(BridgeError::invalid())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn commit_constructor_binds_private_draft_without_an_index_action_escape() {
        let draft = crate::service_git_commit_protocol::Draft::new(
            "Review all staged changes\n\nOwned message".into(),
            "Example Author".into(),
            "author@example.invalid".into(),
        )
        .unwrap();
        let action = Action::approved_commit("a".repeat(64), &draft).unwrap();
        assert!(action.valid());
        assert!(action.kind() == Kind::Commit);
        let Action::Files(file) = &action else {
            panic!("closed file action")
        };
        assert!(file.paths.is_empty());
        assert!(file.message.as_deref() == Some(draft.parts().0));
        assert!(file
            .identity
            .as_ref()
            .is_some_and(|i| i.name == draft.parts().1 && i.email == draft.parts().2));
        assert!(Action::approved_commit("invalid".into(), &draft).is_err());
        assert!(Action::index(Kind::Commit, "a".repeat(64), vec!["a".into()]).is_err());
        let public = serde_json::to_string(&action.public()).unwrap();
        for private in [draft.parts().0, draft.parts().1, draft.parts().2] {
            assert!(!public.contains(private));
        }
    }
}
