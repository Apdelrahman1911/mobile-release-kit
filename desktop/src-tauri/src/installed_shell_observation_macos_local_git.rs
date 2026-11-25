//! Comparison DATA for the nonshipping, debug, local Git observer only.
//! These names are not filesystem custody, a permission, or a hosted identity.
//! All existing canonical-executable, fixture, signature and native checks run.
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Context<'a> {
    pub(super) base_commit: &'a str,
    pub(super) tree_sha256: &'a str,
    pub(super) id: &'a str,
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}

impl<'a> Context<'a> {
    fn data(base_commit: Option<&'a str>, tree_sha256: Option<&'a str>, id: Option<&'a str>,
        role: Option<&str>, scope: Option<&str>, arm: bool, hosted_present: bool) -> Option<Self> {
        let (base_commit, tree_sha256, id) = (base_commit?, tree_sha256?, id?);
        (hex(base_commit, 40) && hex(tree_sha256, 64) && hex(id, 32) && arm && !hosted_present
            && role == Some("installed-shell-observation") && scope == Some("git-native"))
            .then_some(Self { base_commit, tree_sha256, id })
    }

    fn home(home: &Path) -> bool {
        home.is_absolute() && home != Path::new("/") && home.as_os_str().len() <= 256
            && home.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
    }

    pub(super) fn fixture_root(self, home: &Path, scope: &str) -> Option<PathBuf> {
        (Self::home(home) && matches!(scope, "git-index-cli-native" | "git-branch-cli-native"))
            .then(|| home.join("Library/Application Support")
                .join(format!("mrk-local-git-{}-{}-{scope}", self.base_commit, self.id)))
    }

    pub(super) fn application_home(self, home: &Path, case: &str) -> Option<PathBuf> {
        let suffix = match case { "git-index-cli" => 'i', "git-branch-cli" => 'b', _ => return None };
        // Leave room for a longer real account home and Darwin's 104-byte
        // sockaddr_un field. This short comparison name is not an auth token;
        // the full compiled ID still binds the fixture and an occupied home
        // is refused by the invocation owner, never reused.
        if !Self::home(home) { return None; }
        let path = home.join(format!(".g{}{suffix}", &self.id[..9]));
        (path.join("Library/Application Support/dev.mobile-release-kit.desktop/service-v1/s")
            .as_os_str().len() < 104).then_some(path)
    }
}

pub(super) fn current() -> Option<Context<'static>> {
    Context::data(option_env!("MRK_LOCAL_ACCEPTANCE_BASE_COMMIT"),
        option_env!("MRK_LOCAL_ACCEPTANCE_TREE_SHA256"), option_env!("MRK_LOCAL_ACCEPTANCE_ID"),
        option_env!("MRK_MACOS_PACKAGE_ROLE"), option_env!("MRK_MACOS_NATIVE_SCOPE"),
        cfg!(target_arch = "aarch64"),
        [option_env!("GITHUB_ACTIONS"), option_env!("GITHUB_SHA"), option_env!("GITHUB_RUN_ID"),
            option_env!("GITHUB_RUN_ATTEMPT"), option_env!("GITHUB_WORKFLOW_REF")].iter().any(Option::is_some))
}

#[cfg(test)]
mod tests {
    use super::*;
    const SOURCE: &str = "1234567890123456789012345678901234567890";
    const TREE: &str = "1234567890123456789012345678901234567890123456789012345678901234";
    const ID: &str = "12345678901234567890123456789012";
    fn context() -> Context<'static> {
        Context::data(Some(SOURCE), Some(TREE), Some(ID), Some("installed-shell-observation"),
            Some("git-native"), true, false).unwrap()
    }
    #[test]
    fn local_names_are_distinct_and_never_actions_names() {
        let c = context();
        let home = Path::new("/Users/fixture");
        let index = c.fixture_root(home, "git-index-cli-native").unwrap();
        let branch = c.fixture_root(home, "git-branch-cli-native").unwrap();
        assert_ne!(index, branch);
        assert!(index.file_name().unwrap().to_str().unwrap().starts_with("mrk-local-git-"));
        assert_ne!(c.application_home(home, "git-index-cli"), c.application_home(home, "git-branch-cli"));
        assert_eq!(c.application_home(home, "git-index-cli").unwrap().file_name().unwrap().len(), 12);
    }
    #[test]
    fn hosted_or_wrong_role_cannot_enter_a_local_context() {
        for (role, scope, arm, hosted) in [
            (Some("installed-shell-observation"), Some("git-native"), true, true),
            (Some("ordinary-image"), Some("git-native"), true, false),
            (Some("installed-shell-observation"), Some("tool-setup"), true, false),
            (Some("installed-shell-observation"), Some("git-native"), false, false),
        ] {
            assert!(Context::data(Some(SOURCE), Some(TREE), Some(ID), role, scope, arm, hosted).is_none());
        }
    }
    #[test]
    fn local_context_requires_all_exact_nonzero_bindings() {
        for (source, tree, id) in [
            (None, Some(TREE), Some(ID)), (Some(SOURCE), None, Some(ID)),
            (Some(SOURCE), Some(TREE), None), (Some("bad"), Some(TREE), Some(ID)),
            (Some(SOURCE), Some("0"), Some(ID)),
            (Some(SOURCE), Some(TREE), Some("00000000000000000000000000000000")),
        ] {
            assert!(Context::data(source, tree, id, Some("installed-shell-observation"),
                Some("git-native"), true, false).is_none());
        }
    }
    #[test]
    fn names_do_not_admit_arbitrary_cases_or_relative_homes() {
        let c = context();
        for home in [Path::new("/"), Path::new("relative"), Path::new("/Users/fixture/../other")] {
            assert!(c.fixture_root(home, "git-index-cli-native").is_none());
            assert!(c.application_home(home, "git-index-cli").is_none());
        }
        assert!(c.fixture_root(Path::new("/Users/fixture"), "tool-setup").is_none());
        assert!(c.application_home(Path::new("/Users/fixture"), "installed-cli-local-check").is_none());
    }
    #[test]
    fn complete_socket_path_is_bounded_before_any_namespace_is_created() {
        let c = context();
        let home = Path::new("/Users/testaccount");
        let app = c.application_home(home, "git-index-cli").unwrap();
        assert!(app.join("Library/Application Support/dev.mobile-release-kit.desktop/service-v1/s")
            .as_os_str().len() < 104);
        assert!(c.application_home(Path::new("/Users/an-account-home-that-cannot-fit-the-socket"), "git-index-cli").is_none());
    }
}
