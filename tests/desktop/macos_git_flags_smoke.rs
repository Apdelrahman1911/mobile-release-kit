//! Read-only host preflight for the actual Git source flag policy.
//! Compile directly with the pinned rustc; no app build or credentials needed.
#![cfg(target_os = "macos")]

use std::{collections::BTreeSet, env, fs, os::macos::fs::MetadataExt, path::Path};

#[derive(Debug, PartialEq)]
enum Reason { SourceChanged, Capacity }

#[path = "../../desktop/src-tauri/src/git_source_flags_macos.rs"]
mod git_source_flags;

#[test]
fn actual_git_and_user_library_flags_match_the_application_policy() {
    let home = env::var_os("HOME").expect("ordinary user's HOME is required");
    let home = Path::new(&home);
    assert!(home.is_absolute());
    let owner = fs::symlink_metadata(home).expect("HOME metadata").st_uid();
    assert_ne!(owner, 0, "run as the ordinary user");
    let git = Path::new("/Library/Developer/CommandLineTools/usr/bin/git");
    let metadata = fs::symlink_metadata(git).expect("fixed CLT Git metadata");
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.st_uid(), 0, "fixed Git must be root-owned");
    assert!(git_source_flags::permits(metadata.st_flags(), 0, git_source_flags::Kind::SystemGit),
        "fixed Git flags refused: {:#x}", metadata.st_flags());

    let library = home.join("Library");
    let support = library.join("Application Support");
    let mut checked = BTreeSet::new();
    for leaf in [git.parent().unwrap(), support.as_path()] {
        for directory in leaf.ancestors() {
            if !checked.insert(directory.to_path_buf()) { continue; }
            let metadata = fs::symlink_metadata(directory).expect("source ancestor metadata");
            assert!(metadata.is_dir() && !metadata.file_type().is_symlink(),
                "source ancestor is not a directory: {}", directory.display());
            assert!(metadata.st_uid() == 0 || metadata.st_uid() == owner,
                "source ancestor owner differs: {}", directory.display());
            assert!(git_source_flags::permits(metadata.st_flags(), metadata.st_uid(),
                git_source_flags::Kind::Directory), "source ancestor flags refused: {} flags={:#x}",
                directory.display(), metadata.st_flags());
        }
    }
    // This is a flag compatibility preflight, not full native source custody.
    println!("Actual CLT Git and Library ancestor flags accepted; {} directories checked", checked.len());
}
