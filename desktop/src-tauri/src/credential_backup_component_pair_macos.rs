//! Nonshipping comparison handoff from the SAME completed private backup sink.
//! No new descriptor owner, picker receipt, secret getter or write capability.
//! The installed fixture captures this only after actual parent join/current
//! checks, before the ordinary private drain; the next original still performs
//! its own native source PRE/read/POST/close and complete authenticated import.
use super::*;

/// Private pathname DATA plus the exact final output identities. Neither names
/// nor a serializable report can construct this value. No Clone or retry API.
pub(crate) struct ComponentPair {
    original: Weak<OriginalWork>,
    paths: [PathBuf; 2],
    expected: ComponentExpectedPair,
}

pub(crate) struct ComponentExpectedPair {
    parents: [DirectoryIdentity; 2],
    files: [FileIdentity; 2],
}

impl ComponentPair {
    pub(crate) fn matches_original(&self, owner: &Arc<OriginalWork>) -> bool {
        self.original
            .upgrade()
            .is_some_and(|original| Arc::ptr_eq(&original, owner))
    }

    pub(crate) fn matches_folders(&self, folders: [&Path; 2]) -> bool {
        self.paths
            .iter()
            .zip(folders)
            .all(|(path, folder)| path.parent() == Some(folder))
    }

    pub(crate) fn retained_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(self.paths[0].capacity())?
            .checked_add(self.paths[1].capacity())
    }

    pub(in crate::asset_source) fn into_parts(self) -> ([PathBuf; 2], ComponentExpectedPair) {
        (self.paths, self.expected)
    }
}

impl ComponentExpectedPair {
    /// Called at the actual SourceBook's held/named PRE, BEFORE private body
    /// allocation. Its unchanged terminal_check/read/EOF also rematch these
    /// same file originals; a fresh unrelated pair cannot be adopted by name.
    pub(in crate::asset_source) fn matches(
        &self,
        index: usize,
        parent: DirectoryIdentity,
        file: FileIdentity,
    ) -> bool {
        self.parents.get(index) == Some(&parent) && self.files.get(index) == Some(&file)
    }
}

impl BackupDestinations {
    /// Memory-only observation of the actual completed sink, not a native
    /// call or finality mint. Only the fixed installed post-join publication
    /// hook calls this; ordinary export/import still requires its real pickers.
    pub(crate) fn component_published_pair(
        &self,
        owner: &Arc<OriginalWork>,
    ) -> Result<ComponentPair, Reason> {
        if !self.component.admitted || !self.candidate_ready(owner) {
            return Err(Reason::SourceChanged);
        }
        let parents = [
            self.book
                .directory(self.outputs[0].parent.ok_or(Reason::CleanupUnknown)?)?,
            self.book
                .directory(self.outputs[1].parent.ok_or(Reason::CleanupUnknown)?)?,
        ];
        let keys = [
            self.outputs[0].key.ok_or(Reason::CleanupUnknown)?,
            self.outputs[1].key.ok_or(Reason::CleanupUnknown)?,
        ];
        if parents[0].same_object(parents[1])
            || keys[0].file.common.same_object(keys[1].file.common)
            || keys.iter().any(|key| key.flags != 0)
        {
            return Err(Reason::SourceChanged);
        }
        let mut paths = [PathBuf::new(), PathBuf::new()];
        for (index, path) in paths.iter_mut().enumerate() {
            let length = self.paths[index]
                .as_os_str()
                .len()
                .checked_add(1)
                .and_then(|value| value.checked_add(self.outputs[index].published.len()))
                .filter(|value| *value <= PATH_LIMIT)
                .ok_or(Reason::Capacity)?;
            path.try_reserve_exact(length)
                .map_err(|_| Reason::Capacity)?;
            if path.capacity() > PATH_LIMIT {
                return Err(Reason::Capacity);
            }
            path.push(&self.paths[index]);
            path.push(&self.outputs[index].published);
            if path.as_os_str().len() != length || path.capacity() > PATH_LIMIT {
                return Err(Reason::Capacity);
            }
        }
        Ok(ComponentPair {
            original: Arc::downgrade(owner),
            paths,
            expected: ComponentExpectedPair {
                parents,
                // These are the post-rename identities already verified by
                // the SAME output FD. Rename's original ctime is not reused.
                files: [keys[0].file, keys[1].file],
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_expected_pair_compares_full_original_before_read_not_names() {
        let parent = DirectoryIdentity::synthetic_evidence_identity();
        let file = FileIdentity {
            common: DirectoryIdentity {
                ino: 4,
                mode: 0o100600,
                ..parent
            },
            nlink: 1,
            size: 87,
            mtime: (1, 2),
            ctime: (3, 4),
        };
        let expected = ComponentExpectedPair {
            parents: [parent; 2],
            files: [file; 2],
        };
        assert!(expected.matches(0, parent, file));
        assert!(!expected.matches(2, parent, file));
        for changed in [
            FileIdentity {
                common: DirectoryIdentity {
                    ino: 5,
                    ..file.common
                },
                ..file
            },
            FileIdentity {
                size: file.size + 1,
                ..file
            },
            FileIdentity {
                mtime: (2, 2),
                ..file
            },
            FileIdentity {
                ctime: (3, 5),
                ..file
            },
            FileIdentity { nlink: 2, ..file },
        ] {
            assert!(!expected.matches(0, parent, changed));
        }
        for changed in [
            DirectoryIdentity {
                ino: parent.ino + 1,
                ..parent
            },
            DirectoryIdentity {
                dev: parent.dev + 1,
                ..parent
            },
            DirectoryIdentity {
                mode: 0o40777,
                ..parent
            },
            DirectoryIdentity {
                uid: parent.uid + 1,
                ..parent
            },
        ] {
            assert!(!expected.matches(0, changed, file));
        }
        // Comparison DATA above cannot create a completed sink, output, FD,
        // selected pair or native join; no native function is called here.
    }

    #[test]
    fn unentered_or_unknown_component_sink_has_no_published_pair() {
        let owner = OriginalWork::artifact_unentered_original_data();
        let ordinary = BackupDestinations::new_component_fixture(
            &owner,
            ["/private/synthetic/a".into(), "/private/synthetic/b".into()],
        )
        .unwrap();
        assert!(ordinary.component_published_pair(&owner).is_err());
        let unknown = BackupDestinations::unknown_effect_predicate_data(&owner);
        assert!(unknown.component_published_pair(&owner).is_err());
        let unsynced = BackupDestinations::unsynced_publication_predicate_data(&owner);
        assert!(unsynced.component_published_pair(&owner).is_err());
    }
}
