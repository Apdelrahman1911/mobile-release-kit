//! Projection from the SAME returned acquisition SourceSlots, not a picker or
//! registration Review. This performs no IO and cannot revive closed handles.
use super::*;
use crate::tool_acquisition_protocol::sdk;

fn stamp(identity: Identity) -> [u8; sdk::STAMP_BYTES] {
    let mut output = [0; sdk::STAMP_BYTES];
    let mut offset = 0;
    macro_rules! field {
        ($value:expr) => {{
            let bytes = $value.to_le_bytes();
            output[offset..offset + bytes.len()].copy_from_slice(&bytes);
            offset += bytes.len();
        }};
    }
    field!(identity.dev);
    field!(identity.ino);
    field!(identity.mode);
    field!(identity.uid);
    field!(identity.gid);
    field!(identity.links);
    field!(identity.size);
    field!(identity.mtime);
    field!(identity.mtime_ns);
    field!(identity.ctime);
    field!(identity.ctime_ns);
    field!(identity.flags);
    debug_assert_eq!(offset, sdk::STAMP_BYTES);
    output
}
impl SourceSlots {
    pub(crate) fn acquisition_sdk_copy_input(
        &self,
        root: &RegisteredRoot,
    ) -> Result<Option<sdk::CopyInput>> {
        let (partition, _) = self
            .acquisition_finding()
            .ok_or(AdmissionFailure::Unknown)?;
        let Some(component) = sdk::Component::for_partition(partition) else {
            return Ok(None);
        };
        let checked = supplier::acquisition::picked_roster_for(self.selected_profile()?)
            .ok_or(AdmissionFailure::Inventory)?;
        let path = crate::tool_acquisition_protocol::native_path(&root.path)
            .ok_or(AdmissionFailure::Identity)?;
        let original = self.identity(self.roots[1].ok_or(AdmissionFailure::Identity)?)?;
        let expected = root
            .identity
            .posix()
            .map_err(|_| AdmissionFailure::Identity)?
            .preflight_identity();
        if u64::try_from(original.dev).ok() != expected.device.parse().ok()
            || Some(original.ino) != expected.inode.parse().ok()
            || u32::from(original.mode) != expected.mode
            || original.uid != expected.uid
            || original.gid != expected.gid
            || path.split('/').count() > ANCESTORS
        {
            return Err(AdmissionFailure::Identity);
        }
        let tree = checked
            .roster
            .trees
            .get(component.index())
            .ok_or(AdmissionFailure::Inventory)?;
        if tree.group != SourceGroup::Sdk || tree.prefix != component.prefix() {
            return Err(AdmissionFailure::Inventory);
        }
        // One pointer/ordinal vector within the existing post-read workspace;
        // no 11k-member JSON or second native source/registration reservation.
        let mut indices = vec_with(checked.roster.members.len())?;
        for (i, spec) in checked.roster.members.iter().enumerate() {
            if in_tree(spec, tree) {
                indices.push(i);
            }
        }
        indices.sort_unstable_by(|a, b| {
            checked.roster.members[*a]
                .relative
                .split('/')
                .cmp(checked.roster.members[*b].relative.split('/'))
        });
        let root_identity = stamp(original);
        let mut observed =
            sdk::Observation::new(checked.reference_sha256, component, root_identity);
        for i in indices {
            let spec = checked.roster.members[i];
            let member = self
                .observed
                .get(i)
                .and_then(Option::as_ref)
                .ok_or(AdmissionFailure::Inventory)?;
            if member.group != spec.group || member.relative != spec.relative {
                return Err(AdmissionFailure::Inventory);
            }
            let directory = match (&member.kind, spec.kind) {
                (MemberKind::Directory(_), SourceKindSpec::Directory { .. }) => true,
                (MemberKind::File(_), SourceKindSpec::File { .. }) => false,
                _ => return Err(AdmissionFailure::Inventory),
            };
            observed
                .member(spec.relative, directory, stamp(member.identity))
                .ok_or(AdmissionFailure::Bounds)?;
        }
        let metadata = self.optional_sdk_metadata[component.index() - 1]
            .as_ref()
            .map(|m| (stamp(m.identity), Sha256::digest(&m.contents).into()));
        let observation = observed
            .finish(metadata)
            .ok_or(AdmissionFailure::Inventory)?;
        let mut owned = String::new();
        owned.try_reserve_exact(path.len()).map_err(native_error)?;
        owned.push_str(path);
        Ok(Some(sdk::CopyInput {
            component,
            root: owned,
            root_identity,
            observation,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sdk_copy_projection_requires_actual_source_return_and_closes() {
        let (_audit, receiver) = watch::channel(Instant::now());
        let source = SourceSlots::new_original(receiver, None, None);
        let root = RegisteredRoot {
            path: std::path::PathBuf::from("/not-opened"),
            identity: crate::asset_source::ProjectIdentity::Posix(
                crate::asset_source::DirectoryIdentity::synthetic_evidence_identity(),
            ),
        };
        assert!(source.acquisition_sdk_copy_input(&root).is_err());
    }
}
