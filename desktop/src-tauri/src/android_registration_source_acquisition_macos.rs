//! Read-only partial picks, on the SAME SourceSlots original. No full Review,
//! proposal, provider, payload pass, install or executable loan is created.
use super::*;
use crate::tool_acquisition_protocol::components::Partition;
#[path = "android_registration_source_acquisition_sdk_macos.rs"]
mod sdk_copy;

// Present only inside acquisition_read / its bounded walk and XML validation.
// None of these buffers survive the returned read, unlike every source record,
// picked metadata byte and original close state, which remain retained.
const READ_WORKSPACE: usize =
    18 * BLOCK + 17 * 1024 + crate::android_sdk_metadata_macos::PARSER_WORK_BYTES;

pub(super) struct Work {
    pub(super) gate: crate::saved_command_owner::ToolAcquisitionSourceGate,
    absent: [Option<(usize, &'static str)>; 2],
    finding: Option<(Partition, [u8; 32])>,
}

fn reservation(checked: supplier::acquisition::PickedRoster) -> Option<SourceReservation> {
    let roster = checked.roster;
    if roster.members.is_empty() || roster.members.len() > policy::ENTRY_LIMIT {
        return None;
    }
    let mut shape = SourceStorage {
        members: roster.members.len(),
        aliases: 0,
        originals: 0,
        file_heap: 0,
        alias_heap: 0,
        alias_original_heap: 0,
    };
    let mut files = 0usize;
    for member in roster.members {
        if member.relative.len() > 512 || member.group == SourceGroup::FixedSupport {
            return None;
        }
        match member.kind {
            SourceKindSpec::Directory { .. } => {}
            SourceKindSpec::File { .. } => {
                files = files.checked_add(1)?;
                shape.file_heap = shape
                    .file_heap
                    .checked_add(member.relative.len())?
                    .checked_add(64)?;
            }
            SourceKindSpec::Alias {
                target, canonical, ..
            } => {
                if target.len() > 512 || canonical.len() > 512 {
                    return None;
                }
                shape.aliases = shape.aliases.checked_add(1)?;
                shape.alias_heap = shape
                    .alias_heap
                    .checked_add(member.relative.len())?
                    .checked_add(target.len())?
                    .checked_add(canonical.len())?;
                shape.alias_original_heap = shape.alias_original_heap.checked_add(target.len())?;
            }
        }
    }
    if files > policy::FILE_COUNT || shape.aliases > policy::ALIAS_COUNT {
        return None;
    }
    // One selected read pass only. The spill covers three full ancestor chains,
    // fixed JDK/SDK prefix/release/optional-XML opens and alias targets. There is
    // NO canonical payload second pass or synthetic registration proposal.
    shape.originals = shape
        .members
        .checked_sub(shape.aliases)?
        .checked_add(SOURCE_ORIGINAL_SPILL)?;
    if shape.originals > SOURCE_ORIGINAL_LIMIT {
        return None;
    }
    let bytes = size_of::<SourceSlots>()
        .checked_add(shape.originals.checked_mul(size_of::<Original>())?)?
        .checked_add(shape.aliases.checked_mul(size_of::<AliasOriginal>())?)?
        .checked_add(shape.members.checked_mul(size_of::<Option<Member>>())?)?
        .checked_add(shape.file_heap)?
        .checked_add(shape.alias_heap)?
        .checked_add(shape.alias_original_heap)?
        .checked_add(3 * 4096 + 3 * ANCESTORS * size_of::<usize>())?
        .checked_add(READ_WORKSPACE + 16384)? // Actual walk/read/XML workspace + retained ACL frame bound.
        .checked_add(2 * (SDK_METADATA_BYTES + 512 + 64))?;
    Some(SourceReservation {
        profile: checked.profile,
        phase: SourcePhase::Inspection,
        storage: shape,
        proposal_validity: 0,
        supplier_work: 0,
        bytes,
    })
}
impl SourceReservation {
    pub(crate) fn acquisition_retained_bytes(&self) -> Option<usize> {
        if self.phase != SourcePhase::Inspection
            || self.supplier_work != 0
            || self.proposal_validity != 0
        {
            return None;
        }
        self.bytes.checked_sub(READ_WORKSPACE)
    }
}

impl SourceSlots {
    pub(crate) fn acquisition_reservation(
        profile: crate::android_build_protocol::Profile,
    ) -> Option<SourceReservation> {
        reservation(supplier::acquisition::picked_roster_for(profile)?)
    }
    pub(crate) fn new_acquisition(
        audit: watch::Receiver<Instant>,
        gate: crate::saved_command_owner::ToolAcquisitionSourceGate,
        reservation: SourceReservation,
    ) -> Self {
        let mut source = Self::new_original(audit, None, Some(reservation));
        source.acquisition = Some(Work {
            gate,
            absent: [None; 2],
            finding: None,
        });
        source
    }
    /// This returned DATA is usable only alongside this SAME retained source
    /// original and the outer worker/driver joins. It cannot create SourceReview.
    pub(crate) fn acquisition_finding(&self) -> Option<(Partition, [u8; 32])> {
        if !self.settled() || self.first_failure().is_some() {
            return None;
        }
        self.acquisition.as_ref()?.finding
    }
    pub(crate) fn acquisition_once(
        &mut self,
        roots: &[Option<RegisteredRoot>; 3],
        end: Instant,
        stop: &watch::Receiver<bool>,
        publish: &mut Publish<'_>,
    ) -> Result<()> {
        let result = self.acquisition_read(roots, end, stop);
        if let Err(failure) = result {
            self.note(failure, Instant::now(), publish);
        }
        result
    }
    fn acquisition_read(
        &mut self,
        roots: &[Option<RegisteredRoot>; 3],
        end: Instant,
        stop: &watch::Receiver<bool>,
    ) -> Result<()> {
        let profile = self.selected_profile()?;
        let checked =
            supplier::acquisition::picked_roster_for(profile).ok_or(AdmissionFailure::Inventory)?;
        let expected = reservation(checked).ok_or(AdmissionFailure::Bounds)?;
        if self.gate.is_some()
            || self.acquisition.is_none()
            || !roots.iter().any(Option::is_some)
            || self.reservation.is_none_or(|r| {
                r.profile != expected.profile
                    || r.phase != SourcePhase::Inspection
                    || r.supplier_work != 0
                    || r.proposal_validity != 0
                    || r.storage != expected.storage
                    || r.bytes != expected.bytes
            })
        {
            return Err(AdmissionFailure::Inventory);
        }
        let roster = checked.roster;
        optional_sdk_metadata_roster(roster)?;
        self.allocate_records(SourcePhase::Inspection)?;
        self.point(end, stop)?;
        self.account = Some(native::real_user().map_err(native_error)?);
        self.point(end, stop)?;
        if matches!(self.account, None | Some(0) | Some(u32::MAX)) {
            return Err(AdmissionFailure::Ownership);
        }
        self.frame_entered = true;
        self.frame = Some(SnapshotBook::new());
        if !self.frame.as_ref().is_some_and(|frame| {
            frame.not_started()
                && frame.quiescent()
                && (1..=16384).contains(&frame.retained_frame_bytes())
        }) {
            return Err(AdmissionFailure::Bounds);
        }
        let mut jdk_home = None;
        for (role, selected) in roots.iter().enumerate() {
            let Some(root) = selected else {
                continue;
            };
            let chain = self.chain(root, end, stop)?;
            let picked = *chain.last().ok_or(AdmissionFailure::Unknown)?;
            self.roots[role] = Some(picked);
            if role == 0 {
                if self.originals[picked].name.text().ends_with(".jdk") {
                    let contents = self.child(picked, "Contents", true, end, stop)?;
                    jdk_home = Some(self.child(contents, "Home", true, end, stop)?);
                } else if self.originals[picked].name.text() == "Home" && chain.len() >= 3 {
                    let contents = chain[chain.len() - 2];
                    let bundle = chain[chain.len() - 3];
                    if self.originals[contents].name.text() != "Contents"
                        || !self.originals[bundle].name.text().ends_with(".jdk")
                        || self.originals[picked].parent != Some(contents)
                        || self.originals[contents].parent != Some(bundle)
                    {
                        return Err(AdmissionFailure::Inventory);
                    }
                    self.roots[0] = Some(bundle);
                    jdk_home = Some(picked);
                } else {
                    return Err(AdmissionFailure::Inventory);
                }
            }
        }
        if let Some(home) = jdk_home {
            let release = self.child(home, "release", false, end, stop)?;
            let bytes = usize::try_from(self.identity(release)?.size).map_err(native_error)?;
            if bytes == 0 || bytes > BLOCK {
                return Err(AdmissionFailure::Bounds);
            }
            let (_, raw) = self.read(release, bytes as u64, bytes, end, stop, None)?;
            let (vendor, version) = release_layout(&raw)?;
            if vendor != checked.jdk_vendor || version != checked.jdk_version {
                return Err(AdmissionFailure::Inventory);
            }
        }
        self.observed = vec_with(roster.members.len())?;
        for _ in roster.members {
            self.observed.push(None);
        }
        let mut values = [Some(false); 4]; // Unchosen roles in this declared lookup set ONLY.
        for (component, tree) in roster.trees.iter().enumerate() {
            let role = group_index(tree.group).ok_or(AdmissionFailure::Inventory)?;
            let Some(root) = self.roots[role] else {
                continue;
            };
            let mut parent = root;
            let mut missing = false;
            if !tree.prefix.is_empty() {
                for part in tree.prefix.split('/') {
                    if self.acquisition_absent(parent, part, end, stop)? {
                        // Only these two exact selected SDK subtree edges may
                        // be absent. Present malformed/wrong/denied is an error.
                        if tree.group != SourceGroup::Sdk {
                            return Err(AdmissionFailure::Inventory);
                        }
                        self.acquisition
                            .as_mut()
                            .ok_or(AdmissionFailure::Unknown)?
                            .absent[component - 1] = Some((parent, part));
                        missing = true;
                        break;
                    }
                    parent = self.child(parent, part, true, end, stop)?;
                    self.originals[parent].retained = true;
                }
                if missing {
                    continue;
                }
                let position = member_index(roster, tree.group, tree.prefix)?;
                self.directory_observed(position, parent, roster.members[position])?;
            }
            self.walk(parent, tree.group, tree.prefix, roster, 0, end, stop)?;
            // Presence is compatible only after every exact required member,
            // all optional metadata and the SAME parent POST have passed.
            for (i, spec) in roster.members.iter().enumerate() {
                if in_tree(spec, tree) && self.observed[i].is_none() {
                    return Err(AdmissionFailure::Inventory);
                }
            }
            if tree.group == SourceGroup::Sdk {
                let slot = component - 1;
                if self.sdk_metadata_parents[slot].is_none()
                    || self.optional_sdk_metadata[slot]
                        .as_ref()
                        .is_some_and(|metadata| {
                            !crate::android_sdk_metadata_macos::observation_valid(
                                &roster.optional_sdk_metadata[slot],
                                &metadata.data(),
                            )
                        })
                {
                    return Err(AdmissionFailure::Inventory);
                }
            }
            values[component] = Some(true);
        }
        self.check_remaining(end, stop)?;
        let absent = self
            .acquisition
            .as_ref()
            .ok_or(AdmissionFailure::Unknown)?
            .absent;
        for (parent, name) in absent.into_iter().flatten() {
            if !self.acquisition_absent(parent, name, end, stop)? {
                return Err(AdmissionFailure::Identity);
            }
        }
        let partition = Partition::observed(values).ok_or(AdmissionFailure::Inventory)?;
        let fingerprint = self.acquisition_fingerprint(partition, checked.reference_sha256)?;
        self.point(end, stop)?;
        self.acquisition
            .as_mut()
            .ok_or(AdmissionFailure::Unknown)?
            .finding = Some((partition, fingerprint));
        Ok(())
    }
    fn acquisition_absent(
        &mut self,
        parent: usize,
        name: &'static str,
        end: Instant,
        stop: &watch::Receiver<bool>,
    ) -> Result<bool> {
        self.check(parent, end, stop)?;
        let absent = absent_entry(
            stat::fstatat(self.fd(parent)?, name, AtFlags::AT_SYMLINK_NOFOLLOW).map(|_| ()),
        )?;
        self.check(parent, end, stop)?;
        Ok(absent)
    }
    fn acquisition_fingerprint(
        &self,
        partition: Partition,
        reference: [u8; 32],
    ) -> Result<[u8; 32]> {
        let mut hash = Sha256::new();
        hash.update(b"mrk-picked-component-observation/1\0");
        hash.update(reference);
        hash.update(self.account.ok_or(AdmissionFailure::Unknown)?.to_le_bytes());
        for index in 0..4 {
            hash.update([u8::from(partition.is_compatible(index))]);
        }
        // Canonical roots/roster order, not filesystem directory-return order.
        for (role, root) in self.roots.iter().enumerate() {
            hash.update([role as u8, u8::from(root.is_some())]);
            let mut current = *root;
            while let Some(index) = current {
                let original = self.originals.get(index).ok_or(AdmissionFailure::Unknown)?;
                hash.update((original.name.text().len() as u64).to_le_bytes());
                hash.update(original.name.text().as_bytes());
                hash_identity(&mut hash, self.identity(index)?);
                current = original.parent;
            }
        }
        for (index, member) in self.observed.iter().enumerate() {
            hash.update((index as u64).to_le_bytes());
            hash.update([u8::from(member.is_some())]);
            if let Some(member) = member {
                hash_identity(&mut hash, member.identity);
            }
        }
        for metadata in &self.optional_sdk_metadata {
            hash.update([u8::from(metadata.is_some())]);
            if let Some(metadata) = metadata {
                hash_identity(&mut hash, metadata.identity);
                hash.update(metadata.file.sha256.as_bytes());
            }
        }
        for (parent, name) in self
            .acquisition
            .as_ref()
            .ok_or(AdmissionFailure::Unknown)?
            .absent
            .into_iter()
            .flatten()
        {
            hash_identity(&mut hash, self.identity(parent)?);
            hash.update(name.as_bytes());
            hash.update([0]);
        }
        Ok(hash.finalize().into())
    }
}
// Recognition of an exact no-follow syscall result only. The caller still
// requires the SAME held parent's before/after checks. A present entry of ANY
// kind is not missing; its separate ordinary source inspection must pass.
fn absent_entry(value: std::result::Result<(), nix::errno::Errno>) -> Result<bool> {
    match value {
        Ok(()) => Ok(false),
        Err(nix::errno::Errno::ENOENT) => Ok(true),
        Err(error) => Err(native_error(error)),
    }
}
fn in_tree(member: &SourceMemberSpec, tree: &SourceTree) -> bool {
    member.group == tree.group
        && (tree.prefix.is_empty()
            || member.relative == tree.prefix
            || member
                .relative
                .strip_prefix(tree.prefix)
                .is_some_and(|tail| tail.starts_with('/')))
}
fn hash_identity(hash: &mut Sha256, identity: Identity) {
    hash.update(identity.dev.to_le_bytes());
    hash.update(identity.ino.to_le_bytes());
    hash.update(identity.mode.to_le_bytes());
    hash.update(identity.uid.to_le_bytes());
    hash.update(identity.gid.to_le_bytes());
    hash.update(identity.links.to_le_bytes());
    hash.update(identity.size.to_le_bytes());
    hash.update(identity.mtime.to_le_bytes());
    hash.update(identity.mtime_ns.to_le_bytes());
    hash.update(identity.ctime.to_le_bytes());
    hash.update(identity.ctime_ns.to_le_bytes());
    hash.update(identity.flags.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_requires_exact_enoent_not_denial_link_or_interruption() {
        use nix::errno::Errno;
        assert_eq!(absent_entry(Ok(())), Ok(false)); // File, directory or symlink still requires inspection.
        assert_eq!(absent_entry(Err(Errno::ENOENT)), Ok(true));
        for failure in [
            Errno::EACCES,
            Errno::EPERM,
            Errno::ENOTDIR,
            Errno::ELOOP,
            Errno::EINTR,
            Errno::EIO,
        ] {
            assert!(absent_entry(Err(failure)).is_err());
        }
    }
    #[test]
    fn both_compiled_rosters_reserve_one_read_phase_not_registration_authority() {
        use crate::android_build_protocol::Profile;
        // Actual compiled catalogue DATA, no source/native/cache initialization.
        for profile in [Profile::MacArm64, Profile::MacX64] {
            let checked = supplier::acquisition::picked_roster_data(profile).unwrap();
            let r = reservation(checked).unwrap();
            assert_eq!(r.profile, profile);
            assert_eq!(r.phase, SourcePhase::Inspection);
            assert_eq!((r.supplier_work, r.proposal_validity), (0, 0));
            assert_eq!(r.storage.members, checked.roster.members.len());
            assert_eq!(
                r.storage.originals,
                r.storage.members - r.storage.aliases + SOURCE_ORIGINAL_SPILL
            );
            let retained = r.acquisition_retained_bytes().unwrap();
            assert_eq!(r.bytes, retained + READ_WORKSPACE);
            // Same one owner: read/close returns BEFORE manifest/CA/cache/child.
            // Its earlier work fits the same later82MiB + retained reservation.
            assert!(r.bytes <= 82 * 1024 * 1024 + retained);
            // Both the old Inspect and new Acquire books remain charged. This
            // proves only feasible DATA capacity, not real Doc/native admission.
            assert!(82 * 1024 * 1024 + 2 * retained < 96 * 1024 * 1024);
            assert_eq!(
                checked
                    .roster
                    .trees
                    .iter()
                    .map(|tree| (tree.group, tree.prefix))
                    .collect::<Vec<_>>(),
                vec![
                    (SourceGroup::Jdk, ""),
                    (SourceGroup::Sdk, "platforms/android-35"),
                    (SourceGroup::Sdk, "build-tools/35.0.0"),
                    (SourceGroup::Gradle, "")
                ]
            );
            let (_audit, receiver) = watch::channel(Instant::now());
            let mut source = SourceSlots::new_original(receiver, None, Some(r));
            assert_eq!(
                source.allocate_records(SourcePhase::Reproof),
                Err(AdmissionFailure::Bounds)
            );
            source.allocate_records(SourcePhase::Inspection).unwrap();
            assert_eq!(source.originals.capacity(), r.storage.originals);
            assert_eq!(source.aliases.capacity(), r.storage.aliases);
            assert!(source
                .retained_bytes()
                .is_some_and(|bytes| bytes <= retained));
            assert!(source.acquisition_finding().is_none());
            assert!(source.take_inspection_review().is_err());
            // No original was opened and no settled/finding bit was fabricated.
            assert_eq!(source.live, 0);
            assert!(source.frame.is_none());
        }
        assert!(supplier::acquisition::picked_roster_data(Profile::LinuxX64).is_none());
    }
    #[test]
    fn sdk_scope_never_includes_sibling_packages() {
        let tree = SourceTree {
            group: SourceGroup::Sdk,
            prefix: "platforms/android-35",
        };
        for (path, expected) in [
            ("platforms/android-35", true),
            ("platforms/android-35/android.jar", true),
            ("platforms/android-350/android.jar", false),
            ("platforms/android-34/android.jar", false),
            ("licenses", false),
        ] {
            assert_eq!(
                in_tree(
                    &SourceMemberSpec {
                        group: SourceGroup::Sdk,
                        relative: path,
                        kind: SourceKindSpec::Directory { modes: &[0o755] }
                    },
                    &tree
                ),
                expected
            );
        }
    }
}
