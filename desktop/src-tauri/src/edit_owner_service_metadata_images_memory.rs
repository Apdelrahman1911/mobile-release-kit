//! Image Apply-only continuation of the ORIGINAL borrowed Edit census. This
//! quote starts only after its own Open and Prepare write buffers have returned
//! and dropped. It grants no child/IO/runtime completion or new payload credit.
use super::*;

// A malformed THIRD frame still reaches the SAME bounded Seed before sequence
// refusal: charge Seed plus typed nested Value. Four response terms cover raw
// Vec growth and independent string backing. Open's33MiB buffer is NOT credited
// from child Prepared: the actual original writer counter must be exactly2.
// Remaining Apply queue/writer use the unchanged64KiB small-command encoder.
const IMAGE_FUTURE: usize = 2 * crate::protocol::NODE_LIMIT * 512
    + 4 * i::RESPONSE_LIMIT + 2 * i::SMALL_REQUEST_LIMIT + 2 * i::STATUS_LIMIT
    + 1024 * 1024 // original IO/channel/task/native-call control buffers
    + size_of::<Session>() + size_of::<Resources>() + size_of::<ActiveOwner>()
    + size_of::<agent_metadata_images::Link>()
    + 2 * size_of::<agent_metadata_images::PreparedOriginal>()
    + 2 * size_of::<agent_metadata_images::Claim>()
    + 2 * size_of::<crate::service_metadata_images_requests::Call>()
    + 4 * (size_of::<crate::application_service_host::NativeProject>() + 4096 + 128);

impl EditOwner {
    pub(crate) fn images_agent_edit_backing(&self) -> Result<usize, BridgeError> {
        let r = self
            .inner
            .registry
            .try_lock()
            .map_err(|_| invalid_owner())?;
        if self.inner.poisoned.load(Ordering::SeqCst) || r.exhausted {
            return Err(edit_unknown());
        }
        let mut n = Usage {
            bytes: size_of::<Registry>(),
            nodes: 0,
        };
        r.generation.heap(&mut n)?;
        r.loss_generation.heap(&mut n)?;
        r.window.heap(&mut n)?;
        for keys in [
            &r.blocked_projects,
            &r.image_recovery_projects,
            &r.workflow_recovery_projects,
        ] {
            n.add(keys.len().checked_mul(1024).ok_or_else(invalid_owner)?)?;
            for key in keys {
                key.heap(&mut n)?;
            }
        }
        n.add(
            r.domain_blocks
                .0
                .len()
                .checked_mul(4096)
                .ok_or_else(invalid_owner)?,
        )?;
        for key in r.domain_blocks.0.keys() {
            key.heap(&mut n)?;
        }
        for p in r.last.iter().chain(r.active.iter().map(|a| &a.projection)) {
            // Original retained private context/selected/submission + two full
            // native Status copies. Foreign last stays charged, not discarded.
            n.add(
                projection(p)?
                    .checked_mul(if p.domain == EditDomain::MetadataImages {
                        3
                    } else {
                        1
                    })
                    .ok_or_else(invalid_owner)?,
            )?;
        }
        if let Some(a) = &r.active {
            if a.session.domain != EditDomain::MetadataImages
                || a.projection.phase != Phase::Reviewing
                || a.claimed_seq != 1
                || !a.opened
                || !a.prepared
                || a.unknown
                || a.cleanup_start.is_some()
                || a.session.image_written.load(Ordering::Acquire) != 2
                || a.projection
                    .metadata_images
                    .as_ref()
                    .is_none_or(|d| d.intent != i::Intent::Import)
            {
                return Err(invalid_owner());
            }
            a.session.id.heap(&mut n)?;
            let registration = a.session.registration.as_ref().ok_or_else(invalid_owner)?;
            n.add(registration.root.path.capacity())?;
            if let Some(link) = a.session.agent_metadata_images.get() {
                n.add(link.project.canonical_root.capacity())?;
                link.project.runtime_id.heap(&mut n)?;
            }
            // Do not pretend a live native runtime has zero retained source/ACL
            // backing. Borrow its own existing census; try-lock/opaque refuses.
            #[cfg(all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            ))]
            {
                let resources = a
                    .session
                    .resources
                    .try_lock()
                    .map_err(|_| invalid_owner())?;
                let installed = resources.installed.as_ref().ok_or_else(invalid_owner)?;
                let installed = installed.try_lock().map_err(|_| invalid_owner())?;
                match &*installed {
                    InstalledEditSlots::MetadataImages(slots) => {
                        n.add(slots.retained_bytes().ok_or_else(invalid_owner)?)?
                    }
                    _ => return Err(invalid_owner()),
                }
            }
            #[cfg(not(all(
                target_os = "macos",
                target_pointer_width = "64",
                any(target_arch = "aarch64", target_arch = "x86_64")
            )))]
            {
                return Err(invalid_owner());
            }
        }
        // The absent-active form is only a census for default/overbound tests.
        // images_prepared independently demands the real active native original.
        n.add(IMAGE_FUTURE)?;
        Ok(n.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn data() -> EditProjection {
        EditProjection {
            domain: EditDomain::Configuration,
            project_id: "project".into(),
            session_id: "a".repeat(32),
            owner_generation: "b".repeat(32),
            phase: Phase::Unknown,
            review_remaining_ms: 0,
            checkout: None,
            prepared: None,
            recovery: None,
            workflow: None,
            metadata_text: None,
            release_version: None,
            metadata_images: None,
            initialization: None,
            identity: None,
            apply_submitted: false,
            core_outcome: None,
            native_reason: Reason::None,
            native_finality: NativeFinality::Pending,
            late_settled: false,
        }
    }
    #[test]
    fn retained_image_private_view_capacity_and_foreign_last_are_not_buffer_credit() {
        let owner = EditOwner::new(RuntimeConfig::packaged(PathBuf::from(
            "/never-opened-images-census",
        )));
        let initial = owner.images_agent_edit_backing().unwrap();
        let mut p = data();
        p.domain = EditDomain::MetadataImages;
        let text = String::with_capacity(1024 * 1024);
        let capacity = text.capacity();
        let ptr = text.as_ptr();
        p.metadata_images = Some(i::Details {
            prepared: Some(i::Prepared {
                revision: "c".repeat(32),
                plan_token: "d".repeat(32),
                draft_revision: 1,
                baseline_generation: 1,
                view: Value::String(text),
            }),
            intent: i::Intent::Import,
            checkout: None,
            context: Some(i::Context {
                platform: crate::metadata_text_edit_protocol::Platform::Android,
                locale: "en-US".into(),
                asset_type: "phoneScreenshots".into(),
            }),
            selected: Vec::new(),
            submission: None,
        });
        owner.inner.lock().last = Some(p);
        assert!(owner.images_agent_edit_backing().unwrap() >= initial + 3 * capacity);
        assert_eq!(
            owner
                .inner
                .lock()
                .last
                .as_ref()
                .unwrap()
                .metadata_images
                .as_ref()
                .unwrap()
                .prepared
                .as_ref()
                .unwrap()
                .view
                .as_str()
                .unwrap()
                .as_ptr(),
            ptr
        );
        let mut foreign = data();
        foreign.checkout = Some(c::Checkout {
            revision: "e".repeat(32),
            base: Value::String(String::with_capacity(1024 * 1024)),
        });
        owner.inner.lock().last = Some(foreign);
        assert!(owner.images_agent_edit_backing().unwrap() >= initial + 1024 * 1024);
        assert!(owner.inner.lock().last.as_ref().unwrap().checkout.is_some());
        assert!(
            IMAGE_FUTURE
                >= 2 * crate::protocol::NODE_LIMIT * 512
                    + 4 * i::RESPONSE_LIMIT
                    + 2 * i::SMALL_REQUEST_LIMIT
                    + 2 * i::STATUS_LIMIT
        );
        assert_eq!(
            (i::REQUEST_LIMIT, i::BATCH_LIMIT, i::MAX_FILES),
            (33 * 1024 * 1024, 24 * 1024 * 1024, 10)
        );
    }
}
