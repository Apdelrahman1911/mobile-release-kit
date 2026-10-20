//! Closed routing of the existing single Prepared/Session link. No runner,
//! registry, task, timer or general action interface is introduced.
use super::*;
use crate::agent_build_requests::{Entry, Family, NativeLink};
pub(super) enum Preparation {
    Android(agent_android_build::Preparation),
    Ios(agent_ios_archive::Preparation),
}
pub(super) fn prepare(
    input: Option<Preparation>,
    inner: &Arc<Inner>,
    r: &Registry,
    context: &Context,
    registration: u32,
    root: &RegisteredRoot,
    id: &str,
    generation: &str,
    revision: u32,
    expires: Instant,
) -> Result<Option<Arc<NativeLink>>, BridgeError> {
    match input {
        None => Ok(None),
        Some(Preparation::Android(p)) => agent_android_build::prepare(
            Some(p),
            inner,
            r,
            context,
            registration,
            root,
            id,
            generation,
            revision,
            expires,
        ),
        Some(Preparation::Ios(p)) => agent_ios_archive::prepare(
            Some(p),
            inner,
            r,
            context,
            registration,
            root,
            id,
            generation,
            revision,
            expires,
        ),
    }
}
pub(super) fn start_matches(p: &Prepared, entry: Option<&Arc<Entry>>) -> bool {
    match (&p.agent_build, entry) {
        (None, None) => true,
        (Some(link), Some(entry)) if link.entry().family() == entry.family() => {
            match entry.family() {
                Family::AndroidInspect => agent_android_build::start_matches(p, Some(entry)),
                Family::IosArchive => agent_ios_archive::start_matches(p, Some(entry)),
            }
        }
        _ => false,
    }
}
pub(super) fn consume(p: &Prepared) -> Result<(), BridgeError> {
    match &p.agent_build {
        None => Ok(()),
        Some(link) => match link.entry().family() {
            Family::AndroidInspect => agent_android_build::consume(p),
            Family::IosArchive => agent_ios_archive::consume(p),
        },
    }
}
fn family(r: &Registry) -> Option<Family> {
    r.active
        .as_ref()
        .and_then(|a| a.owner.agent_build.as_ref())
        .or_else(|| r.prepared.as_ref().and_then(|p| p.agent_build.as_ref()))
        .map(|l| l.entry().family())
}
pub(super) fn changed(r: &Registry) {
    match family(r) {
        Some(Family::AndroidInspect) => agent_android_build::changed(r),
        Some(Family::IosArchive) => agent_ios_archive::changed(r),
        None => {}
    }
}
pub(super) fn retired_prepared(p: &Prepared, reason: Reason, revision: u32) {
    if let Some(link) = &p.agent_build {
        match link.entry().family() {
            Family::AndroidInspect => agent_android_build::retired_prepared(p, reason, revision),
            Family::IosArchive => agent_ios_archive::retired_prepared(p, reason, revision),
        }
    }
}
pub(super) fn retired(a: &Active, revision: u32) {
    if let Some(link) = &a.owner.agent_build {
        match link.entry().family() {
            Family::AndroidInspect => agent_android_build::retired(a, revision),
            Family::IosArchive => agent_ios_archive::retired(a, revision),
        }
    }
}
