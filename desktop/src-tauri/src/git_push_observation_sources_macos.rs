//! Observer-only addition to the SAME GitLocalSources and SourceBook. The
//! production tool nomination remains None. No supplied hash or path is a grant.
use super::*;
use crate::shell::installed_observation::git_push::{Control, DATA_FILE, DATA_LIMIT};
impl GitLocalSources {
    pub(crate) fn configure_push_observation(
        &mut self,
        control: std::sync::Arc<Control>,
    ) -> Result<(), Reason> {
        if !self.not_started() || self.push_observation.is_some() || !control.live() {
            return Err(Reason::SourceRefused);
        }
        self.push_observation = Some(control);
        Ok(())
    }
    pub(super) fn observed_push_tool(
        &mut self,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<bool, Reason> {
        let Some(control) = self.push_observation.clone() else {
            return Ok(false);
        };
        let n = self.native.as_ref().ok_or(Reason::SourceChanged)?.clone();
        if !control.live()
            || std::path::Path::new(&n.root) != control.project()
            || self.push_observation_file.is_some()
        {
            return Err(Reason::SourceRefused);
        }
        // Actual held project/.git bytes BEFORE first worker/CLT command. The
        // file receives the same original named/held ACL/post/sole-close paths.
        let index = self.file(
            self.git.ok_or(Reason::SourceChanged)?,
            DATA_FILE.as_bytes(),
            n.uid,
            DATA_LIMIT,
            false,
            stop,
        )?;
        let snapshot = self.snapshot(index, DATA_LIMIT, stop)?;
        self.push_observation_file = Some((index, snapshot.clone()));
        if !control.pin_sources(&n.tool, &snapshot, &n.root) {
            return Err(Reason::SourceRefused);
        }
        Ok(true)
    }
    pub(super) fn post_push_observation(
        &self,
        stop: &mut dyn FnMut() -> bool,
    ) -> Result<(), Reason> {
        if let Some((i, s)) = &self.push_observation_file {
            // Cleanup POST may run after observer STOP: preserve the original
            // deadline guard, not a fresh work/live-observer check here.
            if self.snapshot(*i, DATA_LIMIT, stop)? != *s {
                return Err(Reason::SourceChanged);
            }
        }
        Ok(())
    }
}
