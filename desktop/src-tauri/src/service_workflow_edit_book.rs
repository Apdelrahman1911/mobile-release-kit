//! SAME Configuration/Text/Images Book, IDs and occupied/retained32 limits.
use super::*;
use crate::{service_workflow_edit_protocol as wire, service_workflow_edit_requests as rows};
const _: () = assert!(rows::ROW_BYTES <= p::STATUS_BYTES + 8192 + std::mem::size_of::<Entry>());
impl Inbox {
    pub(crate) fn workflow_edit_prepare(
        &self,
        input: wire::Prepare,
        source: Source,
        read: Arc<ReadPermission>,
    ) -> Result<wire::Status, Error> {
        input.validate()?;
        let mut b = self.lock()?;
        if input.origin.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        if let Some(r) = b.rows.iter().find(|r| {
            r.origin()
                .is_some_and(|q| q.request_id == input.origin.request_id)
        }) {
            let old = r.workflow_edit().ok_or(Error::Conflict)?;
            if old.input != input {
                return Err(Error::Conflict);
            }
            return old.status();
        }
        if b.closed || self.failed.load(Ordering::Acquire) {
            return Err(Error::Unavailable);
        }
        for r in &b.rows {
            if r.occupied()? {
                return Err(Error::Busy);
            }
        }
        if b.rows.len() >= p::REQUEST_LIMIT {
            return Err(Error::Busy);
        }
        b.rows.try_reserve_exact(1).map_err(|_| Error::Busy)?;
        let row = rows::Entry::new(
            input,
            source,
            read,
            self.failed.clone(),
            self.changes.clone(),
        )?;
        b.rows.push(SharedRow::WorkflowEdit(row.clone()));
        self.images_changed()?;
        row.status()
    }
    pub(crate) fn workflow_edit_entry(&self, q: &wire::Query) -> Result<Arc<rows::Entry>, Error> {
        if q.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        self.lock()?
            .rows
            .iter()
            .filter_map(SharedRow::workflow_edit)
            .find(|e| e.input.origin == *q)
            .cloned()
            .ok_or(Error::Conflict)
    }
    pub(crate) fn workflow_edit_desktop(
        &self,
        q: Option<&wire::Query>,
    ) -> Result<wire::DesktopStatus, Error> {
        let request = if let Some(q) = q {
            Some(self.workflow_edit_entry(q)?.status()?)
        } else {
            self.lock()?
                .rows
                .iter()
                .rev()
                .find_map(SharedRow::workflow_edit)
                .map(|e| e.status())
                .transpose()?
        };
        let s = wire::DesktopStatus {
            service_instance: self.instance.clone(),
            request,
        };
        s.validate()?;
        Ok(s)
    }
    pub(crate) fn workflow_edit_entries(&self) -> Result<Vec<Arc<rows::Entry>>, Error> {
        Ok(self
            .lock()?
            .rows
            .iter()
            .filter_map(SharedRow::workflow_edit)
            .cloned()
            .collect())
    }
}
