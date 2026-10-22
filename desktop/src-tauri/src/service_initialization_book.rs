//! SAME Configuration/Text/Images Book, IDs and occupied/retained32 limits.
use super::*;
use crate::{service_initialization_protocol as init, service_initialization_requests as rows};
const _: () = assert!(rows::ROW_BYTES <= p::STATUS_BYTES + 8192 + std::mem::size_of::<Entry>());
impl Inbox {
    pub(crate) fn initialization_prepare(
        &self,
        input: init::Prepare,
        source: Source,
        read: Arc<ReadPermission>,
    ) -> Result<init::Status, Error> {
        input.validate()?;
        let mut b = self.lock()?;
        if input.origin.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        if let Some(r) = b.rows.iter().find(|r| {
            r.origin()
                .is_some_and(|q| q.request_id == input.origin.request_id)
        }) {
            let old = r.initialization().ok_or(Error::Conflict)?;
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
        b.rows.push(SharedRow::Initialization(row.clone()));
        self.images_changed()?;
        row.status()
    }
    pub(crate) fn initialization_entry(&self, q: &init::Query) -> Result<Arc<rows::Entry>, Error> {
        if q.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        self.lock()?
            .rows
            .iter()
            .filter_map(SharedRow::initialization)
            .find(|e| e.input.origin == *q)
            .cloned()
            .ok_or(Error::Conflict)
    }
    pub(crate) fn initialization_desktop(
        &self,
        q: Option<&init::Query>,
    ) -> Result<init::DesktopStatus, Error> {
        let request = if let Some(q) = q {
            Some(self.initialization_entry(q)?.status()?)
        } else {
            self.lock()?
                .rows
                .iter()
                .rev()
                .find_map(SharedRow::initialization)
                .map(|e| e.status())
                .transpose()?
        };
        let s = init::DesktopStatus {
            service_instance: self.instance.clone(),
            request,
        };
        s.validate()?;
        Ok(s)
    }
    pub(crate) fn initialization_entries(&self) -> Result<Vec<Arc<rows::Entry>>, Error> {
        Ok(self
            .lock()?
            .rows
            .iter()
            .filter_map(SharedRow::initialization)
            .cloned()
            .collect())
    }
}
