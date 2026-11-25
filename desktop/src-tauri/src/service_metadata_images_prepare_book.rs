//! The existing Config Book owns inspection/preparation and Apply rows. Two
//! genuine slots, including all tombstones; never another pool or fake grant.
use super::*;
use crate::{
    service_metadata_images_prepare_protocol as images,
    service_metadata_images_prepare_requests as rows,
};
impl Inbox {
    pub(crate) fn images_read(
        &self,
        input: images::Read,
        scope: crate::service_metadata_images_requests::Scope,
    ) -> Result<images::Status, Error> {
        let mut book = self.lock()?;
        if input.origin.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        if let Some(row) = book.rows.iter().find(|r| {
            r.origin()
                .is_some_and(|q| q.request_id == input.origin.request_id)
        }) {
            let e = row.image_preparation().ok_or(Error::Conflict)?;
            if e.input != input {
                return Err(Error::Conflict);
            }
            return e.status();
        }
        if book.closed || self.failed.load(Ordering::Acquire) {
            return Err(Error::Unavailable);
        }
        for row in &book.rows {
            if row.occupied()? {
                return Err(Error::Busy);
            }
        }
        if book.rows.len() >= p::REQUEST_LIMIT {
            return Err(Error::Busy);
        }
        book.rows.try_reserve_exact(1).map_err(|_| Error::Busy)?;
        let e = rows::Entry::new(input, scope, self.failed.clone(), self.changes.clone())?;
        book.rows.push(SharedRow::MetadataImagesPrepare(e.clone()));
        self.images_changed()?;
        e.status()
    }
    pub(crate) fn images_preparation_entry(
        &self,
        q: &images::Query,
    ) -> Result<Arc<rows::Entry>, Error> {
        if q.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        self.lock()?
            .rows
            .iter()
            .filter_map(SharedRow::image_preparation)
            .find(|e| e.input.origin == *q)
            .cloned()
            .ok_or(Error::Conflict)
    }
    pub(crate) fn images_preparation_kind(&self, q: &images::Query) -> Result<bool, Error> {
        if q.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        let b = self.lock()?;
        let r = b
            .rows
            .iter()
            .find(|r| r.origin() == Some(q))
            .ok_or(Error::Conflict)?;
        if r.image_preparation().is_some() {
            Ok(true)
        } else if r.images().is_some() {
            Ok(false)
        } else {
            Err(Error::Conflict)
        }
    }
    pub(crate) fn images_preparation_status(
        &self,
        q: Option<&images::Query>,
    ) -> Result<Option<images::Status>, Error> {
        if let Some(q) = q {
            return self.images_preparation_entry(q)?.status().map(Some);
        }
        self.lock()?
            .rows
            .iter()
            .rev()
            .find_map(SharedRow::image_preparation)
            .map(|e| e.status())
            .transpose()
    }
    pub(crate) fn images_preparation_entries(&self) -> Result<Vec<Arc<rows::Entry>>, Error> {
        Ok(self
            .lock()?
            .rows
            .iter()
            .filter_map(SharedRow::image_preparation)
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_metadata_images_protocol::fixtures::*;
    use crate::service_metadata_images_requests::fixtures::{grant, input};
    #[test]
    fn inspection_and_apply_use_two_original_config_slots_and_both_occupancy_cuts() {
        let inbox = Inbox::new(id('1'));
        let wake = Arc::new(tokio::sync::Notify::new());
        let marker = Arc::new(());
        let g = grant(&wake);
        let read = images::Read { origin: query() };
        inbox
            .images_read(read.clone(), rows::fixtures::copy_scope(&g.scope))
            .unwrap();
        let e = inbox.images_preparation_entry(&read.origin).unwrap();
        rows::fixtures::reviewing(&e, &marker, &wake);
        assert!(inbox
            .images_install(id('6'), grant(&wake), |_| Ok(()))
            .is_err());
        inbox
            .images_install_with_preparation(id('6'), g, Some(&e), |_| Ok(()))
            .unwrap();
        assert_eq!(inbox.lock().unwrap().rows.len(), 2);
        let mut submit = input();
        submit.origin.request_id = id('7');
        inbox.images_submit(submit.clone()).unwrap();
        assert!(inbox.images_entry(&submit.origin).is_ok());
        assert!(inbox.images_preparation_entry(&submit.origin).is_err());
        assert!(inbox.images_preparation_kind(&read.origin).unwrap());
        assert!(!inbox.images_preparation_kind(&submit.origin).unwrap());
        assert_eq!(
            inbox
                .images_read(read, rows::fixtures::copy_scope(&e.scope))
                .unwrap()
                .phase,
            images::Phase::Reviewing
        );
        let mut bad = submit;
        bad.origin.request_id = id('3');
        assert!(inbox.images_submit(bad).is_err());
    }
    #[test]
    fn full_shared32_refuses_allow_without_discarding_or_transferring_original() {
        let inbox = Inbox::new(id('1'));
        let wake = Arc::new(tokio::sync::Notify::new());
        for n in 100..131 {
            inbox
                .images_revoke(&Id::parse(&format!("{n:032x}")).unwrap(), Instant::now())
                .unwrap();
        }
        let g = grant(&wake);
        let read = images::Read { origin: query() };
        inbox
            .images_read(read.clone(), rows::fixtures::copy_scope(&g.scope))
            .unwrap();
        let e = inbox.images_preparation_entry(&read.origin).unwrap();
        let marker = Arc::new(());
        rows::fixtures::reviewing(&e, &marker, &wake);
        let mut called = false;
        assert!(inbox
            .images_install_with_preparation(id('6'), g, Some(&e), |_| {
                called = true;
                Ok(())
            })
            .is_err());
        assert!(!called);
        assert!(!e.transferred());
        assert!(e.reviewing(&review()));
        assert_eq!(inbox.lock().unwrap().rows.len(), 32);
        e.cancel(Instant::now()).unwrap();
        assert!(e.native_stop(Instant::now()).unwrap().is_some());
        assert!(inbox.images_preparation_entry(&read.origin).is_ok());
    }
}
