//! The existing Config Book owns these rows, nonce reservations and collisions.
//! No second pool: an unused grant/tombstone has no fabricated request origin.
use super::*;
use crate::{
    service_metadata_images_protocol as images, service_metadata_images_requests as image_rows,
};

impl Inbox {
    pub(crate) fn images_install(
        &self,
        nonce: Id,
        grant: image_rows::Grant,
        install: impl FnOnce(&Arc<image_rows::Entry>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut book = self.lock()?;
        if book.closed || self.failed.load(Ordering::Acquire) {
            return Err(Error::Unavailable);
        }
        if book
            .rows
            .iter()
            .filter_map(SharedRow::images)
            .any(|e| e.nonce == nonce)
        {
            return Err(Error::Conflict);
        }
        for r in &book.rows {
            if r.occupied()? {
                return Err(Error::Busy);
            }
        }
        if book.rows.len() >= p::REQUEST_LIMIT {
            return Err(Error::Busy);
        }
        // Allocate before the native link is installed. Nothing after that cut
        // can omit the permanent row because a Vec growth was refused.
        book.rows.try_reserve_exact(1).map_err(|_| Error::Busy)?;
        let entry = image_rows::Entry::new(
            nonce,
            Some(grant),
            self.failed.clone(),
            self.changes.clone(),
        )?;
        install(&entry)?;
        book.rows.push(SharedRow::MetadataImages(entry));
        self.images_changed()
    }
    fn images_changed(&self) -> Result<(), Error> {
        let mut good = true;
        self.changes.send_modify(|n| {
            if let Some(next) = n.checked_add(1).filter(|n| *n < u32::MAX) {
                *n = next
            } else {
                good = false;
            }
        });
        if good {
            Ok(())
        } else {
            self.fence();
            Err(Error::StateUnknown)
        }
    }
    pub(crate) fn images_revoke(&self, nonce: &Id, at: Instant) -> Result<images::Revoked, Error> {
        let mut book = self.lock()?;
        if let Some(e) = book
            .rows
            .iter()
            .filter_map(SharedRow::images)
            .find(|e| &e.nonce == nonce)
        {
            e.revoke(at)?;
            let reply = images::Revoked {
                nonce: nonce.clone(),
                access: e.access(&self.instance)?,
            };
            reply.validate()?;
            return Ok(reply);
        }
        if book.closed || self.failed.load(Ordering::Acquire) {
            return Err(Error::Unavailable);
        }
        if book.rows.len() >= p::REQUEST_LIMIT {
            return Err(Error::Busy);
        }
        book.rows.try_reserve_exact(1).map_err(|_| Error::Busy)?;
        // This exact nonce can never later become an Allow, even if that RAW
        // caller arrives after Revoke. It is not a submitted CLI request.
        let e = image_rows::Entry::new(
            nonce.clone(),
            None,
            self.failed.clone(),
            self.changes.clone(),
        )?;
        book.rows.push(SharedRow::MetadataImages(e));
        self.images_changed()?;
        Ok(images::Revoked {
            nonce: nonce.clone(),
            access: images::Access::empty(self.instance.clone()),
        })
    }
    pub(crate) fn images_submit(&self, input: images::Submit) -> Result<images::Status, Error> {
        input.validate()?;
        let book = self.lock()?;
        if input.origin.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        if let Some(row) = book.rows.iter().find(|r| {
            r.origin()
                .is_some_and(|q| q.request_id == input.origin.request_id)
        }) {
            let e = row.images().ok_or(Error::Conflict)?;
            if e.input() != Some(&input) {
                return Err(Error::Conflict);
            }
            return e.status();
        }
        if book.closed || self.failed.load(Ordering::Acquire) {
            return Err(Error::Unavailable);
        }
        let entry = book
            .rows
            .iter()
            .filter_map(SharedRow::images)
            .find(|e| e.grant.as_ref().is_some_and(|g| g.id == input.grant_id))
            .ok_or(Error::AccessDenied)?;
        for row in &book.rows {
            if !row.images().is_some_and(|e| Arc::ptr_eq(e, entry)) && row.occupied()? {
                return Err(Error::Busy);
            }
        }
        entry.submit(input)
    }
    pub(crate) fn images_entry(&self, q: &images::Query) -> Result<Arc<image_rows::Entry>, Error> {
        if q.service_instance != self.instance {
            return Err(Error::Conflict);
        }
        self.lock()?
            .rows
            .iter()
            .filter_map(SharedRow::images)
            .find(|e| e.origin() == Some(q))
            .cloned()
            .ok_or(Error::Conflict)
    }
    pub(crate) fn images_access(&self, q: Option<&images::Query>) -> Result<images::Access, Error> {
        if let Some(q) = q {
            return self.images_entry(q)?.access(&self.instance);
        }
        self.lock()?
            .rows
            .iter()
            .rev()
            .filter_map(SharedRow::images)
            .find(|e| e.grant.is_some())
            .map_or_else(
                || Ok(images::Access::empty(self.instance.clone())),
                |e| e.access(&self.instance),
            )
    }
    pub(crate) fn images_entries(&self) -> Result<Vec<Arc<image_rows::Entry>>, Error> {
        Ok(self
            .lock()?
            .rows
            .iter()
            .filter_map(SharedRow::images)
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image_rows::fixtures::{grant, input};
    use images::fixtures::*;
    #[test]
    fn image_nonce_tombstones_and_config_rows_share_original32_without_fake_origins() {
        let inbox = Inbox::new(id('1'));
        let wake = Arc::new(tokio::sync::Notify::new());
        let nonce = id('5');
        let revoked = inbox.images_revoke(&nonce, Instant::now()).unwrap();
        assert!(revoked.access.request.is_none());
        assert!(inbox.catalogue(&id('2')).unwrap().is_empty());
        let mut called = false;
        assert!(inbox
            .images_install(nonce, grant(&wake), |_| {
                called = true;
                Ok(())
            })
            .is_err());
        assert!(!called);
        let read = p::Read {
            origin: query(),
            expected_observation_revision: 3,
        };
        // Original Config admission/cancellation, not a fabricated image row.
        let source = Source {
            runtime_id: "project".into(),
            root: "/never-opened-image-book".into(),
            device: 1,
            inode: 2,
            observation_revision: 3,
        };
        let permission = Arc::new(ReadPermission::new(
            Instant::now() + std::time::Duration::from_secs(300),
        ));
        inbox.read(read.clone(), source, permission).unwrap();
        inbox
            .entry(&read.origin)
            .unwrap()
            .cancel(Instant::now())
            .unwrap();
        for n in 0..30 {
            let nonce = Id::parse(&format!("{:032x}", n + 100)).unwrap();
            inbox.images_revoke(&nonce, Instant::now()).unwrap();
        }
        assert_eq!(inbox.lock().unwrap().rows.len(), 32);
        assert!(inbox.images_revoke(&id('6'), Instant::now()).is_err());
        assert!(inbox
            .images_install(id('7'), grant(&wake), |_| Ok(()))
            .is_err());
        let catalogue = inbox.catalogue(&id('2')).unwrap();
        assert_eq!(catalogue.len(), 1);
        assert_eq!(catalogue[0].request_id, read.origin.request_id);
        assert_eq!(
            catalogue[0].family,
            crate::service_request_catalogue::AdditionalFamily::Configuration
        );
        assert!(inbox.images_entry(&read.origin).is_err());
    }
    #[test]
    fn exact_old_image_origin_survives_next_grant_and_cross_family_collision_refuses() {
        let inbox = Inbox::new(id('1'));
        let wake = Arc::new(tokio::sync::Notify::new());
        inbox
            .images_install(id('5'), grant(&wake), |_| Ok(()))
            .unwrap();
        let first = input();
        inbox.images_submit(first.clone()).unwrap();
        let e = inbox.images_entry(&first.origin).unwrap();
        let call = e.caller().unwrap();
        e.preclaim().unwrap();
        e.enqueue().unwrap();
        call.returned().unwrap();
        e.retired(Some(done())).unwrap();
        e.history().unwrap().unwrap();
        e.history_returned(true).unwrap();
        let mut next = grant(&wake);
        next.id = id('6');
        inbox.images_install(id('7'), next, |_| Ok(())).unwrap();
        assert_eq!(inbox.images_access(None).unwrap().grant_id, Some(id('6')));
        assert_eq!(
            inbox
                .images_access(Some(&first.origin))
                .unwrap()
                .request
                .unwrap()
                .phase,
            images::Phase::Final
        );
        assert!(Arc::ptr_eq(&e, &inbox.images_entry(&first.origin).unwrap()));
        let mut wrong = first.origin.clone();
        wrong.project_id = id('f');
        assert!(inbox.images_entry(&wrong).is_err());
        wrong = first.origin.clone();
        wrong.service_instance = id('f');
        assert!(inbox.images_entry(&wrong).is_err());
        let mut retry = first.clone();
        retry.grant_id = id('6');
        assert!(inbox.images_submit(retry).is_err());
        assert_eq!(inbox.catalogue(&id('2')).unwrap().len(), 1); // unused second grant is not a request
        assert_eq!(
            inbox.catalogue(&id('2')).unwrap()[0].family,
            crate::service_request_catalogue::AdditionalFamily::MetadataImages
        );
        let collision = p::Read {
            origin: first.origin.clone(),
            expected_observation_revision: 3,
        };
        let source = Source {
            runtime_id: "project".into(),
            root: "/never-opened-image-book".into(),
            device: 1,
            inode: 2,
            observation_revision: 3,
        };
        assert!(inbox
            .read(
                collision,
                source,
                Arc::new(ReadPermission::new(
                    Instant::now() + std::time::Duration::from_secs(300)
                ))
            )
            .is_err());
        inbox.close(Instant::now());
        assert_eq!(
            inbox.images_submit(first).unwrap().phase,
            images::Phase::Final
        );
    }
}
