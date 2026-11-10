// NONSHIPPING: included in installer only for one exclusive fixed Fresh cut.
// All native effects use the existing Install originals. No alternate paths,
// worker protocol frames, control marker files, or caller-selected boundaries.
impl Install {
    fn fresh_control_boundary(&self,n:usize,owner:&FreshOutputOwner)->Result<()> {
        let effects=self.maintenance.as_ref().ok_or("fresh-cut-maintenance")?;
        check(effects.action==ActionData::FreshInstall && effects.state.is_none()
            && effects.state_bytes.is_none() && !effects.state_published && !effects.inverse
            && self.worker_stderr_is_gate && self.worker_go_eof && self.worker_deadline.is_some()
            && !self.unknown && !self.payload_verified && self.launcher_writes.bytes==0
            && self.runtime_publication=="not-attempted" && self.app_publication=="not-attempted"
            && self.app.is_none() && self.runtime.is_none() && !owner.failed
            && self.stage==Some(owner.stage) && self.stage_name.as_deref()==Some(self.originals[owner.stage].name.as_str())
            && self.originals[n].role==Role::PayloadWriter && self.originals[n].state==State::Owned
            && self.identity(n)?.size==0,"fresh-cut-boundary")?;
        self.registration_ready()?;
        self.check_name(owner.stage,false)?;self.protected(owner.stage,true,Some(0o700))?;
        self.absent(owner.root,paths::APP_NAME)?;
        self.check_name(n,false)?;self.protected(n,false,Some(0o600))?;
        native::no_xattrs(self.fd(n)?.as_fd()).map_err(|_|"fresh-cut-payload-attributes")?;
        self.clock()
    }
    #[cfg(feature="macos-installed-fresh-write-cut")]
    fn fresh_control_after_first_write(&self,n:usize,count:usize)->Result<()> {
        let owner=self.fresh_outputs.as_ref().ok_or("fresh-cut-enrollment")?;
        self.fresh_control_boundary(n,owner)?;
        self.fresh_output_post(owner)?;
        check(!owner.pending && owner.readback && owner.persist_returned==Some(true)
            && owner.written>0 && self.payload_write_calls==1 && self.payload_written==count as u64
            && count>0 && count<=65536,"fresh-cut-first-write")?;
        let identity=self.fresh_output_identity(n)?;
        let parent=self.fresh_output_identity(self.originals[n].parent.ok_or("fresh-cut-parent")?)?;
        let mut found=owner.index.rows_data().filter(|row|row.identity_data()==identity);
        let row=found.next().ok_or("fresh-cut-enrolled-payload")?;
        check(found.next().is_none() && row.role_data()==fresh_data::OutputRoleData::PayloadFile
            && row.parent_data()==parent && row.expected_file_data().is_some_and(|(size,_)|size>=count as u64),
            "fresh-cut-enrolled-payload")?;
        let actual=stat::fstat(self.fd(n)?).map_err(|_|"fresh-cut-payload-stat")?;
        check(actual.st_flags==0 && actual.st_size==count as i64 && actual.st_nlink==1,
            "fresh-cut-returned-payload")?;
        self.clock()?;native::fresh_write_cut_exit()
    }
    #[cfg(feature="macos-installed-fresh-torn-cut")]
    fn fresh_control_torn_first_frame(&self,n:usize,owner:&mut FreshOutputOwner,
        entry:&fresh_data::OutputEnrollmentData,frame:&[u8])->Result<()> {
        self.fresh_control_boundary(n,owner)?;
        check(owner.pending && owner.written==0 && owner.persist_returned.is_none() && !owner.readback
            && self.payload_write_calls==0 && self.payload_written==0
            && entry.role_data()==fresh_data::OutputRoleData::PayloadFile
            && entry.identity_data()==self.fresh_output_identity(n)?
            && entry.parent_data()==self.fresh_output_identity(self.originals[n].parent.ok_or("fresh-cut-parent")?)?
            && !owner.index.rows_data().any(|row|row.role_data()==fresh_data::OutputRoleData::PayloadFile)
            && frame.len()>4 && frame.len()<=fresh_data::ENTRY_LIMIT+4,"fresh-cut-first-frame")?;
        self.check_name(owner.writer,true)?;self.check_name(owner.reader,true)?;
        let before=stat::fstat(self.fd(owner.writer)?).map_err(|_|"fresh-cut-journal-stat")?;
        check(before.st_size>=0 && before.st_size as usize==owner.index.bytes_data()
            && self.fresh_output_identity(owner.writer)?==owner.index.origin_data().identities_data()[2],
            "fresh-cut-journal-original")?;
        self.clock()?;
        let used=unistd::write(self.fd(owner.writer)?,&frame[..1]).map_err(|_|"fresh-cut-torn-write")?;
        owner.written=used; // Exact native return, before a possible later veto.
        check(used==1,"fresh-cut-torn-write-count")?;
        // No sync, readback, index append, pending-clear, valid-frame fiction,
        // Rust Drop or atexit work intervenes between this return and fixed exit.
        native::fresh_torn_cut_exit()
    }
}
