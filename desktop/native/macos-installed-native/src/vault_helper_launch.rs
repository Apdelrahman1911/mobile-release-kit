//! Fixed vault-only command transport. LookupBook remains the process/pipe/clock
//! owner. No caller command, argument list, environment, raw FD or callback API.
use std::{io,os::{fd::AsRawFd,unix::process::CommandExt},process::{Child,Command,Stdio}};
use crate::vault_helper_filesystem::{CodeOriginals,WorkerHandoff,HELPER_BINARY,FIXED_CWD};
unsafe extern "C" { fn mrk_vault_gate_child_inherit(descriptor:i32,parent_pid:i32)->i32; }

pub struct FixedCommand{command:Option<Command>,handoff:Option<WorkerHandoff>,entered:bool}
impl FixedCommand{
    pub fn new()->Self{Self{command:None,handoff:None,entered:false}}
    pub fn ready(&self)->bool{!self.entered && self.command.is_some() && self.handoff.is_some()}
    pub fn storage_empty(&self)->bool{self.command.is_none() && self.handoff.is_none()}
    pub fn prepare(&mut self,originals:&mut CodeOriginals)->io::Result<()>{
        if self.entered || !self.storage_empty(){return Err(io::ErrorKind::PermissionDenied.into());}
        let handoff=originals.prepare_worker_handoff().map_err(|_|io::Error::from(io::ErrorKind::PermissionDenied))?;
        // All allocation/formatting/argv/environment work precedes fork and the
        // actual document launch claim. No hooks exist on this stored builder.
        let mut command=Command::new(HELPER_BINARY);
        command.env_clear().current_dir(FIXED_CWD).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .arg("--mrk-vault-worker-gate-v1").arg(handoff.descriptor.to_string()).arg(handoff.parent_pid.to_string());
        self.handoff=Some(handoff);self.command=Some(command);Ok(())
    }
    pub fn spawn_once(&mut self,originals:&mut CodeOriginals)->io::Result<Child>{
        if !self.ready(){return Err(io::ErrorKind::PermissionDenied.into());}
        self.entered=true;
        let mut command=self.command.take().ok_or(io::ErrorKind::PermissionDenied)?;
        let handoff=self.handoff.take().ok_or(io::ErrorKind::PermissionDenied)?;
        let gate=originals.claim_worker_spawn(handoff).map_err(|_|io::Error::from(io::ErrorKind::PermissionDenied))?;
        let descriptor=gate.as_raw_fd();let parent_pid=handoff.parent_pid;
        // SAFETY: this exact retained original is exclusively borrowed through
        // the one synchronous spawn below. The local builder is never exported,
        // reused or stored with a callback. No other code can close/recycle it.
        // Child-only C performs getpid/getppid/fcntl and scalar errno work; no
        // allocation, mutex, environment, logging, path or cleanup call occurs.
        // Parent CLOEXEC is never cleared. Only nonallocating OS errors return.
        unsafe {command.pre_exec(move ||{
            let returned=mrk_vault_gate_child_inherit(descriptor,parent_pid);
            if returned==0{Ok(())}else{Err(io::Error::from_raw_os_error(returned))}
        });}
        let returned=command.spawn();
        let _same_original_still_borrowed=gate.as_raw_fd();
        // Errors remain unknown to LookupBook. This adapter cannot close a gate,
        // invent no-child evidence, wait/kill, pump a pipe or grant GO.
        returned
    }
    pub fn retire_prepared_storage(&mut self){
        // Before spawn there are no callback/pipe originals in this builder.
        // After entry spawn_once has consumed both cells, including on error.
        self.command=None;self.handoff=None;
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn inert_fixed_command_cannot_spawn_without_this_original_gate(){
        let mut command=FixedCommand::new();let mut originals=CodeOriginals::new();
        assert!(command.storage_empty() && !command.ready());
        assert!(command.spawn_once(&mut originals).is_err());
        assert!(command.prepare(&mut originals).is_err());
        assert!(command.storage_empty() && !command.ready());
        assert!(!originals.worker_gate_facts().acquired && !originals.worker_gate_facts().spawn_entered);
    }
}
