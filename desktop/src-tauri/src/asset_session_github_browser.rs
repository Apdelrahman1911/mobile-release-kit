//! An explicit ordinary-user browser request, under the SAME original document.
use super::*;
use crate::github_browser_protocol as b;

impl DocumentBinding {
    pub(crate) fn github_browser_open(&self, request:&b::Request)->Result<b::RequestSent,BridgeError> {
        // Synchronous main-thread command: no await, new thread, queue, timer,
        // child process, callback, HTTP call, credential or general URL endpoint.
        let mut state=self.lock();
        self.expire(&mut state,Instant::now());
        installation_reveal_document_gate(&state)?;
        if self.github_gate(&state)!=GitHubReason::None {return Err(b::refused());}
        if !self.installation_reveal_available(){return Err(b::unavailable());}
        let (project,original)=state.github.registration().map(|(p,g)|(p.to_owned(),g)).ok_or_else(b::refused)?;
        let (generation,root)=self.registry_result(&mut state,self.inner.bridge.native_project(&project),None).map_err(|_|b::refused())?;
        if generation!=original{return Err(b::refused());}
        let binding=github_setup_project_binding(&root).map_err(|_|b::refused())?;
        let edit=self.inner.bridge.edits.saved_registration_guard(&self.inner.session_identity).map_err(|_|b::refused())?;
        let destination=state.github.github_browser_destination(request,generation,&root,&binding,&edit,Instant::now(),
            self.inner.bridge.supervisor.github_activity_profile_available(),self.inner.bridge.supervisor.pull_request_profile_available())?;
        #[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
        {
            use mrk_macos_installed_native::github_browser;
            match destination {
                b::Destination::PullRequest{repository,number,page}=>github_browser::pull_request(&repository,&number,page==b::Page::Files),
                b::Destination::Comparison{repository,base_sha,head_sha}=>github_browser::comparison(&repository,&base_sha,&head_sha),
            }.map_err(|_|b::unconfirmed())?;
            Ok(b::request_sent())
        }
        #[cfg(not(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
        {let _=destination;Err(b::unavailable())}
    }
}
