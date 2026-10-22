//! Authenticated, ordinary-user, read-only IPC to the original running host.
//!
//! There is no HTTP listener, child-process route, caller pathname endpoint or
//! window impersonation. The private connection capability is binary, never a
//! JSON/CLI argument/environment value. Peer UID is checked on BOTH ends.
use crate::{application_service::{ApplicationService, ClientSession}, application_state_store as store, service_protocol as p};
use p::{Error, Id};
use std::{path::Path, sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Duration};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{UnixListener, UnixStream}, sync::watch, task::{JoinHandle, JoinSet}, time::{timeout_at, Instant}};
use zeroize::Zeroizing;

const SOCKET: &str = "s";
const DESCRIPTOR: &str = "agent.connection";
const MAGIC: &[u8; 8] = b"MRKIPC01";
const HANDSHAKE: usize = 72;
pub(crate) const CLIENTS: usize = 8;
const SERVER_DEADLINE: Duration = Duration::from_secs(5);
const CLIENT_DEADLINE: Duration = Duration::from_secs(8);

#[cfg(test)]
thread_local! { static CLIENT_CLOSE_UNKNOWN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

struct ConnectionCapability { instance: Id, secret: Zeroizing<[u8; 32]> }
impl ConnectionCapability {
    fn new(instance: Id) -> Result<Self, Error> {
        let mut secret = Zeroizing::new([0u8; 32]);
        getrandom::fill(secret.as_mut()).map_err(|_| Error::Unavailable)?;
        if secret.iter().all(|b| *b == 0) { return Err(Error::Unavailable); }
        Ok(Self { instance, secret })
    }
    fn bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(HANDSHAKE));
        bytes.extend(MAGIC); bytes.extend(self.instance.as_str().as_bytes()); bytes.extend(self.secret.iter());
        bytes
    }
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != HANDSHAKE || &bytes[..8] != MAGIC { return Err(Error::Conflict); }
        let instance = Id::parse(std::str::from_utf8(&bytes[8..40]).map_err(|_| Error::Conflict)?)?;
        let mut secret = Zeroizing::new([0u8; 32]); secret.copy_from_slice(&bytes[40..]);
        if secret.iter().all(|b| *b == 0) { return Err(Error::Conflict); }
        Ok(Self { instance, secret })
    }
    fn accepts(&self, bytes: &[u8; HANDSHAKE]) -> bool {
        // Compare the entire fixed frame; no secret bytes enter error details.
        let expected = self.bytes();
        expected.iter().zip(bytes).fold(0u8, |difference, (a, b)| difference | (a ^ b)) == 0
    }
}

struct Endpoint { socket: store::FileKey, descriptor: store::FileKey, capability: ConnectionCapability, metadata_exchange: AtomicBool }
// Only concurrent allocation exclusion on the SAME endpoint, not a service
// grant/native owner. No waiting queue or renewed deadline is introduced.
struct MetadataExchange<'a> { active: &'a AtomicBool }
impl<'a> MetadataExchange<'a> {
    fn require(active: &'a AtomicBool, held: &mut Option<Self>) -> Result<(), Error> {
        if let Some(original) = held {
            return if std::ptr::eq(original.active, active) { Ok(()) } else { Err(Error::StateUnknown) };
        }
        active.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).map_err(|_| Error::Busy)?;
        *held = Some(Self { active });
        Ok(())
    }
}
impl Drop for MetadataExchange<'_> {
    fn drop(&mut self) { self.active.store(false, Ordering::Release); }
}
// Quote the entire original endpoint (including padding), plus each existing
// worker's retained option and BOTH nested futures' option borrows. No extra
// worker: serve_exchange and read_request_frame borrow the same outer cell.
pub(crate) const METADATA_CONTROL_BACKING: usize = std::mem::size_of::<Endpoint>()
    + CLIENTS * (std::mem::size_of::<Option<MetadataExchange<'static>>>()
        + 2 * std::mem::size_of::<&mut Option<MetadataExchange<'static>>>());
fn metadata_request(body: &p::RequestBody) -> bool {
    matches!(body, p::RequestBody::MetadataTextRead(_) | p::RequestBody::MetadataTextPrepare(_)
        | p::RequestBody::MetadataTextApply(_) | p::RequestBody::MetadataTextStatus(_) | p::RequestBody::MetadataTextCancel(_))
}
fn admit_request_size<'a>(size: usize, active: &'a AtomicBool, held: &mut Option<MetadataExchange<'a>>) -> Result<(), Error> {
    if size == 0 || size > crate::service_metadata_text_protocol::REQUEST_BYTES { return Err(Error::InvalidRequest); }
    if size > p::REQUEST_BYTES { MetadataExchange::require(active, held)?; }
    Ok(())
}
fn admit_request_body<'a>(body: &p::RequestBody, active: &'a AtomicBool, held: &mut Option<MetadataExchange<'a>>) -> Result<(), Error> {
    if metadata_request(body) { MetadataExchange::require(active, held)?; }
    Ok(())
}
impl Endpoint {
    fn check(&self, service: &ApplicationService) -> Result<(), Error> {
        let guard = service.state_directory().ipc_directory().map_err(|e| e.code)?;
        let directory = guard.directory().map_err(|e| e.code)?;
        let fd = directory.file().map_err(|e| e.code)?;
        if store::named(fd, SOCKET).map_err(|e| e.code)? != Some(self.socket)
            || store::named(fd, DESCRIPTOR).map_err(|e| e.code)? != Some(self.descriptor) { return Err(Error::Conflict); }
        Ok(())
    }
    fn remove(self, service: &ApplicationService) -> Result<(), Error> {
        let guard = service.state_directory().ipc_directory().map_err(|e| e.code)?;
        let directory = guard.directory().map_err(|e| e.code)?;
        let fd = directory.file().map_err(|e| e.code)?;
        // Only after original listener/workers close and join. A replaced name
        // is retained, never adopted or deleted because a PID appears absent.
        store::remove_original(fd, DESCRIPTOR, self.descriptor).map_err(|e| e.code)?;
        store::remove_original(fd, SOCKET, self.socket).map_err(|e| e.code)?;
        store::sync(fd).map_err(|e| e.code)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Shutdown { pub(crate) workers_joined: usize }
pub(crate) struct ServerHandle {
    stop: watch::Sender<bool>, task: Option<JoinHandle<Result<Shutdown, Error>>>, service: Arc<ApplicationService>,
    outcome: Option<Result<Shutdown, Error>>, shutdown_error: Option<Error>,
}
impl ServerHandle {
    /// Await on the genuine original handle. Merely sending stop or dropping a
    /// CLI connection is not a shutdown/cleanup receipt.
    pub(crate) async fn shutdown(&mut self) -> Result<Shutdown, Error> {
        if let Some(outcome) = self.outcome { return outcome; }
        // A poisoned grant/state mutex must never strand original IPC work.
        // Retain that failure even if this waiting observer is cancelled.
        if let Err(error) = self.service.revoke_agent_read() { self.shutdown_error.get_or_insert(error); }
        let _ = self.stop.send(true);
        // Borrow the retained original. Cancelling an observer must not detach
        // the only join handle or publish a result-shaped completion.
        let joined = match self.task.as_mut() {
            Some(task) => task.await.unwrap_or(Err(Error::StateUnknown)),
            None => Err(Error::StateUnknown),
        };
        let result = match (joined, self.shutdown_error) {
            (Err(error), _) | (Ok(_), Some(error)) => Err(error),
            (Ok(value), None) => Ok(value),
        };
        self.task.take(); self.outcome = Some(result); result
    }
}
impl Drop for ServerHandle {
    fn drop(&mut self) {
        // The server retains its directory lease until its own worker join.
        // Dropping this handle requests stop but never reports completion.
        let _ = self.stop.send(true);
    }
}

/// Called by the same original Host: Desktop or the explicitly consented
/// foreground history entry. No listener construction grants access by itself;
/// there is no automatic CLI startup, alternate endpoint or action executor.
pub(crate) async fn start(service: Arc<ApplicationService>) -> Result<ServerHandle, Error> {
    service.state_directory().begin_endpoint().map_err(|e| e.code)?;
    let prepared = bind(&service);
    let (listener, endpoint) = match prepared {
        Ok(value) => value,
        Err((error, settled)) => { let _ = service.state_directory().endpoint_settled(settled); return Err(error); }
    };
    let (stop, receive) = watch::channel(false);
    let task = tokio::spawn(run(service.clone(), listener, endpoint, receive, stop.clone()));
    Ok(ServerHandle { stop, task: Some(task), service, outcome: None, shutdown_error: None })
}

fn bind(service: &ApplicationService) -> Result<(UnixListener, Endpoint), (Error, bool)> {
    use nix::sys::stat::{fchmodat, FchmodatFlags, Mode};
    use std::os::unix::{ffi::OsStrExt, net::UnixListener as NativeListener};
    let guard = service.state_directory().ipc_directory().map_err(|e| (e.code, true))?;
    let directory = guard.directory().map_err(|e| (e.code, true))?;
    let fd = directory.file().map_err(|e| (e.code, true))?;
    if store::named(fd, SOCKET).map_err(|e| (e.code, true))?.is_some()
        || store::named(fd, DESCRIPTOR).map_err(|e| (e.code, true))?.is_some() { return Err((Error::RecoveryRequired, true)); }
    let path = directory.path().join(SOCKET);
    // Darwin sockaddr_un.sun_path has 104 bytes including the terminator.
    // No ambient tmp/PID/symlink workaround weakens the checked location.
    if path.as_os_str().as_bytes().len() >= 104 { return Err((Error::UnsupportedPlatform, true)); }
    let capability = ConnectionCapability::new(service.instance().clone()).map_err(|e| (e, true))?;
    let listener = NativeListener::bind(&path).map_err(|_| (Error::Unavailable, false))?;
    let prepared = (|| {
        let before = store::named(fd, SOCKET).map_err(|e| e.code)?.ok_or(Error::Conflict)?;
        if before.mode & 0o170000 != 0o140000 || before.uid != store::uid() || before.links != 1 { return Err(Error::Conflict); }
        fchmodat(fd, SOCKET, Mode::from_bits_truncate(0o600), FchmodatFlags::NoFollowSymlink).map_err(|_| Error::Unavailable)?;
        let socket = store::named(fd, SOCKET).map_err(|e| e.code)?.ok_or(Error::Conflict)?;
        if !socket.private_socket() || socket.device != before.device || socket.inode != before.inode { return Err(Error::Conflict); }
        listener.set_nonblocking(true).map_err(|_| Error::Unavailable)?;
        let descriptor = store::create_private(fd, DESCRIPTOR, &capability.bytes()).map_err(|e| e.code)?;
        store::sync(fd).map_err(|e| e.code)?;
        directory.check().map_err(|e| e.code)?;
        Ok(Endpoint { socket, descriptor, capability, metadata_exchange: AtomicBool::new(false) })
    })();
    match prepared {
        Ok(endpoint) => {
            // Tokio owns the same original socket; it does not create another.
            UnixListener::from_std(listener).map(|listener| (listener, endpoint)).map_err(|_| (Error::StateUnknown, false))
        }
        Err(error) => {
            let _ = nix::unistd::close(listener);
            // Possibly created descriptor/socket are retained. Construction
            // failure cannot authorize deleting a now-replaced pathname.
            Err((error, false))
        }
    }
}

async fn run(service: Arc<ApplicationService>, listener: UnixListener, endpoint: Endpoint, mut stop: watch::Receiver<bool>, signal: watch::Sender<bool>) -> Result<Shutdown, Error> {
    let endpoint = Arc::new(endpoint);
    let mut workers = JoinSet::new();
    let mut joined = 0usize;
    let mut first_error = None;
    let mut resources_known = true;
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            finished = workers.join_next(), if !workers.is_empty() => {
                joined += 1;
                if !matches!(finished, Some(Ok(Ok(())))) { resources_known = false; first_error.get_or_insert(Error::StateUnknown); }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        if workers.len() >= CLIENTS {
                            if close_stream(stream).is_err() { resources_known = false; first_error.get_or_insert(Error::StateUnknown); }
                            continue;
                        }
                        let service = service.clone(); let endpoint = endpoint.clone(); let stop = stop.clone();
                        let deadline = Instant::now() + SERVER_DEADLINE;
                        workers.spawn(async move { serve_one(stream, service, endpoint, stop, deadline).await });
                    }
                    Err(_) => { first_error.get_or_insert(Error::Unavailable); break; }
                }
            }
        }
    }
    let _ = signal.send(true);
    if let Err(error) = service.revoke_agent_read() { first_error.get_or_insert(error); }
    // Retire accept before consuming all original worker handles.
    let listener_closed = match listener.into_std() { Ok(listener) => nix::unistd::close(listener).is_ok(), Err(_) => false };
    if !listener_closed { resources_known = false; first_error.get_or_insert(Error::StateUnknown); }
    while let Some(finished) = workers.join_next().await {
        joined += 1;
        if !matches!(finished, Ok(Ok(()))) { resources_known = false; first_error.get_or_insert(Error::StateUnknown); }
    }
    if resources_known {
        match Arc::try_unwrap(endpoint) {
            Ok(endpoint) => if let Err(error) = endpoint.remove(&service) { first_error = Some(error); },
            Err(_) => { resources_known = false; first_error = Some(Error::StateUnknown); },
        }
    }
    // Endpoint namespace conflict is distinct from original worker finality.
    // A failed owned-name removal still returns failure and preserves that name,
    // but cannot erase actual socket closes/joins or retain fictitious workers.
    let settled = service.state_directory().endpoint_settled(resources_known).map_err(|e| e.code);
    if let Some(error) = first_error { return Err(error); }
    settled?;
    Ok(Shutdown { workers_joined: joined })
}

fn close_stream(stream: UnixStream) -> Result<(), Error> {
    let native = stream.into_std().map_err(|_| Error::StateUnknown)?;
    nix::unistd::close(native).map_err(|_| Error::StateUnknown)
}
async fn serve_one(mut stream: UnixStream, service: Arc<ApplicationService>, endpoint: Arc<Endpoint>, mut stop: watch::Receiver<bool>, deadline: Instant) -> Result<(), Error> {
    // Errors/refusals/disconnects are not leaked to logs and are not operation
    // outcomes. The owner still closes this exact stream before its task joins.
    // OUTSIDE the cancelled future: a timeout/STOP cannot release this lease
    // before the same original stream has taken its explicit close path.
    let mut metadata = None;
    let _exchange = tokio::select! {
        _ = stop.changed() => Err(Error::Unavailable),
        result = timeout_at(deadline, serve_exchange(&mut stream, &service, &endpoint, &mut metadata)) => result.unwrap_or(Err(Error::Unavailable)),
    };
    let closed = close_stream(stream);
    drop(metadata);
    closed
}
fn same_user(stream: &UnixStream) -> Result<(), Error> {
    if stream.peer_cred().map_err(|_| Error::AccessDenied)?.uid() != store::uid() { Err(Error::AccessDenied) } else { Ok(()) }
}
async fn serve_exchange<'a>(stream: &mut UnixStream, service: &ApplicationService, endpoint: &'a Endpoint, metadata: &mut Option<MetadataExchange<'a>>) -> Result<(), Error> {
    same_user(stream)?;
    endpoint.check(service)?;
    let mut handshake = Zeroizing::new([0u8; HANDSHAKE]);
    stream.read_exact(handshake.as_mut()).await.map_err(|_| Error::Unavailable)?;
    if !endpoint.capability.accepts(&handshake) {
        let _ = stream.write_all(b"D").await;
        return Err(Error::AccessDenied);
    }
    let client: ClientSession = match service.admit_client() {
        Ok(client) => client,
        Err(_) => { let _ = stream.write_all(b"D").await; return Err(Error::AccessDenied); }
    };
    stream.write_all(b"A").await.map_err(|_| Error::Unavailable)?;
    stream.write_all(service.instance().as_str().as_bytes()).await.map_err(|_| Error::Unavailable)?;
    let bytes = read_request_frame(stream, endpoint, metadata).await?;
    // One frame/connection; extra bytes are rejected rather than ignored as a
    // possible second action. The client half-closes after its exact request.
    let mut extra = [0u8; 1];
    if stream.read(&mut extra).await.map_err(|_| Error::Unavailable)? != 0 { return Err(Error::InvalidRequest); }
    let request = p::decode_request(&bytes)?;
    drop(bytes); // Parser-only input never overlaps response encoding. Original owners remain retained.
    // All short Metadata methods, especially Status/Cancel returning public
    // Load data, share the same exclusion before any dispatch/result clone.
    admit_request_body(&request.request, &endpoint.metadata_exchange, metadata)?;
    endpoint.check(service)?;
    let response = service.dispatch(&client, request);
    let bytes = p::encode_response(&response)?;
    match &response.response {
        p::ResponseBody::GitHubActionRequest(view) => service.android_tools_client_current(&client, &view.origin.project_id)?,
        p::ResponseBody::AndroidBuildRequest(view) => service.android_tools_client_current(&client, &view.origin.project_id)?,
        p::ResponseBody::IosArchiveRequest(view) => service.android_tools_client_current(&client, &view.origin().project_id)?,
        p::ResponseBody::LocalHistoryPreparation(view)=>service.android_tools_client_current(&client,&view.origin.project_id)?,
        p::ResponseBody::LocalHistoryRequest(view)=>service.android_tools_client_current(&client,&view.origin.project_id)?,
        p::ResponseBody::LocalHistoryAccess(view)=>match &view.project_id{Some(id)=>service.android_tools_client_current(&client,id)?,None=>service.client_current(&client)?},
        p::ResponseBody::MetadataImagesPreparation(view)=>service.android_tools_client_current(&client,&view.origin.project_id)?,
        p::ResponseBody::MetadataImagesRequest(view)=>service.android_tools_client_current(&client,&view.origin.project_id)?,
        p::ResponseBody::MetadataImagesAccess(view)=>match &view.project_id{Some(id)=>service.android_tools_client_current(&client,id)?,None=>service.client_current(&client)?},
        p::ResponseBody::MetadataTextRequest(view)=>service.android_tools_client_current(&client,&view.origin.project_id)?,
        p::ResponseBody::ConfigurationRequest(view)=>service.android_tools_client_current(&client,&view.origin.project_id)?,
        p::ResponseBody::VersionEditRequest(view) => service.android_tools_client_current(&client, &view.origin.project_id)?,
        p::ResponseBody::VersionEditPreparation(view) => service.android_tools_client_current(&client, &view.origin.project_id)?,
        p::ResponseBody::AppleProvisioningPreparation(view) => service.android_tools_client_current(&client, &view.origin.project_id)?,
        p::ResponseBody::ToolSetupRequest(view) => service.android_tools_client_current(&client, &view.origin.project_id)?,
        p::ResponseBody::StoreRequest(view) => service.android_tools_client_current(&client, &view.origin.project_id)?,
        p::ResponseBody::StorePreparation(view) => service.android_tools_client_current(&client, &view.origin.project_id)?,
        p::ResponseBody::VersionReserveReview(view)=>service.android_tools_client_current(&client,&view.origin.project_id)?,
        p::ResponseBody::VersionReserveRequest(view) => service.android_tools_client_current(&client, &view.origin.project_id)?,
        p::ResponseBody::PlayCleanupRequest(view) => service.android_tools_client_current(&client,&view.origin.project_id)?,
        p::ResponseBody::GitIndexScope(view) => service.android_tools_client_current(&client, &view.project_id)?,
        p::ResponseBody::GitCommitScope(view) => service.android_tools_client_current(&client, &view.0.project_id)?,
        p::ResponseBody::GitIndexRequest(view) => service.android_tools_client_current(&client, &view.origin.project_id)?,
        p::ResponseBody::GitCommitRequest(view) => service.android_tools_client_current(&client, &view.0.origin.project_id)?,
        p::ResponseBody::GitRepositoryScope(view) => service.android_tools_client_current(&client, &view.project_id)?,
        p::ResponseBody::GitRepositoryRequest(view) => service.android_tools_client_current(&client, &view.origin.project_id)?,
        p::ResponseBody::AndroidTools(view) => service.android_tools_client_current(&client, &view.project_id)?,
        p::ResponseBody::Requests(view) => service.requests_client_current(&client, &view.project_id)?,
        p::ResponseBody::Repository(view) => service.android_tools_client_current(&client, &view.project_id)?,
        _ => service.client_current(&client)?,
    }
    write_frame(stream, &bytes).await
}
async fn read_request_frame<'a>(stream: &mut UnixStream, endpoint: &'a Endpoint, metadata: &mut Option<MetadataExchange<'a>>) -> Result<Vec<u8>, Error> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.map_err(|_| Error::Unavailable)?;
    let size = u32::from_be_bytes(header) as usize;
    // Before ANY extended Vec allocation/read. Old <=4KiB requests retain the
    // original eight-worker path; oversize old actions still fail the decoder.
    admit_request_size(size, &endpoint.metadata_exchange, metadata)?;
    let mut bytes = vec![0u8; size];
    stream.read_exact(&mut bytes).await.map_err(|_| Error::Unavailable)?;
    Ok(bytes)
}
async fn read_frame(stream: &mut UnixStream, limit: usize) -> Result<Vec<u8>, Error> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.map_err(|_| Error::Unavailable)?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > limit { return Err(Error::InvalidRequest); }
    let mut bytes = vec![0u8; size];
    stream.read_exact(&mut bytes).await.map_err(|_| Error::Unavailable)?;
    Ok(bytes)
}
async fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<(), Error> {
    stream.write_all(&(bytes.len() as u32).to_be_bytes()).await.map_err(|_| Error::Unavailable)?;
    stream.write_all(bytes).await.map_err(|_| Error::Unavailable)
}

/// The installed CLI's only transport. app_data is resolved by the native
/// client bootstrap, not accepted as an endpoint/configuration argument.
pub(crate) async fn request(app_data: &Path, request: &p::Request) -> Result<p::Response, Error> {
    request_until(app_data, request, Instant::now() + CLIENT_DEADLINE).await
}
async fn request_until(app_data: &Path, request: &p::Request, deadline: Instant) -> Result<p::Response, Error> {
    let directory = store::Directory::for_client(app_data).map_err(|e| e.code)?;
    let result = client_exchange(&directory, request, deadline).await;
    directory.close().map_err(|e| e.code)?;
    result
}
async fn client_exchange(directory: &store::Directory, request: &p::Request, deadline: Instant) -> Result<p::Response, Error> {
    directory.check().map_err(|e| e.code)?;
    let fd = directory.file().map_err(|e| e.code)?;
    let (descriptor_key, socket_key) = match (store::named(fd, DESCRIPTOR).map_err(|e| e.code)?, store::named(fd, SOCKET).map_err(|e| e.code)?) {
        // A newly bootstrapping client has not acquired an endpoint yet. A
        // cleanly stopped host leaves both absent, with saved state intact.
        (None, None) => return Err(Error::Unavailable),
        (Some(descriptor), Some(socket)) => (descriptor, socket),
        _ => return Err(Error::RecoveryRequired),
    };
    let (_, raw) = store::read_private(fd, DESCRIPTOR, HANDSHAKE, Some(descriptor_key)).map_err(|e| e.code)?;
    let raw = Zeroizing::new(raw);
    let capability = ConnectionCapability::parse(&raw)?;
    if !socket_key.private_socket() { return Err(Error::Conflict); }
    let mut stream = match timeout_at(deadline, UnixStream::connect(directory.path().join(SOCKET))).await {
        Ok(Ok(stream)) => stream,
        // The constructor has not returned its original socket to us. Its
        // cancellation/error Drop is not a native close receipt.
        _ => return Err(Error::StateUnknown),
    };
    // The timeout only BORROWS this original stream. Even a stalled handshake
    // or incomplete response proceeds to the same sole explicit close below.
    let result = timeout_at(deadline, async {
        same_user(&stream)?;
        directory.check().map_err(|e| e.code)?;
        if store::named(fd, SOCKET).map_err(|e| e.code)? != Some(socket_key)
            || store::named(fd, DESCRIPTOR).map_err(|e| e.code)? != Some(descriptor_key) { return Err(Error::Conflict); }
        stream.write_all(&raw).await.map_err(|_| Error::Unavailable)?;
        let mut accepted = [0u8; 1];
        stream.read_exact(&mut accepted).await.map_err(|_| Error::Unavailable)?;
        if accepted != *b"A" { return Err(Error::AccessDenied); }
        let mut instance = [0u8; 32]; stream.read_exact(&mut instance).await.map_err(|_| Error::Unavailable)?;
        if instance != capability.instance.as_str().as_bytes() { return Err(Error::Conflict); }
        write_frame(&mut stream, &p::encode_request(request)?).await?;
        stream.shutdown().await.map_err(|_| Error::Unavailable)?;
        let response = read_frame(&mut stream, p::RESPONSE_BYTES).await?;
        let mut extra = [0u8; 1];
        if stream.read(&mut extra).await.map_err(|_| Error::Unavailable)? != 0 { return Err(Error::InvalidRequest); }
        directory.check().map_err(|e| e.code)?;
        if store::named(fd, SOCKET).map_err(|e| e.code)? != Some(socket_key)
            || store::named(fd, DESCRIPTOR).map_err(|e| e.code)? != Some(descriptor_key) { return Err(Error::Conflict); }
        p::decode_response(&response, &request.request_id, &capability.instance)
    }).await.unwrap_or(Err(Error::Unavailable));
    let closed = close_stream(stream);
    #[cfg(test)]
    let closed = if CLIENT_CLOSE_UNKNOWN.with(|cut| cut.replace(false)) {
        // Real close was attempted once; fault only the reported finality.
        Err(Error::StateUnknown)
    } else { closed };
    closed?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{application_service::tests::{passive, poison_fixture, register_fixture}, application_state_store::{Fixture, PrivateStateDirectory, DIRECTORY}};
    use std::{future::Future, os::unix::fs::{symlink, MetadataExt, PermissionsExt}, task::Poll};
    use tokio::time::timeout;
    fn list() -> p::Request { p::Request { version: 1, request_id: Id::random().unwrap(), request: p::RequestBody::Projects(p::Empty {}) } }
    fn runtime() -> tokio::runtime::Runtime { tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap() }
    #[test]
    fn metadata_exchange_admission_is_fixed_fail_fast_and_reuses_only_its_original_lease() {
        use crate::service_metadata_text_protocol as wire;
        let id = |n: char| Id::parse(&n.to_string().repeat(32)).unwrap();
        let query = wire::Query { service_instance: id('1'), project_id: id('2'), request_id: id('3') };
        let bodies = [
            p::RequestBody::MetadataTextRead(wire::Read { origin: query.clone(), expected_observation_revision: 1, platform: wire::Platform::Android, locale: "en-US".into() }),
            p::RequestBody::MetadataTextPrepare(wire::Prepare { origin: query.clone(), proposal: wire::Fields { platform: wire::Platform::Android, fields: wire::Platform::Android.ids().iter().map(|id| wire::Field { id: (*id).into(), text: String::new() }).collect() } }),
            p::RequestBody::MetadataTextApply(wire::Apply { origin: query.clone(), original: wire::Original { session_id: id('4'), owner_generation: id('5'), revision: id('6') }, plan_token: id('7'), reviewed: true }),
            p::RequestBody::MetadataTextStatus(query.clone()),
            p::RequestBody::MetadataTextCancel(query),
        ];
        let active = AtomicBool::new(false);
        let mut held = None;
        for size in [0, wire::REQUEST_BYTES + 1] {
            assert_eq!(admit_request_size(size, &active, &mut held), Err(Error::InvalidRequest));
            assert!(held.is_none() && !active.load(Ordering::Acquire));
        }
        admit_request_size(p::REQUEST_BYTES + 1, &active, &mut held).unwrap();
        assert!(active.load(Ordering::Acquire));
        let mut other = None;
        assert_eq!(admit_request_size(wire::REQUEST_BYTES, &active, &mut other), Err(Error::Busy));
        assert!(other.is_none()); // The production size cut precedes Vec allocation.
        for body in [p::RequestBody::Info(p::Empty {}), p::RequestBody::Projects(p::Empty {})] {
            let request = p::Request { version: p::VERSION, request_id: id('8'), request: body };
            let mut bytes = p::encode_request(&request).unwrap();
            bytes.resize(p::REQUEST_BYTES, b' ');
            let ordinary = p::decode_request(&bytes).unwrap();
            admit_request_size(bytes.len(), &active, &mut other).unwrap();
            admit_request_body(&ordinary.request, &active, &mut other).unwrap();
            assert!(other.is_none()); // All eight ordinary workers remain available.
        }
        for body in &bodies {
            let request = p::Request { version: p::VERSION, request_id: id('8'), request: body.clone() };
            let bytes = p::encode_request(&request).unwrap();
            assert!(bytes.len() <= p::REQUEST_BYTES);
            let decoded = p::decode_request(&bytes).unwrap();
            assert!(metadata_request(&decoded.request));
            assert_eq!(admit_request_body(&decoded.request, &active, &mut other), Err(Error::Busy));
            assert!(other.is_none());
            admit_request_body(&decoded.request, &active, &mut held).unwrap();
        }
        // Already admitted large input retains its SAME original lease; a
        // different Endpoint can never adopt that cell as its own admission.
        admit_request_size(wire::REQUEST_BYTES, &active, &mut held).unwrap();
        let foreign = AtomicBool::new(false);
        assert_eq!(MetadataExchange::require(&foreign, &mut held), Err(Error::StateUnknown));
        assert!(!foreign.load(Ordering::Acquire));
        drop(held);
        assert!(!active.load(Ordering::Acquire));
        for body in &bodies {
            let mut fresh = None;
            admit_request_size(p::REQUEST_BYTES, &active, &mut fresh).unwrap();
            assert!(fresh.is_none());
            admit_request_body(body, &active, &mut fresh).unwrap();
            assert!(fresh.is_some() && active.load(Ordering::Acquire));
            drop(fresh);
            assert!(!active.load(Ordering::Acquire));
        }
        assert_eq!(CLIENTS, 8);
        assert_eq!(SERVER_DEADLINE, Duration::from_secs(5));
        assert_eq!(METADATA_CONTROL_BACKING, std::mem::size_of::<Endpoint>() + CLIENTS *
            (std::mem::size_of::<Option<MetadataExchange<'static>>>() + 2 * std::mem::size_of::<&mut Option<MetadataExchange<'static>>>()));
    }
    #[test]
    fn metadata_stalled_large_frame_keeps_lease_until_original_stop_close_and_return() {
        // Genuine private Store/Service/socket fixture, not native Load/Edit
        // evidence. All three original serve_one futures and clients return;
        // no standalone task, forged grant or background cleanup is used.
        runtime().block_on(async {
            use crate::service_metadata_text_protocol as wire;
            let f = Fixture::short();
            let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
            let service = Arc::new(ApplicationService::open(store.clone()).unwrap());
            let (id, root) = register_fixture(&service, &f.app, "project", "metadata-project");
            service.publish_passive_snapshot("metadata-project", &passive(&root, &"a".repeat(64))).unwrap();
            service.allow_agent_read(vec![id.clone()], Duration::from_secs(300)).unwrap();
            store.begin_endpoint().unwrap();
            let (listener, endpoint) = bind(&service).unwrap();
            let endpoint = Arc::new(endpoint);
            let (signal, stop) = watch::channel(false);
            let mut client = UnixStream::connect(f.app.join(DIRECTORY).join(SOCKET)).await.unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let mut large = Box::pin(serve_one(stream, service.clone(), endpoint.clone(), stop.clone(), Instant::now() + SERVER_DEADLINE));
            let header_only = async {
                client.write_all(&endpoint.capability.bytes()).await.unwrap();
                let mut accepted = [0u8; 1]; client.read_exact(&mut accepted).await.unwrap();
                assert_eq!(accepted, *b"A");
                let mut instance = [0u8; 32]; client.read_exact(&mut instance).await.unwrap();
                assert_eq!(instance, service.instance().as_str().as_bytes());
                client.write_all(&((p::REQUEST_BYTES + 1) as u32).to_be_bytes()).await.unwrap();
                while !endpoint.metadata_exchange.load(Ordering::Acquire) { tokio::task::yield_now().await; }
            };
            tokio::select! {
                _ = large.as_mut() => panic!("incomplete body cannot return an exchange"),
                result = timeout(Duration::from_secs(2), header_only) => result.unwrap(),
            }
            // Ordinary IPC still uses this original listener/Endpoint and
            // closes independently while the admitted large body is stalled.
            let listing = list();
            let (listed, returned) = timeout(Duration::from_secs(2), async {
                tokio::join!(request(&f.app, &listing), async {
                    let (stream, _) = listener.accept().await.unwrap();
                    serve_one(stream, service.clone(), endpoint.clone(), stop.clone(), Instant::now() + SERVER_DEADLINE).await
                })
            }).await.unwrap();
            returned.unwrap();
            let revision = match listed.unwrap().response {
                p::ResponseBody::Projects(rows) => { assert_eq!(rows.len(), 1); rows[0].observation.as_ref().unwrap().revision },
                _ => panic!("wrong ordinary response"),
            };
            let query = wire::Query { service_instance: service.instance().clone(), project_id: id, request_id: Id::random().unwrap() };
            let read = p::Request { version: p::VERSION, request_id: Id::random().unwrap(), request: p::RequestBody::MetadataTextRead(wire::Read {
                origin: query.clone(), expected_observation_revision: revision, platform: wire::Platform::Android, locale: "en-US".into(),
            }) };
            let (blocked, returned) = timeout(Duration::from_secs(2), async {
                tokio::join!(request(&f.app, &read), async {
                    let (stream, _) = listener.accept().await.unwrap();
                    serve_one(stream, service.clone(), endpoint.clone(), stop.clone(), Instant::now() + SERVER_DEADLINE).await
                })
            }).await.unwrap();
            returned.unwrap();
            assert!(blocked.is_err());
            assert!(service.configuration_requests().metadata_entry(&query).is_err());
            assert!(endpoint.metadata_exchange.load(Ordering::Acquire));
            // STOP is not a close/return. The outer original retains its guard
            // even when the borrowed exchange future is about to be cancelled.
            signal.send(true).unwrap();
            assert!(endpoint.metadata_exchange.load(Ordering::Acquire));
            timeout(Duration::from_secs(2), large.as_mut()).await.unwrap().unwrap();
            drop(large);
            assert!(!endpoint.metadata_exchange.load(Ordering::Acquire));
            let mut extra = [0u8; 1];
            assert_eq!(client.read(&mut extra).await.unwrap(), 0);
            close_stream(client).unwrap();
            let mut after_close = None;
            MetadataExchange::require(&endpoint.metadata_exchange, &mut after_close).unwrap();
            drop(after_close);
            nix::unistd::close(listener.into_std().unwrap()).unwrap();
            let endpoint = match Arc::try_unwrap(endpoint) { Ok(endpoint) => endpoint, Err(_) => panic!("original endpoint still retained") };
            endpoint.remove(&service).unwrap();
            store.endpoint_settled(true).unwrap();
            service.stop().unwrap();
            store.close().unwrap();
        });
    }
    #[test]
    fn real_socket_two_clients_share_completed_observations_and_history() {
        runtime().block_on(async {
            let f = Fixture::short(); let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
            let observations = Arc::new(crate::service_android_tools::ObservationSlot::default());
            let service = Arc::new(ApplicationService::open_with_android_tools(store.clone(), observations.clone()).unwrap());
            let (id, root) = register_fixture(&service, &f.app, "project", "project-1");
            service.publish_passive_snapshot("project-1", &passive(&root, &"1".repeat(64))).unwrap();
            service.allow_agent_read(vec![id.clone()], Duration::from_secs(30)).unwrap();
            let mut host = start(service.clone()).await.unwrap();
            let first_request = list(); let second_request = list();
            let (one, two) = tokio::join!(request(&f.app, &first_request), request(&f.app, &second_request));
            assert_eq!(one.unwrap().response, two.unwrap().response);
            // Actual authenticated socket/framing for the new closed read;
            // fixture DATA is not a native tool-selection qualification.
            let tools = p::Request { version: 1, request_id: Id::random().unwrap(), request:
                p::RequestBody::AndroidTools(p::ProjectQuery { project_id: id.clone() }) };
            match request(&f.app, &tools).await.unwrap().response {
                p::ResponseBody::AndroidTools(view) => {
                    assert_eq!(view.capture, crate::service_android_tools::Capture::Unobserved);
                    assert_eq!(view.freshness, crate::service_android_tools::Freshness::HistoricalNotRevalidated);
                    assert_eq!(view.project_compatibility, crate::service_android_tools::Compatibility::NotChecked);
                }
                _ => panic!("wrong response"),
            }
            let discovery = p::Request { version: 1, request_id: Id::random().unwrap(), request:
                p::RequestBody::Requests(p::ProjectQuery { project_id: id.clone() }) };
            let response = request(&f.app, &discovery).await.unwrap();
            match response.response {
                p::ResponseBody::Requests(view) => {
                    assert_eq!(view.service_instance, response.service_instance);
                    assert_eq!(view.project_id, id);
                    assert!(view.requests.is_empty() && view.do_not_replay);
                }
                _ => panic!("wrong response"),
            }
            let repository = p::Request { version: 1, request_id: Id::random().unwrap(), request:
                p::RequestBody::Repository(p::ProjectQuery { project_id: id.clone() }) };
            match request(&f.app, &repository).await.unwrap().response {
                p::ResponseBody::Repository(view) => {
                    assert_eq!(view.project_id, id);
                    assert_eq!(view.capture, crate::service_repository_summary::Capture::Unobserved);
                    assert_eq!(view.basis, crate::service_repository_summary::Basis::LocalRefsNoFetch);
                }
                _ => panic!("wrong response"),
            }
            observations.publish(crate::service_android_tools::tests::catalogue());
            match request(&f.app, &tools).await.unwrap().response {
                p::ResponseBody::AndroidTools(view) => {
                    assert_eq!(view.capture, crate::service_android_tools::Capture::Observed);
                    assert_eq!(view.observation.unwrap().observed_selection.unwrap().versions.jdk_version, "21");
                }
                _ => panic!("wrong response"),
            }
            service.invalidate_native("project-1").unwrap();
            match request(&f.app, &list()).await.unwrap().response { p::ResponseBody::Projects(rows) => assert!(rows[0].observation.as_ref().unwrap().stale), _ => panic!("wrong response") }
            service.publish_passive_snapshot("project-1", &passive(&root, &"2".repeat(64))).unwrap();
            let operation_id = Id::random().unwrap();
            service.publish_operation("project-1", operation_id.clone(), p::Action::EditConfiguration, p::OperationState::Succeeded, p::Settlement::Settled).unwrap();
            let query = p::Request { version: 1, request_id: Id::random().unwrap(), request: p::RequestBody::Operation(p::OperationQuery { project_id: id, operation_id }) };
            assert!(matches!(request(&f.app, &query).await.unwrap().response, p::ResponseBody::Operation(_)));
            let outcome = host.shutdown().await.unwrap(); assert!(outcome.workers_joined >= 4);
            assert!(!f.app.join(DIRECTORY).join(SOCKET).exists());
            service.stop().unwrap(); store.close().unwrap();
        });
    }
    #[test]
    fn stalled_client_and_disconnect_do_not_block_other_client_or_shutdown() {
        runtime().block_on(async {
            let f = Fixture::short(); let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap()); let service = Arc::new(ApplicationService::open(store.clone()).unwrap());
            let (id, _) = register_fixture(&service, &f.app, "project", "project-1"); service.allow_agent_read(vec![id], Duration::from_secs(30)).unwrap();
            let mut host = start(service.clone()).await.unwrap();
            let stalled = UnixStream::connect(f.app.join(DIRECTORY).join(SOCKET)).await.unwrap();
            let disconnected = UnixStream::connect(f.app.join(DIRECTORY).join(SOCKET)).await.unwrap(); close_stream(disconnected).unwrap();
            assert!(timeout(Duration::from_secs(2), request(&f.app, &list())).await.unwrap().is_ok());
            // Cancel only this waiting observer after it has requested STOP.
            // The same real accept task and worker joins stay in ServerHandle.
            let mut waiting = Box::pin(host.shutdown());
            std::future::poll_fn(|cx| {
                assert!(waiting.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            }).await;
            drop(waiting);
            assert!(host.task.is_some() && host.outcome.is_none());
            let outcome = timeout(Duration::from_secs(2), host.shutdown()).await.unwrap().unwrap(); assert!(outcome.workers_joined >= 2);
            assert!(host.task.is_none());
            assert_eq!(host.shutdown().await.unwrap().workers_joined, outcome.workers_joined);
            assert!(!f.app.join(DIRECTORY).join(SOCKET).exists());
            assert!(!f.app.join(DIRECTORY).join(DESCRIPTOR).exists());
            close_stream(stalled).unwrap(); service.stop().unwrap(); store.close().unwrap();
        });
    }
    #[test]
    fn private_capability_wrong_instance_and_revoked_access_are_rejected() {
        runtime().block_on(async {
            let f = Fixture::short(); let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap()); let service = Arc::new(ApplicationService::open(store.clone()).unwrap());
            let (id, root) = register_fixture(&service, &f.app, "project", "project-1");
            service.publish_passive_snapshot("project-1", &passive(&root, &"1".repeat(64))).unwrap();
            service.allow_agent_read(vec![id.clone()], Duration::from_secs(30)).unwrap();
            let first_instance = service.instance().clone();
            let mut host = start(service.clone()).await.unwrap();
            let raw = Zeroizing::new(std::fs::read(f.app.join(DIRECTORY).join(DESCRIPTOR)).unwrap());
            for byte in [8usize, 40usize] {
                let mut bad = Zeroizing::new(raw.to_vec()); bad[byte] ^= 1;
                let mut stream = UnixStream::connect(f.app.join(DIRECTORY).join(SOCKET)).await.unwrap();
                stream.write_all(&bad).await.unwrap(); let mut answer = [0u8; 1]; stream.read_exact(&mut answer).await.unwrap();
                assert_eq!(answer, *b"D"); close_stream(stream).unwrap();
            }
            service.revoke_agent_read().unwrap(); assert_eq!(request(&f.app, &list()).await.err(), Some(Error::AccessDenied));
            host.shutdown().await.unwrap(); service.stop().unwrap(); store.close().unwrap();
            assert_eq!(request(&f.app, &list()).await.err(), Some(Error::Unavailable));
            drop((host, service, store));

            // Reopen only this fixture's persisted reference state, not a
            // Desktop/native operation. No alias or permission is restored.
            let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
            let service = Arc::new(ApplicationService::open(store.clone()).unwrap());
            assert_ne!(service.instance(), &first_instance);
            assert!(!service.read_access_status().unwrap().enabled);
            assert!(service.native_binding("project-1").is_err());
            let mut host = start(service.clone()).await.unwrap();
            let fresh = Zeroizing::new(std::fs::read(f.app.join(DIRECTORY).join(DESCRIPTOR)).unwrap());
            // Never include capability bytes in an assertion's diagnostics.
            assert!(raw[40..] != fresh[40..], "launch capability must rotate");
            let mut old_client = UnixStream::connect(f.app.join(DIRECTORY).join(SOCKET)).await.unwrap();
            old_client.write_all(&raw).await.unwrap();
            let mut answer = [0u8; 1]; old_client.read_exact(&mut answer).await.unwrap();
            assert_eq!(answer, *b"D"); close_stream(old_client).unwrap();
            assert_eq!(request(&f.app, &list()).await.err(), Some(Error::AccessDenied));

            let held_root = std::fs::File::open(&root).unwrap();
            let metadata = held_root.metadata().unwrap();
            let restored = service.register_native("project-7", &root, metadata.dev(), metadata.ino()).unwrap();
            nix::unistd::close(held_root).unwrap();
            assert_eq!(restored.project_id, id);
            service.allow_agent_read(vec![id.clone()], Duration::from_secs(30)).unwrap();
            match request(&f.app, &list()).await.unwrap().response {
                p::ResponseBody::Projects(rows) => {
                    assert_eq!(rows.len(), 1);
                    assert_eq!(rows[0].project_id, id);
                    assert!(rows[0].observation.as_ref().unwrap().stale);
                }
                _ => panic!("wrong response"),
            }
            host.shutdown().await.unwrap(); service.stop().unwrap(); store.close().unwrap();
        });
    }
    #[test]
    fn replaced_endpoint_is_retained_and_state_cannot_close_before_join() {
        runtime().block_on(async {
            let f = Fixture::short(); let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap()); let service = Arc::new(ApplicationService::open(store.clone()).unwrap());
            let (id, _) = register_fixture(&service, &f.app, "project", "project-1"); service.allow_agent_read(vec![id], Duration::from_secs(30)).unwrap();
            let mut host = start(service.clone()).await.unwrap();
            assert_eq!(store.close().err().unwrap().code, Error::Busy);
            let socket = f.app.join(DIRECTORY).join(SOCKET);
            std::fs::rename(&socket, socket.with_extension("original")).unwrap();
            std::fs::write(&socket, b"foreign fixture").unwrap();
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(request(&f.app, &list()).await.err(), Some(Error::Conflict));
            assert!(host.shutdown().await.is_err());
            assert_eq!(std::fs::read(&socket).unwrap(), b"foreign fixture");
            // Actual socket/task finality is separate from this named conflict.
            // The original joined host permits close, not replacement deletion.
            service.stop().unwrap(); store.close().unwrap();
        });
    }
    #[test]
    fn stale_descriptor_and_symlink_are_not_an_auto_cleanup_authority() {
        runtime().block_on(async {
            let f = Fixture::short(); let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap()); let service = Arc::new(ApplicationService::open(store.clone()).unwrap());
            let target = f.app.join("not-a-capability"); std::fs::write(&target, b"fixture").unwrap();
            symlink(&target, f.app.join(DIRECTORY).join(DESCRIPTOR)).unwrap();
            assert_eq!(start(service.clone()).await.err().map(|e| e), Some(Error::RecoveryRequired));
            assert!(f.app.join(DIRECTORY).join(DESCRIPTOR).is_symlink());
            service.stop().unwrap(); store.close().unwrap();
        });
    }
    #[test]
    fn client_handshake_timeout_closes_original_and_preserves_unknown_close() {
        runtime().block_on(async {
            for unknown in [false, true] {
                let f = Fixture::short(); let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
                let service = Arc::new(ApplicationService::open(store.clone()).unwrap());
                store.begin_endpoint().unwrap();
                let (listener, endpoint) = bind(&service).unwrap();
                CLIENT_CLOSE_UNKNOWN.with(|cut| cut.set(unknown));
                let query = list();
                let client = request_until(&f.app, &query, Instant::now() + Duration::from_millis(40));
                let peer = async {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut handshake = Zeroizing::new([0u8; HANDSHAKE]);
                    stream.read_exact(handshake.as_mut()).await.unwrap();
                    // Deliberately never reply to the client's handshake.
                    let mut byte = [0u8; 1];
                    let read = timeout(Duration::from_secs(1), stream.read(&mut byte)).await;
                    let closed = close_stream(stream);
                    assert_eq!(read.unwrap().unwrap(), 0); closed.unwrap();
                };
                let (result, ()) = tokio::join!(client, peer);
                assert_eq!(result.err(), Some(if unknown { Error::StateUnknown } else { Error::Unavailable }));
                nix::unistd::close(listener.into_std().unwrap()).unwrap();
                endpoint.remove(&service).unwrap(); store.endpoint_settled(true).unwrap();
                service.stop().unwrap(); store.close().unwrap();
            }
        });
    }
    #[test]
    fn poisoned_revoke_still_stops_and_joins_original_workers_once() {
        runtime().block_on(async {
            let f = Fixture::short(); let store = Arc::new(PrivateStateDirectory::open(&f.app).unwrap());
            let service = Arc::new(ApplicationService::open(store.clone()).unwrap());
            let (id, _) = register_fixture(&service, &f.app, "project", "project-1");
            service.allow_agent_read(vec![id], Duration::from_secs(30)).unwrap();
            let mut host = start(service.clone()).await.unwrap();
            let capability = Zeroizing::new(std::fs::read(f.app.join(DIRECTORY).join(DESCRIPTOR)).unwrap());
            let mut client = UnixStream::connect(f.app.join(DIRECTORY).join(SOCKET)).await.unwrap();
            client.write_all(&capability).await.unwrap();
            let mut accepted = [0u8; 33]; client.read_exact(&mut accepted).await.unwrap();
            assert_eq!(accepted[0], b'A');
            poison_fixture(&service);
            assert_eq!(timeout(Duration::from_secs(1), host.shutdown()).await.unwrap().err(), Some(Error::StateUnknown));
            assert!(host.task.is_none());
            assert_eq!(host.shutdown().await.err(), Some(Error::StateUnknown));
            let mut byte = [0u8; 1]; assert_eq!(client.read(&mut byte).await.unwrap(), 0);
            close_stream(client).unwrap();
            assert!(!f.app.join(DIRECTORY).join(SOCKET).exists());
            assert!(!f.app.join(DIRECTORY).join(DESCRIPTOR).exists());
            store.close().unwrap();
        });
    }
}
