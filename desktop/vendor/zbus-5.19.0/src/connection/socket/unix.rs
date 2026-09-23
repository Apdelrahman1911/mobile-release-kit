#[cfg(feature = "async-io")]
use async_io::Async;
#[cfg(target_os = "linux")]
use std::os::unix::io::FromRawFd;
#[cfg(unix)]
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, RawFd};
#[cfg(all(unix, feature = "async-io"))]
use std::os::unix::net::UnixStream;
#[cfg(feature = "async-io")]
use std::sync::Arc;
#[cfg(unix)]
use std::{
    future::poll_fn,
    io::{IoSlice, IoSliceMut},
    os::fd::OwnedFd,
    task::Poll,
};
#[cfg(all(windows, feature = "async-io"))]
use uds_windows::UnixStream;

#[cfg(unix)]
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};

#[cfg(unix)]
use crate::utils::FDS_MAX;

// Only the fixed owned constructor selects these halves, before authentication.
// No wrapper performs peer lookups, creates a task or duplicates a connection.
#[cfg(all(unix, feature = "tokio"))]
pub(crate) fn keyring_split(stream: tokio::net::UnixStream) -> super::BoxedSplit {
    let (read, write) = stream.into_split();
    super::Split::new(Box::new(KeyringRead(read)), Box::new(KeyringWrite(write)))
}

#[cfg(all(unix, feature = "tokio"))]
#[derive(Debug)]
struct KeyringRead(tokio::net::unix::OwnedReadHalf);
#[cfg(all(unix, feature = "tokio"))]
#[derive(Debug)]
struct KeyringWrite(tokio::net::unix::OwnedWriteHalf);

#[cfg(all(unix, feature = "tokio"))]
pub(in crate::connection) const fn keyring_half_layouts() -> (
    crate::keyring_wire::control::TypeLayout, crate::keyring_wire::control::TypeLayout,
) {
    use crate::keyring_wire::control::TypeLayout;
    (TypeLayout::of::<KeyringRead>(), TypeLayout::of::<KeyringWrite>())
}

#[cfg(all(unix, feature = "tokio"))]
#[async_trait::async_trait]
impl super::ReadHalf for KeyringRead {
    fn is_keyring_wire(&self) -> bool { true }
    async fn recvmsg(&mut self, buf: &mut [u8]) -> super::RecvmsgResult {
        let stream = self.0.as_ref();
        poll_fn(|cx| loop {
            match stream.try_io(tokio::io::Interest::READABLE, || fd_recvmsg_keyring(stream.as_fd(), buf)) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {},
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => match stream.poll_read_ready(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result?,
                },
                result => return Poll::Ready(result.map(|count| (count, Vec::new()))),
            }
        }).await
    }
}

#[cfg(all(unix, feature = "tokio"))]
#[async_trait::async_trait]
impl super::WriteHalf for KeyringWrite {
    fn is_keyring_wire(&self) -> bool { true }
    async fn sendmsg(&mut self, buffer: &[u8], fds: &[BorrowedFd<'_>]) -> std::io::Result<usize> {
        if !fds.is_empty() || buffer.len() > crate::keyring_wire::FRAME_BYTES {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        #[cfg(not(target_os = "linux"))]
        { Err(std::io::ErrorKind::Unsupported.into()) }
        #[cfg(target_os = "linux")]
        {
            let stream = self.0.as_ref();
            poll_fn(|cx| loop {
                // This profile cannot send rights. Avoid the legacy FDS_MAX
                // ancillary scratch and its extra async-trait adapter entirely.
                match stream.try_io(tokio::io::Interest::WRITABLE, || {
                    rustix::net::send(stream.as_fd(), buffer, SendFlags::NOSIGNAL).map_err(Into::into)
                }) {
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {},
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => match stream.poll_write_ready(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(result) => result?,
                    },
                    Ok(0) => return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into())),
                    result => return Poll::Ready(result),
                }
            }).await
        }
    }
    async fn close(&mut self) -> std::io::Result<()> {
        let original = super::WriteHalf::close(&mut self.0);
        crate::keyring_wire::transport_future_fits(original.as_ref().get_ref())?;
        original.await
    }
}

#[cfg(all(unix, feature = "tokio"))]
fn fd_recvmsg_keyring(fd: BorrowedFd<'_>, buffer: &mut [u8]) -> std::io::Result<usize> {
    #[cfg(not(target_os = "linux"))]
    {
        // The closed constructor is Linux-only. Do not infer other kernels'
        // ancillary-disposal semantics from the Linux qualification.
        let _ = (fd, buffer);
        Err(std::io::ErrorKind::Unsupported.into())
    }
    #[cfg(target_os = "linux")]
    {
        let mut iov = [IoSliceMut::new(buffer)];
        // Zero capacity is deliberate: no ancillary message, known or unknown
        // to rustix's iterator, can be silently admitted. Linux reports CTRUNC
        // for control that cannot fit and closes every undisclosed right. No
        // received FD is installed, collected or left for an error-path drain.
        let mut ancillary = RecvAncillaryBuffer::new(&mut []);
        let message = recvmsg(fd, &mut iov, &mut ancillary, RecvFlags::CMSG_CLOEXEC)?;
        if message.flags.contains(rustix::net::ReturnFlags::CTRUNC) {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        if message.bytes == 0 { return Err(std::io::ErrorKind::UnexpectedEof.into()); }
        Ok(message.bytes)
    }
}

#[cfg(all(target_os = "linux", feature = "tokio", any(test, feature = "mrk-owned-test-support")))]
pub(crate) mod keyring_tests {
    use super::*;
    use std::{io::Read, mem::MaybeUninit, os::unix::net::UnixStream};

    // Native, credential-free, unnamed socket pairs only. Run separately from
    // DATA selectors in the reviewed private Unix execution environment.
    #[cfg_attr(test, test)]
    #[cfg_attr(test, ignore = "requires the admitted private Linux Unix-socket fixture")]
    pub(crate) fn keyring_zero_control_refuses_and_disposes_original_rights() {
        for count in [1, 17] {
            let (receive, send) = UnixStream::pair().unwrap();
            receive.set_nonblocking(true).unwrap();
            let (mut witness, right) = UnixStream::pair().unwrap();
            witness.set_nonblocking(true).unwrap();
            {
                let rights = [right.as_fd(); 17];
                let mut scratch = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(17))];
                let mut ancillary = SendAncillaryBuffer::new(&mut scratch);
                assert!(ancillary.push(SendAncillaryMessage::ScmRights(&rights[..count])));
                assert_eq!(sendmsg(&send, &[IoSlice::new(b"x")], &mut ancillary, SendFlags::NOSIGNAL).unwrap(), 1);
            }
            drop(right);
            // The original queued right(s), not a process-wide FD count, prove
            // both retention before recv and disposal by this exact refusal.
            assert_eq!(witness.read(&mut [0u8; 1]).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
            assert_eq!(fd_recvmsg_keyring(receive.as_fd(), &mut [0u8; 1]).unwrap_err().kind(), std::io::ErrorKind::InvalidData);
            assert_eq!(witness.read(&mut [0u8; 1]).unwrap(), 0);
        }
        let (receive, send) = UnixStream::pair().unwrap();
        receive.set_nonblocking(true).unwrap();
        assert_eq!(rustix::net::send(&send, b"ok", SendFlags::NOSIGNAL).unwrap(), 2);
        let mut bytes = [0u8; 2];
        assert_eq!(fd_recvmsg_keyring(receive.as_fd(), &mut bytes).unwrap(), 2);
        assert_eq!(&bytes, b"ok");
        // Also refuse a control message other than rights, regardless of which
        // ancillary kinds rustix's typed iterator knows how to expose.
        rustix::net::sockopt::set_socket_passcred(&receive, true).unwrap();
        assert_eq!(rustix::net::send(&send, b"c", SendFlags::NOSIGNAL).unwrap(), 1);
        assert_eq!(fd_recvmsg_keyring(receive.as_fd(), &mut bytes).unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }
}

#[cfg(all(unix, feature = "async-io"))]
#[async_trait::async_trait]
impl super::ReadHalf for Arc<Async<UnixStream>> {
    async fn recvmsg(&mut self, buf: &mut [u8]) -> super::RecvmsgResult {
        poll_fn(|cx| {
            let (len, fds) = loop {
                match fd_recvmsg(self.as_fd(), buf) {
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        match self.poll_readable(cx) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(res) => res?,
                        }
                    }
                    v => break v?,
                }
            };
            Poll::Ready(Ok((len, fds)))
        })
        .await
    }

    /// Supports passing file descriptors.
    fn can_pass_unix_fd(&self) -> bool {
        true
    }

    async fn peer_credentials(&mut self) -> std::io::Result<crate::fdo::ConnectionCredentials> {
        get_unix_peer_creds(self).await
    }
}

#[cfg(all(unix, feature = "async-io"))]
#[async_trait::async_trait]
impl super::WriteHalf for Arc<Async<UnixStream>> {
    async fn sendmsg(
        &mut self,
        buffer: &[u8],
        #[cfg(unix)] fds: &[BorrowedFd<'_>],
    ) -> std::io::Result<usize> {
        poll_fn(|cx| {
            loop {
                match fd_sendmsg(
                    self.as_fd(),
                    buffer,
                    #[cfg(unix)]
                    fds,
                ) {
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        match self.poll_writable(cx) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(res) => res?,
                        }
                    }
                    v => return Poll::Ready(v),
                }
            }
        })
        .await
    }

    async fn close(&mut self) -> std::io::Result<()> {
        let stream = self.clone();
        crate::Task::spawn_blocking(
            move || stream.get_ref().shutdown(std::net::Shutdown::Both),
            "close socket",
        )
        .await?
    }

    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    async fn send_zero_byte(&mut self) -> std::io::Result<Option<usize>> {
        send_zero_byte(self).await.map(Some)
    }

    /// Supports passing file descriptors.
    fn can_pass_unix_fd(&self) -> bool {
        true
    }

    async fn peer_credentials(&mut self) -> std::io::Result<crate::fdo::ConnectionCredentials> {
        super::ReadHalf::peer_credentials(self).await
    }
}

#[cfg(all(unix, feature = "tokio"))]
impl super::Socket for tokio::net::UnixStream {
    type ReadHalf = tokio::net::unix::OwnedReadHalf;
    type WriteHalf = tokio::net::unix::OwnedWriteHalf;

    fn split(self) -> super::Split<Self::ReadHalf, Self::WriteHalf> {
        let (read, write) = self.into_split();

        super::Split { read, write }
    }
}

#[cfg(all(unix, feature = "tokio"))]
#[async_trait::async_trait]
impl super::ReadHalf for tokio::net::unix::OwnedReadHalf {
    async fn recvmsg(&mut self, buf: &mut [u8]) -> super::RecvmsgResult {
        let stream = self.as_ref();
        poll_fn(|cx| {
            loop {
                match stream.try_io(tokio::io::Interest::READABLE, || {
                    // We use own custom function for reading because we need to receive file
                    // descriptors too.
                    fd_recvmsg(stream.as_fd(), buf)
                }) {
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        match stream.poll_read_ready(cx) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(res) => res?,
                        }
                    }
                    v => return Poll::Ready(v),
                }
            }
        })
        .await
    }

    /// Supports passing file descriptors.
    fn can_pass_unix_fd(&self) -> bool {
        true
    }

    async fn peer_credentials(&mut self) -> std::io::Result<crate::fdo::ConnectionCredentials> {
        get_unix_peer_creds(self.as_ref()).await
    }
}

#[cfg(all(unix, feature = "tokio"))]
#[async_trait::async_trait]
impl super::WriteHalf for tokio::net::unix::OwnedWriteHalf {
    async fn sendmsg(
        &mut self,
        buffer: &[u8],
        #[cfg(unix)] fds: &[BorrowedFd<'_>],
    ) -> std::io::Result<usize> {
        let stream = self.as_ref();
        poll_fn(|cx| {
            loop {
                match stream.try_io(tokio::io::Interest::WRITABLE, || {
                    fd_sendmsg(
                        stream.as_fd(),
                        buffer,
                        #[cfg(unix)]
                        fds,
                    )
                }) {
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        match stream.poll_write_ready(cx) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(res) => res?,
                        }
                    }
                    v => return Poll::Ready(v),
                }
            }
        })
        .await
    }

    async fn close(&mut self) -> std::io::Result<()> {
        tokio::io::AsyncWriteExt::shutdown(self).await
    }

    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    async fn send_zero_byte(&mut self) -> std::io::Result<Option<usize>> {
        send_zero_byte(self.as_ref()).await.map(Some)
    }

    /// Supports passing file descriptors.
    fn can_pass_unix_fd(&self) -> bool {
        true
    }

    async fn peer_credentials(&mut self) -> std::io::Result<crate::fdo::ConnectionCredentials> {
        get_unix_peer_creds(self.as_ref()).await
    }
}

#[cfg(all(windows, feature = "async-io"))]
#[async_trait::async_trait]
impl super::ReadHalf for Arc<Async<UnixStream>> {
    async fn recvmsg(&mut self, buf: &mut [u8]) -> super::RecvmsgResult {
        match futures_lite::AsyncReadExt::read(&mut self.as_ref(), buf).await {
            Err(e) => Err(e),
            Ok(len) => {
                #[cfg(unix)]
                let ret = (len, vec![]);
                #[cfg(not(unix))]
                let ret = len;
                Ok(ret)
            }
        }
    }

    async fn peer_credentials(&mut self) -> std::io::Result<crate::fdo::ConnectionCredentials> {
        let stream = self.clone();
        crate::Task::spawn_blocking(
            move || {
                use crate::win32::{ProcessToken, unix_stream_get_peer_pid};

                let pid = unix_stream_get_peer_pid(stream.get_ref())? as _;
                let sid = ProcessToken::open(if pid != 0 { Some(pid as _) } else { None })
                    .and_then(|process_token| process_token.sid())?;
                Ok(crate::fdo::ConnectionCredentials::default()
                    .set_process_id(pid)
                    .set_windows_sid(sid))
            },
            "peer credentials",
        )
        .await?
    }
}

#[cfg(all(windows, feature = "async-io"))]
#[async_trait::async_trait]
impl super::WriteHalf for Arc<Async<UnixStream>> {
    async fn sendmsg(
        &mut self,
        buf: &[u8],
        #[cfg(unix)] _fds: &[BorrowedFd<'_>],
    ) -> std::io::Result<usize> {
        futures_lite::AsyncWriteExt::write(&mut self.as_ref(), buf).await
    }

    async fn close(&mut self) -> std::io::Result<()> {
        let stream = self.clone();
        crate::Task::spawn_blocking(
            move || stream.get_ref().shutdown(std::net::Shutdown::Both),
            "close socket",
        )
        .await?
    }

    async fn peer_credentials(&mut self) -> std::io::Result<crate::fdo::ConnectionCredentials> {
        super::ReadHalf::peer_credentials(self).await
    }
}

#[cfg(unix)]
fn fd_recvmsg(fd: BorrowedFd<'_>, buffer: &mut [u8]) -> std::io::Result<(usize, Vec<OwnedFd>)> {
    use std::mem::MaybeUninit;

    let mut iov = [IoSliceMut::new(buffer)];
    let mut cmsg_buffer = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(FDS_MAX))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut cmsg_buffer);

    let msg = recvmsg(fd, &mut iov, &mut ancillary, RecvFlags::empty())?;
    if msg.bytes == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "failed to read from socket",
        ));
    }
    let mut fds = vec![];
    for msg in ancillary.drain() {
        match msg {
            RecvAncillaryMessage::ScmRights(iter) => {
                fds.extend(iter);
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            RecvAncillaryMessage::ScmCredentials(_) => {
                // On Linux, credentials might be received. This shouldn't normally happen
                // in our use case since we don't request them, but ignore if present.
                continue;
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unexpected CMSG kind",
                ));
            }
        }
    }
    Ok((msg.bytes, fds))
}

#[cfg(unix)]
fn fd_sendmsg(fd: BorrowedFd<'_>, buffer: &[u8], fds: &[BorrowedFd<'_>]) -> std::io::Result<usize> {
    use std::mem::MaybeUninit;

    let iov = [IoSlice::new(buffer)];
    let mut cmsg_buffer = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(FDS_MAX))];
    let mut ancillary = SendAncillaryBuffer::new(&mut cmsg_buffer);

    if !fds.is_empty() && !ancillary.push(SendAncillaryMessage::ScmRights(fds)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "too many file descriptors",
        ));
    }

    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
        target_os = "redox"
    )))]
    let flags = SendFlags::NOSIGNAL;
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
        target_os = "redox"
    ))]
    let flags = SendFlags::empty();

    let sent = sendmsg(fd, &iov, &mut ancillary, flags)?;
    if sent == 0 {
        // can it really happen?
        return Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "failed to write to buffer",
        ));
    }

    Ok(sent)
}

#[cfg(unix)]
async fn get_unix_peer_creds(fd: &impl AsFd) -> std::io::Result<crate::fdo::ConnectionCredentials> {
    let fd = fd.as_fd().as_raw_fd();
    // FIXME: Is it likely enough for sending of 1 byte to block, to justify a task (possibly
    // launching a thread in turn)?
    crate::Task::spawn_blocking(move || get_unix_peer_creds_blocking(fd), "peer credentials")
        .await?
}

#[cfg(unix)]
fn get_unix_peer_creds_blocking(fd: RawFd) -> std::io::Result<crate::fdo::ConnectionCredentials> {
    // TODO: get this BorrowedFd directly from get_unix_peer_creds(), but this requires a
    // 'static lifetime due to the Task.
    let fd = unsafe { BorrowedFd::borrow_raw(fd) };
    let mut creds = crate::fdo::ConnectionCredentials::default();

    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        use rustix::net::sockopt::socket_peercred;
        use tracing::debug;

        let ucred = socket_peercred(fd)?;
        let uid = ucred.uid.as_raw();
        let gid = ucred.gid.as_raw();
        let pid = ucred.pid.as_raw_nonzero().get() as u32;

        creds = creds.set_unix_user_id(uid).set_process_id(pid);

        // The dbus spec requires groups to be either absent or complete (primary +
        // secondary groups).

        // FIXME: rustix does not and [will not] provide `getpwuid_r` and `getgrouplist` so we're
        // left with no choice but to use libc directly. We could consider using `sysinfo` crate
        // though.
        //
        // [will not]: https://docs.rs/rustix/latest/rustix/not_implemented/higher_level/index.html
        let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 16384];
        let mut result: *mut libc::passwd = std::ptr::null_mut();

        unsafe {
            libc::getpwuid_r(
                uid,
                &mut passwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            );
        }

        if !result.is_null() {
            let username = unsafe { std::ffi::CStr::from_ptr((*result).pw_name) };

            // Get supplementary groups.
            let mut ngroups = 64i32;
            let mut groups = vec![0u32; ngroups as usize];

            unsafe {
                if libc::getgrouplist(
                    username.as_ptr(),
                    gid,
                    groups.as_mut_ptr() as *mut libc::gid_t,
                    &mut ngroups,
                ) >= 0
                {
                    groups.truncate(ngroups as usize);
                    // The spec also requires the groups to be numerically sorted.
                    groups.sort();
                    for group in groups {
                        creds = creds.add_unix_group_id(group);
                    }
                } else {
                    debug!("Group lookup failed for user {:?}", username);
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            // FIXME: Replace with rustix API when it provides SO_PEERPIDFD sockopt:
            // https://github.com/bytecodealliance/rustix/pull/1474
            use libc::{c_int, socklen_t};
            use std::mem::{MaybeUninit, size_of};

            let mut pidfd = MaybeUninit::<c_int>::zeroed();
            let mut len = size_of::<c_int>() as socklen_t;

            let ret = unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERPIDFD,
                    pidfd.as_mut_ptr().cast(),
                    &mut len,
                )
            };

            if ret == 0 {
                let pidfd = unsafe { pidfd.assume_init() };
                creds = creds
                    .set_process_fd(unsafe { std::os::fd::OwnedFd::from_raw_fd(pidfd).into() });
            } else if ret < 0 {
                let err = std::io::Error::last_os_error();
                // ENOPROTOOPT means the kernel doesn't support this feature.
                if err.raw_os_error() != Some(libc::ENOPROTOOPT) {
                    return Err(err);
                }
            }
        }
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        // FIXME: Replace with rustix API when it provides the require API:
        // https://github.com/bytecodealliance/rustix/issues/1533
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;

        let ret = unsafe { libc::getpeereid(fd.as_raw_fd(), &mut uid, &mut gid) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }

        creds = creds.set_unix_user_id(uid);

        // FIXME: Handle pid fetching too
    }

    Ok(creds)
}

// Send 0 byte as a separate SCM_CREDS message.
#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
async fn send_zero_byte(fd: &impl AsFd) -> std::io::Result<usize> {
    let fd = fd.as_fd().as_raw_fd();
    crate::Task::spawn_blocking(move || send_zero_byte_blocking(fd), "send zero byte").await?
}

#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
fn send_zero_byte_blocking(fd: RawFd) -> std::io::Result<usize> {
    // FIXME: Replace with rustix API when it provides SCM_CREDS support for BSD.
    // For now, use libc directly since rustix doesn't support sending SCM_CREDS on BSD.
    use std::mem::MaybeUninit;

    let mut iov = libc::iovec {
        iov_base: c"".as_ptr() as *mut libc::c_void,
        iov_len: 1,
    };

    let mut msg: libc::msghdr = unsafe { MaybeUninit::zeroed().assume_init() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;

    // SCM_CREDS on BSD doesn't actually send data in the control message.
    // Instead, it tells the kernel to attach credentials when receiving.
    // We just need to allocate space for the cmsg header with no data.
    let cmsg_space = unsafe { libc::CMSG_SPACE(0) as usize };
    let mut cmsg_buf = vec![0u8; cmsg_space];

    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if !cmsg.is_null() {
        unsafe {
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_CREDS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(0) as _;
        }
    }

    let ret = unsafe { libc::sendmsg(fd, &msg, 0) };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}
