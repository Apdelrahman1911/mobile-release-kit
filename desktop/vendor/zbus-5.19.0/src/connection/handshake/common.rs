use tracing::{instrument, trace};

use super::{AuthMechanism, BoxedSplit, Command};
use crate::{Error, Result};

// Common code for the client and server side of the handshake.
#[derive(Debug)]
pub(super) struct Common {
    socket: BoxedSplit,
    recv_buffer: Vec<u8>,
    #[cfg(unix)]
    received_fds: Vec<std::os::fd::OwnedFd>,
    cap_unix_fd: bool,
    mechanism: AuthMechanism,
    first_command: bool,
}

impl Common {
    /// Start a handshake on this client socket
    pub fn new(socket: BoxedSplit, mechanism: AuthMechanism) -> Self {
        Self {
            socket,
            recv_buffer: Vec::new(),
            #[cfg(unix)]
            received_fds: Vec::new(),
            cap_unix_fd: false,
            mechanism,
            first_command: true,
        }
    }

    #[cfg(all(unix, feature = "p2p"))]
    pub fn socket(&self) -> &BoxedSplit {
        &self.socket
    }

    pub fn socket_mut(&mut self) -> &mut BoxedSplit {
        &mut self.socket
    }

    pub fn set_cap_unix_fd(&mut self, cap_unix_fd: bool) {
        self.cap_unix_fd = cap_unix_fd;
    }

    pub fn mechanism(&self) -> AuthMechanism {
        self.mechanism
    }

    pub fn is_keyring_wire(&self) -> bool { self.socket.read().is_keyring_wire() }

    pub fn into_components(self) -> IntoComponentsReturn {
        (
            self.socket,
            self.recv_buffer,
            #[cfg(unix)]
            self.received_fds,
            self.cap_unix_fd,
            self.mechanism,
        )
    }

    pub async fn write_command(&mut self, command: Command) -> Result<()> {
        if self.is_keyring_wire() {
            return self.write_keyring_commands(&[command], None).await;
        }
        self.write_command_legacy(command).await
    }

    #[instrument(name = "write_command", skip(self))]
    async fn write_command_legacy(&mut self, command: Command) -> Result<()> {
        self.write_commands(&[command], None).await
    }

    pub async fn write_commands(
        &mut self,
        commands: &[Command],
        extra_bytes: Option<&[u8]>,
    ) -> Result<()> {
        if self.is_keyring_wire() { return self.write_keyring_commands(commands, extra_bytes).await; }
        self.write_commands_legacy(commands, extra_bytes).await
    }

    #[instrument(name = "write_commands", skip(self))]
    async fn write_commands_legacy(
        &mut self, commands: &[Command], extra_bytes: Option<&[u8]>,
    ) -> Result<()> {
        let mut send_buffer =
            commands
                .iter()
                .map(Vec::<u8>::from)
                .fold(vec![], |mut acc, mut c| {
                    if self.first_command {
                        // The first command is sent by the client so we can assume it's the client.
                        self.first_command = false;
                        // leading 0 is sent separately for `freebsd` and `dragonfly`.
                        #[cfg(not(any(target_os = "freebsd", target_os = "dragonfly")))]
                        acc.push(b'\0');
                    }
                    acc.append(&mut c);
                    acc.extend_from_slice(b"\r\n");
                    acc
                });
        if let Some(extra_bytes) = extra_bytes {
            send_buffer.extend_from_slice(extra_bytes);
        }
        while !send_buffer.is_empty() {
            let written = self
                .socket
                .write_mut()
                .sendmsg(
                    &send_buffer,
                    #[cfg(unix)]
                    &[],
                )
                .await?;
            send_buffer.drain(..written);
        }
        trace!("Wrote all commands");
        Ok(())
    }

    pub async fn read_command(&mut self) -> Result<Command> {
        if self.is_keyring_wire() { return self.read_keyring_command().await; }
        self.read_command_legacy().await
    }

    #[instrument(name = "read_command", skip(self))]
    async fn read_command_legacy(&mut self) -> Result<Command> {
        self.read_commands(1)
            .await
            .map(|cmds| cmds.into_iter().next().unwrap())
    }

    pub async fn read_commands(&mut self, n_commands: usize) -> Result<Vec<Command>> {
        if self.is_keyring_wire() {
            if n_commands != 1 { return Err(Error::InvalidField); }
            return self.read_keyring_command().await.map(|command| vec![command]);
        }
        self.read_commands_legacy(n_commands).await
    }

    #[instrument(name = "read_commands", skip(self))]
    async fn read_commands_legacy(&mut self, n_commands: usize) -> Result<Vec<Command>> {
        let mut commands = Vec::with_capacity(n_commands);
        let mut n_received_commands = 0;
        'outer: loop {
            while let Some(lf_index) = self.recv_buffer.iter().position(|b| *b == b'\n') {
                if lf_index == 0 || self.recv_buffer[lf_index - 1] != b'\r' {
                    return Err(Error::Handshake("Invalid line ending in handshake".into()));
                }

                #[allow(unused_mut)]
                let mut start_index = 0;
                if self.first_command {
                    // The first command is sent by the client so we can assume it's the server.
                    self.first_command = false;
                    if self.recv_buffer[0] != b'\0' {
                        return Err(Error::Handshake(
                            "First client byte is not NUL!".to_string(),
                        ));
                    }

                    start_index = 1;
                };

                let line_bytes = self.recv_buffer.drain(..=lf_index);
                let line = std::str::from_utf8(&line_bytes.as_slice()[start_index..])
                    .map_err(|e| Error::Handshake(e.to_string()))?;

                trace!("Reading {line}");
                commands.push(line.parse()?);
                n_received_commands += 1;

                if n_received_commands == n_commands {
                    break 'outer;
                }
            }

            let mut buf = vec![0; 1024];
            let res = self.socket.read_mut().recvmsg(&mut buf).await?;
            let read = {
                #[cfg(unix)]
                {
                    let (read, fds) = res;
                    if !fds.is_empty() {
                        // Most likely belonging to the messages already received.
                        self.received_fds.extend(fds);
                    }
                    read
                }
                #[cfg(not(unix))]
                {
                    res
                }
            };
            if read == 0 {
                return Err(Error::Handshake("Unexpected EOF during handshake".into()));
            }
            self.recv_buffer.extend(&buf[..read]);
        }

        Ok(commands)
    }

    async fn write_keyring_commands(&mut self, commands: &[Command], extra: Option<&[u8]>) -> Result<()> {
        use super::AuthMechanism;
        use crate::keyring_wire::{buffer, SASL_BYTES};
        if commands.len() != 1 { return Err(Error::InvalidField); }
        let mut bytes = buffer(SASL_BYTES, SASL_BYTES)?;
        match (&commands[0], self.first_command) {
            (Command::Auth(Some(AuthMechanism::External), Some(id)), true)
                if !id.is_empty() && id.len() <= 10 && id.iter().all(u8::is_ascii_digit) && extra.is_none() => {
                bytes.extend_from_slice(b"\0AUTH EXTERNAL ");
                const HEX: &[u8; 16] = b"0123456789abcdef";
                for &byte in id { bytes.push(HEX[(byte >> 4) as usize]); bytes.push(HEX[(byte & 15) as usize]); }
                bytes.extend_from_slice(b"\r\n");
            }
            (Command::Begin, false) => bytes.extend_from_slice(b"BEGIN\r\n"),
            _ => return Err(Error::InvalidField),
        }
        if let Some(extra) = extra {
            if extra.len() > SASL_BYTES - bytes.len() { return Err(Error::ExcessData); }
            bytes.extend_from_slice(extra);
        }
        self.first_command = false;
        let mut offset = 0;
        while offset < bytes.len() {
            let original = self.socket.write_mut().sendmsg(&bytes[offset..], #[cfg(unix)] &[]);
            crate::keyring_wire::transport_future_fits(original.as_ref().get_ref())?;
            let count = original.await?;
            if count == 0 || count > bytes.len() - offset { return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into()); }
            offset += count;
        }
        Ok(())
    }

    async fn read_keyring_command(&mut self) -> Result<Command> {
        use crate::keyring_wire::{buffer, SASL_BYTES};
        if self.first_command || self.recv_buffer.len() > SASL_BYTES || self.recv_buffer.capacity() > SASL_BYTES {
            return Err(Error::InvalidField);
        }
        if self.recv_buffer.capacity() == 0 { self.recv_buffer = buffer(SASL_BYTES, SASL_BYTES)?; }
        loop {
            if let Some(lf) = self.recv_buffer.iter().position(|&byte| byte == b'\n') {
                // The fixed EXTERNAL client expects only an OK GUID here. A
                // negative/unrecognized reply is refused without allocating,
                // formatting or logging its peer-supplied private detail.
                if lf == 0 || self.recv_buffer[lf - 1] != b'\r' || lf != 36
                    || &self.recv_buffer[..3] != b"OK "
                    || !self.recv_buffer[3..35].iter().all(u8::is_ascii_hexdigit)
                { return Err(Error::Handshake("keyring authentication refused".into())); }
                let guid = std::str::from_utf8(&self.recv_buffer[3..35]).map_err(|_| Error::InvalidField)?;
                let command = Command::Ok(crate::Guid::try_from(guid)?.into());
                self.recv_buffer.drain(..=lf);
                return Ok(command);
            }
            let remaining = SASL_BYTES - self.recv_buffer.len();
            if remaining == 0 { return Err(Error::ExcessData); }
            let mut scratch = [0u8; 1024];
            let size = remaining.min(scratch.len());
            let original = self.socket.read_mut().recvmsg(&mut scratch[..size]);
            crate::keyring_wire::transport_future_fits(original.as_ref().get_ref())?;
            let received = original.await?;
            #[cfg(unix)]
            let count = {
                if !received.1.is_empty() || received.1.capacity() != 0 { return Err(Error::InvalidField); }
                received.0
            };
            #[cfg(not(unix))]
            let count = received;
            if count == 0 || count > size { return Err(Error::Handshake("keyring authentication ended".into())); }
            self.recv_buffer.extend_from_slice(&scratch[..count]);
        }
    }
}

#[cfg(unix)]
type IntoComponentsReturn = (
    BoxedSplit,
    Vec<u8>,
    Vec<std::os::fd::OwnedFd>,
    bool,
    AuthMechanism,
);
#[cfg(not(unix))]
type IntoComponentsReturn = (BoxedSplit, Vec<u8>, bool, AuthMechanism);

#[cfg(all(unix, feature = "tokio", any(test, feature = "mrk-owned-test-support")))]
pub(super) mod keyring_contract {
    use super::*;
    use crate::{connection::socket::{ReadHalf, Split, WriteHalf}, keyring_wire, Message};
    use std::{io, os::fd::{BorrowedFd, OwnedFd}, sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}}};

    #[derive(Debug)]
    struct Input { bytes: Vec<u8>, position: Arc<AtomicUsize>, fragment: usize }
    #[async_trait::async_trait]
    impl ReadHalf for Input {
        fn is_keyring_wire(&self) -> bool { true }
        async fn recvmsg(&mut self, target: &mut [u8]) -> io::Result<(usize, Vec<OwnedFd>)> {
            let at = self.position.load(Ordering::SeqCst);
            let count = target.len().min(self.fragment).min(self.bytes.len() - at);
            target[..count].copy_from_slice(&self.bytes[at..at + count]);
            self.position.store(at + count, Ordering::SeqCst);
            Ok((count, Vec::new()))
        }
    }
    #[derive(Debug)]
    struct Output(Arc<Mutex<Vec<u8>>>);
    #[async_trait::async_trait]
    impl WriteHalf for Output {
        fn is_keyring_wire(&self) -> bool { true }
        async fn sendmsg(&mut self, bytes: &[u8], fds: &[BorrowedFd<'_>]) -> io::Result<usize> {
            assert!(fds.is_empty());
            let count = bytes.len().min(7);
            self.0.lock().unwrap().extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        async fn close(&mut self) -> io::Result<()> { Ok(()) }
    }
    fn socket(bytes: Vec<u8>, fragment: usize) -> (BoxedSplit, Arc<AtomicUsize>, Arc<Mutex<Vec<u8>>>) {
        let position = Arc::new(AtomicUsize::new(0));
        let output = Arc::new(Mutex::new(Vec::new()));
        let socket = Split::new(
            Box::new(Input { bytes, position: position.clone(), fragment }) as Box<dyn ReadHalf>,
            Box::new(Output(output.clone())) as Box<dyn WriteHalf>,
        );
        (socket, position, output)
    }
    fn run<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(future)
    }
    const OK: &[u8] = b"OK 0123456789abcdef0123456789abcdef\r\n";
    const SENT: &[u8] = b"\0AUTH EXTERNAL 31303030\r\nBEGIN\r\n";

    #[cfg_attr(test, test)]
    pub(crate) fn keyring_authentication_and_hello_use_the_bounded_transport() {
        let request = Message::method_call("/org/freedesktop/DBus", "Hello").unwrap().build(&()).unwrap();
        let reply = Message::method_return(&request.header()).unwrap().keyring_wire(true).build(&":1.7").unwrap();
        for fragment in [1, 1024] {
            let mut input = OK.to_vec(); input.extend_from_slice(reply.data());
            let length = input.len();
            let (socket, position, output) = socket(input, fragment);
            // Supplied synthetic uid avoids even ambient credential lookup.
            let result = run(super::super::Authenticated::client(socket, None, None, true, Some(1000))).unwrap();
            assert_eq!(result.unique_name.as_ref().unwrap().as_str(), ":1.7");
            assert!(!result.cap_unix_fd && result.already_received_fds.is_empty());
            assert!(result.already_received_bytes.capacity() <= keyring_wire::SASL_BYTES);
            assert_eq!(position.load(Ordering::SeqCst), length);
            let output = output.lock().unwrap();
            assert!(output.starts_with(SENT)); // No NEGOTIATE_UNIX_FD or retry.
            keyring_wire::preflight(&output[SENT.len()..]).unwrap();
        }
        // Actual Hello transport, including the complete body boundary. The
        // generic string decoder alone used to ignore its terminator/trailing
        // bytes and allocate an owned name before enforcing the 255-byte cap.
        let body_offset = reply.data().len() - reply.body().len();
        let valid = reply.data().to_vec();
        let mut nonzero_nul = valid.clone(); *nonzero_nul.last_mut().unwrap() = b'X';
        let mut missing_nul = valid.clone(); missing_nul.pop();
        missing_nul[4..8].copy_from_slice(&((reply.body().len() - 1) as u32).to_le_bytes());
        let mut trailing = valid.clone(); trailing.push(0);
        trailing[4..8].copy_from_slice(&((reply.body().len() + 1) as u32).to_le_bytes());
        let mut advertised = valid.clone();
        advertised[body_offset..body_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let wrong_type = Message::method_return(&request.header()).unwrap()
            .keyring_wire(true).build(&7u32).unwrap().data().to_vec();
        for malformed in [nonzero_nul, missing_nul, trailing, advertised, wrong_type] {
            let mut input = OK.to_vec(); input.extend_from_slice(&malformed);
            let (socket, _, _) = socket(input, 3);
            assert!(run(super::super::Authenticated::client(socket, None, None, true, Some(1000))).is_err());
        }
        for length in [255, 256] {
            let name = format!(":x.{}", "a".repeat(length - 3));
            let reply = Message::method_return(&request.header()).unwrap()
                .keyring_wire(true).build(&name).unwrap();
            let mut input = OK.to_vec(); input.extend_from_slice(reply.data());
            let (socket, _, _) = socket(input, 11);
            let result = run(super::super::Authenticated::client(socket, None, None, true, Some(1000)));
            assert_eq!(result.is_ok(), length == 255);
        }
        for invalid in [b"\n".to_vec(), b"REJECTED EXTERNAL\r\n".to_vec(), vec![b'X'; keyring_wire::SASL_BYTES + 1]] {
            let length = invalid.len();
            let (socket, position, output) = socket(invalid, 1024);
            assert!(run(super::super::Authenticated::client(socket, None, None, true, Some(1000))).is_err());
            assert_eq!(position.load(Ordering::SeqCst), length.min(keyring_wire::SASL_BYTES));
            assert_eq!(&*output.lock().unwrap(), b"\0AUTH EXTERNAL 31303030\r\n");
        }
        // Hello must pass the same preallocation refusal as later replies.
        let mut primary = [0u8; 16]; primary[..4].copy_from_slice(&[b'l', 2, 0, 1]);
        primary[4..8].copy_from_slice(&(keyring_wire::FRAME_BYTES as u32).to_le_bytes());
        primary[8..12].copy_from_slice(&1u32.to_le_bytes());
        let mut input = OK.to_vec(); input.extend_from_slice(&primary);
        let (transport, position, _) = socket(input, 1);
        assert!(matches!(run(super::super::Authenticated::client(transport, None, None, true, Some(1000))), Err(Error::ExcessData)));
        assert_eq!(position.load(Ordering::SeqCst), OK.len() + 16);
        // A genuine Error keeps its original bounded frame; it is not logged or
        // rewritten into an invented successful Hello result.
        let error = Message::error(&request.header(), "org.example.Refused").unwrap()
            .keyring_wire(true).build(&"synthetic refusal").unwrap();
        let mut input = OK.to_vec(); input.extend_from_slice(error.data());
        let (socket, _, _) = socket(input, 5);
        let result = run(super::super::Authenticated::client(socket, None, None, true, Some(1000)));
        let Err(Error::MethodError(_, Some(detail), original)) = result else { panic!("expected original Hello error"); };
        assert_eq!(detail, "synthetic refusal");
        assert_eq!(&**original.data(), &**error.data());
    }
}
