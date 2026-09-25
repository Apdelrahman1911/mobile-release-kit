//! Closed wire limits for the owned keyring client, not the general D-Bus API.
//!
//! The caller's one-MiB reservation additionally requires its fixed one-reader,
//! one-queue, one-RPC/raw-result topology. No arbitrary Message may escape that
//! application owner. These limits do not authenticate the peer or the provider.

use std::io::{self, Cursor, Seek, SeekFrom, Write};

use crate::{Error, Result};

#[cfg(all(unix, feature = "tokio"))]
pub(crate) mod control;

pub(crate) const SASL_BYTES: usize = 4096;
pub(crate) const HEADER_BYTES: usize = 4096;
pub(crate) const FRAME_BYTES: usize = 64 * 1024;
pub(crate) const ATTEMPT_BYTES: usize = 1024 * 1024;
pub(crate) const FUTURE_BYTES: usize = 8 * 1024;
pub(crate) const TRANSPORT_FUTURE_BYTES: usize = 1024;
const HEADER_SLOT_BYTES: usize = 16 * 1024;
const SIGNATURE_BYTES: usize = 255;
const SIGNATURE_NODES: usize = 32;
const SIGNATURE_DEPTH: usize = 16;

/// No geometric growth: callers may only fill this already-reserved capacity.
pub(crate) fn buffer(size: usize, limit: usize) -> Result<Vec<u8>> {
    if size > limit { return Err(Error::ExcessData); }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|_| Error::ExcessData)?;
    if bytes.capacity() > limit { return Err(Error::ExcessData); }
    Ok(bytes)
}

pub(crate) fn future_fits<T: ?Sized>(future: &T) -> Result<()> {
    if std::mem::size_of_val(future) > FUTURE_BYTES || std::mem::align_of_val(future) > 128 {
        Err(Error::ExcessData)
    } else { Ok(()) }
}

/// Measure an async-trait future's actual erased pointee, never its Box handle.
/// These finite transport types contain no peer-controlled allocation inline.
/// Each adapter is checked before its first poll, separately from its owner.
pub(crate) fn transport_future_fits<T: ?Sized>(future: &T) -> io::Result<()> {
    if std::mem::size_of_val(future) > TRANSPORT_FUTURE_BYTES || std::mem::align_of_val(future) > 128 {
        Err(io::ErrorKind::InvalidData.into())
    } else { Ok(()) }
}

/// Compact only local errors, before the reader can copy them into its queues
/// and closed state. Keep an actual method error's name, detail and ORIGINAL
/// Message intact: it carries the ordering/provenance needed by reconciliation.
/// Local strings/custom I/O payloads are not logged or retained by this profile.
pub(crate) fn local_error(error: Error) -> Error {
    match error {
        Error::InputOutput(source) => {
            let kind = source.kind();
            let raw = source.raw_os_error();
            drop(source);
            raw.map(io::Error::from_raw_os_error).unwrap_or_else(|| kind.into()).into()
        }
        Error::Handshake(_) => Error::Handshake(String::new()),
        Error::Failure(_) => Error::Failure(String::new()),
        error @ (Error::MethodError(..) | Error::ExcessData | Error::InvalidField
            | Error::IncorrectEndian | Error::InvalidReply | Error::MissingField
            | Error::InvalidGUID | Error::Unsupported | Error::InvalidSerial
            | Error::InvalidMatchRule | Error::InterfaceNotFound | Error::NameTaken
            | Error::MissingParameter(_)) => error,
        _ => Error::InvalidField,
    }
}

/// Ordinary returned-error backing for THIS closed body/transport topology,
/// not arbitrary user serializers, panic hooks, or a process-memory bound.
/// The exact std/dependency source closure is qualified with control's carrier.
#[cfg(all(unix, feature = "tokio"))]
pub(crate) const fn local_error_backing_bytes() -> Option<usize> {
    use control::TypeLayout;
    let io = TypeLayout::of::<io::Error>();
    let string = TypeLayout::of::<String>();
    if io.size != 8 || io.align != 8 || string.size != 24 || string.align != 8
        || std::mem::size_of::<io::ErrorKind>() > 8
        || std::mem::align_of::<io::ErrorKind>() > 8 { return None; }
    let io_arc = match control::arc_allocation_bytes(io) { Some(bytes) => bytes, None => return None };
    // Six conservative retained/returned IO-Arc surfaces: reader, closed_error,
    // pending reply, app raw OR startup failure, currently polled owner result,
    // and shutdown's fail_all argument. Normalized fanout only clones the Arc.
    // Only reader + serialized owner construct opaque returned errors at once.
    // std1.98's Custom is <=40B; StringError is one24B String; Tokio1.48's
    // longest reachable runtime-shutdown literal is56B. The old source payload
    // is consumed before its normalized replacement is allocated.
    // Each256B construction row covers fixed header-name diagnostics <=117B,
    // fixed signature diagnostics, and scalar string decode diagnostics with
    // temporary realloc overlap (<=156B), not arbitrary dynamic decoding.
    // Two36B state-error strings cover poisoned startup + state inspection.
    Some(6 * io_arc + 2 * (40 + string.size + 56) + 2 * 256 + 2 * 36)
}

/// Per-frame header backing, including its fixed heap metadata. The actual
/// Message::Inner includes OnceLock<QuickFields>, the Data handle/context/range,
/// primary header and sequence. Data slices and Message clones share their Arcs.
/// zvariant5.15.0's private serialized::data::Inner has exactly Cow<[u8]> and
/// Vec<Fd> on Unix; the zero-FD profile gives the latter no backing. Its source
/// roster and these actual field layouts bound that otherwise-private pointee.
/// Inline Fields/Header/Value temporaries are also inside the measured futures.
#[cfg(all(unix, feature = "tokio"))]
pub(crate) const fn header_slot_bytes() -> Option<usize> {
    use control::TypeLayout;
    let bytes = TypeLayout::of::<std::borrow::Cow<'static, [u8]>>();
    let fds = TypeLayout::of::<Vec<zvariant::Fd<'static>>>();
    let signature = TypeLayout::of::<zvariant::Signature>();
    if bytes.size != 24 || bytes.align != 8 || fds.size != 24 || fds.align != 8
        || signature.size > 64 || signature.align > 8 { return None; }
    let message = match control::arc_allocation_bytes(TypeLayout::of::<crate::message::Inner>()) {
        Some(value) => value, None => return None,
    };
    let data = match control::arc_allocation_bytes(TypeLayout { size: bytes.size + fds.size, align: 8 }) {
        Some(value) => value, None => return None,
    };
    // <=33 nodes including the implicit argument-list root. Count geometric
    // Vec capacity2x, two complete deep signature/header copies and even two
    // Message/Data metadata pairs. No extra slot spends the reserved headroom.
    let total = 2 * (2 * (SIGNATURE_NODES + 1) * signature.size
        + 2 * SIGNATURE_BYTES + HEADER_BYTES) + 2 * (message + data);
    if total <= HEADER_SLOT_BYTES { Some(total) } else { None }
}

pub(crate) async fn receive<R: crate::connection::socket::ReadHalf + ?Sized>(
    read: &mut R, seq: u64, carry: &mut Vec<u8>,
    #[cfg(unix)] carry_fds: &mut Vec<std::os::fd::OwnedFd>,
) -> Result<crate::Message> {
    if carry.len() > SASL_BYTES || carry.capacity() > SASL_BYTES { return Err(Error::ExcessData); }
    #[cfg(unix)]
    if !carry_fds.is_empty() || carry_fds.capacity() != 0 {
        carry_fds.clear();
        return Err(Error::InvalidField);
    }
    async fn fill<R: crate::connection::socket::ReadHalf + ?Sized>(read: &mut R, bytes: &mut [u8]) -> Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            let original = read.recvmsg(&mut bytes[offset..]);
            transport_future_fits(original.as_ref().get_ref())?;
            let received = original.await?;
            #[cfg(unix)]
            let count = {
                // The real bounded Unix half has already consumed/refused all
                // ancillary rights without creating an FD Vec. Refuse any
                // nonconforming custom half too; never accumulate its rights.
                if !received.1.is_empty() || received.1.capacity() != 0 { return Err(Error::InvalidField); }
                received.0
            };
            #[cfg(not(unix))]
            let count = received;
            if count == 0 || count > bytes.len() - offset {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
            offset += count;
        }
        Ok(())
    }
    let mut primary = [0u8; 16];
    let taken = carry.len().min(primary.len());
    primary[..taken].copy_from_slice(&carry[..taken]);
    carry.drain(..taken);
    fill(read, &mut primary[taken..]).await?;
    let (_, total) = frame_layout(&primary)?;
    // Only now may advertised lengths influence allocation. No append below
    // can grow this Vec; both read buffers are fixed-length slices.
    let mut bytes = buffer(total, FRAME_BYTES)?;
    bytes.resize(total, 0);
    bytes[..16].copy_from_slice(&primary);
    let taken = carry.len().min(total - 16);
    bytes[16..16 + taken].copy_from_slice(&carry[..taken]);
    carry.drain(..taken);
    fill(read, &mut bytes[16 + taken..]).await?;
    preflight(&bytes)?;
    let endian = if primary[0] == b'l' { zvariant::Endian::Little } else { zvariant::Endian::Big };
    let context = zvariant::serialized::Context::new_dbus(endian, 0);
    crate::Message::from_raw_parts(zvariant::serialized::Data::new(bytes, context), seq)
}

fn align(offset: usize, alignment: usize) -> Result<usize> {
    offset.checked_add((alignment - offset % alignment) % alignment).ok_or(Error::ExcessData)
}

fn u32_at(bytes: &[u8], offset: usize, little: bool) -> Result<u32> {
    let end = offset.checked_add(4).ok_or(Error::ExcessData)?;
    let word: [u8; 4] = bytes.get(offset..end).ok_or(Error::InvalidField)?.try_into().unwrap();
    Ok(if little { u32::from_le_bytes(word) } else { u32::from_be_bytes(word) })
}

/// Hello returns exactly one D-Bus string. Check its complete borrowed encoding
/// before asking the generic decoder to create any owned name. The generic
/// decoder alone does not enforce the final NUL or body exhaustion.
pub(crate) fn hello_name(reply: &crate::Message) -> Result<crate::names::OwnedUniqueName> {
    let body = reply.body();
    if body.signature() != &zvariant::Signature::Str { return Err(Error::InvalidReply); }
    let bytes = body.data().bytes();
    let little = reply.data().bytes().first() == Some(&b'l');
    let length = usize::try_from(u32_at(bytes, 0, little)?).map_err(|_| Error::ExcessData)?;
    if length > 255 || length.checked_add(5) != Some(bytes.len())
        || bytes.last() != Some(&0) { return Err(Error::InvalidReply); }
    let raw: &str = body.deserialize()?;
    let name = crate::names::UniqueName::try_from(raw)?;
    Ok(name.into_owned().into())
}

/// This is called with only the fixed 16-byte primary header, BEFORE a frame
/// allocation, including for Hello, errors and unsolicited messages.
pub(crate) fn frame_layout(primary: &[u8]) -> Result<(usize, usize)> {
    if primary.len() < 16 { return Err(Error::InvalidField); }
    let little = match primary[0] { b'l' => true, b'B' => false, _ => return Err(Error::IncorrectEndian) };
    if !(1..=4).contains(&primary[1]) || primary[2] & !7 != 0 || primary[3] != 1
        || u32_at(primary, 8, little)? == 0 { return Err(Error::InvalidField); }
    let fields = usize::try_from(u32_at(primary, 12, little)?).map_err(|_| Error::ExcessData)?;
    let body = usize::try_from(u32_at(primary, 4, little)?).map_err(|_| Error::ExcessData)?;
    if fields > HEADER_BYTES { return Err(Error::ExcessData); }
    let header_end = 16usize.checked_add(fields).ok_or(Error::ExcessData)?;
    let total = align(header_end, 8)?.checked_add(body).ok_or(Error::ExcessData)?;
    if total > FRAME_BYTES { return Err(Error::ExcessData); }
    Ok((header_end, total))
}

/// Borrowed validation before Fields deserializes any generic Value. Only the
/// nine specified scalar header variants can reach that decoder. In particular
/// an array/structure/variant cannot make it allocate a nested Value tree.
pub(crate) fn preflight(bytes: &[u8]) -> Result<()> {
    let (header_end, total) = frame_layout(bytes)?;
    if bytes.len() != total { return Err(Error::InvalidField); }
    let little = bytes[0] == b'l';
    let fields = &bytes[..header_end];
    let mut offset = 16;
    let mut seen = 0u16;
    while offset < header_end {
        let next = align(offset, 8)?;
        if next >= header_end || fields[offset..next].iter().any(|&b| b != 0) {
            return Err(Error::InvalidField);
        }
        offset = next;
        let code = *fields.get(offset).ok_or(Error::InvalidField)?;
        let expected = match code { 1 => b'o', 2 | 3 | 4 | 6 | 7 => b's', 5 | 9 => b'u', 8 => b'g', _ => return Err(Error::InvalidField) };
        if seen & (1 << code) != 0 { return Err(Error::InvalidField); }
        seen |= 1 << code;
        if fields.get(offset + 1..offset + 4) != Some(&[1, expected, 0]) {
            return Err(Error::InvalidField);
        }
        offset += 4;
        if expected == b'u' {
            let value = u32_at(fields, offset, little)?;
            if (code == 5 && value == 0) || (code == 9 && value != 0) { return Err(Error::InvalidField); }
            offset += 4;
        } else {
            let len = if expected == b'g' {
                let len = usize::from(*fields.get(offset).ok_or(Error::InvalidField)?);
                offset += 1;
                len
            } else {
                let len = usize::try_from(u32_at(fields, offset, little)?).map_err(|_| Error::ExcessData)?;
                offset += 4;
                len
            };
            let end = offset.checked_add(len).ok_or(Error::ExcessData)?;
            let value = fields.get(offset..end).ok_or(Error::InvalidField)?;
            if fields.get(end) != Some(&0) || value.contains(&0) { return Err(Error::InvalidField); }
            if expected == b'g' { signature(value)?; }
            else {
                let text = std::str::from_utf8(value).map_err(|_| Error::InvalidField)?;
                // Generic Value's object-path variant is constructed unchecked;
                // QuickFields later assumes validity. Refuse here rather than
                // allowing peer bytes to trigger its reconstruction expect.
                if code == 1 { zvariant::ObjectPath::try_from(text).map_err(|_| Error::InvalidField)?; }
            }
            offset = end + 1;
        }
    }
    if bytes[header_end..align(header_end, 8)?].iter().any(|&b| b != 0) { return Err(Error::InvalidField); }
    Ok(())
}

/// A finite, allocation-free signature grammar. The depth check precedes every
/// recursive descent, including array chains (not just parentheses).
pub(crate) fn signature(bytes: &[u8]) -> Result<()> {
    if bytes.len() > SIGNATURE_BYTES { return Err(Error::ExcessData); }
    fn basic(byte: u8) -> bool { matches!(byte, b'y' | b'b' | b'n' | b'q' | b'i' | b'u' | b'x' | b't' | b'd' | b's' | b'o' | b'g') }
    fn item(bytes: &[u8], at: &mut usize, nodes: &mut usize, depth: usize) -> Result<()> {
        if depth > SIGNATURE_DEPTH || *nodes == SIGNATURE_NODES { return Err(Error::ExcessData); }
        *nodes += 1;
        let byte = *bytes.get(*at).ok_or(Error::InvalidField)?;
        *at += 1;
        if basic(byte) || byte == b'v' { return Ok(()); }
        match byte {
            b'a' if bytes.get(*at) == Some(&b'{') => {
                *at += 1;
                if !bytes.get(*at).copied().is_some_and(basic) { return Err(Error::InvalidField); }
                item(bytes, at, nodes, depth + 1)?;
                item(bytes, at, nodes, depth + 1)?;
                if bytes.get(*at) != Some(&b'}') { return Err(Error::InvalidField); }
                *at += 1;
            }
            b'a' => item(bytes, at, nodes, depth + 1)?,
            b'(' => {
                let start = *at;
                while bytes.get(*at) != Some(&b')') { item(bytes, at, nodes, depth + 1)?; }
                if *at == start { return Err(Error::InvalidField); }
                *at += 1;
            }
            _ => return Err(Error::InvalidField), // Includes FDs and GVariant-only types.
        }
        Ok(())
    }
    let (mut at, mut nodes) = (0, 0);
    while at < bytes.len() { item(bytes, &mut at, &mut nodes, 1)?; }
    Ok(())
}

/// Use the already-parsed signature without first constructing an unbounded
/// String. This private stack writer also limits serializer header copies.
pub(crate) fn checked_signature(value: &zvariant::Signature) -> Result<()> {
    fn shape(value: &zvariant::Signature, depth: usize, nodes: &mut usize) -> Result<()> {
        use zvariant::Signature;
        if depth > SIGNATURE_DEPTH || *nodes == SIGNATURE_NODES { return Err(Error::ExcessData); }
        *nodes += 1;
        match value {
            Signature::Unit if depth != 1 => return Err(Error::InvalidField),
            Signature::Array(child) => shape(child, depth + 1, nodes)?,
            Signature::Dict { key, value } => { shape(key, depth + 1, nodes)?; shape(value, depth + 1, nodes)?; },
            Signature::Structure(fields) => for field in fields.iter() { shape(field, depth + 1, nodes)?; },
            _ => {},
        }
        Ok(())
    }
    let mut nodes = 0;
    if let zvariant::Signature::Structure(fields) = value {
        // The outer Rust tuple is the body argument list, not a wire struct.
        for field in fields.iter() { shape(field, 1, &mut nodes)?; }
    } else { shape(value, 1, &mut nodes)?; }
    struct Text { bytes: [u8; SIGNATURE_BYTES], len: usize }
    impl std::fmt::Write for Text {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            let end = self.len.checked_add(s.len()).ok_or(std::fmt::Error)?;
            let target = self.bytes.get_mut(self.len..end).ok_or(std::fmt::Error)?;
            target.copy_from_slice(s.as_bytes()); self.len = end; Ok(())
        }
    }
    let mut text = Text { bytes: [0; SIGNATURE_BYTES], len: 0 };
    value.write_as_string_no_parens(&mut text).map_err(|_| Error::ExcessData)?;
    signature(&text.bytes[..text.len])
}

/// The legacy writer keeps its existing Vec behavior. The keyring writer owns
/// no growable reference: underestimated serializers can only return an error.
pub(crate) enum MessageWriter<'a> {
    Legacy(Cursor<&'a mut Vec<u8>>),
    Keyring(Cursor<&'a mut [u8]>),
}
impl MessageWriter<'_> {
    pub(crate) fn position(&self) -> u64 {
        match self { Self::Legacy(c) => c.position(), Self::Keyring(c) => c.position() }
    }
}
impl Write for MessageWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self { Self::Legacy(c) => c.write(bytes), Self::Keyring(c) => c.write(bytes) }
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
impl Seek for MessageWriter<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        match self { Self::Legacy(c) => c.seek(position), Self::Keyring(c) => c.seek(position) }
    }
}

#[cfg(all(unix, feature = "tokio", any(test, feature = "mrk-owned-test-support")))]
pub(crate) mod tests {
    use super::*;
    use crate::{Message, connection::socket::ReadHalf};
    use std::os::fd::OwnedFd;

    #[derive(Debug)]
    struct Bytes { bytes: Vec<u8>, position: usize, fragment: usize, max_read: usize }
    #[async_trait::async_trait]
    impl ReadHalf for Bytes {
        fn is_keyring_wire(&self) -> bool { true }
        async fn recvmsg(&mut self, target: &mut [u8]) -> io::Result<(usize, Vec<OwnedFd>)> {
            self.max_read = self.max_read.max(target.len());
            let count = target.len().min(self.fragment).min(self.bytes.len() - self.position);
            target[..count].copy_from_slice(&self.bytes[self.position..self.position + count]);
            self.position += count;
            Ok((count, Vec::new()))
        }
    }
    fn read(bytes: Vec<u8>, fragment: usize) -> Bytes { Bytes { bytes, position: 0, fragment, max_read: 0 } }
    fn run<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(future)
    }

    #[cfg_attr(test, test)]
    pub(crate) fn keyring_fragmented_frames_refuse_before_oversized_allocation() {
        let empty = Message::signal("/", "org.example.Wire", "Changed").unwrap()
            .keyring_wire(true).build(&Vec::<u8>::new()).unwrap();
        let payload = vec![7u8; FRAME_BYTES - empty.data().len()];
        let message = Message::signal("/", "org.example.Wire", "Changed").unwrap()
            .keyring_wire(true).build(&payload).unwrap();
        assert_eq!(message.data().len(), FRAME_BYTES);
        let mut source = read(message.data().to_vec(), 47);
        let mut carry = buffer(SASL_BYTES, SASL_BYTES).unwrap();
        carry.extend_from_slice(&source.bytes[..3]); source.position = 3;
        let received = run(source.receive_message(9, &mut carry, &mut Vec::new())).unwrap();
        assert_eq!(&**received.data(), &**message.data());
        assert!(carry.is_empty() && carry.capacity() <= SASL_BYTES);
        assert_eq!(received.body().deserialize::<Vec<u8>>().unwrap(), payload);

        for kind in 1..=4 { // calls, Hello/replies, errors, unsolicited signals
            for (fields, body) in [(0u32, FRAME_BYTES as u32), (HEADER_BYTES as u32 + 1, 0), (u32::MAX, u32::MAX)] {
                let mut primary = vec![0u8; 16]; primary[..4].copy_from_slice(&[b'l', kind, 0, 1]);
                primary[4..8].copy_from_slice(&body.to_le_bytes()); primary[8..12].copy_from_slice(&1u32.to_le_bytes());
                primary[12..16].copy_from_slice(&fields.to_le_bytes());
                let mut source = read(primary, 3);
                assert!(matches!(run(source.receive_message(0, &mut Vec::new(), &mut Vec::new())), Err(Error::ExcessData)));
                assert_eq!(source.position, 16);
                assert!(source.max_read <= 16); // refusal precedes a frame-sized receive/reserve
            }
        }
        let mut source = read(Vec::new(), 1);
        let mut excess_carry = vec![0u8; SASL_BYTES + 1];
        assert!(run(source.receive_message(0, &mut excess_carry, &mut Vec::new())).is_err());
        assert_eq!(source.max_read, 0);
    }

    fn frame(fields: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; (16 + fields.len() + 7) & !7];
        bytes[..4].copy_from_slice(&[b'l', 4, 0, 1]);
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&(fields.len() as u32).to_le_bytes());
        bytes[16..16 + fields.len()].copy_from_slice(fields); bytes
    }
    #[cfg_attr(test, test)]
    pub(crate) fn keyring_borrowed_header_and_signature_gate() {
        let mut field = vec![8, 1, b'g', 0, 5]; field.extend_from_slice(b"a{sv}\0");
        assert!(preflight(&frame(&field)).is_ok());
        let mut wrong = field.clone(); wrong[2] = b'v';
        assert!(preflight(&frame(&wrong)).is_err()); // no generic nested Value decode
        wrong[0] = 10; assert!(preflight(&frame(&wrong)).is_err());
        let mut duplicate = field.clone(); duplicate.resize(16, 0); duplicate.extend_from_slice(&field);
        assert!(preflight(&frame(&duplicate)).is_err());
        assert!(preflight(&frame(&[9, 1, b'u', 0, 0, 0, 0, 0])).is_ok());
        assert!(preflight(&frame(&[9, 1, b'u', 0, 1, 0, 0, 0])).is_err());
        assert!(preflight(&frame(&[5, 1, b'u', 0, 0, 0, 0, 0])).is_err());
        assert!(preflight(&frame(&[6, 1, b's', 0, 255, 255, 255, 255])).is_err());
        assert!(preflight(&frame(&[1, 1, b'o', 0, 1, 0, 0, 0, b'/', 0])).is_ok());
        assert!(preflight(&frame(&[1, 1, b'o', 0, 1, 0, 0, 0, b'x', 0])).is_err());
        assert!(signature(b"aaaaaaaaaaaaaaas").is_ok());
        assert!(signature(b"aaaaaaaaaaaaaaaas").is_err());
        assert!(signature(&[b's'; 32]).is_ok());
        assert!(signature(&[b's'; 33]).is_err());
        for invalid in [b"a{vs}".as_slice(), b"()", b"a", b"((s)", b"h", b"m", b"s\0"] {
            assert!(signature(invalid).is_err());
        }
        assert!(signature(&[b's'; 256]).is_err());
        assert!(checked_signature(&zvariant::Signature::from_bytes(b"a{sv}").unwrap()).is_ok());
        // Truncated/reordered-endian primary fields cannot cause unchecked size arithmetic.
        assert!(frame_layout(&[0; 15]).is_err());
        let mut big = frame(&[]); big[0] = b'B'; big[8..12].copy_from_slice(&1u32.to_be_bytes());
        assert!(preflight(&big).is_ok());
        big[4..8].copy_from_slice(&u32::MAX.to_be_bytes()); assert!(frame_layout(&big).is_err());
    }

    #[cfg_attr(test, test)]
    pub(crate) fn keyring_capped_writer_and_fixed_control_budget() {
        let mut bytes = [0u8; 8];
        let mut writer = MessageWriter::Keyring(Cursor::new(bytes.as_mut_slice()));
        writer.write_all(b"abcd").unwrap(); writer.seek(SeekFrom::Start(7)).unwrap();
        assert!(writer.write_all(b"xy").is_err());
        writer.seek(SeekFrom::Start(100)).unwrap(); assert!(writer.write_all(b"z").is_err());
        assert_eq!(bytes.len(), 8);
        assert!(buffer(FRAME_BYTES + 1, FRAME_BYTES).is_err());
        assert!(future_fits(&[0u8; FUTURE_BYTES]).is_ok());
        assert!(future_fits(&[0u8; FUTURE_BYTES + 1]).is_err());
        // Actual private root/queue/map/transport layouts feed the same census
        // that refuses construction. Formula-only synthetic layouts are not
        // substituted for those product types.
        control::formula_regressions();
        let census = crate::connection::OwnedConnectionAttempt::keyring_control_census();
        if control::supported_target() {
            assert!(header_slot_bytes().unwrap() <= HEADER_SLOT_BYTES);
            assert!(census.unwrap().total() <= control::FIXED_SDK_BYTES);
            assert_eq!(local_error_backing_bytes(), Some(968));
        } else { assert!(census.is_err()); assert!(header_slot_bytes().is_none()); }
        let io = local_error(io::Error::new(io::ErrorKind::PermissionDenied, "synthetic private detail").into());
        let Error::InputOutput(io) = io else { panic!("local IO class changed"); };
        assert_eq!(io.kind(), io::ErrorKind::PermissionDenied);
        assert!(io.get_ref().is_none());
        let raw = local_error(io::Error::from_raw_os_error(13).into());
        assert!(matches!(raw, Error::InputOutput(ref error) if error.raw_os_error() == Some(13)));
        assert!(matches!(local_error(Error::Handshake("synthetic detail".into())), Error::Handshake(text) if text.capacity() == 0));
        assert_eq!(control::FUTURE_CONTROL_BYTES, 31 * 1024);
        assert_eq!(8 * FRAME_BYTES + FRAME_BYTES + 8 * 16 * 1024 + 8 * SASL_BYTES
            + 32 * 1024 + 64 * 1024 + 192 * 1024, ATTEMPT_BYTES);
    }
}
