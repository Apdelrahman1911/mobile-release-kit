//! Fixed binary framing only. This module does not perform cryptography or
//! provide original-process, cleanup, source or consent authority.

use std::io::{self, Read, Write};

pub(crate) const MAX_PLAINTEXT: usize = 49_152;
pub(crate) const PUBLIC_KEY_BYTES: usize = 32;
pub(crate) const SEAL_BYTES: usize = 48;
pub(crate) const REQUEST_PREFIX: usize = 8 + 4;
pub(crate) const REQUEST_HEADER: usize = REQUEST_PREFIX + PUBLIC_KEY_BYTES;
pub(crate) const MAX_INPUT_FRAME: usize = REQUEST_HEADER + MAX_PLAINTEXT;
// The EOF probe is in the SAME wiped allocation, not an untracked stack byte.
pub(crate) const INPUT_STORAGE: usize = MAX_INPUT_FRAME + 1;
pub(crate) const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + SEAL_BYTES;
pub(crate) const MAX_OUTPUT_FRAME: usize = 8 + 4 + MAX_CIPHERTEXT;
const REQUEST_MAGIC: &[u8; 8] = b"MRKSEAL1";
const RESPONSE_MAGIC: &[u8; 8] = b"MRKBOX01";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Refusal {
    Header,
    InputLimit,
    Truncated,
    Trailing,
    Read,
    OutputLength,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Request {
    plaintext_bytes: usize,
}

impl Request {
    pub(crate) fn plaintext_bytes(self) -> usize { self.plaintext_bytes }
    pub(crate) fn ciphertext_bytes(self) -> usize { self.plaintext_bytes + SEAL_BYTES }
}

fn input_error(error: io::Error) -> Refusal {
    if error.kind() == io::ErrorKind::UnexpectedEof { Refusal::Truncated } else { Refusal::Read }
}

pub(crate) fn read_request<R: Read>(input: &mut R, storage: &mut [u8; INPUT_STORAGE])
    -> Result<Request, Refusal>
{
    input.read_exact(&mut storage[..REQUEST_HEADER]).map_err(input_error)?;
    if &storage[..8] != REQUEST_MAGIC { return Err(Refusal::Header); }
    let size = u32::from_be_bytes([storage[8], storage[9], storage[10], storage[11]]);
    let size = usize::try_from(size).map_err(|_| Refusal::InputLimit)?;
    if size > MAX_PLAINTEXT { return Err(Refusal::InputLimit); }
    let end = REQUEST_HEADER + size;
    input.read_exact(&mut storage[REQUEST_HEADER..end]).map_err(input_error)?;
    loop {
        // A trailing byte may itself be sensitive. It stays in the caller's
        // initialized, full-capacity wipe rather than a separate temporary.
        match input.read(&mut storage[end..end + 1]) {
            Ok(0) => return Ok(Request { plaintext_bytes: size }),
            Ok(_) => return Err(Refusal::Trailing),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Refusal::Read),
        }
    }
}

pub(crate) fn write_response<W: Write>(output: &mut W, request: Request, ciphertext: &[u8])
    -> Result<(), Refusal>
{
    if ciphertext.len() != request.ciphertext_bytes() || ciphertext.len() > MAX_CIPHERTEXT {
        return Err(Refusal::OutputLength);
    }
    let size = u32::try_from(ciphertext.len()).map_err(|_| Refusal::OutputLength)?;
    let mut header = [0u8; 12];
    header[..8].copy_from_slice(RESPONSE_MAGIC);
    header[8..].copy_from_slice(&size.to_be_bytes());
    output.write_all(&header).map_err(|_| Refusal::Write)?;
    output.write_all(ciphertext).map_err(|_| Refusal::Write)
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod tests;
