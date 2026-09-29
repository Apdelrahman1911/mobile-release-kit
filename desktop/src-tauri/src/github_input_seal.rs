//! Private, synchronous GitHub sealed-body byte adapter; not mutation authority.
//!
//! The caller loans an already validated original UTF-8 envelope. This module
//! never parses or reserializes it. Context/key/assignment/token checks, private
//! framing, the final one-use GO and transport remain with their original owner.
//! Finish all of those preparations before claiming GO; a prepared body cannot
//! renew consent or bypass a later refusal.
//!
//! Zeroizing covers our owned seed/scratch/ciphertext/body buffers only.
//! crypto_box retains raw ephemeral-key bytes, rand_chacha does not wipe its
//! state, and AEAD internals can copy plaintext into ordinary allocations.
//! Stack/register/allocator/process erasure and recoverable OOM are not promised.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use crypto_box::{aead::rand_core::SeedableRng, PublicKey};
use curve25519_dalek::montgomery::MontgomeryPoint;
use rand_chacha::ChaCha20Rng;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const MAX_ENVELOPE_BYTES: usize = 48_000;
pub(crate) const MAX_PUT_BODY_BYTES: usize = 70 * 1024;
const MAX_CIPHERTEXT_BYTES: usize = 48_048;
const MAX_ENCODED_BYTES: usize = 64_064;
const MAX_KEY_ID_BYTES: usize = 128;
const PUBLIC_KEY_ENCODED_BYTES: usize = 44;
const SEED_BYTES: usize = 32;

// This is deliberately PUBLIC and NONSECRET. It is only a contributory-key
// check through maintained arithmetic, never the encryption's ephemeral secret.
const PUBLIC_VALIDATION_SCALAR: [u8; 32] = [0x42; 32];
const BODY_PREFIX: &[u8] = b"{\"encrypted_value\":\"";
const BODY_MIDDLE: &[u8] = b"\",\"key_id\":\"";
const BODY_SUFFIX: &[u8] = b"\"}";
const _: [(); 48] = [(); crypto_box::SEALBYTES];

/// Fixed categories only: no reflected values, library strings or body data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Envelope,
    PublicKey,
    KeyId,
    Size,
    Allocation,
    Random,
    Seal,
    Encoding,
}

/// Private data, never permission to PUT. No Clone, Debug, Serialize or getter
/// for its bytes; the original native owner alone supplies the transport closure.
pub(crate) struct SealedBody {
    bytes: Zeroizing<Vec<u8>>,
}

impl SealedBody {
    /// Metadata only, for charging the original owner's retained-memory ledger.
    /// This is Vec capacity, not a total allocator/RSS measurement.
    pub(crate) fn retained_capacity(&self) -> usize {
        self.bytes.capacity()
    }

    /// Consume the buffer, lend its exact compact bytes once, then wipe our
    /// backing. The borrow cannot escape in T. Only the original private native
    /// transport/framing owner may supply this closure, never a renderer route.
    pub(crate) fn with_transport_body<T>(
        self,
        transport: impl for<'body> FnOnce(&'body [u8]) -> T,
    ) -> T {
        transport(self.bytes.as_slice())
    }
}

/// Seal only the already validated original bytes and exact observed recipient.
/// The caller must bind key/key_id to its preview and original identity brackets.
pub(crate) fn seal(
    envelope: &[u8],
    observed_public_key: &str,
    observed_key_id: &str,
) -> Result<SealedBody, Error> {
    seal_with_entropy(
        envelope,
        observed_public_key,
        observed_key_id,
        fill_os_seed,
    )
}

fn fill_os_seed(seed: &mut [u8; SEED_BYTES]) -> Result<(), Error> {
    getrandom::fill(seed).map_err(|_| Error::Random)
}

// A private dependency seam, not a public alternate entropy route. Production
// has exactly the call above; injected deterministic/failing fills live in tests.
// This is not an RNG implementation: maintained ChaCha20Rng supplies CryptoRng.
fn seal_with_entropy(
    envelope: &[u8],
    observed_public_key: &str,
    observed_key_id: &str,
    fill_seed: impl FnOnce(&mut [u8; SEED_BYTES]) -> Result<(), Error>,
) -> Result<SealedBody, Error> {
    if envelope.is_empty() {
        return Err(Error::Envelope);
    }
    if envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(Error::Size);
    }
    std::str::from_utf8(envelope).map_err(|_| Error::Envelope)?;
    validate_key_id(observed_key_id)?;
    let recipient = validate_recipient(observed_public_key)?;
    let lengths = Lengths::new(envelope.len(), observed_key_id.len())?;
    let mut body = reserve_body(lengths.body)?;

    let ciphertext = {
        let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
        fill_seed(&mut seed)?;
        // Conservative fault check only, not a claim about entropy quality.
        if seed.iter().all(|byte| *byte == 0) {
            return Err(Error::Random);
        }
        #[cfg(test)]
        tests::record_rng_construction();
        let mut rng = ChaCha20Rng::from_seed(*seed);
        seed.zeroize();
        #[cfg(test)]
        tests::record_seal_call();
        // The pinned library allocates internally with infallible Vec APIs.
        // We cannot recover an allocator abort or erase its internal copies.
        Zeroizing::new(
            recipient
                .seal(&mut rng, envelope)
                .map_err(|_| Error::Seal)?,
        )
    }; // promptly drop the RNG and our already-cleared seed storage

    if ciphertext.len() != lengths.ciphertext
        || ciphertext.len() > MAX_CIPHERTEXT_BYTES
    {
        return Err(Error::Seal);
    }

    let mut cursor = 0usize;
    append_bytes(body.as_mut_slice(), &mut cursor, BODY_PREFIX)?;
    let encoded_end = cursor.checked_add(lengths.encoded).ok_or(Error::Size)?;
    let encoded = STANDARD
        .encode_slice(
            ciphertext.as_slice(),
            body.get_mut(cursor..encoded_end).ok_or(Error::Size)?,
        )
        .map_err(|_| Error::Encoding)?;
    if encoded != lengths.encoded || encoded > MAX_ENCODED_BYTES {
        return Err(Error::Encoding);
    }
    cursor = encoded_end;
    append_bytes(body.as_mut_slice(), &mut cursor, BODY_MIDDLE)?;
    append_bytes(
        body.as_mut_slice(),
        &mut cursor,
        observed_key_id.as_bytes(),
    )?;
    append_bytes(body.as_mut_slice(), &mut cursor, BODY_SUFFIX)?;
    drop(ciphertext);

    if cursor != body.len() || body.len() != lengths.body
        || body.len() > MAX_PUT_BODY_BYTES
    {
        return Err(Error::Size);
    }
    Ok(SealedBody { bytes: body })
}

fn validate_key_id(key_id: &str) -> Result<(), Error> {
    if key_id.is_empty() || key_id.len() > MAX_KEY_ID_BYTES
        || !key_id.bytes().all(|byte| {
            byte.is_ascii_graphic() && byte != b'"' && byte != b'\\'
        })
    {
        return Err(Error::KeyId);
    }
    Ok(())
}

fn validate_recipient(encoded: &str) -> Result<PublicKey, Error> {
    if encoded.len() != PUBLIC_KEY_ENCODED_BYTES || !encoded.is_ascii() {
        return Err(Error::PublicKey);
    }
    // A 44-byte input has a conservative 33-byte decoded-size estimate.
    let mut decoded = Zeroizing::new([0u8; 33]);
    let decoded_len = STANDARD
        .decode_slice(encoded.as_bytes(), &mut decoded[..])
        .map_err(|_| Error::PublicKey)?;
    if decoded_len != 32 {
        return Err(Error::PublicKey);
    }
    let mut canonical = Zeroizing::new([0u8; PUBLIC_KEY_ENCODED_BYTES]);
    let canonical_len = STANDARD
        .encode_slice(&decoded[..32], &mut canonical[..])
        .map_err(|_| Error::PublicKey)?;
    if canonical_len != PUBLIC_KEY_ENCODED_BYTES
        || &canonical[..] != encoded.as_bytes()
    {
        return Err(Error::PublicKey);
    }

    let mut key_bytes = Zeroizing::new([0u8; 32]);
    key_bytes.copy_from_slice(&decoded[..32]);
    let contribution = Zeroizing::new(
        MontgomeryPoint(*key_bytes).mul_clamped(PUBLIC_VALIDATION_SCALAR),
    );
    if contribution.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(Error::PublicKey);
    }
    Ok(PublicKey::from_bytes(*key_bytes))
}

struct Lengths {
    ciphertext: usize,
    encoded: usize,
    body: usize,
}

impl Lengths {
    fn new(envelope_bytes: usize, key_id_bytes: usize) -> Result<Self, Error> {
        if !(1..=MAX_ENVELOPE_BYTES).contains(&envelope_bytes)
            || !(1..=MAX_KEY_ID_BYTES).contains(&key_id_bytes)
        {
            return Err(Error::Size);
        }
        let ciphertext = envelope_bytes
            .checked_add(crypto_box::SEALBYTES)
            .ok_or(Error::Size)?;
        let encoded = ciphertext
            .checked_add(2)
            .map(|value| value / 3)
            .and_then(|value| value.checked_mul(4))
            .ok_or(Error::Size)?;
        let body = BODY_PREFIX.len()
            .checked_add(encoded)
            .and_then(|value| value.checked_add(BODY_MIDDLE.len()))
            .and_then(|value| value.checked_add(key_id_bytes))
            .and_then(|value| value.checked_add(BODY_SUFFIX.len()))
            .ok_or(Error::Size)?;
        if ciphertext > MAX_CIPHERTEXT_BYTES || encoded > MAX_ENCODED_BYTES
            || body > MAX_PUT_BODY_BYTES
        {
            return Err(Error::Size);
        }
        Ok(Self { ciphertext, encoded, body })
    }
}

fn reserve_body(length: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    if length > MAX_PUT_BODY_BYTES {
        return Err(Error::Size);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.try_reserve_exact(length).map_err(|_| Error::Allocation)?;
    // Account actual retained capacity, not just the requested byte length.
    if bytes.capacity() > MAX_PUT_BODY_BYTES {
        return Err(Error::Size);
    }
    // Reservation succeeded; resizing u8s within capacity does not allocate.
    bytes.resize(length, 0);
    Ok(bytes)
}

fn append_bytes(
    destination: &mut [u8],
    cursor: &mut usize,
    value: &[u8],
) -> Result<(), Error> {
    let end = cursor.checked_add(value.len()).ok_or(Error::Size)?;
    let target = destination.get_mut(*cursor..end).ok_or(Error::Size)?;
    target.copy_from_slice(value);
    *cursor = end;
    Ok(())
}

#[cfg(test)]
#[path = "github_input_seal_tests.rs"]
mod tests;
