// key exchange and crypto for session:
// 1. Before session negotiation (openSession), set private key and public key using DH method.
// 2. In session negotiation, send public key.
// 3. As result of session negotiation, get object path for session, which (I think
//      it means that it uses the same server public key to create an aes key which is used
//      to decode the encoded secret using the aes seed that's sent with the secret).
// 4. As result of session negotition, get server public key.
// 5. Use server public key, my private key, to set an aes key using HKDF.
// 6. Format Secret: aes iv is random seed, in secret struct it's the parameter (Array(Byte))
// 7. Format Secret: encode the secret value for the value field in secret struct.
//      This encoding uses the aes_key from the associated Session.

use crate::Error;
use crate::proxy::service::{OpenSessionResult, ServiceProxy, ServiceProxyBlocking};
use crate::ss::{ALGORITHM_DH, ALGORITHM_PLAIN};

use hybrid_array::{Array, typenum::U16};
use num::{
    FromPrimitive,
    bigint::BigUint,
    integer::Integer,
    traits::{One, Zero},
};
use once_cell::sync::Lazy;
use zbus::zvariant::OwnedObjectPath;

use std::ops::{Mul, Rem, Shr};

// for key exchange
static DH_GENERATOR: Lazy<BigUint> = Lazy::new(|| BigUint::from_u64(0x2).unwrap());
static DH_PRIME: Lazy<BigUint> = Lazy::new(|| {
    BigUint::from_bytes_be(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2,
        0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67,
        0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E,
        0x34, 0x04, 0xDD, 0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
        0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5,
        0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF,
        0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE,
        0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ])
});

#[allow(unused_macros)]
macro_rules! feature_needed {
    () => {
        compile_error!("Please enable a cryptography feature (crypto-rust or crypto-openssl) for the secret-service crate")
    }
}

type AesKey = Array<u8, U16>;
/// AES-CBC initialization vector
pub type AesIv = [u8; 16];

#[derive(Debug, Eq, PartialEq)]
pub enum EncryptionType {
    Plain,
    Dh,
}

// Additive checked retrieval support. The legacy Session API below is unchanged.
#[cfg(feature = "crypto-rust")]
pub use checked::{
    CheckedDhExchange, CheckedSessionKey, RETRIEVAL_CRYPTO_BYTES, WrappingKeyCandidate,
};
#[cfg(feature = "mrk-retrieval-test-support")]
pub use checked::test_support;

#[cfg(feature = "crypto-rust")]
mod checked {
    use super::{DH_GENERATOR, DH_PRIME};
    use crate::Error;
    use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
    use hkdf::Hkdf;
    use num::bigint::BigUint;
    use once_cell::sync::Lazy;
    use sha2::Sha256;
    use zeroize::{Zeroize, Zeroizing};

    const DH_BYTES: usize = 128;
    static DH_SUBGROUP_ORDER: Lazy<BigUint> = Lazy::new(|| (&*DH_PRIME - 1u32) >> 1usize);

    /// Separate, conservative simultaneous-live crypto reservation for the
    /// selected num-bigint0.4.8/RustCrypto closure, not a larger wire allowance.
    ///
    /// Fixed1024-bit operands select num-bigint's4-bit Montgomery path:16 table
    /// entries, x/rr/one/z/zz, one2n-limb product scratch and one result. Its
    /// largest setup dividend is2049 bits; division is below the recursive
    /// threshold.16KiB covers these live limb buffers/headers/realloc overlap;
    /// another12KiB covers HKDF/SHA/AES/CBC fixed state and stack temporaries,
    /// and4KiB covers domains and owned private/public/shared/AES/key buffers.
    /// Calls are sequential, not concurrent modpow jobs. Original Message,
    /// session path, request/future storage and allocator/process overhead must
    /// remain separately charged. This is a source-informed capacity allowance,
    /// not a measured RSS, complete allocator bound or erasure/constant-time claim.
    pub const RETRIEVAL_CRYPTO_BYTES: usize = 32 * 1024;

    /// One checked, not-yet-negotiated exchange. Only the public bytes may leave
    /// this owner. No BigUint/private arithmetic state is retained across awaits.
    pub struct CheckedDhExchange {
        // Reverse the initially big-endian random bytes in their zeroizing
        // owner, then use from_bytes_le. This avoids from_bytes_be's additional
        // nonzeroizing byte-reversal Vec for our private scalar.
        private_le: Zeroizing<[u8; DH_BYTES]>,
        public: [u8; DH_BYTES],
    }

    /// An AES transport key, not an authenticated vault key. Consumed by the
    /// single checked GetSecret decryption; deliberately no Debug/Clone/serde.
    pub struct CheckedSessionKey {
        aes: Zeroizing<[u8; 16]>,
    }

    /// Private candidate only: no access, formatting, cloning or IPC surface.
    /// A future store consumer still owes exact-header AEAD authentication and
    /// same-operation charge/finality; the current application can only keep/drop.
    pub struct WrappingKeyCandidate {
        bytes: Zeroizing<[u8; 32]>,
    }

    impl CheckedDhExchange {
        /// One fallible128-byte fill, high bit cleared, then2<=x<q or refusal.
        /// There is no retry, reduction modulo q, weak fallback or Plain branch.
        pub fn generate() -> Result<Self, Error> {
            Self::generate_with(|bytes| {
                getrandom::fill(bytes).map_err(|_| Error::Crypto("random source refused"))
            })
        }

        fn generate_with(fill: impl FnOnce(&mut [u8]) -> Result<(), Error>) -> Result<Self, Error> {
            let mut private_le = Zeroizing::new([0u8; DH_BYTES]);
            fill(&mut private_le[..])?;
            private_le[0] &= 0x7f;
            private_le.reverse();
            let public = {
                let private = BigUint::from_bytes_le(&private_le[..]);
                if private < *DH_GENERATOR || private >= *DH_SUBGROUP_ORDER {
                    return Err(Error::Crypto("private scalar refused"));
                }
                let public = DH_GENERATOR.modpow(&private, &DH_PRIME);
                *padded_1024(&public)?
            };
            Ok(Self { private_le, public })
        }

        /// Fixed128-byte unsigned big-endian encoding, including leading zeros.
        pub fn public_key(&self) -> &[u8; DH_BYTES] {
            &self.public
        }

        /// Consume the exchange only after retaining the separately decoded
        /// original session path. Invalid/empty peers do not erase a Close debt.
        pub fn derive(self, peer_bytes: &[u8]) -> Result<CheckedSessionKey, Error> {
            let shared = {
                let peer = checked_peer(peer_bytes)?;
                let private = BigUint::from_bytes_le(&self.private_le[..]);
                peer.modpow(&private, &DH_PRIME)
            };
            drop(self); // wipe owned private staging before HKDF
            let shared_padded = padded_1024(&shared)?;
            drop(shared); // BigUint/library limb copies are NOT proven erased
            let hkdf = {
                let (mut prk, hkdf) = Hkdf::<Sha256>::extract(None, &shared_padded[..]);
                prk.as_mut_slice().zeroize(); // wipe our accessible returned PRK
                hkdf
            };
            let mut key = CheckedSessionKey { aes: Zeroizing::new([0u8; 16]) };
            hkdf.expand(&[], &mut key.aes[..])
                .map_err(|_| Error::Crypto("key derivation refused"))?;
            // shared_padded is zeroized on all exits. HMAC/HKDF internal state
            // and compiler/library copies are outside that erasure guarantee.
            Ok(key)
        }
    }

    fn checked_peer(bytes: &[u8]) -> Result<BigUint, Error> {
        if bytes.is_empty() || bytes.len() > DH_BYTES {
            return Err(Error::Crypto("peer key refused"));
        }
        let peer = BigUint::from_bytes_be(bytes);
        if peer < *DH_GENERATOR || peer > (&*DH_PRIME - 2u32)
            || peer.modpow(&DH_SUBGROUP_ORDER, &DH_PRIME) != BigUint::from(1u32)
        {
            return Err(Error::Crypto("peer key refused"));
        }
        Ok(peer)
    }

    fn padded_1024(value: &BigUint) -> Result<Zeroizing<[u8; DH_BYTES]>, Error> {
        if value.bits() > (8 * DH_BYTES) as u64 {
            return Err(Error::Crypto("shared value refused"));
        }
        let bytes = Zeroizing::new(value.to_bytes_be());
        let start = DH_BYTES.checked_sub(bytes.len())
            .ok_or(Error::Crypto("shared value refused"))?;
        let mut padded = Zeroizing::new([0u8; DH_BYTES]);
        padded[start..].copy_from_slice(&bytes);
        Ok(padded)
    }

    impl CheckedSessionKey {
        /// Decrypt only a checked IV16/ciphertext48 envelope. The original raw
        /// Message is immutable; all48 private scratch bytes are wiped even on
        /// invalid padding or a validly padded plaintext of the wrong length.
        pub fn decrypt_wrapping_key(
            self, iv: &[u8; 16], ciphertext: &[u8; 48],
        ) -> Result<WrappingKeyCandidate, Error> {
            let mut scratch = Zeroizing::new([0u8; 48]);
            scratch.copy_from_slice(ciphertext);
            let decryptor = cbc::Decryptor::<aes::Aes128>::new_from_slices(&self.aes[..], iv)
                .map_err(|_| Error::Crypto("secret decryption refused"))?;
            let plaintext = decryptor.decrypt_padded::<Pkcs7>(&mut scratch[..])
                .map_err(|_| Error::Crypto("secret decryption refused"))?;
            if plaintext.len() != 32 {
                return Err(Error::Crypto("secret length refused"));
            }
            let mut candidate = WrappingKeyCandidate { bytes: Zeroizing::new([0u8; 32]) };
            candidate.bytes.copy_from_slice(plaintext);
            Ok(candidate)
        }
    }

    /// Fixed synthetic fixtures only; excluded from the normal dependency graph.
    #[cfg(feature = "mrk-retrieval-test-support")]
    pub mod test_support {
        use super::*;
        use aes::cipher::BlockModeEncrypt;

        /// The real checked exchange (x=2), peer8, IV16 and library-encrypted
        /// synthetic32-byte key. No OS randomness, native call or public scalar
        /// constructor is used; there is deliberately no plaintext accessor.
        pub fn exchange_and_secret(
        ) -> Result<(CheckedDhExchange, [u8; 1], [u8; 16], [u8; 48]), Error> {
            fn exchange() -> Result<CheckedDhExchange, Error> {
                CheckedDhExchange::generate_with(|bytes| { bytes[127] = 2; Ok(()) })
            }
            let original = exchange()?;
            let peer = [8];
            let aes = exchange()?.derive(&peer)?;
            let iv = [0x27; 16];
            let mut scratch = Zeroizing::new([0u8; 48]);
            scratch[..32].fill(0xa5);
            cbc::Encryptor::<aes::Aes128>::new_from_slices(&aes.aes[..], &iv)
                .map_err(|_| Error::Crypto("synthetic cipher refused"))?
                .encrypt_padded::<Pkcs7>(&mut scratch[..], 32)
                .map_err(|_| Error::Crypto("synthetic padding refused"))?;
            Ok((original, peer, iv, *scratch))
        }

        /// Run the same actual-helper assertions as the SDK's inert unit tests,
        /// permitting an app libtest to cover this delta in one compilation.
        pub fn assert_crypto_helpers() {
            super::tests::one_fill_and_exact_private_domain_no_retry();
            super::tests::peer_range_subgroup_and_leading_zero_encoding();
            super::tests::dh_and_padded_hkdf_known_answer();
            super::tests::cbc_known_answer_prefix_and_checked_key();
            super::tests::in_place_secret_exact_length_bad_padding_and_raw_copy();
            super::tests::actual_owned_and_library_state_sizes_fit_separate_allowance();
        }
    }

    #[cfg(any(test, feature = "mrk-retrieval-test-support"))]
    mod tests {
        // Synthetic local DATA only. Filter this module, never the crate's
        // unrelated legacy bus/keyring integration tests, for inert validation.
        use super::*;
        use aes::cipher::BlockModeEncrypt;

        fn exchange(scalar: &BigUint) -> Result<CheckedDhExchange, Error> {
            let bytes = scalar.to_bytes_be();
            CheckedDhExchange::generate_with(|output| {
                let start = output.len() - bytes.len();
                output[start..].copy_from_slice(&bytes);
                Ok(())
            })
        }

        #[cfg_attr(test, test)]
        pub(super) fn one_fill_and_exact_private_domain_no_retry() {
            let mut calls = 0;
            let result = CheckedDhExchange::generate_with(|output| {
                calls += 1;
                assert_eq!(output.len(), 128);
                output.fill(0xa5);
                Err(Error::Crypto("synthetic RNG refusal"))
            });
            assert!(result.is_err());
            assert_eq!(calls, 1);
            for scalar in [BigUint::from(0u32), BigUint::from(1u32),
                DH_SUBGROUP_ORDER.clone(), &*DH_SUBGROUP_ORDER + 1u32]
            {
                assert!(exchange(&scalar).is_err());
            }
            let largest = exchange(&(&*DH_SUBGROUP_ORDER - 1u32)).unwrap();
            assert_eq!(BigUint::from_bytes_be(largest.public_key()), &*DH_SUBGROUP_ORDER + 1u32);
            let cleared = CheckedDhExchange::generate_with(|output| {
                output[0] = 0x80;
                output[127] = 2;
                Ok(())
            }).unwrap();
            assert!(cleared.public_key()[..127].iter().all(|byte| *byte == 0));
            assert_eq!(cleared.public_key()[127], 4);
            assert!(CheckedDhExchange::generate_with(|output| { output.fill(0xff); Ok(()) }).is_err());
        }

        #[cfg_attr(test, test)]
        pub(super) fn peer_range_subgroup_and_leading_zero_encoding() {
            assert_eq!(DH_GENERATOR.modpow(&DH_SUBGROUP_ORDER, &DH_PRIME), BigUint::from(1u32));
            for bytes in [vec![], vec![0], vec![1], (&*DH_PRIME - 1u32).to_bytes_be(),
                DH_PRIME.to_bytes_be(), (&*DH_PRIME + 1u32).to_bytes_be(), vec![2; 129]]
            {
                assert!(checked_peer(&bytes).is_err());
            }
            // p-2 is in the numerical range but outside the order-q subgroup.
            let nonmember = &*DH_PRIME - 2u32;
            assert_eq!(nonmember.modpow(&DH_SUBGROUP_ORDER, &DH_PRIME), &*DH_PRIME - 1u32);
            assert!(checked_peer(&nonmember.to_bytes_be()).is_err());
            assert_eq!(checked_peer(&[2]).unwrap(), BigUint::from(2u32));
            assert_eq!(checked_peer(&[0, 8]).unwrap(), BigUint::from(8u32));
            let mut padded = [0u8; 128]; padded[127] = 8;
            assert_eq!(checked_peer(&padded).unwrap(), BigUint::from(8u32));
            assert!(exchange(&BigUint::from(2u32)).unwrap().derive(&[]).is_err());
        }

        #[cfg_attr(test, test)]
        pub(super) fn dh_and_padded_hkdf_known_answer() {
            // g^2=4, g^3=8, shared=64. Independent Python stdlib hmac/hashlib
            // DATA calculation pins HKDF-SHA256(None, 00*127||40, empty,16).
            let expected = [0xdd, 0x73, 0x52, 0xd6, 0x48, 0xb8, 0x1b, 0x68,
                0xe7, 0xcf, 0xbf, 0x88, 0xf5, 0xc3, 0xe2, 0xee];
            let client = exchange(&BigUint::from(2u32)).unwrap();
            let server = exchange(&BigUint::from(3u32)).unwrap();
            assert_eq!(client.public_key()[127], 4);
            assert_eq!(server.public_key()[127], 8);
            let server_key = server.derive(client.public_key()).unwrap();
            let client_key = client.derive(&[0, 8]).unwrap();
            assert_eq!(&client_key.aes[..], &expected);
            assert_eq!(&server_key.aes[..], &expected);
            let padded = padded_1024(&BigUint::from(64u32)).unwrap();
            assert!(padded[..127].iter().all(|byte| *byte == 0));
            assert_eq!(padded[127], 64);
            assert!(padded_1024(&(BigUint::from(1u32) << 1024usize)).is_err());
        }

        fn aes_key() -> CheckedSessionKey {
            CheckedSessionKey { aes: Zeroizing::new([0x39; 16]) }
        }

        fn ciphertext(plaintext: &[u8]) -> [u8; 48] {
            // Use the selected CBC library, not another cipher implementation.
            let mut scratch = [0u8; 48];
            scratch[..plaintext.len()].copy_from_slice(plaintext);
            cbc::Encryptor::<aes::Aes128>::new_from_slices(&[0x39; 16], &[0x27; 16]).unwrap()
                .encrypt_padded::<Pkcs7>(&mut scratch, plaintext.len()).unwrap();
            scratch
        }

        #[cfg_attr(test, test)]
        pub(super) fn cbc_known_answer_prefix_and_checked_key() {
            // NIST SP800-38A F.2.1 AES128-CBC first two blocks. The library adds
            // the third PKCS7 block for the exact32-byte checked helper input.
            let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
            let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
            let plaintext = [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51];
            let expected = [0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
                0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
                0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
                0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2];
            let mut ciphertext = [0u8; 48];
            ciphertext[..32].copy_from_slice(&plaintext);
            cbc::Encryptor::<aes::Aes128>::new_from_slices(&key, &iv).unwrap()
                .encrypt_padded::<Pkcs7>(&mut ciphertext, 32).unwrap();
            assert_eq!(&ciphertext[..32], &expected);
            let aes = CheckedSessionKey { aes: Zeroizing::new(key) };
            let candidate = aes.decrypt_wrapping_key(&iv, &ciphertext).unwrap();
            assert_eq!(&candidate.bytes[..], &plaintext);
        }

        #[cfg_attr(test, test)]
        pub(super) fn in_place_secret_exact_length_bad_padding_and_raw_copy() {
            let plaintext = [0xa5; 32];
            let encrypted = ciphertext(&plaintext);
            let original = encrypted;
            let key = aes_key().decrypt_wrapping_key(&[0x27; 16], &encrypted).unwrap();
            assert_eq!(&key.bytes[..], &plaintext);
            assert_eq!(encrypted, original); // retained raw ciphertext was not mutated
            let mut bad_padding = encrypted;
            bad_padding[31] ^= 0x10; // last plaintext padding byte becomes zero
            assert!(aes_key().decrypt_wrapping_key(&[0x27; 16], &bad_padding).is_err());
            for length in [33, 40, 47] {
                let bytes = [0xa5; 47];
                let encrypted = ciphertext(&bytes[..length]);
                assert!(matches!(aes_key().decrypt_wrapping_key(&[0x27; 16], &encrypted),
                    Err(Error::Crypto("secret length refused"))));
            }
        }

        #[cfg_attr(test, test)]
        pub(super) fn actual_owned_and_library_state_sizes_fit_separate_allowance() {
            use std::mem::size_of;
            assert_eq!(size_of::<CheckedDhExchange>(), 256);
            assert_eq!(size_of::<CheckedSessionKey>(), 16);
            assert_eq!(size_of::<WrappingKeyCandidate>(), 32);
            assert!(size_of::<BigUint>() <= 64);
            let fixed = size_of::<Hkdf<Sha256>>() + size_of::<cbc::Decryptor<aes::Aes128>>()
                + size_of::<CheckedDhExchange>() + size_of::<CheckedSessionKey>()
                + size_of::<WrappingKeyCandidate>() + 128 + 128 + 48 + 32;
            assert!(fixed <= 4 * 1024);
            // This checks inline state only; source-reviewed modpow heap/stack
            // scratch is additionally charged, not inferred from this assertion.
            assert_eq!(RETRIEVAL_CRYPTO_BYTES, 32 * 1024);
        }
    }
}

struct Keypair {
    private: BigUint,
    public: BigUint,
}

impl Keypair {
    fn generate() -> Self {
        let mut private_key_bytes = [0; 128];
        getrandom::fill(&mut private_key_bytes).expect("platform RNG failed");

        let private_key = BigUint::from_bytes_be(&private_key_bytes);
        let public_key = powm(&DH_GENERATOR, &private_key, &DH_PRIME);

        Self {
            private: private_key,
            public: public_key,
        }
    }

    fn derive_shared(&self, server_public_key: &BigUint) -> AesKey {
        // Derive the shared secret the server and us.
        let common_secret = powm(server_public_key, &self.private, &DH_PRIME);

        let mut common_secret_bytes = common_secret.to_bytes_be();
        let mut common_secret_padded = vec![0; 128 - common_secret_bytes.len()];
        common_secret_padded.append(&mut common_secret_bytes);

        // hkdf

        // input keying material
        let ikm = common_secret_padded;
        let salt = None;

        // output keying material
        let mut okm = [0; 16];
        hkdf(ikm, salt, &mut okm);

        Array::from(okm)
    }
}

#[cfg(feature = "crypto-openssl")]
fn hkdf(ikm: Vec<u8>, salt: Option<&[u8]>, okm: &mut [u8]) {
    let mut ctx = openssl::pkey_ctx::PkeyCtx::new_id(openssl::pkey::Id::HKDF)
        .expect("hkdf context should not fail");
    ctx.derive_init().expect("hkdf derive init should not fail");
    ctx.set_hkdf_md(openssl::md::Md::sha256())
        .expect("hkdf set md should not fail");

    ctx.set_hkdf_key(&ikm)
        .expect("hkdf set key should not fail");
    if let Some(salt) = salt {
        ctx.set_hkdf_salt(salt)
            .expect("hkdf set salt should not fail");
    }

    ctx.add_hkdf_info(&[]).unwrap();
    ctx.derive(Some(okm))
        .expect("hkdf expand should never fail");
}

#[cfg(feature = "crypto-rust")]
fn hkdf(ikm: Vec<u8>, salt: Option<&[u8]>, okm: &mut [u8]) {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let info = [];
    let (_, hk) = Hkdf::<Sha256>::extract(salt, &ikm);
    hk.expand(&info, okm)
        .expect("hkdf expand should never fail");
}

#[cfg(all(not(feature = "crypto-rust"), not(feature = "crypto-openssl")))]
fn hkdf(ikm: Vec<u8>, salt: Option<&[u8]>, okm: &mut [u8]) {
    feature_needed!()
}

pub struct Session {
    pub object_path: OwnedObjectPath,
    aes_key: Option<AesKey>,
}

impl Session {
    fn encrypted_session(keypair: &Keypair, session: OpenSessionResult) -> Result<Self, Error> {
        let server_public_key = session
            .output
            .try_into()
            .map(|key: Vec<u8>| BigUint::from_bytes_be(&key))?;

        let aes_key = keypair.derive_shared(&server_public_key);

        Ok(Session {
            object_path: session.result,
            aes_key: Some(aes_key),
        })
    }

    pub fn new_blocking(
        service_proxy: &ServiceProxyBlocking,
        encryption: EncryptionType,
    ) -> Result<Self, Error> {
        match encryption {
            EncryptionType::Plain => {
                let session = service_proxy.open_session(ALGORITHM_PLAIN, "".into())?;
                let session_path = session.result;

                Ok(Session {
                    object_path: session_path,
                    aes_key: None,
                })
            }
            EncryptionType::Dh => {
                let keypair = Keypair::generate();

                let session = service_proxy
                    .open_session(ALGORITHM_DH, keypair.public.to_bytes_be().into())?;

                Self::encrypted_session(&keypair, session)
            }
        }
    }

    pub async fn new(
        service_proxy: &ServiceProxy<'_>,
        encryption: EncryptionType,
    ) -> Result<Self, Error> {
        match encryption {
            EncryptionType::Plain => {
                let session = service_proxy
                    .open_session(ALGORITHM_PLAIN, "".into())
                    .await?;
                let session_path = session.result;

                Ok(Session {
                    object_path: session_path,
                    aes_key: None,
                })
            }
            EncryptionType::Dh => {
                let keypair = Keypair::generate();

                let session = service_proxy
                    .open_session(ALGORITHM_DH, keypair.public.to_bytes_be().into())
                    .await?;

                Self::encrypted_session(&keypair, session)
            }
        }
    }

    pub fn get_aes_key(&self) -> Option<&AesKey> {
        self.aes_key.as_ref()
    }
}

/// from https://github.com/plietar/librespot/blob/master/core/src/util/mod.rs#L53
fn powm(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    let mut base = base.clone();
    let mut exp = exp.clone();
    let mut result: BigUint = One::one();

    while !exp.is_zero() {
        if exp.is_odd() {
            result = result.mul(&base).rem(modulus);
        }
        exp = exp.shr(1);
        base = (&base).mul(&base).rem(modulus);
    }

    result
}

#[cfg(feature = "crypto-rust")]
pub fn encrypt(data: &[u8], key: &AesKey, iv: &AesIv) -> Vec<u8> {
    use aes::cipher::block_padding::Pkcs7;
    use aes::cipher::{BlockModeEncrypt, KeyIvInit};

    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    Aes128CbcEnc::new(key, &Array::from(*iv)).encrypt_padded_vec::<Pkcs7>(data)
}

#[cfg(feature = "crypto-rust")]
pub fn decrypt(encrypted_data: &[u8], key: &AesKey, iv: &AesIv) -> Result<Vec<u8>, Error> {
    use aes::cipher::block_padding::Pkcs7;
    use aes::cipher::{BlockModeDecrypt, KeyIvInit};

    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

    Aes128CbcDec::new(key, &Array::from(*iv))
        .decrypt_padded_vec::<Pkcs7>(encrypted_data)
        .map_err(|_| Error::Crypto("message decryption failed"))
}

#[cfg(feature = "crypto-openssl")]
pub fn encrypt(data: &[u8], key: &AesKey, iv: &[u8]) -> Vec<u8> {
    use openssl::cipher::Cipher;
    use openssl::cipher_ctx::CipherCtx;

    let mut ctx = CipherCtx::new().expect("cipher creation should not fail");
    ctx.encrypt_init(Some(Cipher::aes_128_cbc()), Some(key), Some(iv))
        .expect("cipher init should not fail");

    let mut output = vec![];
    ctx.cipher_update_vec(data, &mut output)
        .expect("cipher update should not fail");
    ctx.cipher_final_vec(&mut output)
        .expect("cipher final should not fail");
    output
}

#[cfg(feature = "crypto-openssl")]
pub fn decrypt(encrypted_data: &[u8], key: &AesKey, iv: &[u8]) -> Result<Vec<u8>, Error> {
    use openssl::cipher::Cipher;
    use openssl::cipher_ctx::CipherCtx;

    let mut ctx = CipherCtx::new().expect("cipher creation should not fail");
    ctx.decrypt_init(Some(Cipher::aes_128_cbc()), Some(key), Some(iv))
        .expect("cipher init should not fail");

    let mut output = vec![];
    ctx.cipher_update_vec(encrypted_data, &mut output)
        .map_err(|_| Error::Crypto("message decryption failed"))?;
    ctx.cipher_final_vec(&mut output)
        .map_err(|_| Error::Crypto("message decryption failed"))?;
    Ok(output)
}

#[cfg(all(not(feature = "crypto-rust"), not(feature = "crypto-openssl")))]
pub fn encrypt(data: &[u8], key: &AesKey, iv: &AesIv) -> Vec<u8> {
    feature_needed!()
}

#[cfg(all(not(feature = "crypto-rust"), not(feature = "crypto-openssl")))]
pub fn decrypt(encrypted_data: &[u8], key: &AesKey, iv: &AesIv) -> Result<Vec<u8>, Error> {
    feature_needed!()
}

#[cfg(test)]
mod test {
    use super::*;

    // There is no async test because this tests that an encryption session can be made, nothing more.

    #[test]
    fn should_create_plain_session() {
        let conn = zbus::blocking::Connection::session().unwrap();
        let service_proxy = ServiceProxyBlocking::new(&conn).unwrap();
        let session = Session::new_blocking(&service_proxy, EncryptionType::Plain).unwrap();
        assert!(session.get_aes_key().is_none());
    }

    #[test]
    fn should_create_encrypted_session() {
        let conn = zbus::blocking::Connection::session().unwrap();
        let service_proxy = ServiceProxyBlocking::new(&conn).unwrap();
        let session = Session::new_blocking(&service_proxy, EncryptionType::Dh).unwrap();
        assert!(session.get_aes_key().is_some());
    }
}
