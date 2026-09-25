//! Private reply support for a deliberately narrow wire profile.
//!
//! Callers must retain the original Message and its Body while using these
//! borrowed views. The original `body.message().recv_position()` remains the
//! same-connection ordering source, not a remote serial number. Successful and
//! error replies still need later owner-event reconciliation before further work.
//! The additive checked_lookup facade uses these helpers; legacy high-level
//! APIs remain unchanged. This module does not bound
//! earlier transport/header allocation, validate DH peers, decrypt secrets,
//! settle prompts/tasks, or qualify a durable/persistent provider.

use crate::Error;
use serde::de::{Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;
use zbus::message::{Body, PrimaryHeader, Type as MessageType};
use zbus::names::UniqueName;
use zbus::zvariant::as_value::Deserialize as Variant;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, Signature, Type};

const MAX_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_PROPERTY_BYTES: usize = 2 * 1024;
const MAX_PATH_BYTES: usize = 512;
const INVALID_VALUE: &str = "invalid bounded reply";
const SECRET_CONTENT_TYPE: &str = "application/octet-stream";

// Parsed Signature collapses `aoo`/`(aoo)`, `vo`/`(vo)` and
// `oayays`/`(oayays)`. Only these concrete reply shapes select a raw signature.
trait ReplySignature: Type {
    const WIRE_SIGNATURE: &'static str;
}

fn checked_body<'a, T>(body: &'a Body, sender: &UniqueName<'_>) -> Result<T, Error>
where
    T: ReplySignature + Deserialize<'a>,
{
    checked_typed_body(body, sender, MessageType::MethodReturn)
}

fn checked_envelope(body: &Body, sender: &UniqueName<'_>, kind: MessageType) -> Result<(), Error> {
    let message = body.message();
    // This is defensive admission after transport allocation, not a transport cap.
    if message.data().len() > MAX_MESSAGE_BYTES {
        return Err(Error::InvalidReply);
    }
    #[cfg(unix)]
    if !message.data().fds().is_empty() {
        return Err(Error::InvalidReply);
    }

    let header = message.header();
    if header.message_type() != kind
        || header.sender().map(|name| name.as_str()) != Some(sender.as_str())
    {
        return Err(Error::InvalidReply);
    }
    Ok(())
}

fn checked_typed_body<'a, T>(body: &'a Body, sender: &UniqueName<'_>, kind: MessageType) -> Result<T, Error>
where
    T: ReplySignature + Deserialize<'a>,
{
    checked_envelope(body, sender, kind)?;
    if wire_signature(body)? != T::WIRE_SIGNATURE || body.signature() != T::SIGNATURE {
        return Err(Error::InvalidReply);
    }

    let (value, consumed): (T, usize) = body
        .data()
        .deserialize_for_dynamic_signature(body.signature())
        .map_err(|_| Error::InvalidReply)?;
    if consumed != body.len() {
        return Err(Error::InvalidReply);
    }
    Ok(value)
}

struct BorrowedStrVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BorrowedStrVisitor<MAX> {
    type Value = &'de str;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded borrowed string")
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() > MAX {
            return Err(E::custom(INVALID_VALUE));
        }
        Ok(value)
    }
}

/// Validated path bytes only. `/` is an operation-specific sentinel, not an item.
#[derive(Clone, Copy)]
pub(crate) struct BoundedPath<'a>(&'a str);

impl<'a> BoundedPath<'a> {
    pub(crate) fn as_str(&self) -> &'a str {
        self.0
    }

    /// Ownership is acquired only after bounded borrowed validation has succeeded.
    pub(crate) fn into_owned(self) -> Result<OwnedObjectPath, Error> {
        OwnedObjectPath::try_from(self.0).map_err(|_| Error::InvalidReply)
    }
}

impl Type for BoundedPath<'_> {
    const SIGNATURE: &'static Signature = &Signature::ObjectPath;
}

impl ReplySignature for BoundedPath<'_> {
    const WIRE_SIGNATURE: &'static str = "o";
}

impl<'de> Deserialize<'de> for BoundedPath<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = deserializer.deserialize_str(BorrowedStrVisitor::<MAX_PATH_BYTES>)?;
        ObjectPath::try_from(value).map_err(|_| D::Error::custom(INVALID_VALUE))?;
        Ok(Self(value))
    }
}

// SeqAccess/MapAccess determines whether another element exists. If it does,
// refuse before decoding that value, rather than traversing or collecting it.
struct RejectExtra;

impl<'de> Deserialize<'de> for RejectExtra {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Err(D::Error::custom(INVALID_VALUE))
    }
}

pub(crate) struct AtMostOnePath<'a>(pub(crate) Option<BoundedPath<'a>>);

impl Type for AtMostOnePath<'_> {
    const SIGNATURE: &'static Signature = &Signature::static_array(&Signature::ObjectPath);
}

impl ReplySignature for AtMostOnePath<'_> {
    const WIRE_SIGNATURE: &'static str = "ao";
}

impl<'de> Deserialize<'de> for AtMostOnePath<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PathsVisitor;
        impl<'de> Visitor<'de> for PathsVisitor {
            type Value = AtMostOnePath<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("zero or one bounded path")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let Some(first) = seq.next_element::<BoundedPath<'de>>()? else {
                    return Ok(AtMostOnePath(None));
                };
                let _ = seq.next_element::<RejectExtra>()?;
                Ok(AtMostOnePath(Some(first)))
            }
        }
        deserializer.deserialize_seq(PathsVisitor)
    }
}

pub(crate) struct Attributes<'a>(pub(crate) [Option<(&'a str, &'a str)>; 4]);

impl Type for Attributes<'_> {
    const SIGNATURE: &'static Signature =
        &Signature::static_dict(&Signature::Str, &Signature::Str);
}

impl<'de> Deserialize<'de> for Attributes<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AttributesVisitor;
        impl<'de> Visitor<'de> for AttributesVisitor {
            type Value = Attributes<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("four distinct bounded attribute pairs")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut entries: [Option<(&'de str, &'de str)>; 4] = [None; 4];
                for index in 0..4 {
                    let key = map
                        .next_key::<&'de str>()?
                        .ok_or_else(|| A::Error::custom(INVALID_VALUE))?;
                    if key.len() > 64
                        || entries[..index].iter().flatten().any(|(seen, _)| *seen == key)
                    {
                        return Err(A::Error::custom(INVALID_VALUE));
                    }
                    let value = map.next_value::<&'de str>()?;
                    if value.len() > 256 {
                        return Err(A::Error::custom(INVALID_VALUE));
                    }
                    entries[index] = Some((key, value));
                }
                let _ = map.next_key::<RejectExtra>()?;
                Ok(Attributes(entries))
            }
        }
        deserializer.deserialize_map(AttributesVisitor)
    }
}

struct BorrowedBytes<'a, const MAX: usize>(&'a [u8]);

impl<const MAX: usize> Type for BorrowedBytes<'_, MAX> {
    const SIGNATURE: &'static Signature = &Signature::static_array(&Signature::U8);
}

impl<'de, const MAX: usize> Deserialize<'de> for BorrowedBytes<'de, MAX> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor<const MAX: usize>;
        impl<'de, const MAX: usize> Visitor<'de> for BytesVisitor<MAX> {
            type Value = BorrowedBytes<'de, MAX>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded borrowed byte array")
            }

            fn visit_borrowed_bytes<E>(self, value: &'de [u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.len() > MAX {
                    return Err(E::custom(INVALID_VALUE));
                }
                Ok(BorrowedBytes(value))
            }
        }
        deserializer.deserialize_bytes(BytesVisitor::<MAX>)
    }
}

struct BorrowedSignature<'a>(&'a str);

impl Type for BorrowedSignature<'_> {
    const SIGNATURE: &'static Signature = &Signature::Signature;
}

impl<'de> Deserialize<'de> for BorrowedSignature<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_str(BorrowedStrVisitor::<255>)
            .map(Self)
    }
}

struct WireHeaderField<'a> {
    code: u8,
    signature: Option<&'a str>,
}

impl<'de> Deserialize<'de> for WireHeaderField<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FieldVisitor;
        impl<'de> Visitor<'de> for FieldVisitor {
            type Value = WireHeaderField<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a known bounded header field")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let code = seq
                    .next_element::<u8>()?
                    .ok_or_else(|| A::Error::custom(INVALID_VALUE))?;
                let signature = match code {
                    1 => {
                        let _: Variant<'de, BoundedPath<'de>> = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom(INVALID_VALUE))?;
                        None
                    }
                    2 | 3 | 4 | 6 | 7 => {
                        let value: Variant<'de, &'de str> = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom(INVALID_VALUE))?;
                        if value.0.len() > 255 {
                            return Err(A::Error::custom(INVALID_VALUE));
                        }
                        None
                    }
                    5 | 9 => {
                        let value: Variant<'de, u32> = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom(INVALID_VALUE))?;
                        if code == 9 && value.0 != 0 {
                            return Err(A::Error::custom(INVALID_VALUE));
                        }
                        None
                    }
                    8 => {
                        let value: Variant<'de, BorrowedSignature<'de>> = seq
                            .next_element()?
                            .ok_or_else(|| A::Error::custom(INVALID_VALUE))?;
                        Some(value.0.0)
                    }
                    _ => return Err(A::Error::custom(INVALID_VALUE)),
                };
                let _ = seq.next_element::<RejectExtra>()?;
                Ok(WireHeaderField { code, signature })
            }
        }
        deserializer.deserialize_tuple(2, FieldVisitor)
    }
}

struct WireHeaderFields<'a> {
    // Absence is legal for an empty message, not for any nonempty codec.
    // Do not collapse absence into an empty signature during header traversal.
    signature: Option<&'a str>,
}

static WIRE_HEADER_FIELD_SIGNATURE: Signature =
    Signature::static_structure(&[&Signature::U8, &Signature::Variant]);

impl Type for WireHeaderFields<'_> {
    const SIGNATURE: &'static Signature =
        &Signature::static_array(&WIRE_HEADER_FIELD_SIGNATURE);
}

impl<'de> Deserialize<'de> for WireHeaderFields<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FieldsVisitor;
        impl<'de> Visitor<'de> for FieldsVisitor {
            type Value = WireHeaderFields<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("at most nine distinct known header fields")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut seen = 0u16;
                let mut signature = None;
                for _ in 0..9 {
                    let Some(field) = seq.next_element::<WireHeaderField<'de>>()? else {
                        // zvariant ends its array on None; do not probe it again.
                        return Ok(WireHeaderFields { signature });
                    };
                    // FieldVisitor admits only codes1..9, so the shift is bounded.
                    let bit = 1u16 << field.code;
                    if seen & bit != 0 {
                        return Err(A::Error::custom(INVALID_VALUE));
                    }
                    seen |= bit;
                    if field.code == 8 {
                        signature = field.signature;
                    }
                }
                // Do not return early upon finding the signature: later fields
                // must also satisfy the closed profile and duplicate prohibition.
                let _ = seq.next_element::<RejectExtra>()?;
                Ok(WireHeaderFields { signature })
            }
        }
        deserializer.deserialize_seq(FieldsVisitor)
    }
}

fn raw_wire_signature<'a>(body: &'a Body) -> Result<Option<&'a str>, Error> {
    // Reuse the SDK's primary header and standard a(yv) serde traversal. No
    // header offsets, endian words or signature grammar are parsed by hand.
    let data = body.message().data();
    let ((primary, fields), consumed): ((PrimaryHeader, WireHeaderFields<'a>), usize) =
        data.deserialize().map_err(|_| Error::InvalidReply)?;
    let body_start = data.len().checked_sub(body.len()).ok_or(Error::InvalidReply)?;
    let aligned_end = consumed
        .checked_add(7)
        .map(|end| end & !7)
        .ok_or(Error::InvalidReply)?;
    if primary.body_len() as usize != body.len() || aligned_end != body_start {
        return Err(Error::InvalidReply);
    }
    Ok(fields.signature)
}

fn wire_signature<'a>(body: &'a Body) -> Result<&'a str, Error> {
    raw_wire_signature(body)?.ok_or(Error::InvalidReply)
}

const BUS: &str = "org.freedesktop.DBus";
const BUS_PATH: &str = "/org/freedesktop/DBus";
const SERVICE: &str = "org.freedesktop.secrets";

struct BoundedName<'a>(&'a str);
impl Type for BoundedName<'_> {
    const SIGNATURE: &'static Signature = &Signature::Str;
}
impl ReplySignature for BoundedName<'_> {
    const WIRE_SIGNATURE: &'static str = "s";
}
impl<'de> Deserialize<'de> for BoundedName<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(BorrowedStrVisitor::<255>).map(Self)
    }
}
type OwnerChangedWire<'a> = (BoundedName<'a>, BoundedName<'a>, BoundedName<'a>);
impl ReplySignature for OwnerChangedWire<'_> {
    const WIRE_SIGNATURE: &'static str = "sss";
}

fn provider_name(value: &str) -> Result<&str, Error> {
    // zbus_names deliberately accepts the bus daemon as a special UniqueName;
    // it is never an admissible Secret Service provider identity here.
    if value == BUS || value.len() > 255 || UniqueName::try_from(value).is_err() {
        return Err(Error::InvalidReply);
    }
    Ok(value)
}

pub(crate) fn decode_name_owner<'a>(body: &'a Body) -> Result<&'a str, Error> {
    let bus = UniqueName::try_from(BUS).map_err(|_| Error::InvalidReply)?;
    provider_name(checked_body::<BoundedName<'a>>(body, &bus)?.0)
}

pub(crate) fn decode_owner_changed<'a>(body: &'a Body) -> Result<(Option<&'a str>, Option<&'a str>), Error> {
    let header = body.message().header();
    if header.path().map(|path| path.as_str()) != Some(BUS_PATH)
        || header.interface().map(|name| name.as_str()) != Some(BUS)
        || header.member().map(|name| name.as_str()) != Some("NameOwnerChanged")
    {
        return Err(Error::InvalidReply);
    }
    let bus = UniqueName::try_from(BUS).map_err(|_| Error::InvalidReply)?;
    let (name, old, new): OwnerChangedWire<'a> = checked_typed_body(body, &bus, MessageType::Signal)?;
    if name.0 != SERVICE { return Err(Error::InvalidReply); }
    let old = if old.0.is_empty() { None } else { Some(provider_name(old.0)?) };
    let new = if new.0.is_empty() { None } else { Some(provider_name(new.0)?) };
    Ok((old, new))
}

pub(crate) fn check_empty_bus_reply(body: &Body) -> Result<(), Error> {
    let bus = UniqueName::try_from(BUS).map_err(|_| Error::InvalidReply)?;
    check_empty_reply(body, &bus)
}

pub(crate) fn check_empty_owner_reply(body: &Body, sender: &UniqueName<'_>) -> Result<(), Error> {
    provider_name(sender.as_str())?;
    check_empty_reply(body, sender)
}

fn check_empty_reply(body: &Body, sender: &UniqueName<'_>) -> Result<(), Error> {
    checked_envelope(body, sender, MessageType::MethodReturn)?;
    // raw_wire_signature also checks the actual/primary body lengths and the
    // complete aligned header. Both legal empty-signature forms remain valid.
    if !matches!(raw_wire_signature(body)?, None | Some(""))
        || body.len() != 0 || body.signature() != &Signature::Unit
    {
        return Err(Error::InvalidReply);
    }
    Ok(())
}

type UnlockWire<'a> = (AtMostOnePath<'a>, BoundedPath<'a>);
type SecretWire<'a> = (
    BoundedPath<'a>,
    BorrowedBytes<'a, 16>,
    BorrowedBytes<'a, 48>,
    &'a str,
);
type OpenSessionWire<'a> = (Variant<'a, BorrowedBytes<'a, 128>>, BoundedPath<'a>);

impl ReplySignature for UnlockWire<'_> {
    const WIRE_SIGNATURE: &'static str = "aoo";
}

impl ReplySignature for SecretWire<'_> {
    const WIRE_SIGNATURE: &'static str = "(oayays)";
}

impl ReplySignature for OpenSessionWire<'_> {
    const WIRE_SIGNATURE: &'static str = "vo";
}

impl ReplySignature for Variant<'_, bool> {
    const WIRE_SIGNATURE: &'static str = "v";
}

impl<'a> ReplySignature for Variant<'a, Attributes<'a>> {
    const WIRE_SIGNATURE: &'static str = "v";
}

pub(crate) fn decode_read_alias<'a>(
    body: &'a Body,
    sender: &UniqueName<'_>,
) -> Result<BoundedPath<'a>, Error> {
    checked_body(body, sender)
}

pub(crate) fn decode_search_items<'a>(
    body: &'a Body,
    sender: &UniqueName<'_>,
) -> Result<AtMostOnePath<'a>, Error> {
    checked_body(body, sender)
}

/// Both fields are retained; neither a returned path nor emptiness proves finality.
pub(crate) struct UnlockReply<'a> {
    pub(crate) object_paths: AtMostOnePath<'a>,
    pub(crate) prompt: BoundedPath<'a>,
}

pub(crate) fn decode_unlock<'a>(
    body: &'a Body,
    sender: &UniqueName<'_>,
) -> Result<UnlockReply<'a>, Error> {
    let (object_paths, prompt): UnlockWire<'a> = checked_body(body, sender)?;
    Ok(UnlockReply { object_paths, prompt })
}

pub(crate) fn decode_locked<'a>(body: &'a Body, sender: &UniqueName<'_>) -> Result<bool, Error> {
    Ok(checked_body::<Variant<'a, bool>>(body, sender)?.0)
}

pub(crate) fn decode_attributes<'a>(
    body: &'a Body,
    sender: &UniqueName<'_>,
    expected: &[(&str, &str); 4],
) -> Result<Attributes<'a>, Error> {
    if body.len() > MAX_PROPERTY_BYTES {
        return Err(Error::InvalidReply);
    }
    let attributes = checked_body::<Variant<'a, Attributes<'a>>>(body, sender)?.0;
    // Four unique actual keys and four matched pairs also refuse duplicate or
    // missing expected keys. Expected names/values belong to the trusted caller.
    if !attributes.0.iter().flatten().all(|pair| expected.contains(pair)) {
        return Err(Error::InvalidReply);
    }
    Ok(attributes)
}

/// An encrypted borrowed envelope, not plaintext or a persistence receipt.
pub(crate) struct EncryptedSecret<'a> {
    pub(crate) session: BoundedPath<'a>,
    pub(crate) iv: &'a [u8; 16],
    pub(crate) ciphertext: &'a [u8; 48],
    pub(crate) content_type: &'a str,
}

pub(crate) fn decode_get_secret<'a>(
    body: &'a Body,
    sender: &UniqueName<'_>,
    expected_session: &ObjectPath<'_>,
) -> Result<EncryptedSecret<'a>, Error> {
    let (session, parameters, value, content_type): SecretWire<'a> = checked_body(body, sender)?;
    if session.as_str() != expected_session.as_str() || content_type != SECRET_CONTENT_TYPE {
        return Err(Error::InvalidReply);
    }
    let iv = parameters.0.try_into().map_err(|_| Error::InvalidReply)?;
    let ciphertext = value.0.try_into().map_err(|_| Error::InvalidReply)?;
    Ok(EncryptedSecret { session, iv, ciphertext, content_type })
}

/// Wire-bounded only: even empty peer bytes retain a valid returned session path
/// for cleanup. DH/domain validity belongs to the separate checked crypto step;
/// this view establishes neither a Session nor permission for a successor call.
pub(crate) struct WireBoundedOpenSession<'a> {
    pub(crate) peer_bytes: &'a [u8],
    pub(crate) session: BoundedPath<'a>,
}

pub(crate) fn decode_open_session<'a>(
    body: &'a Body,
    sender: &UniqueName<'_>,
) -> Result<WireBoundedOpenSession<'a>, Error> {
    let (output, session): OpenSessionWire<'a> = checked_body(body, sender)?;
    Ok(WireBoundedOpenSession { peer_bytes: output.0.0, session })
}

#[cfg(feature = "mrk-retrieval-test-support")]
pub(crate) fn assert_retrieval_empty_reply_helper() {
    tests::owner_empty_reply_is_not_a_bus_receipt_or_a_body_guess();
}

// Fixed native-fixture setup codecs only. Reuse the same raw-signature,
// owner/envelope, bounded borrowed path and complete-consumption checks. These
// helpers do not create a shipping collection/item creation API.
#[cfg(feature = "mrk-retrieval-test-support")]
pub(crate) mod native_fixture {
    use super::*;
    type Created<'a> = (BoundedPath<'a>, BoundedPath<'a>);
    impl ReplySignature for Created<'_> { const WIRE_SIGNATURE: &'static str = "oo"; }
    impl ReplySignature for u32 { const WIRE_SIGNATURE: &'static str = "u"; }

    pub fn decode_session_alias<'a>(body: &'a Body, owner: &UniqueName<'_>) -> Result<&'a str, Error> {
        let path = decode_read_alias(body, owner)?;
        if path.as_str() == "/" { return Err(Error::InvalidReply); }
        Ok(path.as_str())
    }
    pub fn decode_created_item<'a>(body: &'a Body, owner: &UniqueName<'_>) -> Result<&'a str, Error> {
        let (item, prompt): Created<'a> = checked_body(body, owner)?;
        if item.as_str() == "/" || prompt.as_str() != "/" { return Err(Error::InvalidReply); }
        Ok(item.as_str())
    }
    pub fn decode_bus_identity(body: &Body) -> Result<u32, Error> {
        let bus = UniqueName::try_from(BUS).map_err(|_| Error::InvalidReply)?;
        checked_body(body, &bus)
    }
    pub fn assert_setup_decoders() {
        use zbus::{Message, zvariant::ObjectPath};
        let owner = UniqueName::try_from(":1.23").unwrap();
        let call = Message::method_call("/", "Fixture").unwrap().build(&()).unwrap();
        let item = ObjectPath::try_from("/item").unwrap();
        let root = ObjectPath::try_from("/").unwrap();
        let prompt = ObjectPath::try_from("/prompt").unwrap();
        for (path, prompt, accepted) in [(item.clone(), root.clone(), true),
            (root.clone(), root.clone(), false), (item.clone(), prompt, false)] {
            let reply = Message::method_return(&call.header()).unwrap().sender(":1.23").unwrap()
                .build(&(path, prompt)).unwrap();
            assert_eq!(decode_created_item(&reply.body(), &owner).is_ok(), accepted);
        }
        let nested = Message::method_return(&call.header()).unwrap().sender(":1.23").unwrap()
            .build(&((item.clone(), root.clone()),)).unwrap();
        assert!(decode_created_item(&nested.body(), &owner).is_err());
        let reply = Message::method_return(&call.header()).unwrap().sender(":1.23").unwrap()
            .build(&(item.clone(), root.clone())).unwrap();
        assert!(decode_created_item(&reply.body(), &UniqueName::try_from(":1.24").unwrap()).is_err());
        let absent = Message::method_return(&call.header()).unwrap().sender(":1.23").unwrap().build(&root).unwrap();
        assert!(decode_session_alias(&absent.body(), &owner).is_err());
        let alias = Message::method_return(&call.header()).unwrap().sender(":1.23").unwrap().build(&item).unwrap();
        assert_eq!(decode_session_alias(&alias.body(), &owner).unwrap(), "/item");
        let id = Message::method_return(&call.header()).unwrap().sender(BUS).unwrap().build(&123u32).unwrap();
        assert_eq!(decode_bus_identity(&id.body()).unwrap(), 123);
        let false_id = Message::method_return(&call.header()).unwrap().sender(":1.23").unwrap().build(&123u32).unwrap();
        assert!(decode_bus_identity(&false_id.body()).is_err());
    }
}

#[cfg(any(test, feature = "mrk-retrieval-test-support"))]
mod tests {
    // Synthetic DATA only. These tests never connect to a bus or a keyring.
    // The crate's unfiltered legacy tests are NOT safe substitutes for this set.
    use super::*;
    use serde::ser::SerializeMap;
    use serde::{Serialize, Serializer};
    use zbus::Message;
    use zbus::zvariant::as_value::Serialize as AsVariant;
    use zbus::zvariant::{DynamicType, LE, serialized::Context, to_bytes};

    fn owner() -> UniqueName<'static> {
        UniqueName::try_from(":1.23").unwrap()
    }

    fn path(value: &str) -> ObjectPath<'_> {
        ObjectPath::try_from(value).unwrap()
    }

    fn reply_builder() -> zbus::message::Builder<'static> {
        let call = Message::method_call("/", "Test").unwrap().build(&()).unwrap();
        Message::method_return(&call.header())
            .unwrap()
            .sender(":1.23")
            .unwrap()
    }

    fn reply<T: Serialize + DynamicType>(value: &T) -> Message {
        reply_builder().build(value).unwrap()
    }

    fn raw_reply(bytes: &[u8], signature: Signature) -> Message {
        // SAFETY: initialized synthetic bytes with no FD indices; only fallible
        // local decoders inspect them. No message is dispatched to a connection.
        unsafe {
            reply_builder()
                .build_raw_body(
                    bytes,
                    signature,
                    #[cfg(unix)]
                    Vec::new(),
                )
                .unwrap()
        }
    }

    fn invalid<T>(result: Result<T, Error>) {
        assert!(matches!(result, Err(Error::InvalidReply)));
    }

    fn assert_borrowed(body: &Body, bytes: &[u8]) {
        let start = body.data().bytes().as_ptr() as usize;
        let end = start + body.len();
        let borrowed = bytes.as_ptr() as usize;
        assert!(borrowed >= start && borrowed + bytes.len() <= end);
    }

    // Test-only scalar admission fixture, not another supported operation.
    impl ReplySignature for &str {
        const WIRE_SIGNATURE: &'static str = "s";
    }

    // A signature-typed string retains parentheses through existing serialization.
    impl Serialize for BorrowedSignature<'_> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(self.0)
        }
    }

    fn rejected_header_codes(codes: &[u8]) {
        let signature = BorrowedSignature("o");
        let fields: Vec<_> = codes
            .iter()
            .map(|&code| (code, AsVariant(&signature)))
            .collect();
        let header = (PrimaryHeader::new(MessageType::MethodReturn, 0), fields);
        let encoded = to_bytes(Context::new_dbus(LE, 0), &header).unwrap();
        assert!(encoded.deserialize::<(PrimaryHeader, WireHeaderFields<'_>)>().is_err());
    }

    #[test]
    fn checked_admission_requires_exact_envelope_and_complete_data() {
        let sender = owner();
        let message = reply(&path("/item"));
        let body = message.body();
        let decoded = decode_read_alias(&body, &sender).unwrap();
        assert_eq!(decoded.as_str(), "/item");
        assert_borrowed(&body, decoded.as_str().as_bytes());
        // Synthetic positions do not prove bus ordering; they are merely retained.
        assert!(body.message().recv_position() == message.recv_position());

        let wrong_signature = reply(&"/item");
        let wrong_body = wrong_signature.body();
        invalid(decode_read_alias(&wrong_body, &sender));
        let wrong_sender = reply_builder().sender(":1.24").unwrap().build(&path("/item")).unwrap();
        let wrong_body = wrong_sender.body();
        invalid(decode_read_alias(&wrong_body, &sender));

        let call = Message::method_call("/", "Test").unwrap().build(&()).unwrap();
        let absent_sender = Message::method_return(&call.header()).unwrap().build(&path("/item")).unwrap();
        let absent_body = absent_sender.body();
        invalid(decode_read_alias(&absent_body, &sender));
        let wrong_type = Message::signal("/", "org.example.Test", "Reply")
            .unwrap().sender(":1.23").unwrap().build(&path("/item")).unwrap();
        let wrong_body = wrong_type.body();
        invalid(decode_read_alias(&wrong_body, &sender));
        let method_error = Message::error(&call.header(), "org.example.Refused")
            .unwrap().sender(":1.23").unwrap().build(&path("/item")).unwrap();
        let error_body = method_error.body();
        invalid(decode_read_alias(&error_body, &sender));

        let mut trailing = body.data().bytes().to_vec();
        trailing.push(0);
        let trailing_message = raw_reply(&trailing, Signature::ObjectPath);
        let trailing_body = trailing_message.body();
        invalid(decode_read_alias(&trailing_body, &sender));

        // The body alone fits exactly; the complete DATA (header included) does not.
        let text = "x".repeat(MAX_MESSAGE_BYTES - 5);
        let oversized = reply(&text.as_str());
        let oversized_body = oversized.body();
        assert_eq!(oversized_body.len(), MAX_MESSAGE_BYTES);
        assert!(oversized.data().len() > MAX_MESSAGE_BYTES);
        invalid(checked_body::<&str>(&oversized_body, &sender));

        // An absent signature is now preserved for empty bus replies only;
        // all nonempty codecs still require their exact present signature.
        rejected_header_codes(&[8, 8]);   // duplicate after the first signature
        rejected_header_codes(&[10]);     // unknown code
        rejected_header_codes(&[8, 10]);  // must not stop at the signature
        assert_eq!(Error::InvalidReply.to_string(), "SS error: invalid reply");
    }

    #[test]
    fn paths_are_borrowed_bounded_and_unlock_keeps_both_results() {
        let sender = owner();
        let paths = [path("/one"), path("/two")];
        for count in 0..=2 {
            let slice = &paths[..count];
            let message = reply(&slice);
            let body = message.body();
            let result = decode_search_items(&body, &sender);
            if count == 2 {
                invalid(result);
            } else {
                let result = result.unwrap();
                assert_eq!(
                    result.0.as_ref().map(|value| value.as_str()),
                    slice.first().map(|value| value.as_str()),
                );
            }
        }

        let root_message = reply(&path("/"));
        let root_body = root_message.body();
        assert_eq!(decode_read_alias(&root_body, &sender).unwrap().as_str(), "/");
        for length in [MAX_PATH_BYTES, MAX_PATH_BYTES + 1] {
            let value = format!("/{}", "a".repeat(length - 1));
            let message = reply(&path(&value));
            let body = message.body();
            let result = decode_read_alias(&body, &sender);
            if length == MAX_PATH_BYTES {
                let result = result.unwrap();
                assert_eq!(result.into_owned().unwrap().as_str(), value);
            } else {
                invalid(result);
            }
        }
        for value in ["/bad-path", "relative", "/empty//part"] {
            let string_message = reply(&value);
            let string_body = string_message.body();
            let message = raw_reply(string_body.data().bytes(), Signature::ObjectPath);
            let body = message.body();
            invalid(decode_read_alias(&body, &sender));
        }

        let one = &paths[..1];
        let message = reply(&(one, path("/prompt")));
        let body = message.body();
        let decoded = decode_unlock(&body, &sender).unwrap();
        assert_eq!(decoded.object_paths.0.unwrap().as_str(), "/one");
        assert_eq!(decoded.prompt.as_str(), "/prompt");
        assert_eq!(wire_signature(&body).unwrap(), "aoo");
        let nested = reply(&((one, path("/prompt")),));
        let nested_body = nested.body();
        assert_eq!(body.signature(), nested_body.signature());
        assert_eq!(wire_signature(&nested_body).unwrap(), "(aoo)");
        invalid(decode_unlock(&nested_body, &sender));

        let empty = &paths[..0];
        let message = reply(&(empty, path("/prompt")));
        let body = message.body();
        let decoded = decode_unlock(&body, &sender).unwrap();
        assert!(decoded.object_paths.0.is_none());
        assert_eq!(decoded.prompt.as_str(), "/prompt");
        let two = &paths[..];
        let message = reply(&(two, path("/")));
        let body = message.body();
        invalid(decode_unlock(&body, &sender));
    }

    struct Entries<'a>(&'a [(&'a str, &'a str)]);

    impl Type for Entries<'_> {
        const SIGNATURE: &'static Signature = Attributes::SIGNATURE;
    }

    impl Serialize for Entries<'_> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut map = serializer.serialize_map(Some(self.0.len()))?;
            for (key, value) in self.0 {
                map.serialize_entry(key, value)?;
            }
            map.end()
        }
    }

    fn attributes_reply(entries: &[(&str, &str)]) -> Message {
        reply(&AsVariant(&Entries(entries)))
    }

    #[test]
    fn attributes_match_exactly_four_pairs_and_enforce_limits() {
        let sender = owner();
        let expected = [("a", "1"), ("b", "2"), ("c", "3"), ("d", "4")];
        let reordered = [expected[3], expected[1], expected[0], expected[2]];
        let message = attributes_reply(&reordered);
        let body = message.body();
        let decoded = decode_attributes(&body, &sender, &expected).unwrap();
        for (key, value) in decoded.0.into_iter().flatten() {
            assert_borrowed(&body, key.as_bytes());
            assert_borrowed(&body, value.as_bytes());
        }

        let duplicate = [expected[0], expected[0], expected[2], expected[3]];
        let extra = [expected[0], expected[1], expected[2], expected[3], ("e", "5")];
        let wrong = [("a", "wrong"), expected[1], expected[2], expected[3]];
        let unknown = [("other", "1"), expected[1], expected[2], expected[3]];
        for entries in [&expected[..3], &duplicate[..], &extra[..], &wrong[..], &unknown[..]] {
            let message = attributes_reply(entries);
            let body = message.body();
            invalid(decode_attributes(&body, &sender, &expected));
        }
        invalid(decode_attributes(&body, &sender, &duplicate));

        let key_at_limit = "k".repeat(64);
        let value_at_limit = "v".repeat(256);
        let limits = [
            (key_at_limit.as_str(), value_at_limit.as_str()),
            expected[1], expected[2], expected[3],
        ];
        let message = attributes_reply(&limits);
        let limit_body = message.body();
        decode_attributes(&limit_body, &sender, &limits).unwrap();
        let long_key = "k".repeat(65);
        let long_value = "v".repeat(257);
        for pairs in [
            [(long_key.as_str(), "1"), expected[1], expected[2], expected[3]],
            [("a", long_value.as_str()), expected[1], expected[2], expected[3]],
        ] {
            let message = attributes_reply(&pairs);
            let body = message.body();
            invalid(decode_attributes(&body, &sender, &pairs));
        }

        let mut oversized = body.data().bytes().to_vec();
        oversized.resize(MAX_PROPERTY_BYTES + 1, 0);
        let message = raw_reply(&oversized, Signature::Variant);
        let body = message.body();
        invalid(decode_attributes(&body, &sender, &expected));
    }

    #[test]
    fn known_variants_reject_wrong_inner_types() {
        let sender = owner();
        let message = reply(&AsVariant(&true));
        let body = message.body();
        assert!(decode_locked(&body, &sender).unwrap());
        let wrong = reply(&AsVariant(&"true"));
        let wrong_body = wrong.body();
        invalid(decode_locked(&wrong_body, &sender));

        let expected = [("a", "1"), ("b", "2"), ("c", "3"), ("d", "4")];
        invalid(decode_attributes(&body, &sender, &expected));
        let wrong_open = reply(&(AsVariant(&true), path("/session")));
        let wrong_body = wrong_open.body();
        invalid(decode_open_session(&wrong_body, &sender));
        // A fixed Rust array is a D-Bus structure, not the required byte array.
        let wrong_open = reply(&(AsVariant(&[1u8, 2, 3]), path("/session")));
        let wrong_body = wrong_open.body();
        invalid(decode_open_session(&wrong_body, &sender));
    }

    fn secret_reply(session: &str, iv: &[u8], ciphertext: &[u8], content_type: &str) -> Message {
        // One method-result argument containing the nested Secret structure.
        reply(&((path(session), iv, ciphertext, content_type),))
    }

    #[test]
    fn secret_envelope_requires_exact_session_sizes_and_content_type() {
        let sender = owner();
        let expected_session = path("/session");
        let message = secret_reply("/session", &[1; 16], &[2; 48], SECRET_CONTENT_TYPE);
        let body = message.body();
        let decoded = decode_get_secret(&body, &sender, &expected_session).unwrap();
        assert_eq!(decoded.session.as_str(), "/session");
        assert_eq!(decoded.iv, &[1; 16]);
        assert_eq!(decoded.ciphertext, &[2; 48]);
        assert_eq!(decoded.content_type, SECRET_CONTENT_TYPE);
        assert_borrowed(&body, decoded.iv);
        assert_borrowed(&body, decoded.ciphertext);
        assert_borrowed(&body, decoded.content_type.as_bytes());
        assert_eq!(wire_signature(&body).unwrap(), "(oayays)");

        let iv: &[u8] = &[1; 16];
        let ciphertext: &[u8] = &[2; 48];
        let flattened = reply(&(path("/session"), iv, ciphertext, SECRET_CONTENT_TYPE));
        let flattened_body = flattened.body();
        assert_eq!(body.signature(), flattened_body.signature());
        assert_eq!(wire_signature(&flattened_body).unwrap(), "oayays");
        invalid(decode_get_secret(&flattened_body, &sender, &expected_session));
        invalid(decode_get_secret(&body, &sender, &path("/other")));
        for length in [0, 15, 17] {
            let iv = vec![1; length];
            let message = secret_reply("/session", &iv, ciphertext, SECRET_CONTENT_TYPE);
            let body = message.body();
            invalid(decode_get_secret(&body, &sender, &expected_session));
        }
        for length in [0, 47, 49] {
            let ciphertext = vec![2; length];
            let message = secret_reply("/session", iv, &ciphertext, SECRET_CONTENT_TYPE);
            let body = message.body();
            invalid(decode_get_secret(&body, &sender, &expected_session));
        }
        for content_type in ["", "text/plain", "application/octet-stream "] {
            let message = secret_reply("/session", iv, ciphertext, content_type);
            let body = message.body();
            invalid(decode_get_secret(&body, &sender, &expected_session));
        }
    }

    #[test]
    fn open_session_is_only_wire_bounded_and_preserves_multi_result_shape() {
        let sender = owner();
        for length in [0, 1, 128, 129] {
            let bytes = vec![7u8; length];
            let slice = bytes.as_slice();
            let message = reply(&(AsVariant(&slice), path("/session")));
            let body = message.body();
            let result = decode_open_session(&body, &sender);
            if length <= 128 {
                let decoded = result.unwrap();
                assert_eq!(decoded.peer_bytes, slice);
                assert_eq!(decoded.session.as_str(), "/session");
                assert_borrowed(&body, decoded.peer_bytes);
            } else {
                invalid(result);
            }
        }

        let bytes: &[u8] = &[7];
        let message = reply(&(AsVariant(&bytes), path("/session")));
        let body = message.body();
        let nested = reply(&((AsVariant(&bytes), path("/session")),));
        let nested_body = nested.body();
        assert_eq!(wire_signature(&body).unwrap(), "vo");
        assert_eq!(wire_signature(&nested_body).unwrap(), "(vo)");
        assert_eq!(body.signature(), nested_body.signature());
        invalid(decode_open_session(&nested_body, &sender));
        // No DH/domain or established-session assertion belongs to these fixtures.
    }

    struct BusFields<'a> { signature: Option<&'a str>, descriptors: u32, sender: &'a str }
    impl Type for BusFields<'_> {
        const SIGNATURE: &'static Signature = WireHeaderFields::SIGNATURE;
    }
    impl Serialize for BusFields<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeSeq;
            let mut fields = serializer.serialize_seq(None)?;
            fields.serialize_element(&(5u8, AsVariant(&1u32)))?;
            fields.serialize_element(&(7u8, AsVariant(&self.sender)))?;
            if let Some(signature) = self.signature {
                fields.serialize_element(&(8u8, AsVariant(&BorrowedSignature(signature))))?;
            }
            fields.serialize_element(&(9u8, AsVariant(&self.descriptors)))?;
            fields.end()
        }
    }
    fn raw_bus_reply(signature: Option<&str>, primary_len: u32, body: &[u8], descriptors: u32) -> Message {
        raw_empty_reply(BUS, signature, primary_len, body, descriptors)
    }
    fn raw_empty_reply(sender: &str, signature: Option<&str>, primary_len: u32, body: &[u8], descriptors: u32) -> Message {
        let header = (PrimaryHeader::new(MessageType::MethodReturn, primary_len), BusFields { signature, descriptors, sender });
        let data = to_bytes(Context::new_dbus(LE, 0), &header).unwrap();
        let mut bytes = data.bytes().to_vec();
        bytes.resize((bytes.len() + 7) & !7, 0);
        bytes.extend_from_slice(body);
        // SAFETY: bounded initialized synthetic DATA with no attached FDs or FD
        // indices. Fallible local decoders only; synthetic recv_position is zero.
        unsafe { Message::from_bytes(zbus::zvariant::serialized::Data::new(bytes, Context::new_dbus(LE, 0))).unwrap() }
    }

    #[test]
    fn bus_empty_replies_preserve_absence_and_require_both_empty_lengths() {
        for signature in [None, Some("")] {
            let message = raw_bus_reply(signature, 0, &[], 0);
            let body = message.body();
            assert_eq!(raw_wire_signature(&body).unwrap(), signature);
            check_empty_bus_reply(&body).unwrap();
            invalid(decode_name_owner(&body)); // absence never admits nonempty codecs
            invalid(check_empty_bus_reply(&raw_bus_reply(signature, 1, &[0], 0).body()));
            invalid(check_empty_bus_reply(&raw_bus_reply(signature, 1, &[], 0).body()));
            invalid(check_empty_bus_reply(&raw_bus_reply(signature, 0, &[0], 0).body()));
            invalid(check_empty_bus_reply(&raw_bus_reply(signature, 0, &[], 1).body()));
        }
        invalid(check_empty_bus_reply(&raw_bus_reply(Some("s"), 0, &[], 0).body()));
        let normal_empty = reply_builder().sender(BUS).unwrap().build(&()).unwrap();
        check_empty_bus_reply(&normal_empty.body()).unwrap();
        invalid(check_empty_bus_reply(&reply(&()).body()));
        let owner = reply_builder().sender(BUS).unwrap().build(&":1.23").unwrap();
        let owner_body = owner.body();
        let absent = raw_bus_reply(None, owner_body.len() as u32, owner_body.data().bytes(), 0);
        invalid(decode_name_owner(&absent.body()));
    }

    #[cfg_attr(test, test)]
    pub(super) fn owner_empty_reply_is_not_a_bus_receipt_or_a_body_guess() {
        let owner = owner();
        for signature in [None, Some("")] {
            let message = raw_empty_reply(owner.as_str(), signature, 0, &[], 0);
            check_empty_owner_reply(&message.body(), &owner).unwrap();
            invalid(check_empty_bus_reply(&message.body()));
            invalid(check_empty_owner_reply(&raw_empty_reply(":1.24", signature, 0, &[], 0).body(), &owner));
            invalid(check_empty_owner_reply(&raw_empty_reply(owner.as_str(), signature, 1, &[0], 0).body(), &owner));
            invalid(check_empty_owner_reply(&raw_empty_reply(owner.as_str(), signature, 1, &[], 0).body(), &owner));
            invalid(check_empty_owner_reply(&raw_empty_reply(owner.as_str(), signature, 0, &[0], 0).body(), &owner));
            invalid(check_empty_owner_reply(&raw_empty_reply(owner.as_str(), signature, 0, &[], 1).body(), &owner));
        }
        invalid(check_empty_owner_reply(&raw_empty_reply(owner.as_str(), Some("s"), 0, &[], 0).body(), &owner));
        let bus = UniqueName::try_from(BUS).unwrap();
        invalid(check_empty_owner_reply(&raw_bus_reply(None, 0, &[], 0).body(), &bus));
        let call = Message::method_call("/", "Test").unwrap().build(&()).unwrap();
        let error = Message::error(&call.header(), "org.example.Refused").unwrap()
            .sender(owner.clone()).unwrap().build(&()).unwrap();
        invalid(check_empty_owner_reply(&error.body(), &owner));
        let signal = Message::signal("/session", "org.example.Test", "Closed").unwrap()
            .sender(owner.clone()).unwrap().build(&()).unwrap();
        invalid(check_empty_owner_reply(&signal.body(), &owner));
        invalid(check_empty_owner_reply(&reply(&0u32).body(), &owner));
    }

    fn owner_signal<T: Serialize + DynamicType>(value: &T) -> Message {
        Message::signal(BUS_PATH, BUS, "NameOwnerChanged").unwrap().sender(BUS).unwrap().build(value).unwrap()
    }

    #[test]
    fn owner_views_reject_nonprovider_names_and_inexact_event_envelopes() {
        let message = reply_builder().sender(BUS).unwrap().build(&":1.23").unwrap();
        let body = message.body();
        let selected = decode_name_owner(&body).unwrap();
        assert_eq!(selected, ":1.23");
        assert_borrowed(&body, selected.as_bytes());
        invalid(decode_name_owner(&reply(&":1.23").body()));
        for value in ["", BUS, SERVICE, ":invalid", ":bad space.1"] {
            let message = reply_builder().sender(BUS).unwrap().build(&value).unwrap();
            invalid(decode_name_owner(&message.body()));
        }
        let long = format!(":1.{}", "x".repeat(253));
        let message = reply_builder().sender(BUS).unwrap().build(&long.as_str()).unwrap();
        invalid(decode_name_owner(&message.body()));
        for values in [(SERVICE, "", ":1.23"), (SERVICE, ":1.23", ""), (SERVICE, ":1.23", ":1.24")] {
            let message = owner_signal(&values);
            let body = message.body();
            let (old, new) = decode_owner_changed(&body).unwrap();
            assert_eq!(old, (!values.1.is_empty()).then_some(values.1));
            assert_eq!(new, (!values.2.is_empty()).then_some(values.2));
        }
        let value = (SERVICE, ":1.23", ":1.24");
        invalid(decode_owner_changed(&owner_signal(&(value,)).body())); // (sss) != sss
        for value in [("org.example.Other", ":1.23", ""), (SERVICE, BUS, ""), (SERVICE, "", SERVICE)] {
            invalid(decode_owner_changed(&owner_signal(&value).body()));
        }
        for (sender, path, interface, member) in [
            (":1.23", BUS_PATH, BUS, "NameOwnerChanged"),
            (BUS, "/wrong", BUS, "NameOwnerChanged"),
            (BUS, BUS_PATH, "org.example.Other", "NameOwnerChanged"),
            (BUS, BUS_PATH, BUS, "Other"),
        ] {
            let message = Message::signal(path, interface, member).unwrap().sender(sender).unwrap().build(&value).unwrap();
            invalid(decode_owner_changed(&message.body()));
        }
        let wrong_type = reply_builder().sender(BUS).unwrap().build(&value).unwrap();
        invalid(decode_owner_changed(&wrong_type.body()));
        let message = owner_signal(&value);
        let body = message.body();
        let mut trailing = body.data().bytes().to_vec(); trailing.push(0);
        // SAFETY: initialized synthetic string DATA, no FD indices or native IO.
        let trailing = unsafe { Message::signal(BUS_PATH, BUS, "NameOwnerChanged").unwrap().sender(BUS).unwrap()
            .build_raw_body(&trailing, body.signature().clone(), #[cfg(unix)] Vec::new()).unwrap() };
        invalid(decode_owner_changed(&trailing.body()));
        let huge = "x".repeat(MAX_MESSAGE_BYTES);
        invalid(decode_owner_changed(&owner_signal(&(SERVICE, "", huge.as_str())).body()));
    }
}
