//! Narrow raw lookup and existing-unlocked-key calls for an original owner.
//!
//! The additive owned retrieval starters open only encrypted sessions; they do
//! not unlock, prompt, create keys, or follow a replacement owner/item. Keep
//! every original success/MethodError Message until
//! its same-connection owner stream is reconciled through `recv_position()`.
//! These are post-allocation bounds, not transport or task-finality guarantees.

use crate::{bounded_reply, Error};
use serde::{ser::SerializeMap, Serialize, Serializer};
use zbus::{message::Body, names::UniqueName, Connection, Message};
use zbus::zvariant::{ObjectPath, Signature, Type};

#[cfg(feature = "crypto-rust")]
pub use crate::session::{
    CheckedDhExchange, CheckedSessionKey, RETRIEVAL_CRYPTO_BYTES, WrappingKeyCandidate,
};

const ITEM_INTERFACE: &str = "org.freedesktop.Secret.Item";
const ATTRIBUTES_PROPERTY: &str = "Attributes";
const PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const SERVICE_INTERFACE: &str = "org.freedesktop.Secret.Service";
const SESSION_INTERFACE: &str = "org.freedesktop.Secret.Session";

// A tuple array is a(ss), not the Collection.SearchItems a{ss} argument.
struct Query<'a>(&'a [(&'a str, &'a str); 4]);
impl Type for Query<'_> {
    const SIGNATURE: &'static Signature = &Signature::static_dict(&Signature::Str, &Signature::Str);
}
impl Serialize for Query<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(4))?;
        for (key, value) in self.0 { map.serialize_entry(key, value)?; }
        map.end()
    }
}
fn query<'a>(attributes: &'a [(&'a str, &'a str); 4]) -> zbus::Result<Query<'a>> {
    for (index, (key, value)) in attributes.iter().enumerate() {
        if key.is_empty() || key.len() > 64 || value.len() > 256
            || key.contains('\0') || value.contains('\0')
            || attributes[..index].iter().any(|(seen, _)| seen == key)
        {
            return Err(zbus::Error::InvalidField);
        }
    }
    Ok(Query(attributes))
}
fn route(owner: &UniqueName<'_>, path: &ObjectPath<'_>) -> zbus::Result<()> {
    if owner.as_str() == "org.freedesktop.DBus" || path.as_str().len() > 512 {
        return Err(zbus::Error::InvalidField);
    }
    Ok(())
}
fn attributes_body() -> (&'static str, &'static str) { (ITEM_INTERFACE, ATTRIBUTES_PROPERTY) }
fn locked_body() -> (&'static str, &'static str) { (ITEM_INTERFACE, "Locked") }
fn nonroot_route(owner: &UniqueName<'_>, path: &ObjectPath<'_>) -> zbus::Result<()> {
    route(owner, path)?;
    if path.as_str() == "/" { return Err(zbus::Error::InvalidField); }
    Ok(())
}

/// One collection lookup to the supplied immutable unique destination.
/// An input error occurs before dispatch; all actual remote results stay raw.
pub async fn search_items_reply(
    connection: &Connection, owner: &UniqueName<'_>, collection: &ObjectPath<'_>,
    attributes: &[(&str, &str); 4],
) -> zbus::Result<Message> {
    route(owner, collection)?;
    let body = query(attributes)?;
    connection.call_method(Some(owner.clone()), collection, Some("org.freedesktop.Secret.Collection"), "SearchItems", &body).await
}

/// One exact Properties.Get on an already-bounded item, with no property cache.
pub async fn attributes_reply(
    connection: &Connection, owner: &UniqueName<'_>, item: &ObjectPath<'_>,
) -> zbus::Result<Message> {
    route(owner, item)?;
    if item.as_str() == "/" { return Err(zbus::Error::InvalidField); }
    connection.call_method(Some(owner.clone()), item, Some("org.freedesktop.DBus.Properties"), "Get", &attributes_body()).await
}

// The fixed owned connection cannot lend out an ordinary Connection (or a
// MessageStream convertible back into one). These concrete starters reuse
// the same validators and request body, but retain owned arguments in its one
// original RPC slot. They do not first-poll a native operation.
#[cfg(all(unix, feature = "rt-tokio"))]
struct OwnedQuery([(String, String); 4]);
#[cfg(all(unix, feature = "rt-tokio"))]
impl Type for OwnedQuery {
    const SIGNATURE: &'static Signature = Query::SIGNATURE;
}
#[cfg(all(unix, feature = "rt-tokio"))]
impl Serialize for OwnedQuery {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let pairs = self.0.each_ref().map(|(key, value)| (key.as_str(), value.as_str()));
        Query(&pairs).serialize(serializer)
    }
}

/// Stage the same bounded SearchItems call in a fixed owned original attempt.
#[cfg(all(unix, feature = "rt-tokio"))]
pub fn start_owned_search_items(
    attempt: &mut zbus::connection::OwnedConnectionAttempt,
    owner: &UniqueName<'_>, collection: &ObjectPath<'_>, attributes: &[(&str, &str); 4],
) -> zbus::Result<()> {
    route(owner, collection)?;
    query(attributes)?;
    let body = OwnedQuery(attributes.map(|(key, value)| (key.to_owned(), value.to_owned())));
    attempt.start_raw_call(
        owner.as_str().to_owned().try_into()?, collection.as_str().to_owned().try_into()?,
        "org.freedesktop.Secret.Collection".try_into()?, "SearchItems".try_into()?, body,
    )
}

/// Stage the same fixed Properties.Get, without a proxy or property-cache task.
#[cfg(all(unix, feature = "rt-tokio"))]
pub fn start_owned_attributes(
    attempt: &mut zbus::connection::OwnedConnectionAttempt,
    owner: &UniqueName<'_>, item: &ObjectPath<'_>,
) -> zbus::Result<()> {
    route(owner, item)?;
    if item.as_str() == "/" { return Err(zbus::Error::InvalidField); }
    attempt.start_raw_call(
        owner.as_str().to_owned().try_into()?, item.as_str().to_owned().try_into()?,
        "org.freedesktop.DBus.Properties".try_into()?, "Get".try_into()?, attributes_body(),
    )
}

/// Stage exactly Properties.Get(Item, Locked); never prompt or unlock.
#[cfg(all(unix, feature = "rt-tokio"))]
pub fn start_owned_locked(
    attempt: &mut zbus::connection::OwnedConnectionAttempt,
    owner: &UniqueName<'_>, item: &ObjectPath<'_>,
) -> zbus::Result<()> {
    nonroot_route(owner, item)?;
    attempt.start_raw_call(
        owner.as_str().to_owned().try_into()?, item.as_str().to_owned().try_into()?,
        PROPERTIES_INTERFACE.try_into()?, "Get".try_into()?, locked_body(),
    )
}

// Own only the fixed public bytes. A Rust [u8;128] is otherwise a structure,
// not ay; the actual serializer deliberately emits its slice in a variant.
#[cfg(all(unix, feature = "rt-tokio"))]
struct OpenSessionBody([u8; 128]);
#[cfg(all(unix, feature = "rt-tokio"))]
impl Type for OpenSessionBody {
    const SIGNATURE: &'static Signature =
        &Signature::static_structure(&[&Signature::Str, &Signature::Variant]);
}
#[cfg(all(unix, feature = "rt-tokio"))]
impl Serialize for OpenSessionBody {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use zbus::zvariant::as_value::Serialize as AsVariant;
        let public: &[u8] = &self.0;
        (crate::ss::ALGORITHM_DH, AsVariant(&public)).serialize(serializer)
    }
}

/// Stage one fixed encrypted OpenSession. Caller records possible creation at
/// FIRST POLL, retaining any subsequently decoded valid path even if DH fails.
#[cfg(all(unix, feature = "rt-tokio"))]
pub fn start_owned_open_session(
    attempt: &mut zbus::connection::OwnedConnectionAttempt,
    owner: &UniqueName<'_>, public_key: &[u8; 128],
) -> zbus::Result<()> {
    let service = ObjectPath::try_from(SERVICE_PATH)?;
    nonroot_route(owner, &service)?;
    attempt.start_raw_call(
        owner.as_str().to_owned().try_into()?, SERVICE_PATH.try_into()?,
        SERVICE_INTERFACE.try_into()?, "OpenSession".try_into()?, OpenSessionBody(*public_key),
    )
}

/// Stage one GetSecret to the selected item and retained original session.
#[cfg(all(unix, feature = "rt-tokio"))]
pub fn start_owned_get_secret(
    attempt: &mut zbus::connection::OwnedConnectionAttempt,
    owner: &UniqueName<'_>, item: &ObjectPath<'_>, session: &ObjectPath<'_>,
) -> zbus::Result<()> {
    nonroot_route(owner, item)?;
    nonroot_route(owner, session)?;
    let session: zbus::zvariant::OwnedObjectPath = session.as_str().to_owned().try_into()?;
    attempt.start_raw_call(
        owner.as_str().to_owned().try_into()?, item.as_str().to_owned().try_into()?,
        ITEM_INTERFACE.try_into()?, "GetSecret".try_into()?, session,
    )
}

/// Stage an explicit Close to the original unique owner/path; no proxy Drop.
#[cfg(all(unix, feature = "rt-tokio"))]
pub fn start_owned_close_session(
    attempt: &mut zbus::connection::OwnedConnectionAttempt,
    owner: &UniqueName<'_>, session: &ObjectPath<'_>,
) -> zbus::Result<()> {
    nonroot_route(owner, session)?;
    attempt.start_raw_call(
        owner.as_str().to_owned().try_into()?, session.as_str().to_owned().try_into()?,
        SESSION_INTERFACE.try_into()?, "Close".try_into()?, (),
    )
}

/// Borrow zero or one <=512-byte item path; `/` is never an item candidate.
pub fn decode_item_path<'a>(body: &'a Body, owner: &UniqueName<'_>) -> Result<Option<&'a str>, Error> {
    let path = bounded_reply::decode_search_items(body, owner)?.0;
    match path {
        Some(path) if path.as_str() == "/" => Err(Error::InvalidReply),
        Some(path) => Ok(Some(path.as_str())),
        None => Ok(None),
    }
}

/// Accept exactly the four bounded distinct expected attribute pairs.
pub fn check_attributes(body: &Body, owner: &UniqueName<'_>, expected: &[(&str, &str); 4]) -> Result<(), Error> {
    query(expected).map_err(|_| Error::InvalidReply)?;
    bounded_reply::decode_attributes(body, owner, expected).map(|_| ())
}

/// Borrow the bounded provider name from a checked bus GetNameOwner reply.
pub fn decode_name_owner<'a>(body: &'a Body) -> Result<&'a str, Error> {
    bounded_reply::decode_name_owner(body)
}

/// Check the fixed Secret Service NameOwnerChanged signal without generic DATA decoding.
pub fn decode_owner_changed<'a>(body: &'a Body) -> Result<(Option<&'a str>, Option<&'a str>), Error> {
    bounded_reply::decode_owner_changed(body)
}

/// Check the successful, exactly-empty bus AddMatch/RemoveMatch reply.
pub fn check_empty_bus_reply(body: &Body) -> Result<(), Error> {
    bounded_reply::check_empty_bus_reply(body)
}

/// One borrowed, owner-validated Locked property. True is a refusal, not consent.
pub fn decode_locked(body: &Body, owner: &UniqueName<'_>) -> Result<bool, Error> {
    bounded_reply::decode_locked(body, owner)
}

/// Borrow (peer, nonroot original session path). Empty or semantically bad DH
/// peers STILL return their valid path: retain it before the separate derive.
/// Wire-malformed, oversized or wrong-owner tuples cannot supply a cleanup path.
pub fn decode_open_session<'a>(
    body: &'a Body, owner: &UniqueName<'_>,
) -> Result<(&'a [u8], &'a str), Error> {
    let reply = bounded_reply::decode_open_session(body, owner)?;
    if reply.session.as_str() == "/" { return Err(Error::InvalidReply); }
    Ok((reply.peer_bytes, reply.session.as_str()))
}

/// Borrow only the checked IV16/ciphertext48 pair for this exact session/type.
pub fn decode_get_secret<'a>(
    body: &'a Body, owner: &UniqueName<'_>, session: &ObjectPath<'_>,
) -> Result<(&'a [u8; 16], &'a [u8; 48]), Error> {
    nonroot_route(owner, session).map_err(|_| Error::InvalidReply)?;
    let reply = bounded_reply::decode_get_secret(body, owner, session)?;
    Ok((reply.iv, reply.ciphertext))
}

/// Exactly empty MethodReturn from the original provider, not a bus receipt.
/// Original request routing and later owner reconciliation remain the caller's.
pub fn check_empty_owner_reply(body: &Body, owner: &UniqueName<'_>) -> Result<(), Error> {
    bounded_reply::check_empty_owner_reply(body, owner)
}

/// Inert fixtures/assertions only, excluded from the normal dependency graph.
#[cfg(feature = "mrk-retrieval-test-support")]
pub mod test_support {
    pub use crate::session::test_support::{assert_crypto_helpers, exchange_and_secret};

    pub fn assert_facade_helpers() {
        #[cfg(all(unix, feature = "rt-tokio"))]
        super::tests::retrieval_request_bodies_and_nonroot_routes_are_fixed();
        super::tests::retrieval_views_preserve_path_before_peer_validity();
        super::tests::retrieval_secret_and_close_views_are_exact();
        crate::bounded_reply::assert_retrieval_empty_reply_helper();
    }
}

#[cfg(any(test, feature = "mrk-retrieval-test-support"))]
mod tests {
    // Synthetic DATA only; never open a session bus, provider or item.
    use super::*;
    use zbus::zvariant::as_value::Serialize as AsVariant;

    fn reply<T: Serialize + zbus::zvariant::DynamicType>(value: &T) -> Message {
        let call = Message::method_call("/", "Test").unwrap().build(&()).unwrap();
        Message::method_return(&call.header()).unwrap().sender(":1.23").unwrap().build(value).unwrap()
    }
    fn attrs() -> [(&'static str, &'static str); 4] {
        [("application", "dev.mobile-release-kit.desktop"), ("purpose", "vault-wrapping-key-v1"),
            ("vault-id", "reserved-vault"), ("generation-id", "reserved-generation")]
    }
    #[test]
    fn actual_request_bodies_are_a_dict_and_two_strings() {
        let expected = attrs();
        let body = query(&expected).unwrap();
        let call = Message::method_call("/collection", "SearchItems").unwrap().build(&body).unwrap();
        let call_body = call.body();
        assert_eq!(call_body.signature(), Query::SIGNATURE);
        let decoded: std::collections::HashMap<&str, &str> = call_body.deserialize().unwrap();
        assert_eq!(decoded.len(), 4);
        for (key, value) in expected { assert_eq!(decoded.get(key), Some(&value)); }
        #[cfg(all(unix, feature = "rt-tokio"))]
        {
            let owned = OwnedQuery(expected.map(|(key, value)| (key.to_owned(), value.to_owned())));
            let owned_call = Message::method_call("/collection", "SearchItems").unwrap().build(&owned).unwrap();
            let owned_body = owned_call.body();
            assert_eq!(owned_body.signature(), call_body.signature());
            assert_eq!(owned_body.data().bytes(), call_body.data().bytes());
            assert_eq!(owned_body.deserialize::<std::collections::HashMap<&str, &str>>().unwrap(), decoded);
        }
        let get = Message::method_call("/item", "Get").unwrap().build(&attributes_body()).unwrap();
        assert_eq!(get.body().signature().to_string_no_parens(), "ss");
        assert_eq!(get.body().deserialize::<(&str, &str)>().unwrap(), (ITEM_INTERFACE, ATTRIBUTES_PROPERTY));
        let duplicate = [expected[0], expected[0], expected[2], expected[3]];
        assert!(query(&duplicate).is_err());
        let long = "x".repeat(257);
        assert!(query(&[("a", long.as_str()), expected[1], expected[2], expected[3]]).is_err());
        assert!(query(&[("a\0b", "x"), expected[1], expected[2], expected[3]]).is_err());
        assert!(route(&UniqueName::try_from("org.freedesktop.DBus").unwrap(), &ObjectPath::try_from("/collection").unwrap()).is_err());
    }
    #[test]
    fn bounded_facade_never_fans_out_or_admits_a_root_item() {
        let owner = UniqueName::try_from(":1.23").unwrap();
        let paths = [ObjectPath::try_from("/one").unwrap(), ObjectPath::try_from("/two").unwrap()];
        for count in 0..=2 {
            let message = reply(&&paths[..count]);
            let body = message.body();
            let decoded = decode_item_path(&body, &owner);
            match count {
                0 => assert_eq!(decoded.unwrap(), None),
                1 => assert_eq!(decoded.unwrap(), Some("/one")),
                _ => assert!(decoded.is_err()),
            }
        }
        let root = [ObjectPath::try_from("/").unwrap()];
        assert!(decode_item_path(&reply(&&root[..]).body(), &owner).is_err());
        let expected = attrs();
        let message = reply(&AsVariant(&Query(&expected)));
        check_attributes(&message.body(), &owner, &expected).unwrap();
        let wrong = [expected[0], expected[1], ("vault-id", "another"), expected[3]];
        assert!(check_attributes(&message.body(), &owner, &wrong).is_err());
    }

    #[cfg(all(unix, feature = "rt-tokio"))]
    #[cfg_attr(test, test)]
    pub(super) fn retrieval_request_bodies_and_nonroot_routes_are_fixed() {
        let owner = UniqueName::try_from(":1.23").unwrap();
        let item = ObjectPath::try_from("/item").unwrap();
        let session = ObjectPath::try_from("/session").unwrap();
        nonroot_route(&owner, &item).unwrap();
        let locked = Message::method_call(item.clone(), "Get").unwrap()
            .destination(owner.clone()).unwrap().interface(PROPERTIES_INTERFACE).unwrap()
            .build(&locked_body()).unwrap();
        assert_eq!(locked.body().signature().to_string_no_parens(), "ss");
        assert_eq!(locked.body().deserialize::<(&str, &str)>().unwrap(), (ITEM_INTERFACE, "Locked"));
        let mut public = [0u8; 128]; public[127] = 4;
        let open = Message::method_call(SERVICE_PATH, "OpenSession").unwrap()
            .destination(owner.clone()).unwrap().interface(SERVICE_INTERFACE).unwrap()
            .build(&OpenSessionBody(public)).unwrap();
        let body = open.body();
        assert_eq!(body.signature().to_string_no_parens(), "sv");
        let (algorithm, encoded): (&str, zbus::zvariant::as_value::Deserialize<'_, Vec<u8>>) =
            body.deserialize().unwrap();
        assert_eq!(algorithm, crate::ss::ALGORITHM_DH);
        assert_eq!(encoded.0.as_slice(), &public);
        assert_eq!(open.header().destination().map(|name| name.as_str()), Some(owner.as_str()));
        assert_eq!(open.header().path().map(|path| path.as_str()), Some(SERVICE_PATH));
        let owned_session: zbus::zvariant::OwnedObjectPath = session.as_str().to_owned().try_into().unwrap();
        let secret = Message::method_call(item, "GetSecret").unwrap()
            .destination(owner.clone()).unwrap().interface(ITEM_INTERFACE).unwrap()
            .build(&owned_session).unwrap();
        assert_eq!(secret.body().signature().to_string_no_parens(), "o");
        assert_eq!(secret.body().deserialize::<ObjectPath<'_>>().unwrap().as_str(), "/session");
        let close = Message::method_call(session.clone(), "Close").unwrap()
            .destination(owner.clone()).unwrap().interface(SESSION_INTERFACE).unwrap()
            .build(&()).unwrap();
        assert_eq!(close.body().len(), 0);
        assert_eq!(close.body().signature(), &Signature::Unit);
        assert!(nonroot_route(&owner, &ObjectPath::try_from("/").unwrap()).is_err());
        assert!(nonroot_route(&UniqueName::try_from("org.freedesktop.DBus").unwrap(), &session).is_err());
        let long = format!("/{}", "x".repeat(512));
        assert!(nonroot_route(&owner, &ObjectPath::try_from(long).unwrap()).is_err());
    }

    #[cfg_attr(test, test)]
    pub(super) fn retrieval_views_preserve_path_before_peer_validity() {
        let owner = UniqueName::try_from(":1.23").unwrap();
        let peers: [&[u8]; 4] = [&[], &[0], &[1], &[8]];
        for peer in peers {
            let message = reply(&(AsVariant(&peer), ObjectPath::try_from("/session").unwrap()));
            let body = message.body();
            let (borrowed, session) = decode_open_session(&body, &owner).unwrap();
            assert_eq!(borrowed, peer);
            assert_eq!(session, "/session");
            let data = body.data().bytes();
            assert!(borrowed.as_ptr() as usize >= data.as_ptr() as usize);
            assert!(borrowed.as_ptr() as usize + borrowed.len() <= data.as_ptr() as usize + data.len());
        }
        let peer: &[u8] = &[8];
        let session = ObjectPath::try_from("/session").unwrap();
        let good = reply(&(AsVariant(&peer), session.clone()));
        assert!(decode_open_session(&good.body(), &UniqueName::try_from(":1.24").unwrap()).is_err());
        assert!(decode_open_session(&reply(&(AsVariant(&peer), ObjectPath::try_from("/").unwrap())).body(), &owner).is_err());
        let large: &[u8] = &[8; 129];
        assert!(decode_open_session(&reply(&(AsVariant(&large), session.clone())).body(), &owner).is_err());
        assert!(decode_open_session(&reply(&((AsVariant(&peer), session),)).body(), &owner).is_err());
        assert!(decode_open_session(&reply(&(AsVariant(&peer), "/not_an_object_path")).body(), &owner).is_err());
        for locked in [false, true] {
            assert_eq!(decode_locked(&reply(&AsVariant(&locked)).body(), &owner).unwrap(), locked);
        }
        assert!(decode_locked(&reply(&AsVariant(&1u32)).body(), &owner).is_err());
    }

    #[cfg_attr(test, test)]
    pub(super) fn retrieval_secret_and_close_views_are_exact() {
        let owner = UniqueName::try_from(":1.23").unwrap();
        let session = ObjectPath::try_from("/session").unwrap();
        let iv: &[u8] = &[0x27; 16];
        let ciphertext: &[u8] = &[0x39; 48];
        let message = reply(&((session.clone(), iv, ciphertext, "application/octet-stream"),));
        let body = message.body();
        let (decoded_iv, decoded_ciphertext) = decode_get_secret(&body, &owner, &session).unwrap();
        assert_eq!(decoded_iv, iv);
        assert_eq!(decoded_ciphertext, ciphertext);
        assert!(decode_get_secret(&body, &owner, &ObjectPath::try_from("/other").unwrap()).is_err());
        assert!(decode_get_secret(&body, &UniqueName::try_from(":1.24").unwrap(), &session).is_err());
        for (bad_iv, bad_ciphertext, content_type) in [
            (&iv[..15], ciphertext, "application/octet-stream"),
            (iv, &ciphertext[..47], "application/octet-stream"),
            (iv, ciphertext, "text/plain"),
        ] {
            let message = reply(&((session.clone(), bad_iv, bad_ciphertext, content_type),));
            assert!(decode_get_secret(&message.body(), &owner, &session).is_err());
        }
        check_empty_owner_reply(&reply(&()).body(), &owner).unwrap();
        assert!(check_empty_owner_reply(&reply(&0u32).body(), &owner).is_err());
        assert!(check_empty_owner_reply(&reply(&()).body(), &UniqueName::try_from(":1.24").unwrap()).is_err());
    }
}
