//! Narrow, non-mutating raw lookup calls for an original-connection owner.
//!
//! These calls do not open an encryption session, unlock, retrieve a secret or
//! follow a returned item. Keep every original success/MethodError Message until
//! its same-connection owner stream is reconciled through `recv_position()`.
//! These are post-allocation bounds, not transport or task-finality guarantees.

use crate::{bounded_reply, Error};
use serde::{ser::SerializeMap, Serialize, Serializer};
use zbus::{message::Body, names::UniqueName, Connection, Message};
use zbus::zvariant::{ObjectPath, Signature, Type};

const ITEM_INTERFACE: &str = "org.freedesktop.Secret.Item";
const ATTRIBUTES_PROPERTY: &str = "Attributes";

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

#[cfg(test)]
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
}
