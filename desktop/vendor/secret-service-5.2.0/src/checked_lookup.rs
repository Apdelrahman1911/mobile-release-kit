//! Narrow raw keyring calls for one original owner and reserved vault identity.
//!
//! The fixed owned starters open only encrypted sessions and never follow a
//! replacement owner/item or implicitly drive a returned prompt. Keep
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
const COLLECTION_INTERFACE: &str = "org.freedesktop.Secret.Collection";
const ATTRIBUTES_PROPERTY: &str = "Attributes";
const PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const SERVICE_INTERFACE: &str = "org.freedesktop.Secret.Service";
const SESSION_INTERFACE: &str = "org.freedesktop.Secret.Session";
const PROMPT_INTERFACE: &str = "org.freedesktop.Secret.Prompt";
const WRAPPING_KEY_LABEL: &str = "Mobile Release Kit vault wrapping key";
const BUS: &str = "org.freedesktop.DBus";
const BUS_PATH: &str = "/org/freedesktop/DBus";
const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";

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

/// The initialization target is a collection, not an Item property lookup.
/// This separate fixed call cannot select an arbitrary interface/property.
#[cfg(all(unix, feature = "rt-tokio"))]
pub fn start_owned_collection_locked(
    attempt: &mut zbus::connection::OwnedConnectionAttempt,
    owner: &UniqueName<'_>, collection: &ObjectPath<'_>,
) -> zbus::Result<()> {
    nonroot_route(owner, collection)?;
    attempt.start_raw_call(
        owner.as_str().to_owned().try_into()?, collection.as_str().to_owned().try_into()?,
        PROPERTIES_INTERFACE.try_into()?, "Get".try_into()?, (COLLECTION_INTERFACE, "Locked"),
    )
}

/// Only these two profile aliases, not a caller-selected default or collection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectionAlias { Login, Session }
impl CollectionAlias {
    fn name(self) -> &'static str { match self { Self::Login => "login", Self::Session => "session" } }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusIdentity { User, Process }
impl BusIdentity {
    fn method(self) -> &'static str { match self {
        Self::User => "GetConnectionUnixUser", Self::Process => "GetConnectionUnixProcessID",
    } }
}

#[cfg(all(unix, feature = "rt-tokio"))]
pub fn start_owned_bus_identity(attempt: &mut zbus::connection::OwnedConnectionAttempt,
    owner: &UniqueName<'_>, kind: BusIdentity) -> zbus::Result<()> {
    nonroot_route(owner, &ObjectPath::try_from(SERVICE_PATH)?)?;
    attempt.start_raw_call(BUS.try_into()?, BUS_PATH.try_into()?, BUS.try_into()?,
        kind.method().try_into()?, owner.as_str().to_owned())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnitProperty {
    Id, FragmentPath, DropInPaths, Transient, NeedDaemonReload,
    LoadState, ActiveState, SubState, MainPid, ExecStart,
}
impl UnitProperty {
    fn body(self) -> (&'static str, &'static str) {
        let unit = "org.freedesktop.systemd1.Unit";
        let service = "org.freedesktop.systemd1.Service";
        match self {
            Self::Id => (unit, "Id"), Self::FragmentPath => (unit, "FragmentPath"),
            Self::DropInPaths => (unit, "DropInPaths"), Self::Transient => (unit, "Transient"),
            Self::NeedDaemonReload => (unit, "NeedDaemonReload"), Self::LoadState => (unit, "LoadState"),
            Self::ActiveState => (unit, "ActiveState"), Self::SubState => (unit, "SubState"),
            Self::MainPid => (service, "MainPID"), Self::ExecStart => (service, "ExecStart"),
        }
    }
    pub fn next(self) -> Option<Self> { match self {
        Self::Id => Some(Self::FragmentPath), Self::FragmentPath => Some(Self::DropInPaths),
        Self::DropInPaths => Some(Self::Transient), Self::Transient => Some(Self::NeedDaemonReload),
        Self::NeedDaemonReload => Some(Self::LoadState), Self::LoadState => Some(Self::ActiveState),
        Self::ActiveState => Some(Self::SubState), Self::SubState => Some(Self::MainPid),
        Self::MainPid => Some(Self::ExecStart), Self::ExecStart => None,
    } }
}

#[cfg(all(unix, feature = "rt-tokio"))]
pub fn start_owned_get_unit_by_pid(attempt: &mut zbus::connection::OwnedConnectionAttempt,
    manager: &UniqueName<'_>, pid: u32) -> zbus::Result<()> {
    nonroot_route(manager, &ObjectPath::try_from(MANAGER_PATH)?)?;
    if pid == 0 || pid > i32::MAX as u32 { return Err(zbus::Error::InvalidField); }
    attempt.start_raw_call(manager.as_str().to_owned().try_into()?, MANAGER_PATH.try_into()?,
        MANAGER_INTERFACE.try_into()?, "GetUnitByPID".try_into()?, pid)
}

#[cfg(all(unix, feature = "rt-tokio"))]
pub fn start_owned_unit_property(attempt: &mut zbus::connection::OwnedConnectionAttempt,
    manager: &UniqueName<'_>, unit: &ObjectPath<'_>, property: UnitProperty) -> zbus::Result<()> {
    nonroot_route(manager, unit)?;
    attempt.start_raw_call(manager.as_str().to_owned().try_into()?, unit.as_str().to_owned().try_into()?,
        PROPERTIES_INTERFACE.try_into()?, "Get".try_into()?, property.body())
}

#[cfg(all(unix, feature = "rt-tokio"))]
pub fn start_owned_read_alias(attempt: &mut zbus::connection::OwnedConnectionAttempt,
    owner: &UniqueName<'_>, alias: CollectionAlias) -> zbus::Result<()> {
    nonroot_route(owner, &ObjectPath::try_from(SERVICE_PATH)?)?;
    attempt.start_raw_call(owner.as_str().to_owned().try_into()?, SERVICE_PATH.try_into()?,
        SERVICE_INTERFACE.try_into()?, "ReadAlias".try_into()?, alias.name())
}

#[cfg(all(unix, feature = "rt-tokio"))]
struct UnlockBody(zbus::zvariant::OwnedObjectPath);
#[cfg(all(unix, feature = "rt-tokio"))]
impl Type for UnlockBody {
    const SIGNATURE: &'static Signature = &Signature::static_array(&Signature::ObjectPath);
}
#[cfg(all(unix, feature = "rt-tokio"))]
impl Serialize for UnlockBody {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        std::slice::from_ref(&self.0).serialize(serializer)
    }
}

/// Stage exactly one retained target. The caller must own prompt subscription
/// and cleanup before dispatch; this helper never follows either reply result.
#[cfg(all(unix, feature = "rt-tokio"))]
pub fn start_owned_unlock(attempt: &mut zbus::connection::OwnedConnectionAttempt,
    owner: &UniqueName<'_>, target: &ObjectPath<'_>) -> zbus::Result<()> {
    nonroot_route(owner, target)?;
    let target = target.as_str().to_owned().try_into()?;
    attempt.start_raw_call(owner.as_str().to_owned().try_into()?, SERVICE_PATH.try_into()?,
        SERVICE_INTERFACE.try_into()?, "Unlock".try_into()?, UnlockBody(target))
}

#[cfg(all(unix, feature = "rt-tokio"))]
pub fn start_owned_prompt(attempt: &mut zbus::connection::OwnedConnectionAttempt,
    owner: &UniqueName<'_>, prompt: &ObjectPath<'_>) -> zbus::Result<()> {
    nonroot_route(owner, prompt)?;
    attempt.start_raw_call(owner.as_str().to_owned().try_into()?, prompt.as_str().to_owned().try_into()?,
        PROMPT_INTERFACE.try_into()?, "Prompt".try_into()?, "")
}

#[cfg(all(unix, feature = "rt-tokio"))]
pub fn start_owned_dismiss(attempt: &mut zbus::connection::OwnedConnectionAttempt,
    owner: &UniqueName<'_>, prompt: &ObjectPath<'_>) -> zbus::Result<()> {
    nonroot_route(owner, prompt)?;
    attempt.start_raw_call(owner.as_str().to_owned().try_into()?, prompt.as_str().to_owned().try_into()?,
        PROMPT_INTERFACE.try_into()?, "Dismiss".try_into()?, ())
}

#[cfg(all(unix, feature = "rt-tokio"))]
struct CreateProperties<'a>(&'a OwnedQuery);
#[cfg(all(unix, feature = "rt-tokio"))]
impl Type for CreateProperties<'_> {
    const SIGNATURE: &'static Signature = &Signature::static_dict(&Signature::Str, &Signature::Variant);
}
#[cfg(all(unix, feature = "rt-tokio"))]
impl Serialize for CreateProperties<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use zbus::zvariant::as_value::Serialize as AsVariant;
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("org.freedesktop.Secret.Item.Label", &AsVariant(&WRAPPING_KEY_LABEL))?;
        map.serialize_entry("org.freedesktop.Secret.Item.Attributes", &AsVariant(self.0))?;
        map.end()
    }
}
#[cfg(all(unix, feature = "rt-tokio"))]
static CREATE_BYTE_ARRAY_SIGNATURE: Signature = Signature::static_array(&Signature::U8);
#[cfg(all(unix, feature = "rt-tokio"))]
static CREATE_SECRET_FIELDS: [&Signature; 4] = [
    &Signature::ObjectPath, &CREATE_BYTE_ARRAY_SIGNATURE,
    &CREATE_BYTE_ARRAY_SIGNATURE, &Signature::Str,
];
#[cfg(all(unix, feature = "rt-tokio"))]
static CREATE_SECRET_SIGNATURE: Signature = Signature::static_structure(&CREATE_SECRET_FIELDS);
#[cfg(all(unix, feature = "rt-tokio"))]
static CREATE_BODY_FIELDS: [&Signature; 3] = [
    CreateProperties::SIGNATURE, &CREATE_SECRET_SIGNATURE, &Signature::Bool,
];
#[cfg(all(unix, feature = "rt-tokio"))]
static CREATE_BODY_SIGNATURE: Signature = Signature::static_structure(&CREATE_BODY_FIELDS);
#[cfg(all(unix, feature = "rt-tokio"))]
struct CreateBody {
    attributes: OwnedQuery, session: zbus::zvariant::OwnedObjectPath,
    iv: [u8; 16], ciphertext: [u8; 48],
}
#[cfg(all(unix, feature = "rt-tokio"))]
impl Type for CreateBody {
    const SIGNATURE: &'static Signature = &CREATE_BODY_SIGNATURE;
}
#[cfg(all(unix, feature = "rt-tokio"))]
impl Serialize for CreateBody {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let secret = (&self.session, self.iv.as_slice(), self.ciphertext.as_slice(), "application/octet-stream");
        (CreateProperties(&self.attributes), secret, false).serialize(serializer)
    }
}

fn initialization_attributes(attributes: &[(&str, &str); 4]) -> zbus::Result<()> {
    query(attributes)?;
    fn id(value: &str) -> bool {
        value.len() == 32 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && value.bytes().any(|b| b != b'0')
    }
    if attributes[0] != ("application", "dev.mobile-release-kit.desktop")
        || attributes[1] != ("purpose", "vault-wrapping-key-v1")
        || attributes[2].0 != "vault-id" || attributes[3].0 != "generation-id"
        || !id(attributes[2].1) || !id(attributes[3].1) || attributes[2].1 == attributes[3].1
    { return Err(zbus::Error::InvalidField); }
    Ok(())
}

/// One fixed encrypted initialization request, always replace=false. This
/// encodes a request only: durable reservation, admitted provider, original
/// session and explicit user's one-shot creation authority remain the caller's.
#[cfg(all(unix, feature = "rt-tokio"))]
pub fn start_owned_create_item(attempt: &mut zbus::connection::OwnedConnectionAttempt,
    owner: &UniqueName<'_>, collection: &ObjectPath<'_>, attributes: &[(&str, &str); 4],
    session: &ObjectPath<'_>, iv: &[u8; 16], ciphertext: &[u8; 48]) -> zbus::Result<()> {
    nonroot_route(owner, collection)?; nonroot_route(owner, session)?;
    initialization_attributes(attributes)?;
    let body = CreateBody { attributes: OwnedQuery(attributes.map(|(key, value)| (key.to_owned(), value.to_owned()))),
        session: session.as_str().to_owned().try_into()?, iv: *iv, ciphertext: *ciphertext };
    attempt.start_raw_call(owner.as_str().to_owned().try_into()?, collection.as_str().to_owned().try_into()?,
        COLLECTION_INTERFACE.try_into()?, "CreateItem".try_into()?, body)
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

/// The only second well-known owner tracked by the closed profile. These
/// manager events are policy/change facts, never executable attestation.
pub fn decode_manager_changed<'a>(body: &'a Body) -> Result<(Option<&'a str>, Option<&'a str>), Error> {
    bounded_reply::decode_owner_changed_for(body, "org.freedesktop.systemd1")
}

/// Check the successful, exactly-empty bus AddMatch/RemoveMatch reply.
pub fn check_empty_bus_reply(body: &Body) -> Result<(), Error> {
    bounded_reply::check_empty_bus_reply(body)
}

/// One borrowed, owner-validated Locked property. True is a refusal, not consent.
pub fn decode_locked(body: &Body, owner: &UniqueName<'_>) -> Result<bool, Error> {
    bounded_reply::decode_locked(body, owner)
}

pub fn decode_read_alias<'a>(body: &'a Body, owner: &UniqueName<'_>) -> Result<&'a str, Error> {
    bounded_reply::decode_read_alias(body, owner).map(|path| path.as_str())
}

pub fn decode_bus_identity(body: &Body) -> Result<u32, Error> {
    bounded_reply::decode_bus_identity(body)
}

pub fn decode_unit_path<'a>(body: &'a Body, manager: &UniqueName<'_>) -> Result<&'a str, Error> {
    let path = bounded_reply::decode_read_alias(body, manager)?.as_str();
    if path == "/" { return Err(Error::InvalidReply); }
    Ok(path)
}

/// Check one fixed known property, not GetAll or a generic Value/cache. These
/// are exact GNOME user-unit policy predicates only, NOT live-image authority.
pub fn check_gnome_unit_property(body: &Body, manager: &UniqueName<'_>, property: UnitProperty,
    pid: u32, control_argument: &str) -> Result<(), Error> {
    let accepted = match property {
        UnitProperty::Id => bounded_reply::decode_property_text(body, manager)? == "gnome-keyring-daemon.service",
        UnitProperty::FragmentPath => bounded_reply::decode_property_text(body, manager)? == "/usr/lib/systemd/user/gnome-keyring-daemon.service",
        UnitProperty::DropInPaths => { bounded_reply::check_empty_strings(body, manager)?; true },
        UnitProperty::Transient | UnitProperty::NeedDaemonReload => !bounded_reply::decode_locked(body, manager)?,
        UnitProperty::LoadState => bounded_reply::decode_property_text(body, manager)? == "loaded",
        UnitProperty::ActiveState => bounded_reply::decode_property_text(body, manager)? == "active",
        UnitProperty::SubState => bounded_reply::decode_property_text(body, manager)? == "running",
        UnitProperty::MainPid => pid != 0 && bounded_reply::decode_property_u32(body, manager)? == pid,
        UnitProperty::ExecStart => { bounded_reply::check_gnome_exec_start(body, manager, control_argument)?; true },
    };
    if accepted { Ok(()) } else { Err(Error::InvalidReply) }
}

/// Keep both results even if their later semantic combination must refuse.
/// Only the original owner can retain and settle actual prompt debt.
pub fn decode_unlock<'a>(body: &'a Body, owner: &UniqueName<'_>) -> Result<(Option<&'a str>, &'a str), Error> {
    let reply = bounded_reply::decode_unlock(body, owner)?;
    Ok((reply.object_paths.0.map(|path| path.as_str()), reply.prompt.as_str()))
}

pub fn decode_created_item<'a>(body: &'a Body, owner: &UniqueName<'_>) -> Result<(&'a str, &'a str), Error> {
    let (item, prompt) = bounded_reply::decode_created(body, owner)?;
    Ok((item.as_str(), prompt.as_str()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptRole { Unlock, Create }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptCompletion<'a> { Dismissed, Unlocked(Option<&'a str>), Created(&'a str) }

/// A bounded original Completed signal, not the return from Prompt/Dismiss.
/// Receipt still needs this same stream's owner reconciliation and final gate.
pub fn decode_prompt_completed<'a>(body: &'a Body, owner: &UniqueName<'_>, prompt: &ObjectPath<'_>,
    role: PromptRole) -> Result<PromptCompletion<'a>, Error> {
    nonroot_route(owner, prompt).map_err(|_| Error::InvalidReply)?;
    let role = match role { PromptRole::Unlock => bounded_reply::PromptRole::Unlock,
        PromptRole::Create => bounded_reply::PromptRole::Create };
    Ok(match bounded_reply::decode_prompt_completed(body, owner, prompt, role)? {
        bounded_reply::PromptCompletion::Dismissed => PromptCompletion::Dismissed,
        bounded_reply::PromptCompletion::Unlocked(path) => PromptCompletion::Unlocked(path.map(|path| path.as_str())),
        bounded_reply::PromptCompletion::Created(path) => PromptCompletion::Created(path.as_str()),
    })
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

/// Fixed DATA assertions and native-fixture setup witnesses only, excluded
/// from the normal dependency graph. No provider is started by these helpers.
#[cfg(feature = "mrk-retrieval-test-support")]
pub mod test_support {
    pub use crate::session::test_support::{assert_crypto_helpers, exchange_and_secret,
        assert_initialization_helpers, assert_native_canary_helpers, encrypt_native_canary, is_native_canary};
    pub use crate::bounded_reply::native_fixture::{assert_setup_decoders,
        decode_bus_identity, decode_created_item, decode_session_alias};

    pub fn assert_facade_helpers() {
        #[cfg(all(unix, feature = "rt-tokio"))]
        super::tests::retrieval_request_bodies_and_nonroot_routes_are_fixed();
        super::tests::retrieval_views_preserve_path_before_peer_validity();
        super::tests::retrieval_secret_and_close_views_are_exact();
        crate::bounded_reply::assert_retrieval_empty_reply_helper();
    }
    pub fn assert_provider_helpers() {
        #[cfg(all(unix, feature = "rt-tokio"))]
        super::tests::provider_requests_and_creation_body_are_fixed();
        super::tests::provider_properties_aliases_and_reserved_ids_are_exact();
        crate::bounded_reply::assert_provider_reply_helpers();
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

    fn reserved_attributes() -> [(&'static str, &'static str); 4] {
        [("application", "dev.mobile-release-kit.desktop"), ("purpose", "vault-wrapping-key-v1"),
            ("vault-id", "11111111111111111111111111111111"), ("generation-id", "22222222222222222222222222222222")]
    }

    #[cfg(all(unix, feature = "rt-tokio"))]
    #[cfg_attr(test, test)]
    pub(super) fn provider_requests_and_creation_body_are_fixed() {
        use std::collections::HashMap;
        use zbus::zvariant::{OwnedObjectPath, Value};
        let owner = UniqueName::try_from(":1.23").unwrap();
        let target: OwnedObjectPath = "/target".to_owned().try_into().unwrap();
        let unlock = Message::method_call(SERVICE_PATH, "Unlock").unwrap().destination(owner.clone()).unwrap()
            .interface(SERVICE_INTERFACE).unwrap().build(&UnlockBody(target)).unwrap();
        assert_eq!(bounded_reply::test_wire_signature(&unlock.body()).unwrap(), "ao");
        assert_eq!(unlock.body().deserialize::<Vec<ObjectPath<'_>>>().unwrap().iter().map(ObjectPath::as_str).collect::<Vec<_>>(), ["/target"]);
        assert_eq!(unlock.header().destination().map(|name| name.as_str()), Some(":1.23"));
        let prompt = Message::method_call("/prompt", "Prompt").unwrap().interface(PROMPT_INTERFACE).unwrap().build(&"").unwrap();
        assert_eq!(bounded_reply::test_wire_signature(&prompt.body()).unwrap(), "s");
        assert_eq!(prompt.body().deserialize::<&str>().unwrap(), "");
        let dismiss = Message::method_call("/prompt", "Dismiss").unwrap().interface(PROMPT_INTERFACE).unwrap().build(&()).unwrap();
        assert_eq!(dismiss.body().len(), 0);
        let expected = reserved_attributes(); initialization_attributes(&expected).unwrap();
        let create = CreateBody { attributes: OwnedQuery(expected.map(|(key, value)| (key.to_owned(), value.to_owned()))),
            session: "/session".to_owned().try_into().unwrap(), iv: [0x27; 16], ciphertext: [0x39; 48] };
        let message = Message::method_call("/login", "CreateItem").unwrap().destination(owner.clone()).unwrap()
            .interface(COLLECTION_INTERFACE).unwrap().build(&create).unwrap();
        let body = message.body();
        assert_eq!(bounded_reply::test_wire_signature(&body).unwrap(), "a{sv}(oayays)b");
        let (mut properties, secret, replace): (HashMap<&str, Value<'_>>, (ObjectPath<'_>, Vec<u8>, Vec<u8>, &str), bool) = body.deserialize().unwrap();
        assert!(!replace); assert_eq!(properties.len(), 2);
        match properties.remove("org.freedesktop.Secret.Item.Label").unwrap() {
            Value::Str(label) => assert_eq!(label.as_str(), "Mobile Release Kit vault wrapping key"),
            _ => panic!("label is not a string variant"),
        }
        match properties.remove("org.freedesktop.Secret.Item.Attributes").unwrap() {
            Value::Dict(attributes) => {
                let attributes: HashMap<String, String> = attributes.try_into().unwrap();
                assert_eq!(attributes.len(), 4);
                for (key, value) in expected { assert_eq!(attributes.get(key).map(String::as_str), Some(value)); }
            }
            _ => panic!("attributes are not the fixed string dictionary"),
        }
        assert!(properties.is_empty());
        assert_eq!(secret.0.as_str(), "/session"); assert_eq!(secret.1, [0x27; 16]);
        assert_eq!(secret.2, [0x39; 48]); assert_eq!(secret.3, "application/octet-stream");
        assert_eq!(message.header().destination().map(|name| name.as_str()), Some(owner.as_str()));
        assert_eq!(message.header().interface().map(|name| name.as_str()), Some(COLLECTION_INTERFACE));
        assert_eq!(message.header().path().map(|path| path.as_str()), Some("/login"));
        for (kind, method) in [(BusIdentity::User, "GetConnectionUnixUser"), (BusIdentity::Process, "GetConnectionUnixProcessID")] {
            assert_eq!(kind.method(), method);
            let message = Message::method_call(BUS_PATH, kind.method()).unwrap().build(&owner.as_str()).unwrap();
            assert_eq!(bounded_reply::test_wire_signature(&message.body()).unwrap(), "s");
        }
        assert_eq!(CollectionAlias::Login.name(), "login"); assert_eq!(CollectionAlias::Session.name(), "session");
        let item_locked = Message::method_call("/item", "Get").unwrap().build(&locked_body()).unwrap();
        let collection_locked = Message::method_call("/login", "Get").unwrap().build(&(COLLECTION_INTERFACE, "Locked")).unwrap();
        assert_ne!(item_locked.body().data().bytes(), collection_locked.body().data().bytes());
        assert_eq!(collection_locked.body().deserialize::<(&str, &str)>().unwrap(), (COLLECTION_INTERFACE, "Locked"));
        assert!(nonroot_route(&owner, &ObjectPath::try_from("/").unwrap()).is_err());
    }

    #[cfg_attr(test, test)]
    pub(super) fn provider_properties_aliases_and_reserved_ids_are_exact() {
        let owner = UniqueName::try_from(":1.23").unwrap();
        let unit = "org.freedesktop.systemd1.Unit"; let service = "org.freedesktop.systemd1.Service";
        let properties = [(UnitProperty::Id, unit, "Id"), (UnitProperty::FragmentPath, unit, "FragmentPath"),
            (UnitProperty::DropInPaths, unit, "DropInPaths"), (UnitProperty::Transient, unit, "Transient"),
            (UnitProperty::NeedDaemonReload, unit, "NeedDaemonReload"), (UnitProperty::LoadState, unit, "LoadState"),
            (UnitProperty::ActiveState, unit, "ActiveState"), (UnitProperty::SubState, unit, "SubState"),
            (UnitProperty::MainPid, service, "MainPID"), (UnitProperty::ExecStart, service, "ExecStart")];
        for (index, (property, interface, name)) in properties.iter().copied().enumerate() {
            let get = Message::method_call("/unit", "Get").unwrap().build(&property.body()).unwrap();
            assert_eq!(bounded_reply::test_wire_signature(&get.body()).unwrap(), "ss");
            assert_eq!(get.body().deserialize::<(&str, &str)>().unwrap(), (interface, name));
            assert_eq!(property.next(), properties.get(index + 1).map(|(next, _, _)| *next));
        }
        let control = "--control-directory=/run/user/1000/keyring";
        for (property, expected) in [(UnitProperty::Id, "gnome-keyring-daemon.service"),
            (UnitProperty::FragmentPath, "/usr/lib/systemd/user/gnome-keyring-daemon.service"),
            (UnitProperty::LoadState, "loaded"), (UnitProperty::ActiveState, "active"), (UnitProperty::SubState, "running")] {
            check_gnome_unit_property(&reply(&AsVariant(&expected)).body(), &owner, property, 123, control).unwrap();
            assert!(check_gnome_unit_property(&reply(&AsVariant(&"other")).body(), &owner, property, 123, control).is_err());
            assert!(check_gnome_unit_property(&reply(&AsVariant(&expected)).body(), &UniqueName::try_from(":1.24").unwrap(), property, 123, control).is_err());
        }
        for property in [UnitProperty::Transient, UnitProperty::NeedDaemonReload] {
            check_gnome_unit_property(&reply(&AsVariant(&false)).body(), &owner, property, 123, control).unwrap();
            assert!(check_gnome_unit_property(&reply(&AsVariant(&true)).body(), &owner, property, 123, control).is_err());
        }
        check_gnome_unit_property(&reply(&AsVariant(&123u32)).body(), &owner, UnitProperty::MainPid, 123, control).unwrap();
        assert!(check_gnome_unit_property(&reply(&AsVariant(&124u32)).body(), &owner, UnitProperty::MainPid, 123, control).is_err());
        check_gnome_unit_property(&reply(&AsVariant(&Vec::<&str>::new())).body(), &owner, UnitProperty::DropInPaths, 123, control).unwrap();
        assert!(check_gnome_unit_property(&reply(&AsVariant(&vec!["/override.conf"])).body(), &owner, UnitProperty::DropInPaths, 123, control).is_err());
        let attributes = reserved_attributes(); initialization_attributes(&attributes).unwrap();
        for (index, value) in [(0, "foreign.app"), (1, "other-purpose"), (2, "00000000000000000000000000000000"),
            (2, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), (2, "123"), (3, attributes[2].1)] {
            let mut bad = attributes; bad[index].1 = value; assert!(initialization_attributes(&bad).is_err());
        }
        let mut reordered = attributes; reordered.swap(2, 3); assert!(initialization_attributes(&reordered).is_err());
        let alias = reply(&ObjectPath::try_from("/login").unwrap());
        assert_eq!(decode_read_alias(&alias.body(), &owner).unwrap(), "/login");
        assert_eq!(decode_unit_path(&alias.body(), &owner).unwrap(), "/login");
        assert!(decode_unit_path(&reply(&ObjectPath::try_from("/").unwrap()).body(), &owner).is_err());
        assert!(decode_read_alias(&reply(&"/login").body(), &owner).is_err());
    }

}
