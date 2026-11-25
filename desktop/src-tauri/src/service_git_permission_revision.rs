//! MAIN-only comparison DATA on the existing four-family Git Book.
//! No service/CLI wire, permission source, clock or native witness is created.
use super::{public, Book, BridgeError};
use crate::service_protocol::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PermissionRevision(u64);

impl PermissionRevision {
    fn decimal(value: &str) -> Option<Self> {
        if value.is_empty()
            || value.len() > 20
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || value.len() > 1 && value.starts_with('0')
        {
            return None;
        }
        value.parse().ok().map(Self)
    }
}
impl Serialize for PermissionRevision {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for PermissionRevision {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::decimal(&value).ok_or_else(|| serde::de::Error::custom("invalid permission revision"))
    }
}

/// Only the four existing MAIN Access handlers instantiate this projection.
/// Its underlying family DTO, including all CLI bytes, remains unchanged.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MainAccess<T> {
    pub(super) permission_revision: PermissionRevision,
    #[serde(flatten)]
    pub(super) access: T,
}
impl<T> MainAccess<T> {
    pub(super) fn new(access: T, revision: PermissionRevision) -> Self {
        Self {
            permission_revision: revision,
            access,
        }
    }
    pub(super) fn map_access<U>(self, map: impl FnOnce(T) -> U) -> MainAccess<U> {
        MainAccess::new(map(self.access), self.permission_revision)
    }
}

impl Book {
    /// Caller holds the original Doc as well as this Book guard. Access and
    /// its comparison revision are projected under that SAME linearization.
    pub(super) fn permission_revision(&self) -> PermissionRevision {
        PermissionRevision(self.revoke_epoch)
    }
    pub(super) fn next_permission(
        &self,
        expected: PermissionRevision,
    ) -> Result<PermissionRevision, BridgeError> {
        if self.permission_revision() != expected {
            return Err(public(Error::Conflict));
        }
        self.revoke_epoch
            .checked_add(1)
            .map(PermissionRevision)
            .ok_or_else(|| public(Error::StateUnknown))
    }
    /// Final same-Doc/Book cut, BEFORE the fallible Inbox installer or any
    /// response projection. A potentially installed/lost attempt cannot reuse
    /// N. This does not replace any source, native Grant or one-use Start gate.
    pub(super) fn consume_permission(
        &mut self,
        expected: PermissionRevision,
        successor: PermissionRevision,
    ) -> Result<(), BridgeError> {
        if self.next_permission(expected)? != successor {
            return Err(public(Error::Conflict));
        }
        self.revoke_epoch = successor.0;
        Ok(())
    }
    /// Overflow stays absorbing. The caller must still invoke original STOP
    /// or close even when this operation returns an error.
    pub(super) fn revoke_permission(&mut self) -> Result<PermissionRevision, BridgeError> {
        let successor = self.next_permission(self.permission_revision())?;
        self.revoke_epoch = successor.0;
        Ok(successor)
    }
}

#[cfg(test)]
#[path = "service_git_permission_revision_tests.rs"]
mod tests;
