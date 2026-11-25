//! Fixed last private material part on the already admitted Apple stdin.
//! No secret getter, arbitrary FD/path, new pipe or caller-selected writer.
use super::*;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

pub(crate) struct PrivateAppleP12Input {
    password: Weak<AppleP12Password>,
    bytes: Zeroizing<[u8; 64]>,
    filled: bool,
}
impl PrivateAppleP12Input {
    /// Called only by the opaque original Fields object, once. The caller
    /// cannot replace the password by passing an equally shaped scalar.
    pub(crate) fn password(
        &mut self,
        original: &AppleP12Password,
        bytes: &[u8],
    ) -> Result<(), BridgeError> {
        if self.filled
            || bytes.len() != 64
            || !bytes
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
            || !self
                .password
                .upgrade()
                .is_some_and(|same| std::ptr::eq(same.as_ref(), original))
        {
            return Err(invalid());
        }
        self.filled = true;
        self.bytes.copy_from_slice(bytes);
        Ok(())
    }
}

/// The existing write_request owns `writer`, its Guard, close and join. This
/// function is its p12-save-only material arm; all other modes keep the normal
/// writer. Header contains lengths/role names only, never private bytes.
pub(in crate::saved_command_owner) async fn write_material(
    owner: &Arc<Session>,
    writer: &mut ChildStdin,
    material: &PrivateSigningMaterial,
    borrowed: &crate::asset_session::P12Material<'_>,
    header: &[u8],
) -> Result<(), std::io::Error> {
    let bad = || std::io::Error::from(std::io::ErrorKind::InvalidData);
    let parent = original(owner).map_err(|_| bad())?;
    let data = state(parent).map_err(|_| bad())?;
    let asset = parent
        .original
        .get()
        .and_then(Weak::upgrade)
        .ok_or_else(bad)?;
    let destination = data
        .destination
        .get()
        .and_then(Weak::upgrade)
        .ok_or_else(bad)?;
    let password = data
        .password
        .get()
        .and_then(Weak::upgrade)
        .ok_or_else(bad)?;
    let PrivateSigningMaterial::Store(_) = material else {
        return Err(bad());
    };
    if parent.mode != wire::Mode::P12Save
        || parent.clock.interrupted()
        || !same_destination(parent, &asset, &destination)
        || !parent.source_returned.load(Ordering::SeqCst)
        || !material.matches(&owner.context, owner.registration, &owner.project)
        || data.password_entered.swap(true, Ordering::SeqCst)
    {
        return Err(bad());
    }
    let parts = borrowed.parts().map_err(|_| bad())?;
    if parts.len() != 6
        || parts.iter().map(|part| part.0).ne([
            "asc-p8",
            "asc-key-id",
            "asc-issuer-id",
            "apple-key-pkcs8-base64",
            "apple-key-csr",
            "apple-key-spki-base64",
        ])
        || header != borrowed.header().map_err(|_| bad())?
    {
        return Err(bad());
    }
    let mut fixed = PrivateAppleP12Input {
        password: Arc::downgrade(&password),
        bytes: Zeroizing::new([0; 64]),
        filled: false,
    };
    destination
        .write_password(&asset, &mut fixed)
        .map_err(|_| bad())?;
    if !fixed.filled || parent.clock.interrupted() {
        return Err(bad());
    }
    writer.write_all(material.prefix()).await?;
    writer.write_all(header).await?;
    for (_, bytes) in parts {
        writer.write_all(bytes).await?;
    }
    writer.write_all(&fixed.bytes[..]).await?;
    writer.write_all(material.suffix()).await?;
    if parent.clock.interrupted() || data.password_returned.swap(true, Ordering::SeqCst) {
        return Err(bad());
    }
    Ok(())
}
