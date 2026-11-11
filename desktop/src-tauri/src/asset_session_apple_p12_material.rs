//! Writer-local borrow of the actual loaded key and optional current P12.
//! The original Vault Work remains the lifetime owner. A completed review
//! retains neither this borrow nor an independent private-material copy.
use super::*;

pub(crate) struct P12Material<'a> {
    material: &'a SelectedStoreMaterial,
    key: Arc<Payload>,
    selected: Option<Arc<vault::AppleP12Loan>>,
    save: bool,
}
impl P12Material<'_> {
    pub(crate) fn parts(&self) -> Result<Vec<(&'static str, &[u8])>, BridgeError> {
#[cfg(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
{
        let sources = self.material.key_sources.as_ref().ok_or_else(refused)?;
        let (p8, key, issuer) = apple_parts(&self.material.payload).ok_or_else(refused)?;
        let key_parts = sources
            .certificate_parts(&self.key)
            .map_err(|_| refused())?;
        let mut parts = Vec::new();
        parts.try_reserve_exact(8).map_err(|_| refused())?;
        parts.extend([
            ("asc-p8", p8),
            ("asc-key-id", key),
            ("asc-issuer-id", issuer),
        ]);
        parts.extend(key_parts);
        if let Some(selected) = &self.selected {
            if self.save {
                return Err(refused());
            }
            parts.extend(
                sources
                    .selected_p12_parts(selected)
                    .map_err(|_| refused())?,
            );
        } else if sources.selected_p12_expected() {
            return Err(refused());
        }
        Ok(parts)
    }
#[cfg(not(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))))]
{Err(refused())}
}
    pub(crate) fn header(&self) -> Result<Vec<u8>, BridgeError> {
#[cfg(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
{
        let parts = self.parts()?;
        #[derive(serde::Serialize)]
        struct Row {
            bytes: usize,
            role: &'static str,
        }
        #[derive(serde::Serialize)]
        struct Header {
            files: Vec<Row>,
            #[serde(rename = "schemaVersion")]
            schema_version: u8,
        }
        let mut files = Vec::new();
        files.try_reserve_exact(8).map_err(|_| refused())?;
        for (role, bytes) in parts {
            files.push(Row {
                bytes: bytes.len(),
                role,
            });
        }
        if self.save {
            files.push(Row {
                bytes: 64,
                role: "p12-password",
            });
        }
        let mut header = Vec::new();
        header.try_reserve_exact(1024).map_err(|_| refused())?;
        serde_json::to_writer(
            &mut header,
            &Header {
                files,
                schema_version: 1,
            },
        )
        .map_err(|_| refused())?;
        header.push(b'\n');
        if header.len() > 1024 {
            return Err(refused());
        }
        Ok(header)
    }
#[cfg(not(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))))]
{Err(refused())}
}
}
impl SelectedStoreMaterial {
    pub(in crate::asset_session::store_material) fn p12_material(&self) -> bool {
#[cfg(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
{
        matches!(&self.command,Some(StoreCommand::Provisioning(context)) if context.mode.p12())
    }
#[cfg(not(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))))]
{false}
}
    pub(crate) fn p12_input(&self) -> Result<Option<P12Material<'_>>, BridgeError> {
#[cfg(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
{
        let Some(StoreCommand::Provisioning(context)) = &self.command else {
            return Ok(None);
        };
        if !context.mode.p12() {
            return Ok(None);
        }
        let sources = self.key_sources.as_ref().ok_or_else(refused)?;
        let key = sources.certificate_payload().ok_or_else(refused)?;
        let selected = sources.selected_p12();
        if sources.selected_p12_expected() != selected.is_some()
            || context.p12_record_id.is_some() != selected.is_some()
            || context.mode == provisioning::Mode::P12Save && selected.is_some()
        {
            return Err(refused());
        }
        Ok(Some(P12Material {
            material: self,
            key,
            selected,
            save: context.mode == provisioning::Mode::P12Save,
        }))
    }
#[cfg(not(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))))]
{Err(refused())}
}
}
