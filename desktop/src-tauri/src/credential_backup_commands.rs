//! Two fixed borrowed requests for the existing native backup picker owner.
//! Neither request accepts a path, private value, replacement or sink receipt.
use super::{bounded, exact, number, record, AssetError, RecordRef, SMALL_LIMIT};
use serde_json::Value;

pub(crate) struct Export<'a> {
    pub(crate) context_revision: u32,
    pub(crate) record: RecordRef<'a>,
}
pub(crate) struct Import {
    pub(crate) context_revision: u32,
}

pub(crate) fn backup_export(body: &Value) -> Result<Export<'_>, AssetError> {
    bounded(body, SMALL_LIMIT)?;
    let object = exact(body, &["contextRevision", "record"])?;
    let context_revision = number(&object["contextRevision"])?;
    let record = record(&object["record"])?;
    if context_revision == 0
        || record.expected_revision == 0
        || record.record_id.bytes().all(|byte| byte == b'0')
    {
        return Err(AssetError::invalid());
    }
    Ok(Export {
        context_revision,
        record,
    })
}
pub(crate) fn backup_import(body: &Value) -> Result<Import, AssetError> {
    bounded(body, SMALL_LIMIT)?;
    let object = exact(body, &["contextRevision"])?;
    let context_revision = number(&object["contextRevision"])?;
    if context_revision == 0 {
        return Err(AssetError::invalid());
    }
    Ok(Import { context_revision })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn exact_reference_only_commands_borrow_the_original_json() {
        let body =
            json!({"contextRevision":7,"record":{"recordId":"b".repeat(32),"expectedRevision":3}});
        let args = backup_export(&body).ok().unwrap();
        assert_eq!(args.context_revision, 7);
        assert_eq!(args.record.expected_revision, 3);
        assert!(std::ptr::eq(
            args.record.record_id.as_ptr(),
            body["record"]["recordId"].as_str().unwrap().as_ptr()
        ));
        assert_eq!(
            backup_import(&json!({"contextRevision":7}))
                .ok()
                .unwrap()
                .context_revision,
            7
        );
    }

    #[test]
    fn backup_commands_refuse_path_code_replacement_and_zero_or_wide_revisions() {
        let original =
            json!({"contextRevision":1,"record":{"recordId":"b".repeat(32),"expectedRevision":1}});
        for name in [
            "path",
            "code",
            "destination",
            "replacement",
            "fields",
            "overwrite",
        ] {
            let mut body = original.clone();
            body[name] = json!("inert-refused");
            assert!(backup_export(&body).is_err());
            let mut body = original.clone();
            body["record"][name] = json!("inert-refused");
            assert!(backup_export(&body).is_err());
            let mut body = json!({"contextRevision":1});
            body[name] = json!("inert-refused");
            assert!(backup_import(&body).is_err());
        }
        for value in [
            json!(0),
            json!(-1),
            json!(1.5),
            json!("1"),
            json!(u64::MAX),
            Value::Null,
        ] {
            assert!(backup_import(&json!({"contextRevision":value})).is_err());
            let mut body = original.clone();
            body["record"]["expectedRevision"] = value;
            assert!(backup_export(&body).is_err());
        }
        for id in [
            "0".repeat(32),
            "B".repeat(32),
            "b".repeat(33),
            String::new(),
        ] {
            let mut body = original.clone();
            body["record"]["recordId"] = json!(id);
            assert!(backup_export(&body).is_err());
        }
    }

    #[test]
    fn backup_commands_reuse_the_small_admitted_payload_bound() {
        assert!(backup_export(&json!({"contextRevision":1,"record":{
            "recordId":"b".repeat(SMALL_LIMIT + 1),"expectedRevision":1
        }}))
        .is_err());
        assert!(backup_import(&json!({"contextRevision":"1".repeat(SMALL_LIMIT + 1)})).is_err());
    }
}
