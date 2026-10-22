//! Original MAIN decoder and Document DATA sizing, not an admitted native owner.
use super::*;
use serde_json::json;
fn pr(ready:bool)->serde_json::Value {
    let mut draft=json!({"base":"b".repeat(200),"head":"h".repeat(200),"title":"é".repeat(128),"body":"\"\\\n".repeat(1365)+"x"});
    if ready{draft["creationMode"]=json!("ready-for-review");}
    json!({"selection":{"kind":"pr-prepare","sessionId":"session-a","expectedRevision":1,"expectedConnectionRevision":2,"draft":draft},
        "consentVersion":p::Kind::PrPrepare.consent(),"expectedPermissionRevision":"0"})
}
#[test]
fn original_main_phase_and_maximum_private_pr_decode_fit_without_changing_old_bounds() {
    use std::mem::size_of;
    use native::operation::{Capture,INPUT_BACKING,ROOT_BACKING,CONTEXT_BACKING};
    // Two actual Review stack cells include their Box pointers, not payloads.
    // Neither allocation nor the constructor/unbox stack frontier is free.
    let other=sum(&[5*ROOT_BACKING,INPUT_BACKING,2*CONTEXT_BACKING,r::NativeScope::unused_main_backing().unwrap(),
        2*size_of::<NativeProject>(),size_of::<crate::asset_source::RegisteredRoot>(),size_of::<Allow>(),
        2*size_of::<crate::edit_owner::SavedEditStamp>(),2048]).unwrap();
    let reviews=size_of::<native::Review>().checked_add(size_of::<Capture>()).unwrap().checked_mul(2).unwrap();
    assert_eq!(allow_bytes(),other.checked_add(reviews).and_then(|n|n.checked_add(size_of::<Capture>())));
    eprintln!("GitHub operation MAIN allow={:?} decode={:?} Review={} boxedCapture={} transientCapture={}",
        allow_bytes(),decode_bytes(),size_of::<native::Review>(),2*size_of::<Capture>(),size_of::<Capture>());
    assert!(main_call_fits(),"decode={:?} allow={:?}",decode_bytes(),allow_bytes());
    assert_eq!(decode_bytes(),Some(47616+2*std::mem::size_of::<Allow>()));
    assert!(super::super::dispatch::main_call_fits());assert_eq!(p::MAIN_CALL_BACKING,48*1024);assert_eq!(p::DOCUMENT_BACKING,786432);assert_eq!(r::retained_document_backing(),Some(p::DOCUMENT_BACKING));
    for ready in [false,true] {let mut raw=serde_json::to_vec(&pr(ready)).unwrap();assert!(raw.len()>4096);
        let a=decode_allow(&raw).unwrap();assert!(a.selection.operation_input().unwrap().retained_fits());
        raw.resize(native::operation::MAIN_RAW_LIMIT,b' ');assert!(decode_allow(&raw).is_ok());raw.push(b' ');assert!(decode_allow(&raw).is_err());
        let mut missing=pr(ready);missing.as_object_mut().unwrap().remove("expectedPermissionRevision");assert!(decode_allow(&serde_json::to_vec(&missing).unwrap()).is_err());
    }
    let old=json!({"selection":{"kind":"repository-create","sessionId":"session-a","consentId":"a".repeat(32),"expectedRevision":1},"consentVersion":p::Kind::RepositoryCreate.consent(),"expectedPermissionRevision":"0"});
    let mut raw=serde_json::to_vec(&old).unwrap();raw.resize(1024,b' ');assert!(decode_allow(&raw).is_ok());raw.push(b' ');assert!(decode_allow(&raw).is_err());
    assert_eq!(p::REQUEST_LIMIT,32);assert_eq!(p::IPC_WORKER_BACKING,32*1024);
}
#[test]
fn main_quota_refuses_dense_escaped_and_deep_input_before_any_deserializer() {
    struct Unentered;
    impl<'de> serde::Deserialize<'de> for Unentered {
        fn deserialize<D:serde::Deserializer<'de>>(_:D)->Result<Self,D::Error> {
            panic!("quota refusal must precede the original serde/Content allocation")
        }
    }
    let dense=format!(r#"{{"selection":{{"kind":"pr-prepare","unknown":[{}]}}}}"#,vec!["0";2000].join(","));
    let escaped=format!(r#"{{"selection":{{"kind":"pr-prepare","unknown":"{}\u00e9"}}}}"#,"a".repeat(4095));
    let total=format!(r#"{{"selection":{{"kind":"pr-prepare","x":"{}","y":"{}"}}}}"#,"a".repeat(4096),"b".repeat(2049));
    for raw in [dense,escaped,total,"1".repeat(33),format!("{}0{}","[".repeat(9),"]".repeat(9))] {
        assert!(raw.len()<=native::operation::MAIN_RAW_LIMIT);
        assert!(bounded_decode::<Unentered>(raw.as_bytes()).is_err());
    }
    // Quotas are inclusive; syntax, duplicate fields and the closed Selection
    // are still validated by the SAME original deserializer, not this scan.
    assert!(lexical_quota(format!("[{}]",vec!["0";47].join(",")).as_bytes()).is_some());
    assert!(lexical_quota(format!("{}0{}","[".repeat(8),"]".repeat(8)).as_bytes()).is_some());
    let valid=serde_json::to_string(&pr(false)).unwrap();
    for malformed in [valid.replacen("\"body\":","\"body\":\"inert\",\"body\":",1),
        valid.replacen("\"draft\":","\"unknown\":[0],\"draft\":",1)] {
        assert!(lexical_quota(malformed.as_bytes()).is_some());
        assert!(decode_allow(malformed.as_bytes()).is_err());
    }
    // This asks the SAME production helper for a typed map on a wrong string.
    // Calling JSON.deserialize_map would format the error before our visitor;
    // merely mapping that error afterwards cannot satisfy this probe. Both the
    // original visitor and custom error refuse to format, and visit_str must
    // actually be reached (even the wrapper's constant expecting cannot hide a
    // typed-backend bypass). No native owner or permission is constructed.
    static VISITS:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
    struct NeverFormat;
    impl std::fmt::Display for NeverFormat {
        fn fmt(&self,_:&mut std::fmt::Formatter<'_>)->std::fmt::Result {panic!("attacker error Display must not run")}
    }
    struct DemandsMap;
    impl<'de> serde::Deserialize<'de> for DemandsMap {
        fn deserialize<D:serde::Deserializer<'de>>(d:D)->Result<Self,D::Error> {
            struct MapVisitor;
            impl<'de> serde::de::Visitor<'de> for MapVisitor {
                type Value=DemandsMap;
                fn expecting(&self,_:&mut std::fmt::Formatter<'_>)->std::fmt::Result {panic!("attacker error expecting must not run")}
                fn visit_str<E:serde::de::Error>(self,_:&str)->Result<Self::Value,E> {
                    VISITS.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
                    Err(E::custom(NeverFormat))
                }
            }
            d.deserialize_map(MapVisitor)
        }
    }
    #[derive(serde::Deserialize)]
    struct Newtype(DemandsMap);
    #[derive(serde::Deserialize)]
    enum Envelope { Wrapped(DemandsMap) }
    assert!(bounded_decode::<DemandsMap>(br#""wrong""#).is_err());
    assert!(bounded_decode::<DemandsMap>(br#""\u0061""#).is_err());
    assert!(bounded_decode::<Option<DemandsMap>>(br#""wrong""#).is_err());
    assert!(bounded_decode::<Newtype>(br#""wrong""#).is_err());
    assert!(bounded_decode::<Vec<DemandsMap>>(br#"["wrong"]"#).is_err());
    assert!(bounded_decode::<std::collections::BTreeMap<String,DemandsMap>>(br#"{"key":"wrong"}"#).is_err());
    assert!(bounded_decode::<Envelope>(br#"{"Wrapped":"wrong"}"#).is_err());
    assert_eq!(VISITS.load(std::sync::atomic::Ordering::SeqCst),7);

    // The quota legitimately allows this malformed typed value. A last escape
    // can grow JSON scratch, other Content strings remain held, and RAW is at
    // its full limit. Derived error formatting must not add a Debug-expanded
    // control string or a formatted-message/shrink copy to the fixed48KiB.
    let mut malformed=pr(false);
    malformed["selection"]["draft"]=json!("\n".repeat(4094)+"é");
    malformed["selection"]["unknown"]=json!("b".repeat(1800));
    let mut raw=serde_json::to_string(&malformed).unwrap().replace('é',"\\u00e9").into_bytes();
    assert!(raw.len()<native::operation::MAIN_RAW_LIMIT);raw.resize(native::operation::MAIN_RAW_LIMIT,b' ');
    assert!(lexical_quota(&raw).is_some());assert!(bounded_decode::<Allow>(&raw).is_err());

    // The real existing unit-enum string/object grammar is retained. The
    // object value and unknown name use Fixed too; actual JSON end checks still
    // reject extra entries or trailing JSON after a successfully decoded value.
    use crate::github_repository_create_protocol::OwnerKind;
    for raw in [br#""user""#.as_slice(),br#"{"user":null}"#.as_slice()] {
        assert_eq!(bounded_decode::<OwnerKind>(raw).unwrap(),serde_json::from_slice::<OwnerKind>(raw).unwrap());
    }
    for raw in [format!(r#"{{"user":"{}\u00e9"}}"#,"\\n".repeat(4094)),
        format!(r#""{}\u00e9""#,"\\n".repeat(4094)),
        r#"{"user":null,"organization":null}"#.into(),r#""user" null"#.into()] {
        assert!(lexical_quota(raw.as_bytes()).is_some());assert!(bounded_decode::<OwnerKind>(raw.as_bytes()).is_err());
    }
}
#[test]
fn main_quota_keeps_maximum_unicode_pr_and_full_old_release_prepare() {
    for (body,escaped) in [("a".repeat(4094)+"é","\\u00e9"),("a".repeat(4092)+"😀","\\ud83d\\ude00")] {
        let mut value=pr(true);value["selection"]["draft"]["body"]=json!(body);
        let raw=serde_json::to_string(&value).unwrap().replace(if escaped=="\\u00e9"{"é"}else{"😀"},escaped);
        assert!(raw.len()<=native::operation::MAIN_RAW_LIMIT);
        let a=decode_allow(raw.as_bytes()).unwrap();
        let native::dispatch::Selection::PrPrepare(input)=a.selection else {panic!("wrong original kind");};
        assert_eq!(input.draft.body.len(),4096);assert_eq!(input.draft.body,body);
        assert_eq!(input.draft.body.capacity(),4096);
    }
    let old=json!({"selection":{"kind":"release-prepare","sessionId":"s".repeat(64),"expectedRevision":1,"expectedConnectionRevision":2,
        "branch":"b".repeat(200),"platform":"ios","selection":{"stage":"production-submit","candidateRunId":"31","externalRunId":"32","recoveryRunId":"33",
            "originalSourceSha":"a".repeat(40),"originalVersion":{"name":"v".repeat(64),"build":2100000000},
            "recoveryConfirmation":format!("retry-ios-operation-creates:{}:{}","a".repeat(64),"b".repeat(64))}},
        "consentVersion":p::Kind::ReleasePrepare.consent(),"expectedPermissionRevision":"18446744073709551614"});
    let raw=serde_json::to_vec(&old).unwrap();assert!(lexical_quota(&raw).is_some());
    let a=decode_allow(&raw).unwrap();assert_eq!(a.selection.kind(),p::Kind::ReleasePrepare);
    assert!(a.selection.valid()&&a.selection.retained_fits());
}
#[cfg(all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))]
#[test]
fn operations_use_complete_current_document_and_private_pr_and_original_future() {
    let bridge=Arc::new(DesktopBridge::new("/never-opened-operations-census".into()));let document=DocumentBinding::new(bridge.clone());bridge.edits.initial_document("main").unwrap();let mut state=document.lock();
    let base=document_bytes(&document,&state).expect("actual default Document + unchanged2MiB owner");
    for (id,kind,file) in [("operation-p8",Kind::AscP8,credential_format::FileKind::AscP8),("operation-sa",Kind::GoogleServiceAccount,credential_format::FileKind::GoogleServiceAccount)] {
        let observation=credential_format::inspect(file,&[],&mut||false).unwrap_or_else(|_|panic!("inert observation interrupted"));
        state.records.push(Record{key:RecordKey{id:Token(id.into()),revision:1},payload:Arc::new(Payload{kind,fields:None,material:Some(Arc::new(Material{
            origin:MaterialOrigin::Selected(asset_source::CapturedSource::memory_data(Vec::with_capacity(16*1024))),observation}))}),mutation_pending:false});
    }
    let extra=String::with_capacity(64*1024);let capacity=extra.capacity();
    state.evidence.operation=Some(EvidenceBinding{operation_id:1,kind:evidence_wire::OperationKind::Observe,selection_id:Some(extra),epoch:1,purpose:EvidencePurpose::Candidate});
    let lookup=lookup_memory::retained_document_bytes(&document.inner,&state).unwrap();let additional=installation_memory::additional_document_bytes(&document,&state).unwrap();
    assert!(additional>=capacity);let full=document_bytes(&document,&state).unwrap();assert_eq!(full,lookup+additional+crate::github_pull_request_protocol::RETAINED_LIMIT);
    assert!(full>=base+2*RECORD_METADATA_BYTES+32*1024+capacity);
    // The real maximum Arc is retained across both Doc captures; its separately
    // checked MAIN envelope remains fully in the common Doc debit, not free.
    let input=decode_allow(&serde_json::to_vec(&pr(true)).unwrap()).unwrap().selection.operation_input().unwrap();
    assert!(input.heap().unwrap()<=native::operation::INPUT_BACKING);assert!(main_call_fits());
    eprintln!("operation completeDoc+future={full} nativeFuture={} MAINallow={:?} MAINdecode={:?} privateInput={:?}",crate::github_pull_request_protocol::RETAINED_LIMIT,allow_bytes(),decode_bytes(),input.heap());
    let original=Arc::as_ptr(&state.records[0].payload);state.retiring=true;assert!(document_bytes(&document,&state).is_none());assert_eq!(original,Arc::as_ptr(&state.records[0].payload));state.retiring=false;
    state.evidence.operation.as_mut().unwrap().selection_id=Some(String::with_capacity(crate::vault_store::RESIDENT_BYTES));assert!(document_bytes(&document,&state).is_none());
    assert_eq!(sum(&[usize::MAX,1]),None);
}
