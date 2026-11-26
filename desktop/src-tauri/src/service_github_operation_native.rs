//! Fixed original repository/PR/retry entrypoints. No CLI-supplied draft, token,
//! filesystem path, endpoint or alternate native command reaches this adapter.
use super::*;
impl DocumentBinding {
    pub(super) fn github_operation_agent_start(&self, entry:&Arc<r::Entry>)->Result<(),BridgeError> {
        let input={
            let s=self.lock();
            match entry.scope().review.kind() {
                p::Kind::RepositoryPrepare | p::Kind::RepositoryPending | p::Kind::RepositoryReconcile => s.github.repository_create_operation_input(entry),
                p::Kind::PrPrepare | p::Kind::PrPending | p::Kind::PrReconcile => s.github.pull_request_operation_input(entry),
                p::Kind::FailedJobsPrepare | p::Kind::FailedJobsPending | p::Kind::FailedJobsReconcile => s.github.actions_retry_operation_input(entry),
                _=>Err(BridgeError::invalid()),
            }
        }?;
        if input.kind()!=entry.scope().review.kind() {return Err(BridgeError::invalid());}
        match input.kind() {
            p::Kind::RepositoryPrepare | p::Kind::RepositoryPending | p::Kind::RepositoryReconcile => {
                self.repository_create_execute(input.repository_create_command()?,Some(entry.clone()))?;
            }
            p::Kind::PrPrepare | p::Kind::PrPending | p::Kind::PrReconcile => {
                self.pull_request_execute(input.pull_request_command()?,Some(entry.clone()))?;
            }
            p::Kind::FailedJobsPrepare | p::Kind::FailedJobsPending | p::Kind::FailedJobsReconcile => {
                self.actions_retry_execute(input.actions_retry_command()?,Some(entry.clone()))?;
            }
            _=>return Err(BridgeError::invalid()),
        }
        Ok(()) // the relay caller return, NOT the retained native/history return
    }
}
fn sum(values:&[usize])->Option<usize> {values.iter().try_fold(0usize,|n,v|n.checked_add(*v))}
const MAIN_TOKENS:usize=48;
const MAIN_DEPTH:usize=8;
const MAIN_ATOM:usize=32;
const MAIN_STRING:usize=4096;
const MAIN_STRINGS:usize=6144;
/// A fixed MAIN-only lexical quota, before serde can buffer the internally
/// tagged Selection. Like credential_format's lexical quota, this constructs
/// no Value, Content, String, Vec or key set. Escape widths are counted to bound
/// serde's scratch, not to replace its JSON/UTF-8/unknown/duplicate validation.
fn lexical_quota(bytes:&[u8])->Option<()> {
    fn hex4(bytes:&[u8],at:usize)->Option<u16> {
        bytes.get(at..at.checked_add(4)?)?.iter().try_fold(0u16,|n,b| {
            let v=match b {b'0'..=b'9'=>b-b'0',b'a'..=b'f'=>b-b'a'+10,b'A'..=b'F'=>b-b'A'+10,_=>return None};
            n.checked_mul(16)?.checked_add(u16::from(v))
        })
    }
    let(mut at,mut tokens,mut depth,mut strings)=(0usize,0usize,0usize,0usize);
    while at<bytes.len() {
        match bytes[at] {
            b' '|b'\t'|b'\r'|b'\n'|b','|b':'=>at+=1,
            b'{'|b'['=>{tokens=tokens.checked_add(1)?;depth=depth.checked_add(1)?;at+=1;},
            b'}'|b']'=>{depth=depth.checked_sub(1)?;at+=1;},
            b'"'=>{
                tokens=tokens.checked_add(1)?;at+=1;let mut length=0usize;
                loop {
                    let byte=*bytes.get(at)?;
                    if byte==b'"' {at+=1;break;}
                    let width=if byte==b'\\' {
                        at+=1;
                        match *bytes.get(at)? {
                            b'"'|b'\\'|b'/'|b'b'|b'f'|b'n'|b'r'|b't'=>{at+=1;1},
                            b'u'=>{
                                let n=hex4(bytes,at+1)?;at+=5;
                                match n {
                                    0xD800..=0xDBFF=>{
                                        if bytes.get(at..at+2)?!=b"\\u" {return None;}
                                        let low=hex4(bytes,at+2)?;
                                        if !(0xDC00..=0xDFFF).contains(&low) {return None;}
                                        at+=6;4
                                    },
                                    0xDC00..=0xDFFF=>return None,
                                    0..=0x7F=>1,0x80..=0x7FF=>2,_=>3,
                                }
                            },
                            _=>return None,
                        }
                    } else {if byte<0x20 {return None;}at+=1;1};
                    length=length.checked_add(width).filter(|n|*n<=MAIN_STRING)?;
                }
                strings=strings.checked_add(length).filter(|n|*n<=MAIN_STRINGS)?;
            },
            _=>{
                tokens=tokens.checked_add(1)?;let start=at;
                while at<bytes.len()&&!matches!(bytes[at],b' '|b'\t'|b'\r'|b'\n'|b'{'|b'}'|b'['|b']'|b','|b':'|b'"') {
                    at+=1;if at-start>MAIN_ATOM {return None;}
                }
            },
        }
        if tokens>MAIN_TOKENS||depth>MAIN_DEPTH {return None;}
    }
    (depth==0).then_some(())
}
/// Keep attacker text out of serde's formatted type/field/variant errors. This
/// is private to the one MAIN Allow decoder, not another JSON representation.
/// The real JSON parser still owns syntax, scratch, recursion and end checks.
mod main_decode {
    use serde::de::{self, Error as _};
    use std::fmt;
    const INVALID:&str="invalid MAIN input";
    #[derive(Clone,Copy,Debug)]
    struct Fixed;
    impl fmt::Display for Fixed {
        fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result {f.write_str(INVALID)}
    }
    impl std::error::Error for Fixed {}
    impl de::Error for Fixed {
        // In particular, do not evaluate Unexpected::Str's Debug expansion or
        // a Visitor's expecting() while all RAW/Content/scratch remain held.
        fn custom<T:fmt::Display>(_:T)->Self {Self}
    }
    struct Quiet<D>(D);
    struct Visit<V> {original:V,as_enum:bool}
    impl<'de,D:de::Deserializer<'de>> de::Deserializer<'de> for Quiet<D> {
        type Error=Fixed;
        fn deserialize_any<V:de::Visitor<'de>>(self,v:V)->Result<V::Value,Fixed> {
            self.0.deserialize_any(Visit{original:v,as_enum:false}).map_err(|_|Fixed)
        }
        // Do not forward typed requests to JSON's typed peek_invalid_type: it
        // formats a wrong string BEFORE our visitor could replace the error.
        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf unit unit_struct seq tuple tuple_struct map struct
            identifier ignored_any
        }
        fn deserialize_option<V:de::Visitor<'de>>(self,v:V)->Result<V::Value,Fixed> {
            self.0.deserialize_option(Visit{original:v,as_enum:false}).map_err(|_|Fixed)
        }
        fn deserialize_newtype_struct<V:de::Visitor<'de>>(self,_:&'static str,v:V)->Result<V::Value,Fixed> {
            v.visit_newtype_struct(self)
        }
        fn deserialize_enum<V:de::Visitor<'de>>(self,_:&'static str,_:&'static[&'static str],v:V)->Result<V::Value,Fixed> {
            // No raw JSON EnumAccess/VariantAccess escapes: even unit_variant
            // must deserialize its value with Fixed rather than JSON's Error.
            self.0.deserialize_any(Visit{original:v,as_enum:true}).map_err(|_|Fixed)
        }
        fn is_human_readable(&self)->bool {self.0.is_human_readable()}
    }
    macro_rules! scalar_visits {
        ($($name:ident($ty:ty)),* $(,)?)=>{$(
            fn $name<E:de::Error>(self,value:$ty)->Result<Self::Value,E> {
                self.original.$name::<Fixed>(value).map_err(|_|E::custom(INVALID))
            }
        )*};
    }
    impl<'de,V:de::Visitor<'de>> de::Visitor<'de> for Visit<V> {
        type Value=V::Value;
        fn expecting(&self,f:&mut fmt::Formatter<'_>)->fmt::Result {f.write_str(INVALID)}
        scalar_visits! {
            visit_bool(bool),visit_i8(i8),visit_i16(i16),visit_i32(i32),visit_i64(i64),visit_i128(i128),
            visit_u8(u8),visit_u16(u16),visit_u32(u32),visit_u64(u64),visit_u128(u128),
            visit_f32(f32),visit_f64(f64),visit_char(char),visit_bytes(&[u8]),
            visit_borrowed_bytes(&'de[u8]),visit_byte_buf(Vec<u8>),
        }
        fn visit_str<E:de::Error>(self,v:&str)->Result<Self::Value,E> {
            let value=if self.as_enum {self.original.visit_enum(de::value::StrDeserializer::<Fixed>::new(v))}
                else {self.original.visit_str::<Fixed>(v)};
            value.map_err(|_|E::custom(INVALID))
        }
        fn visit_borrowed_str<E:de::Error>(self,v:&'de str)->Result<Self::Value,E> {
            let value=if self.as_enum {self.original.visit_enum(de::value::BorrowedStrDeserializer::<Fixed>::new(v))}
                else {self.original.visit_borrowed_str::<Fixed>(v)};
            value.map_err(|_|E::custom(INVALID))
        }
        fn visit_string<E:de::Error>(self,v:String)->Result<Self::Value,E> {
            let value=if self.as_enum {self.original.visit_enum(de::value::StringDeserializer::<Fixed>::new(v))}
                else {self.original.visit_string::<Fixed>(v)};
            value.map_err(|_|E::custom(INVALID))
        }
        fn visit_unit<E:de::Error>(self)->Result<Self::Value,E> {
            self.original.visit_unit::<Fixed>().map_err(|_|E::custom(INVALID))
        }
        fn visit_none<E:de::Error>(self)->Result<Self::Value,E> {
            self.original.visit_none::<Fixed>().map_err(|_|E::custom(INVALID))
        }
        fn visit_some<D:de::Deserializer<'de>>(self,d:D)->Result<Self::Value,D::Error> {
            self.original.visit_some(Quiet(d)).map_err(|_|D::Error::custom(INVALID))
        }
        fn visit_newtype_struct<D:de::Deserializer<'de>>(self,d:D)->Result<Self::Value,D::Error> {
            self.original.visit_newtype_struct(Quiet(d)).map_err(|_|D::Error::custom(INVALID))
        }
        fn visit_seq<A:de::SeqAccess<'de>>(self,a:A)->Result<Self::Value,A::Error> {
            self.original.visit_seq(Seq(a)).map_err(|_|A::Error::custom(INVALID))
        }
        fn visit_map<A:de::MapAccess<'de>>(self,a:A)->Result<Self::Value,A::Error> {
            let a=Map(a);
            let value=if self.as_enum {self.original.visit_enum(de::value::MapAccessDeserializer::new(a))}
                else {self.original.visit_map(a)};
            value.map_err(|_|A::Error::custom(INVALID))
        }
    }
    struct Seed<S>(S);
    impl<'de,S:de::DeserializeSeed<'de>> de::DeserializeSeed<'de> for Seed<S> {
        type Value=S::Value;
        fn deserialize<D:de::Deserializer<'de>>(self,d:D)->Result<Self::Value,D::Error> {
            self.0.deserialize(Quiet(d)).map_err(|_|D::Error::custom(INVALID))
        }
    }
    struct Seq<A>(A);
    impl<'de,A:de::SeqAccess<'de>> de::SeqAccess<'de> for Seq<A> {
        type Error=Fixed;
        fn next_element_seed<S:de::DeserializeSeed<'de>>(&mut self,s:S)->Result<Option<S::Value>,Fixed> {
            self.0.next_element_seed(Seed(s)).map_err(|_|Fixed)
        }
        fn size_hint(&self)->Option<usize> {self.0.size_hint()}
    }
    struct Map<A>(A);
    impl<'de,A:de::MapAccess<'de>> de::MapAccess<'de> for Map<A> {
        type Error=Fixed;
        fn next_key_seed<S:de::DeserializeSeed<'de>>(&mut self,s:S)->Result<Option<S::Value>,Fixed> {
            self.0.next_key_seed(Seed(s)).map_err(|_|Fixed)
        }
        fn next_value_seed<S:de::DeserializeSeed<'de>>(&mut self,s:S)->Result<S::Value,Fixed> {
            self.0.next_value_seed(Seed(s)).map_err(|_|Fixed)
        }
        fn size_hint(&self)->Option<usize> {self.0.size_hint()}
    }
    pub(super) fn decode<T:de::DeserializeOwned>(bytes:&[u8])->Result<T,()> {
        let mut original=serde_json::Deserializer::from_slice(bytes);
        let value=T::deserialize(Quiet(&mut original)).map_err(|_|())?;
        original.end().map_err(|_|())?;
        Ok(value)
    }
}
/// Production has only Allow as T. Tests use an unentered deserializer through
/// this SAME helper to prove dense/escaped input refuses before Content exists.
pub(super) fn bounded_decode<T:serde::de::DeserializeOwned>(bytes:&[u8])->Result<T,BridgeError> {
    if bytes.is_empty()||bytes.len()>native::operation::MAIN_RAW_LIMIT||!main_call_fits()
        || lexical_quota(bytes).is_none() {return Err(BridgeError::invalid());}
    main_decode::decode(bytes).map_err(|_|BridgeError::invalid())
}
/// One PR input allocation shared by Allow and both Doc captures. The RAW Tauri
/// Request is explicitly dropped before entering this phase. Root/String/Scope
/// copies and the typed enum expansion are still charged, not "shared" away.
/// Both Review boxes coexist before drop(current); charge their full payloads
/// plus a Capture stack cell at the constructor/unbox move frontier.
pub(super) fn allow_bytes()->Option<usize> {
    use std::mem::size_of;
    use native::operation::{Capture,INPUT_BACKING,ROOT_BACKING,CONTEXT_BACKING};
    sum(&[5*ROOT_BACKING,INPUT_BACKING,2*CONTEXT_BACKING,r::NativeScope::unused_main_backing()?,
        2*size_of::<native::Review>(),2usize.checked_mul(size_of::<Capture>())?,size_of::<Capture>(),
        2*size_of::<NativeProject>(),size_of::<crate::asset_source::RegisteredRoot>(),
        size_of::<Allow>(),2*size_of::<crate::edit_owner::SavedEditStamp>(),2048])
}
pub(super) fn decode_bytes()->Option<usize> {
    use std::mem::size_of;
    // The prepass allocates nothing. serde_json1.0.145's SliceRead scratch holds
    // one <=4096-byte decoded string; reserve(4) for Unicode may round capacity
    // to8192. Charge old+new12288 at growth, plus already-held decoded strings.
    // At owned conversion/normalization the final scratch8192 and old strings
    // may coexist with the one8192-byte private input. Neither is a free move.
    let strings=sum(&[12288,MAIN_STRINGS])?.max(sum(&[8192,MAIN_STRINGS,native::operation::INPUT_BACKING])?);
    let decode=sum(&[native::operation::MAIN_RAW_LIMIT,strings,MAIN_TOKENS*128,
        2*size_of::<Allow>(),2048])?;
    // <=48 tokens count keys too.128/token covers tagged Content/map/sequence
    // cells, their capacity/growth frontier and bounded numeric scratch. The
    // actual locked serde228/serde_json145 sources were inspected; the locked
    // regression still must run. Fixed errors never format the supplied text;
    // the existing2048 also covers the small adapter/constant-error frontier.
    // After main_decode returns, Content and Deserializer scratch are gone.
    // Input.valid's original fixed16KiB encoder then coexists with all <=6144
    // decoded string bytes, the real Arc/typed cells and SAME still-held RAW.
    let validation=sum(&[native::operation::MAIN_RAW_LIMIT,MAIN_STRINGS,16*1024,
        size_of::<crate::github_pull_request_protocol::PrepareArgs>(),2*size_of::<usize>(),
        2*size_of::<Allow>(),2048])?;
    Some(decode.max(validation))
}
pub(super) fn main_call_fits()->bool {
    allow_bytes().zip(decode_bytes()).is_some_and(|(a,d)|a.max(d)<=p::MAIN_CALL_BACKING)
}
#[cfg(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64"))))]
pub(super) fn document_bytes(document:&DocumentBinding,state:&DocumentState)->Option<usize> {
    let retained=lookup_memory::retained_document_bytes(&document.inner,state).ok()?;
    let additional=installation_memory::additional_document_bytes(document,state).ok()?;
    // All three original owners have the SAME2MiB retained limit. The original
    // Connection admits only one active native operation; old real rows/material
    // stay in D. No subtraction from D, incoming MAIN or their original futures.
    if crate::github_repository_create_protocol::RETAINED_LIMIT!=crate::github_pull_request_protocol::RETAINED_LIMIT
        || crate::github_actions_retry_protocol::RETAINED_LIMIT!=crate::github_pull_request_protocol::RETAINED_LIMIT {return None;}
    retained.checked_add(additional)?.checked_add(crate::github_pull_request_protocol::RETAINED_LIMIT)
        .filter(|n|*n<=crate::vault_store::RESIDENT_BYTES)
}
#[cfg(not(any(all(target_os="linux",target_arch="x86_64",target_env="gnu"),all(target_os="macos",target_pointer_width="64",any(target_arch="aarch64",target_arch="x86_64")))))]
pub(super) fn document_bytes(_: &DocumentBinding,_:&DocumentState)->Option<usize>{None}

#[cfg(test)]
#[path="service_github_operation_native_tests.rs"]
mod tests;
