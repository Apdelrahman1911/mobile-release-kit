//! SG1 finite direct-GTK protocol; never portal/broker/Zenity authority.
//! Exact new API/source/installed/loader/writer pins remain deliberately absent.
use super::*;
use serde::de::{self,DeserializeSeed,MapAccess,SeqAccess,Visitor};
use std::fmt;
pub(super) const PROFILE:&str="linux-x11-atspi-direct-gtk-sg1-v1";
const BASELINE:&str="e6abe8fdc6df328da336301ebfa4fffb36555d58f5611873016ef4bc8df53c50";
const API:Option<&str>=None;
const AUDIT_PINS:Option<[&str;4]>=None;
const FREEZE:&str="/opt/mrk-native-reviewed/session-gtk-freeze.json";
const FEATURES:&str="test\ndebug_assertions\ndesktop-shell\ndevelopment-runtime\nx86_64-unknown-linux-gnu\n";
const COMMON:&str="v type case profile binding roots file writer writtenNs";
const BUILD:&str="baselineManifest sourceRoster contractSource helperSource launcherSource appBinary helperBinary launcherRuntime pythonRuntime frontend featuresSha256 apiInventory";
const READY:&str="helper registry sessionBusId a11yBusId subscriptions";
const ADMISSION:&str="build readySha256 outer app helper appSpawnNs outerEndNs display fixtures pipes aliases sourceProfileSha256 installedClosureSha256 loaderClosureSha256 writerAuditSha256";
const PRESENTED:&str="admissionSha256 n kind observedNs association dialog button dialogRole states buttonRole buttonAction";
const GO:&str="admissionSha256 n kind presentedSha256 action gate operation showOrdinal producerOrdinal ownership checkpointNs inputEndNs selected";
const OWNERSHIP:&str="method operation mainId dialogId tagOrdinal checkOrdinal checkedNs transientForMain";
const INPUT:&str="admissionSha256 n kind presentedSha256 goSha256 action startedNs completedNs steps completion selected counts";
const SETTLED:&str="admissionSha256 lastInputSha256 helper waitStatus waitNs stdout stderr";
pub(super) fn audit_gate()->Check<()> {
    check(AUDIT_PINS.is_some_and(|p|p.iter().all(|s|digest(s,64))) && API.is_some_and(|s|digest(s,64)),"sg1_reviewed_execution_pins_unavailable")
}
pub(super) fn now_ns() -> Check<u64> {
    let t = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC).map_err(|_| "native_clock")?;
    let s = u64::try_from(t.tv_sec()).map_err(|_| "native_clock_negative")?;
    let ns = u64::try_from(t.tv_nsec()).map_err(|_| "native_clock_negative")?;
    check(ns < 1_000_000_000, "native_clock_range")?;
    s.checked_mul(1_000_000_000).and_then(|n| n.checked_add(ns)).ok_or("native_clock_overflow")
}
fn plus(t: u64, ns: u64) -> Check<u64> { t.checked_add(ns).ok_or("native_clock_overflow") }
fn s<'a>(v: &'a Value, k: &str) -> Check<&'a str> { v.get(k).and_then(Value::as_str).ok_or("native_string") }
fn u(v: &Value, k: &str) -> Check<u64> { v.get(k).and_then(Value::as_u64).filter(|n| *n <= u32::MAX as u64).ok_or("native_integer") }
fn d(v: &Value, k: &str) -> Check<u64> { decimal(s(v, k)?) }
fn decimal(s: &str) -> Check<u64> {
    check(!s.is_empty() && s.len() <= 20 && (s == "0" || !s.starts_with('0')) && s.bytes().all(|c| c.is_ascii_digit()), "native_decimal")?;
    s.parse().map_err(|_| "native_decimal_overflow")
}
fn keys(v: &Value, expected: &str) -> Check<()> {
    let m = v.as_object().ok_or("native_object")?;
    check(m.len() == expected.split_whitespace().count() && expected.split_whitespace().all(|k| m.contains_key(k)), "native_closed_keys")
}
fn shape(v:&Value)->Check<String> {
    if v.get("v").is_some() {
        let tail=match s(v,"type")? {"ready"=>READY,"admission"=>ADMISSION,"presented"=>PRESENTED,"go"=>GO,"input"=>INPUT,"helper-settled"=>SETTLED,_=>return Err("sg1_record_type")};
        return Ok(format!("{COMMON} {tail}"));
    }
    Ok((if v.get("route").is_some() {if v.get("process").is_some() {"route process application mainWindow parent mainId dialogId"} else {"route disappearance dialog"}}
        else if v.get("method").is_some() {OWNERSHIP}
        else if v.get("device").is_some() {if v.get("mode").is_some() {"device inode mode owner"} else {"device inode"}}
        else if v.get("pid").is_some() {"pid startTicks"}
        else if v.get("identity").is_some() {"identity executable"}
        else if v.get("sha256").is_some() && v.get("file").is_some() {"file sha256"}
        else if v.get("bus").is_some() {"bus path"}
        else if v.get("owner").is_some() && v.get("process").is_some() {"owner process"}
        else if v.get("addressSha256").is_some() {"id process addressSha256"}
        else if v.get("fd").is_some() {"fd atNs result"}
        else if v.get("run").is_some() {"run app native"}
        else if v.get("baselineManifest").is_some() {BUILD}
        else if v.get("sandbox").is_some() {"kind display server windowManager sessionBus a11yBus registry sandbox"}
        else if v.get("sourceSha256").is_some() {"project source sourceSha256"}
        else if v.get("appStdout").is_some() {"appStdout appStderr helperStdout helperStderr"}
        else if v.get("appStdoutWrite").is_some() {"appStdoutWrite appStderrWrite helperStdoutWrite helperStderrWrite"}
        else if v.get("wireMessages").is_some() {"events wireMessages queries nodes actions"}
        else if v.get("pipe").is_some() {"pipe bytes sha256 eof read close"}
        else {return Err("sg1_unknown_object");}).into())
}
// The bounded seed rejects duplicates BEFORE Value can discard them. An encoder
// using the closed declaration order then rejects whitespace/order/escape aliases.
struct Seed { depth: usize, tokens: Arc<std::sync::atomic::AtomicUsize>, limit: usize, data: bool }
impl<'de> DeserializeSeed<'de> for Seed {
    type Value = Value;
    fn deserialize<Ds: serde::Deserializer<'de>>(self, deserializer: Ds) -> Result<Value, Ds::Error> {
        if self.depth > 12 || self.tokens.fetch_add(1, Ordering::SeqCst) >= self.limit { return Err(de::Error::custom("native parser bound")); }
        deserializer.deserialize_any(self)
    }
}
impl Seed { fn child(&self) -> Self { Self { depth:self.depth + 1, tokens:self.tokens.clone(), limit:self.limit, data:self.data } } }
struct KeySeed<'a>(&'a Seed);
impl<'de> DeserializeSeed<'de> for KeySeed<'_> {
    type Value = String;
    fn deserialize<Ds: serde::Deserializer<'de>>(self, d: Ds) -> Result<String, Ds::Error> {
        if self.0.tokens.fetch_add(1, Ordering::SeqCst) >= self.0.limit { return Err(de::Error::custom("key token bound")); }
        struct KeyVisitor { limit: usize }
        impl<'de> Visitor<'de> for KeyVisitor {
            type Value = String;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("closed DTO key") }
            fn visit_str<E: de::Error>(self, t: &str) -> Result<String, E> {
                if t.len() > self.limit || !t.is_ascii() || t.contains('\0') { return Err(E::custom("key bound")); }
                Ok(t.to_owned())
            }
        }
        d.deserialize_str(KeyVisitor { limit:if self.0.data {128} else {64} })
    }
}
impl<'de> Visitor<'de> for Seed {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("finite native DTO") }
    fn visit_bool<E: de::Error>(self, b: bool) -> Result<Value, E> { Ok(Value::Bool(b)) }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> { Ok(Value::Null) }
    fn visit_u64<E: de::Error>(self, n: u64) -> Result<Value, E> { if n > u32::MAX as u64 { return Err(E::custom("integer bound")); } Ok(n.into()) }
    fn visit_i64<E: de::Error>(self, n: i64) -> Result<Value, E> { u64::try_from(n).map_err(E::custom).and_then(|v| self.visit_u64(v)) }
    fn visit_str<E: de::Error>(self, t: &str) -> Result<Value, E> {
        if t.len() > 512 || t.contains('\0') { return Err(E::custom("string bound")); } Ok(t.into())
    }
    fn visit_seq<Aa: SeqAccess<'de>>(self, mut a: Aa) -> Result<Value, Aa::Error> {
        let mut out = Vec::new();
        while let Some(v) = a.next_element_seed(self.child())? { if out.len() == 128 { return Err(de::Error::custom("array bound")); } out.push(v); }
        Ok(Value::Array(out))
    }
    fn visit_map<Aa: MapAccess<'de>>(self, mut a: Aa) -> Result<Value, Aa::Error> {
        let mut out = serde_json::Map::new();
        while let Some(k) = a.next_key_seed(KeySeed(&self))? {
            let bound = if self.data {256} else {128};
            if out.len() == bound || out.contains_key(&k) { return Err(de::Error::custom("duplicate/key bound")); }
            out.insert(k, a.next_value_seed(self.child())?);
        }
        Ok(Value::Object(out))
    }
}
fn encode_into(v: &Value, out: &mut Vec<u8>) -> Check<()> {
    match v {
        Value::Object(m) => {
            let order = shape(v)?; keys(v, &order)?; out.push(b'{');
            for (i, k) in order.split_whitespace().enumerate() {
                if i != 0 { out.push(b','); }
                serde_json::to_writer(&mut *out, k).map_err(|_| "native_encoding")?; out.push(b':');
                encode_into(m.get(k).ok_or("native_key")?, out)?;
            } out.push(b'}');
        },
        Value::Array(a) => { out.push(b'['); for (i, x) in a.iter().enumerate() { if i != 0 { out.push(b','); } encode_into(x, out)?; } out.push(b']'); },
        _ => serde_json::to_writer(&mut *out, v).map_err(|_| "native_encoding")?,
    }
    check(out.len() <= 16384, "native_encoding_bound")
}
fn encode(v: &Value) -> Check<Vec<u8>> { let mut b = Vec::new(); encode_into(v, &mut b)?; b.push(b'\n'); Ok(b) }
fn id(v: &Value, directory: bool) -> Check<()> {
    keys(v, "device inode mode owner")?; d(v,"device")?; check(d(v,"inode")? != 0, "native_identity")?; u(v,"owner")?;
    // Executables can be root-owned; only the actual run directories must be
    // non-root. Do not conflate executable owner with process effective UID.
    if directory { check(u(v,"mode")? == 0o40700 && u(v,"owner")? != 0, "native_directory_mode")?; } else { u(v,"mode")?; }
    Ok(())
}
fn reference(v: &Value) -> Check<()> {
    keys(v,"bus path")?; name(s(v,"bus")?)?; object_path(s(v,"path")?)
}
fn name(t: &str) -> Check<()> {
    check(t.starts_with(':') && t.len() <= 64 && t[1..].contains('.') && t[1..].split('.').all(|part|
        !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')), "native_bus_name")
}
fn object_path(t: &str) -> Check<()> { check(t.starts_with('/') && t.len() <= 256 && (t == "/" || t[1..].split('/').all(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))), "native_object_path") }
fn pid(v: &Value) -> Check<()> { keys(v,"pid startTicks")?; check((1..=4194304).contains(&u(v,"pid")?), "native_pid")?; d(v,"startTicks")?; Ok(()) }
fn exe(v: &Value) -> Check<()> { keys(v,"file sha256")?; id(&v["file"],false)?; check(u(&v["file"],"mode")? & 0o170000 == 0o100000,"native_executable_mode")?; h(s(v,"sha256")?) }
fn process(v: &Value) -> Check<()> { keys(v,"identity executable")?; pid(&v["identity"])?; exe(&v["executable"]) }
fn service(v: &Value) -> Check<()> { keys(v,"owner process")?; name(s(v,"owner")?)?; process(&v["process"]) }
fn h(t: &str) -> Check<()> { check(digest(t,64),"native_digest") }
fn close(v: &Value) -> Check<()> {
    keys(v,"fd atNs result")?; check(u(v,"fd")? <= 1048575 && s(v,"result")? == "positive-consuming-close" && d(v,"atNs")? <= now_ns()?,"native_close")
}
fn pipe(v: &Value) -> Check<()> { keys(v,"device inode")?; d(v,"device")?; check(d(v,"inode")? != 0,"native_pipe") }
fn stream(v: &Value) -> Check<()> {
    keys(v,"pipe bytes sha256 eof read close")?; pipe(&v["pipe"])?; h(s(v,"sha256")?)?; close(&v["close"])?;
    check(u(v,"bytes")? <= 16384 && v["eof"] == true && s(v,"read")? == "original-complete","native_stream")
}
fn pid_value(files: &FileBook) -> Check<Value> {
    let p=std::process::id(); let bytes=files.read_kernel(&PathBuf::from(format!("/proc/{p}/stat")),4096)?;
    let text=std::str::from_utf8(&bytes).map_err(|_|"native_proc_utf8")?;
    let tail=text.rsplit_once(')').ok_or("native_proc_stat")?.1;
    let start=tail.split_whitespace().nth(19).ok_or("native_proc_stat")?; decimal(start)?;
    Ok(json!({"pid":p,"startTicks":start}))
}
impl FileBook {
    fn read_native(&self,path:&Path,limit:u64)->Check<Vec<u8>> {
        let before=fs::symlink_metadata(path).map_err(|_|"native_read_metadata")?;
        check(before.mode()==0o100600 && before.uid()!=0 && before.nlink()==1,"native_read_private_original")?;
        let bytes=self.read(path,limit)?; // SAME original book/read/positive consuming close
        let after=fs::symlink_metadata(path).map_err(|_|"native_read_metadata")?;
        check(Identity::of(&before)==Identity::of(&after) && before.len()==after.len() && after.nlink()==1
            && before.mtime()==after.mtime() && before.mtime_nsec()==after.mtime_nsec()
            && before.ctime()==after.ctime() && before.ctime_nsec()==after.ctime_nsec(),"native_read_original_changed")?;
        Ok(bytes)
    }
    fn read_kernel(&self,path:&Path,limit:u64)->Check<Vec<u8>> {
        let mut f=self.locked()?; Self::ready(&mut f)?;
        let original=OpenOptions::new().read(true).custom_flags(nix::libc::O_NOFOLLOW|nix::libc::O_NONBLOCK).open(path).map_err(|_|"native_proc_open")?;
        Self::register(&mut f,original); let mut b=Vec::new();
        let result=f.active.as_mut().ok_or("native_proc_original")?.take(limit+1).read_to_end(&mut b);
        Self::close(&mut f)?; check(result.is_ok() && b.len() as u64 <=limit,"native_proc_read")?; Ok(b)
    }
    fn publish_native(&self,path:&Path,mut v:Value)->Check<(Value,String,Vec<u8>)> {
        let pending=path.with_file_name(format!("{}.pending",path.file_name().and_then(|p|p.to_str()).ok_or("native_filename")?));
        let mut f=self.locked()?; Self::ready(&mut f)?;
        let original=OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(nix::libc::O_NOFOLLOW).open(&pending).map_err(|_|"native_pending_open")?;
        Self::register(&mut f,original);
        let result: Check<(Vec<u8>, Identity)>=(|| {
            let file=f.active.as_mut().ok_or("native_file_original")?;
            let before=file.metadata().map_err(|_|"native_pending_stat")?;
            check(before.mode()==0o100600 && before.nlink()==1 && before.len()==0
                && before.uid() as u64==u(&v["roots"]["run"],"owner")?,"native_pending_identity_before_encoding")?;
            v["file"]=identity_value(Identity::of(&before)); v["writtenNs"]=now_ns()?.to_string().into();
            let bytes=encode(&v)?;
            check(bytes.len()<=4096,"native_go_bound")?;
            // The generated DTO must pass the SAME closed schema/token/depth
            // checks before the one write, not only after being published.
            check(parse(&bytes,"go")?==v,"native_pending_dto")?;
            let count=file.write(&bytes).map_err(|_|"native_pending_write")?; let after=file.metadata().map_err(|_|"native_pending_stat")?;
            check(count==bytes.len() && after.len()==bytes.len() as u64 && after.nlink()==1 && Identity::of(&after)==Identity::of(&before),"native_pending_short_or_changed")?;
            let named=fs::symlink_metadata(&pending).map_err(|_|"native_pending_named_stat")?;
            check(Identity::of(&named)==Identity::of(&before) && named.nlink()==1 && named.len()==bytes.len() as u64,"native_pending_name_changed")?;
            Ok((bytes,Identity::of(&before)))
        })();
        Self::close(&mut f)?; let (bytes,identity)=result?;
        #[cfg(all(target_os="linux",target_arch="x86_64",target_env="gnu"))]
        rustix::fs::renameat_with(rustix::fs::CWD,&pending,rustix::fs::CWD,path,rustix::fs::RenameFlags::NOREPLACE).map_err(|_|"native_publish_noreplace")?;
        #[cfg(not(all(target_os="linux",target_arch="x86_64",target_env="gnu")))]
        return Err("native_linux_only");
        let after=fs::symlink_metadata(path).map_err(|_|"native_published_stat")?;
        check(Identity::of(&after)==identity && after.nlink()==1 && after.len()==bytes.len() as u64,"native_publication_changed")?;
        Ok((v,hash(&bytes),bytes))
    }
}
fn roster()->&'static [&'static str] {&["picker-cancel","picker-select","source-select","quit-cancel","quit-ok"]}
fn action(n:u32)->&'static str {match n {2=>"select-project",3=>"select-source",5=>"ok",_=>"cancel"}}
fn identity_tags(admission_sha:&str,n:u32)->Check<(String,String)> {
    h(admission_sha)?;check((1..=5).contains(&n),"sg1_topology_index")?;
    // ORIGINAL admission bytes, never the reusable build binding or a caller ID.
    Ok((format!("mrk-sg1:{admission_sha}:main"),format!("mrk-sg1:{admission_sha}:d{n}")))
}
fn ownership(v:&Value,admission_sha:&str,n:u32,show:u64,producer:u64,checkpoint:u64)->Check<()> {
    keys(v,OWNERSHIP)?;let (main,dialog)=identity_tags(admission_sha,n)?;
    check(s(v,"method")?=="gtk-window-get-transient-for" && u(v,"operation")?==n as u64
        && s(v,"mainId")?==main && s(v,"dialogId")?==dialog && v["transientForMain"]==true
        && (1..=512).contains(&u(v,"tagOrdinal")?) && u(v,"tagOrdinal")?<show
        && show<u(v,"checkOrdinal")? && u(v,"checkOrdinal")?<producer && producer<=512
        && d(v,"checkedNs")?<=checkpoint,"sg1_original_topology_proof")
}
fn identity_value(x:Identity)->Value {x.value()}
fn selected(a:&Value,n:u32)->Value {match n {2=>a["fixtures"]["project"].clone(),3=>a["fixtures"]["source"].clone(),_=>Value::Null}}
fn tree(bytes:&[u8],limit:usize,data:bool)->Check<Value> {
    let mut de=serde_json::Deserializer::from_slice(bytes);
    let value=Seed {depth:0,tokens:Arc::new(std::sync::atomic::AtomicUsize::new(0)),limit,data}.deserialize(&mut de).map_err(|_|"sg1_finite_json")?;
    de.end().map_err(|_|"sg1_trailing_json")?;Ok(value)
}
fn parse(bytes:&[u8],kind:&str)->Check<Value> {
    let limit=if kind=="admission" {16384} else {4096};
    check(bytes.len()<=limit && bytes.last()==Some(&b'\n'),"sg1_record_bound")?;
    let value=tree(bytes,if kind=="admission" {2048} else {768},false)?;
    check(s(&value,"type")?==kind && encode(&value)?==bytes,"sg1_canonical_record")?; validate(&value)?;Ok(value)
}
fn validate(v:&Value)->Check<()> {
    keys(v,&shape(v)?)?;check(u(v,"v")?==1 && s(v,"case")?=="SG1" && s(v,"profile")?==PROFILE,"sg1_common")?;
    h(s(v,"binding")?)?;keys(&v["roots"],"run app native")?;
    for k in ["run","app","native"] {id(&v["roots"][k],true)?;check(v["roots"][k]["owner"]==v["roots"]["run"]["owner"],"sg1_roots_owner")?;}
    id(&v["file"],false)?;pid(&v["writer"])?;
    check(u(&v["file"],"mode")?==0o100600 && v["file"]["owner"]==v["roots"]["run"]["owner"] && d(v,"writtenNs")?<=now_ns()?,"sg1_original_record")?;
    let kind=s(v,"type")?;
    if !matches!(kind,"ready"|"admission") {h(s(v,"admissionSha256")?)?;}
    match kind {
        "ready"=>{process(&v["helper"])?;service(&v["registry"])?;
            check(digest(s(v,"sessionBusId")?,32) && digest(s(v,"a11yBusId")?,32) && s(v,"subscriptions")?=="direct-gtk-events-v1","sg1_ready")?;},
        "admission"=>{
            keys(&v["build"],BUILD)?;for k in BUILD.split_whitespace() {h(s(&v["build"],k)?)?;}
            for k in ["readySha256","sourceProfileSha256","installedClosureSha256","loaderClosureSha256","writerAuditSha256"] {h(s(v,k)?)?;}
            for k in ["outer","app","helper"] {process(&v[k])?;}
            let x=&v["display"];keys(x,"kind display server windowManager sessionBus a11yBus registry sandbox")?;
            check(s(x,"kind")?=="x11" && s(x,"sandbox")?=="intact-nonroot" && s(x,"display")?.starts_with(':') && s(x,"display")?.len()<=16,"sg1_x11")?;
            for k in ["server","windowManager"] {process(&x[k])?;}service(&x["registry"])?;
            for k in ["sessionBus","a11yBus"] {let b=&x[k];keys(b,"id process addressSha256")?;process(&b["process"])?;h(s(b,"addressSha256")?)?;check(digest(s(b,"id")?,32),"sg1_bus_id")?;}
            keys(&v["fixtures"],"project source sourceSha256")?;id(&v["fixtures"]["project"],true)?;id(&v["fixtures"]["source"],false)?;
            check(v["fixtures"]["source"]["mode"]==0o100600 && v["fixtures"]["source"]["owner"]==v["roots"]["run"]["owner"]
                && v["fixtures"]["project"]["owner"]==v["roots"]["run"]["owner"]
                && s(&v["fixtures"],"sourceSha256")?==hash(&[0xfe,0xed,0xfe,0xed,0,0,0,2,0,0,0,0]),"sg1_synthetic_binding")?;
            keys(&v["pipes"],"appStdout appStderr helperStdout helperStderr")?;
            for k in ["appStdout","appStderr","helperStdout","helperStderr"] {pipe(&v["pipes"][k])?;}
            keys(&v["aliases"],"appStdoutWrite appStderrWrite helperStdoutWrite helperStderrWrite")?;
            for k in ["appStdoutWrite","appStderrWrite","helperStdoutWrite","helperStderrWrite"] {close(&v["aliases"][k])?;check(d(&v["aliases"][k],"atNs")?<=d(v,"writtenNs")?,"sg1_alias_order")?;}
            check(d(v,"outerEndNs")?==plus(d(v,"appSpawnNs")?,90_000_000_000)? && d(v,"appSpawnNs")?<=d(v,"writtenNs")?
                && d(v,"writtenNs")?<=plus(d(v,"appSpawnNs")?,2_000_000_000)?,"sg1_admission_endpoint")?;
        },
        "presented"=>{
            let a=&v["association"];keys(a,"route process application mainWindow parent mainId dialogId")?;
            check(s(a,"route")?=="direct-gtk","sg1_no_foreign_dialog_route")?;process(&a["process"])?;
            for k in ["application","mainWindow","parent"] {reference(&a[k])?;}
            let (main,dialog)=identity_tags(s(v,"admissionSha256")?,u(v,"n")? as u32)?;
            reference(&v["dialog"])?;reference(&v["button"])?;
            check(s(a,"mainId")?==main && s(a,"dialogId")?==dialog && a["mainWindow"]!=a["application"]
                && a["mainWindow"]!=v["dialog"] && a["application"]!=v["dialog"]
                && v["button"]!=a["application"] && v["button"]!=a["mainWindow"]
                && a["parent"]==a["application"]
                && [&a["mainWindow"],&a["parent"],&v["dialog"],&v["button"]].iter().all(|r|r["bus"]==a["application"]["bus"])
                && v["dialog"]!=v["button"] && matches!(s(v,"dialogRole")?,"dialog"|"file-chooser"|"alert")
                && s(v,"states")?=="showing-enabled-sensitive-modal-singleton" && s(v,"buttonRole")?=="push-button"
                && s(v,"buttonAction")?=="click" && d(v,"observedNs")?<=d(v,"writtenNs")?,"sg1_direct_original_refs")?;
        },
        "go"=>{h(s(v,"presentedSha256")?)?;
            ownership(&v["ownership"],s(v,"admissionSha256")?,u(v,"n")? as u32,u(v,"showOrdinal")?,u(v,"producerOrdinal")?,d(v,"checkpointNs")?)?;
            check(u(v,"operation")?==u(v,"n")? && (1..=512).contains(&u(v,"showOrdinal")?) && u(v,"showOrdinal")?<u(v,"producerOrdinal")?
                && u(v,"producerOrdinal")?<=512 && d(v,"checkpointNs")?<=d(v,"writtenNs")?
                && d(v,"inputEndNs")?==plus(d(v,"checkpointNs")?,2_000_000_000)? && d(v,"writtenNs")?<d(v,"inputEndNs")?,"sg1_go_order")?;},
        "input"=>{
            for k in ["presentedSha256","goSha256"] {h(s(v,k)?)?;}
            let n=u(v,"n")? as u32;
            let expected=if matches!(n,2|3) {json!(["focus:true","control-lock:normal","keysym-l:normal","control-unlock:normal","set-location:true","click:true"])} else {json!(["click:true"])};
            check(v["steps"]==expected && d(v,"startedNs")?<=d(v,"completedNs")? && d(v,"completedNs")?<=d(v,"writtenNs")?,"sg1_input_steps")?;
            let c=&v["completion"];keys(c,"route disappearance dialog")?;reference(&c["dialog"])?;
            check(s(c,"route")?=="direct-gtk" && matches!(s(c,"disappearance")?,"defunct"|"removed-from-bound-root"),"sg1_same_object_disappearance")?;
            keys(&v["counts"],"events wireMessages queries nodes actions")?;
            for (k,max) in [("events",1024),("wireMessages",8192),("queries",4096),("nodes",512),("actions",15)] {check(u(&v["counts"],k)?<=max,"sg1_actor_bound")?;}
        },
        "helper-settled"=>{h(s(v,"lastInputSha256")?)?;process(&v["helper"])?;
            check(u(v,"waitStatus")?==0 && d(v,"waitNs")?<=d(v,"writtenNs")?,"sg1_helper_wait")?;
            for k in ["stdout","stderr"] {stream(&v[k])?;check(u(&v[k],"bytes")?==0 && s(&v[k],"sha256")?==hash(b"") && d(&v[k]["close"],"atNs")?<=d(v,"writtenNs")?,"sg1_helper_stream")?;}
        },_=>return Err("sg1_record_type"),
    }
    if matches!(kind,"presented"|"go"|"input") {
        let n=u(v,"n")? as usize;check((1..=5).contains(&n) && s(v,"kind")?==roster()[n-1],"sg1_five_dialog_roster")?;
        if kind!="presented" {
            check(s(v,"action")?==action(n as u32) && v["selected"].is_null()==!matches!(n,2|3),"sg1_action")?;
            if !v["selected"].is_null() {id(&v["selected"],n==2)?;}
        }
        if kind=="go" {check(s(v,"gate")?==if n==1 {"preserved-close"} else {"presented"},"sg1_go_gate")?;}
    }Ok(())
}
fn immutable(path:&Path)->Check<()> {
    check(path.is_absolute() && path.canonicalize().map_err(|_|"sg1_pin_path")?==path,"sg1_pin_alias")?;
    for p in path.ancestors() {let m=fs::symlink_metadata(p).map_err(|_|"sg1_pin_ancestor")?;
        check(m.uid()==0 && m.mode()&0o022==0,"sg1_root_owned_review_pin")?;}
    Ok(())
}
fn recheck_freeze(files:&FileBook,a:&Value)->Check<()> {
    immutable(Path::new(FREEZE))?;let bytes=files.read(Path::new(FREEZE),65536)?;let f=tree(&bytes,16000,true)?;
    keys(&f,"version profile baselineCommit sourceSha frontendSha256 featuresSha256 apiInventory repository app helper python libc display sourceHashes executables installed loader audits")?;
    check(f["version"]==1 && s(&f,"profile")?==PROFILE && s(&f,"baselineCommit")?=="6768b284c0d01f6f70913799f4fadfdd572fb162"
        && s(&f,"apiInventory")?==API.ok_or("sg1_api_pin")? && s(&f,"featuresSha256")?==hash(FEATURES.as_bytes())
        && s(&f,"sourceSha")?==env("MRK_SESSION_GTK_SOURCE_SHA")? && s(&f,"frontendSha256")?==env("MRK_SESSION_GTK_FRONTEND_SHA256")?,"sg1_reviewed_freeze")?;
    let roster=f["sourceHashes"].as_object().ok_or("sg1_frozen_sources")?;
    check(roster.len()==SOURCES.len(),"sg1_frozen_source_roster")?;
    for source in SOURCES {check(roster.get(source.path).and_then(Value::as_str)==Some(hash(source.bytes).as_str()),"sg1_frozen_source_bytes")?;}
    let member=|value:&Value,cap:u64|->Check<String> {
        keys(value,"path sha256")?;let path=PathBuf::from(s(value,"path")?);immutable(&path)?;
        let actual=hash(&files.read(&path,cap)?);check(actual==s(value,"sha256")?,"sg1_frozen_member_changed")?;Ok(actual)
    };
    for (role,key) in [("app","appBinary"),("helper","helperBinary"),("python","pythonRuntime")] {
        check(member(&f[role],256*1024*1024)?==s(&a["build"],key)?,"sg1_frozen_binary")?;
    }
    let audits=f["audits"].as_array().ok_or("sg1_frozen_audits")?;
    check(audits.len()==4,"sg1_frozen_audit_roster")?;
    for (audit,pin) in audits.iter().zip(AUDIT_PINS.ok_or("sg1_audit_pins")?) {check(member(audit,65536)?==pin,"sg1_reviewed_audit_changed")?;}
    // Loader closure already runs before main; these byte/roster rechecks are
    // necessary, never a substitute for the separately pinned pre-main audit.
    for k in ["installed","loader"] {
        let entries=f[k].as_array().ok_or("sg1_closure_roster")?;check(!entries.is_empty() && entries.len()<=128,"sg1_closure_bound")?;
        for value in entries {member(value,256*1024*1024)?;}
    }Ok(())
}
struct Stored {value:Value,sha:String,_bytes:Vec<u8>}
struct Slot {presented:Option<Stored>,go:Option<Stored>,input:Option<Stored>}
struct State {slots:[Slot;5],polls:u32,unknown:bool,settled:Option<Stored>}
pub(super) struct NativeAdmission {admission:Value,_bytes:Vec<u8>,sha:String,root:PathBuf,self_pid:Value,state:Mutex<State>}
struct Operation<'a>{owner:&'a NativeAdmission,done:bool}
impl Operation<'_>{fn done(mut self){self.done=true;}}
impl Drop for Operation<'_>{fn drop(&mut self){if !self.done {self.owner.fail();}}}
impl NativeAdmission {
    pub(super) fn admit(files:&FileBook,stdout:&Stdout)->Check<Self> {
        audit_gate()?;let root=exact_path("MRK_SESSION_GTK_ROOT")?;let native=root.join("native");let own=pid_value(files)?;
        let mut roots=serde_json::Map::new();
        for (key,path) in [("run",root.clone()),("app",root.join("app")),("native",native.clone())] {
            let value=Identity::of(&fs::symlink_metadata(path).map_err(|_|"sg1_root_stat")?).value();id(&value,true)?;roots.insert(key.into(),value);
        }
        let end=plus(now_ns()?,2_000_000_000)?;let path=native.join("admission.json");let mut polls=0;
        for attempt in 0..400 {check(now_ns()?<end,"sg1_admission_deadline")?;polls+=1;
            match fs::symlink_metadata(&path) {Ok(_)=>break,Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{},Err(_)=>return Err("sg1_admission_stat")}
            check(attempt<399,"sg1_admission_missing")?;std::thread::sleep(Duration::from_millis(5));
        }
        let bytes=files.read_native(&path,16384)?;let a=parse(&bytes,"admission")?;
        check(a["roots"]==Value::Object(roots) && a["app"]["identity"]==own && a["writer"]==a["outer"]["identity"]
            && d(&a,"outerEndNs")?>now_ns()? && a["file"]==Identity::of(&fs::symlink_metadata(&path).map_err(|_|"sg1_admission_stat")?).value(),"sg1_admission_originals")?;
        let st=nix::sys::stat::fstat(stdout).map_err(|_|"sg1_stdout_stat")?;
        check(a["pipes"]["appStdout"]==json!({"device":st.st_dev.to_string(),"inode":st.st_ino.to_string()}),"sg1_stdout_original")?;
        let b=&a["build"];let mut roster=String::new();
        for source in SOURCES {roster.push_str(source.path);roster.push(' ');roster.push_str(&hash(source.bytes));roster.push('\n');}
        check(s(b,"baselineManifest")?==BASELINE && s(b,"apiInventory")?==API.ok_or("sg1_api_pin")?
            && s(b,"sourceRoster")?==hash(roster.as_bytes()) && s(b,"featuresSha256")?==hash(FEATURES.as_bytes()),"sg1_build_binding")?;
        for (key,path) in [("contractSource","desktop/src-tauri/src/session_gtk_qualification/native_contract.rs"),("helperSource","desktop/native/session_gtk_input_linux.c"),("launcherSource","desktop/tools/qualify_session_gtk.py")] {
            let source=SOURCES.iter().find(|source|source.path==path).ok_or("sg1_source_missing")?;check(s(b,key)?==hash(source.bytes),"sg1_source_hash")?;
        }
        let mut binding=String::from("MRK_NATIVE_BUILD_V1\n");for k in BUILD.split_whitespace(){binding.push_str(s(b,k)?);binding.push('\n');}
        check(s(&a,"binding")?==hash(binding.as_bytes()) && a["app"]["executable"]["sha256"]==b["appBinary"]
            && a["helper"]["executable"]["sha256"]==b["helperBinary"] && a["outer"]["executable"]["sha256"]==b["launcherRuntime"],"sg1_artifact_binding")?;
        for (key,pin) in ["sourceProfileSha256","installedClosureSha256","loaderClosureSha256","writerAuditSha256"].into_iter().zip(AUDIT_PINS.ok_or("sg1_pins")?) {
            check(s(&a,key)?==pin,"sg1_execution_pin_mismatch")?;
        }
        recheck_freeze(files,&a)?;
        let own_exe=std::env::current_exe().map_err(|_|"sg1_self_exe")?;
        check(a["app"]["executable"]["file"]==Identity::of(&fs::symlink_metadata(own_exe).map_err(|_|"sg1_self_exe")?).value(),"sg1_original_executable")?;
        let admitted=Self {admission:a,_bytes:bytes.clone(),sha:hash(&bytes),root:native,self_pid:own,
            state:Mutex::new(State {slots:std::array::from_fn(|_|Slot {presented:None,go:None,input:None}),polls,unknown:false,settled:None})};
        admitted.roots_unchanged()?;Ok(admitted)
    }
    pub(super) fn run_root(&self)->PathBuf {self.root.parent().map(Path::to_path_buf).unwrap_or_default()}
    pub(super) fn fixtures(&self)->&Value {&self.admission["fixtures"]}
    pub(super) fn app_binary(&self)->Check<&str>{s(&self.admission["build"],"appBinary")}
    pub(super) fn python_binary(&self)->Check<&str>{s(&self.admission["build"],"pythonRuntime")}
    pub(super) fn binding(&self)->Value {json!({"profile":PROFILE,"admissionSha256":self.sha,"build":self.admission["build"]})}
    pub(super) fn identity_tags(&self,n:u32)->Check<(String,String)> {
        let _state=self.locked()?;identity_tags(&self.sha,n)
    }
    pub(super) fn topology_endpoint(&self,n:u32)->Check<u64> {
        let guard=self.operation();check((1..=5).contains(&n),"sg1_topology_index")?;
        let b=self.locked()?;let slot=&b.slots[n as usize-1];check(slot.go.is_none(),"sg1_topology_after_go")?;
        let presented=&slot.presented.as_ref().ok_or("sg1_topology_before_presented")?.value;
        let end=plus(d(presented,"observedNs")?,2_000_000_000)?.min(d(&self.admission,"outerEndNs")?);
        check(now_ns()?<end,"sg1_topology_endpoint")?;guard.done();Ok(end)
    }
    pub(super) fn topology_tick(&self,end:u64)->Check<()> {
        let guard=self.operation();let mut b=self.locked()?;
        let mut pending=b.slots.iter().filter(|s|s.presented.is_some()&&s.go.is_none());
        let presented=&pending.next().ok_or("sg1_topology_no_pending")?.presented.as_ref().ok_or("sg1_topology_before_presented")?.value;
        check(pending.next().is_none(),"sg1_topology_multiple_pending")?;
        let original_end=plus(d(presented,"observedNs")?,2_000_000_000)?.min(d(&self.admission,"outerEndNs")?);
        check(end==original_end && now_ns()?<end,"sg1_topology_endpoint")?;
        // Same finite accounting as native-record polling, not a fresh budget.
        check(b.polls<10000,"sg1_metadata_poll_bound")?;b.polls+=1;guard.done();Ok(())
    }
    fn roots_unchanged(&self)->Check<()> {
        let run=self.run_root();check(run.canonicalize().map_err(|_|"sg1_run_path")?==run,"sg1_run_alias")?;
        for (key,path) in [("run",run.clone()),("app",run.join("app")),("native",self.root.clone())] {
            check(Identity::of(&fs::symlink_metadata(path).map_err(|_|"sg1_root_stat")?).value()==self.admission["roots"][key],"sg1_root_changed")?;
        }Ok(())
    }
    fn fail(&self){if let Ok(mut state)=self.state.lock(){state.unknown=true;}}
    fn operation(&self)->Operation<'_>{Operation {owner:self,done:false}}
    fn locked(&self)->Check<std::sync::MutexGuard<'_,State>> {
        let state=self.state.lock().map_err(|_|"sg1_native_poisoned")?;check(!state.unknown && state.settled.is_none(),"sg1_native_closed")?;Ok(state)
    }
    async fn read(&self,files:&FileBook,name:&str,kind:&str,end:u64)->Check<Stored> {
        self.roots_unchanged()?;let end=end.min(d(&self.admission,"outerEndNs")?);let path=self.root.join(name);
        for attempt in 0..400 {
            check(now_ns()?<end,"sg1_native_read_endpoint")?;
            {let mut b=self.locked()?;check(b.polls<10000,"sg1_metadata_poll_bound")?;b.polls+=1;}
            match fs::symlink_metadata(&path) {Ok(_)=>break,Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{},Err(_)=>return Err("sg1_record_stat")}
            check(attempt<399,"sg1_record_missing")?;tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let bytes=files.read_native(&path,4096)?;let v=parse(&bytes,kind)?;self.roots_unchanged()?;
        check(v["roots"]==self.admission["roots"] && v["binding"]==self.admission["binding"] && s(&v,"admissionSha256")?==self.sha
            && v["file"]==Identity::of(&fs::symlink_metadata(&path).map_err(|_|"sg1_record_stat")?).value()
            && now_ns()?<end && v["writer"]==self.admission[if kind=="helper-settled" {"outer"} else {"helper"}]["identity"],"sg1_record_original_link")?;
        Ok(Stored {value:v,sha:hash(&bytes),_bytes:bytes})
    }
    pub(super) async fn presented(&self,files:&FileBook,n:u32)->Check<()> {
        let guard=self.operation();check((1..=5).contains(&n),"sg1_native_index")?;
        {let b=self.locked()?;check(b.slots[n as usize-1].presented.is_none() && b.slots.iter().take(n as usize-1).all(|s|s.input.is_some()),"sg1_native_step_order")?;}
        let record=self.read(files,&format!("d{n}.presented.json"),"presented",plus(now_ns()?,2_000_000_000)?).await?;
        let v=&record.value;let a=&v["association"];
        check(u(v,"n")?==n as u64 && a["process"]==self.admission["app"] && d(v,"observedNs")?>=d(&self.admission,"appSpawnNs")?,"sg1_actual_app_dialog")?;
        let mut b=self.locked()?;
        if n>1 {
            let first=&b.slots[0].presented.as_ref().ok_or("sg1_original_app_ref")?.value["association"];
            check(a["application"]==first["application"] && a["mainWindow"]==first["mainWindow"] && a["mainId"]==first["mainId"],"sg1_original_app_ref_changed")?;
            for previous in b.slots.iter().take(n as usize-1) {
                check(previous.presented.as_ref().is_some_and(|p|p.value["dialog"]!=v["dialog"] && p.value["button"]!=v["button"]),"sg1_accessible_ref_reused")?;
            }
        }
        b.slots[n as usize-1].presented=Some(record);guard.done();Ok(())
    }
    pub(super) async fn go(&self,files:&FileBook,n:u32,show:u32,ordinal:u32,proof:&OwnershipProof)->Check<()> {
        let guard=self.operation();check((1..=5).contains(&n),"sg1_native_index")?;self.roots_unchanged()?;let mut b=self.locked()?;
        let slot=&mut b.slots[n as usize-1];check(slot.go.is_none(),"sg1_go_repeated")?;
        let presented=slot.presented.as_ref().ok_or("sg1_not_presented")?;let checkpoint=now_ns()?;let end=plus(checkpoint,2_000_000_000)?;
        let proof=serde_json::to_value(proof).map_err(|_|"sg1_topology_encoding")?;
        ownership(&proof,&self.sha,n,show as u64,ordinal as u64,checkpoint)?;
        check(proof["mainId"]==presented.value["association"]["mainId"] && proof["dialogId"]==presented.value["association"]["dialogId"]
            && d(&presented.value,"writtenNs")?<=d(&proof,"checkedNs")?,"sg1_presented_topology_link")?;
        check(checkpoint>=d(&presented.value,"writtenNs")? && checkpoint<=plus(d(&presented.value,"observedNs")?,2_000_000_000)?
            && end<=d(&self.admission,"outerEndNs")?,"sg1_go_endpoint")?;
        let v=json!({"v":1,"type":"go","case":"SG1","profile":PROFILE,"binding":self.admission["binding"],"roots":self.admission["roots"],"file":null,"writer":self.self_pid,"writtenNs":checkpoint.to_string(),
            "admissionSha256":self.sha,"n":n,"kind":roster()[n as usize-1],"presentedSha256":presented.sha,"action":action(n),"gate":if n==1 {"preserved-close"} else {"presented"},
            "operation":n,"showOrdinal":show,"producerOrdinal":ordinal,"ownership":proof,"checkpointNs":checkpoint.to_string(),"inputEndNs":end.to_string(),"selected":selected(&self.admission,n)});
        let (value,sha,bytes)=files.publish_native(&self.root.join(format!("d{n}.go.json")),v)?;
        slot.go=Some(Stored {value,sha,_bytes:bytes});guard.done();Ok(())
    }
    pub(super) async fn completed(&self,files:&FileBook,n:u32)->Check<()> {
        let guard=self.operation();let end={let b=self.locked()?;let s=&b.slots[n as usize-1];check(s.input.is_none(),"sg1_input_reopened")?;d(&s.go.as_ref().ok_or("sg1_no_go")?.value,"inputEndNs")?};
        let record=self.read(files,&format!("d{n}.input.json"),"input",end).await?;let v=&record.value;let mut b=self.locked()?;
        if n>1 {let old=&b.slots[n as usize-2].input.as_ref().ok_or("sg1_prior_input")?.value;
            for k in ["events","wireMessages","queries","nodes","actions"] {check(u(&v["counts"],k)?>=u(&old["counts"],k)?,"sg1_counter_regressed")?;}}
        let slot=&mut b.slots[n as usize-1];let go=slot.go.as_ref().ok_or("sg1_no_go")?;let presented=slot.presented.as_ref().ok_or("sg1_no_presented")?;
        check(u(v,"n")?==n as u64 && s(v,"presentedSha256")?==presented.sha && s(v,"goSha256")?==go.sha
            && d(v,"startedNs")?>=d(&go.value,"writtenNs")? && d(v,"writtenNs")?<end && v["completion"]["dialog"]==presented.value["dialog"]
            && v["selected"]==selected(&self.admission,n) && u(&v["counts"],"actions")?==[1,7,13,14,15][n as usize-1],"sg1_original_input_completion")?;
        slot.input=Some(record);guard.done();Ok(())
    }
    pub(super) async fn settled(&self,files:&FileBook)->Check<()> {
        let guard=self.operation();let (last,end,completed)={let b=self.locked()?;check(b.slots.iter().all(|s|s.input.is_some()),"sg1_inputs_pending")?;
            let last=b.slots[4].input.as_ref().ok_or("sg1_no_last_input")?;let at=d(&last.value,"completedNs")?;(last.sha.clone(),plus(at,2_000_000_000)?,at)};
        let record=self.read(files,"helper-settled.json","helper-settled",end).await?;let v=&record.value;
        check(s(v,"lastInputSha256")?==last && v["helper"]==self.admission["helper"] && d(v,"waitNs")?>=completed
            && v["stdout"]["pipe"]==self.admission["pipes"]["helperStdout"] && v["stderr"]["pipe"]==self.admission["pipes"]["helperStderr"],"sg1_helper_original_settlement")?;
        for k in ["stdout","stderr"] {check(d(&v[k]["close"],"atNs")?>=completed,"sg1_helper_close_order")?;}
        self.locked()?.settled=Some(record);guard.done();Ok(())
    }
    pub(super) fn closed(&self)->Check<()> {
        let state=self.state.lock().map_err(|_|"sg1_native_poisoned")?;check(!state.unknown && state.settled.is_some() && state.slots.iter().all(|s|s.input.is_some()),"sg1_helper_not_preclosed")
    }
}
