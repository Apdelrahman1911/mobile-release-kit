//! Local set-upstream DATA; no network/Connection grant, ref creation or
//! substitute for the original SourceBook, durable Candidate or real joins.
use crate::{error::BridgeError, git_branch_protocol as branch, git_local_protocol as local,
    git_read_protocol as read};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const CONFIG_LIMIT: u64 = 60 * 1024;
pub(crate) const MAX_MISSING: usize = 64;
pub(crate) const MAX_PATH_BYTES: usize = 2048;
pub(crate) const MAX_NAMES: usize = 1024;
pub(crate) const MAX_NAME_BYTES: usize = 32768;
pub(crate) const ACTION_KEYS: &[&str] = &["kind","expectedRevision","expectedReferenceRevision","branch","head","remote","repository","identity"];
pub(crate) const REVIEW_KEYS: &[&str] = &["action","remote","repository","expectedRevision","expectedReferenceRevision","branch","head","expectedIndex","originalConfig","additions","missingDirectories","unchanged","reviewDigest"];
pub(crate) const INTENT_KEYS: &[&str] = &["action","expectedRevision","expectedReferenceRevision","expectedRef","expectedHead","expectedIndex","originalConfig","candidateConfig","remote","repository","missingDirectories","working","configChanged"];
pub(crate) const RESULT_KEYS: &[&str] = &["operationId","action","state","settlement","reason","observation","intent","effectPhase","retainedPaths"];
fn need(v:bool)->Result<(),BridgeError>{if v {Ok(())}else{Err(BridgeError::protocol())}}
pub(crate) fn hash(v:&[u8])->String {Sha256::digest(v).iter().map(|v|format!("{v:02x}")).collect()}
pub(crate) fn reason(v:&str)->bool {matches!(v,"upstream-config"|"upstream-conflict"|"upstream-identity-required"|"upstream-layout"|"upstream-unchanged"|"upstream-parent-changed")}
pub(crate) fn alias(v:&str)->bool { !v.is_empty() && v.len()<=64 && v.as_bytes()[0].is_ascii_alphanumeric()
    && v.bytes().all(|b|b.is_ascii_alphanumeric()||b"_-".contains(&b)) }
pub(crate) fn repository(v:&str)->bool {
    let Some((owner,name))=v.split_once('/') else{return false};
    !owner.is_empty() && owner.len()<=39 && owner.as_bytes()[0].is_ascii_alphanumeric()
        && owner.as_bytes()[owner.len()-1].is_ascii_alphanumeric()
        && owner.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-')
        && !name.is_empty() && name.len()<=100 && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.as_bytes()[name.len()-1].is_ascii_alphanumeric()
        && name.bytes().all(|b|b.is_ascii_alphanumeric()||b"._-".contains(&b))
}
pub(crate) fn target(remote:&str,current:&str)->Option<String> {
    let name=current.strip_prefix("refs/heads/").filter(|v|branch::name(v))?;
    alias(remote).then(||format!("refs/remotes/{remote}/{name}"))
}
pub(crate) fn paths(target:&str)->Vec<String> {
    let mut result=std::collections::BTreeSet::new(); result.insert(".".into());
    for name in [target.to_owned(),format!("logs/{target}")] {
        let mut remaining=name.as_str();
        while let Some((parent,_))=remaining.rsplit_once('/') {result.insert(parent.to_owned());remaining=parent;}
    }
    let mut result:Vec<String>=result.into_iter().collect();
    result.sort_by(|a,b| (a.bytes().filter(|v|*v==b'/').count()+usize::from(a!="."),a)
        .cmp(&(b.bytes().filter(|v|*v==b'/').count()+usize::from(b!="."),b))); result
}
fn missing(v:&[String],target:&str)->bool {
    let p=paths(target);
    v.len()<=MAX_MISSING && v.iter().map(String::len).sum::<usize>()<=MAX_PATH_BYTES
        && v.iter().all(|n|n!="." && p.contains(n)) && v==p.into_iter().filter(|n|v.contains(n)).collect::<Vec<_>>()
        && v.iter().enumerate().all(|(i,n)|!v[..i].contains(n))
}
#[derive(Clone,Copy,Deserialize,Serialize,PartialEq,Eq)]
pub(crate) enum Kind {#[serde(rename="set-upstream")] SetUpstream}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {pub(crate) name:String,pub(crate) email:String}
impl Identity {
    pub(crate) fn valid(&self)->bool {
        read::text(&self.name,128,false) && self.name.chars().next().is_some_and(char::is_alphanumeric)
            && self.name.chars().last().is_some_and(char::is_alphanumeric)
            && !self.name.chars().any(|c|matches!(c,'<'|'>'|'"'|'\''|'\\'|'#'|';'))
            && self.email.len()<=254 && self.email.split('@').count()==2
            && self.email.split('@').all(|v|!v.is_empty())
            && self.email.split_once('@').is_some_and(|(local,domain)|local.as_bytes()[0].is_ascii_alphanumeric()
                && local.bytes().all(|b|b.is_ascii_alphanumeric()||b"._+%-".contains(&b))
                && domain.len()>=2&&domain.as_bytes()[0].is_ascii_alphanumeric()
                && domain.bytes().all(|b|b.is_ascii_alphanumeric()||b".-".contains(&b))) && self.email.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
            && self.email.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
            && self.email.bytes().all(|b|b.is_ascii_alphanumeric()||b"@._+%-".contains(&b))
    }
}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Action {
    pub(crate) kind:Kind,pub(crate) expected_revision:String,pub(crate) expected_reference_revision:String,
    pub(crate) branch:String,pub(crate) head:String,pub(crate) remote:String,pub(crate) repository:String,
    pub(crate) identity:Option<Identity>,
}
impl Action {
    pub(crate) fn valid(&self)->bool {
        read::digest(&self.expected_revision)&&read::digest(&self.expected_reference_revision)&&read::oid(&self.head)
            && self.head.bytes().any(|v|v!=b'0') && target(&self.remote,&self.branch).is_some()
            && repository(&self.repository) && self.identity.as_ref().is_none_or(Identity::valid)
    }
}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Addition {pub(crate) key:String,pub(crate) value:String}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Review {
    pub(crate) action:Kind,pub(crate) remote:String,pub(crate) repository:String,
    pub(crate) expected_revision:String,pub(crate) expected_reference_revision:String,
    pub(crate) branch:String,pub(crate) head:String,pub(crate) expected_index:String,pub(crate) original_config:String,
    pub(crate) additions:Vec<Addition>,pub(crate) missing_directories:Vec<String>,pub(crate) unchanged:bool,pub(crate) review_digest:String,
}
impl Review {
    pub(crate) fn valid(&self)->bool {
        let Some(t)=target(&self.remote,&self.branch) else{return false};
        repository(&self.repository)&&read::oid(&self.head)&&self.head.bytes().any(|v|v!=b'0')
            && [&self.expected_revision,&self.expected_reference_revision,&self.expected_index,&self.original_config,&self.review_digest].iter().all(|v|read::digest(v))
            && missing(&self.missing_directories,&t) && self.unchanged==(self.additions.is_empty()&&self.missing_directories.is_empty())
            && additions_valid(&self.additions,&self.remote,&self.repository,&self.branch)
    }
    pub(crate) fn matches(&self,a:&Action)->bool {
        self.valid() && a.valid() && self.remote==a.remote && self.repository==a.repository && self.branch==a.branch && self.head==a.head
            && self.expected_revision==a.expected_revision && self.expected_reference_revision==a.expected_reference_revision
            && self.additions.iter().filter(|v|v.key.starts_with("user.")).all(|v|a.identity.as_ref().is_some_and(|i|
                v.value==if v.key=="user.name"{i.name.as_str()}else{i.email.as_str()}))
    }
}
pub(crate) fn additions_valid(rows:&[Addition],remote:&str,repo:&str,current:&str)->bool {
    if rows.len()>6{return false}
    let Some(name)=current.strip_prefix("refs/heads/") else{return false};
    let allowed=[(format!("remote.{remote}.url"),format!("https://github.com/{repo}.git")),
        (format!("remote.{remote}.fetch"),format!("+refs/heads/*:refs/remotes/{remote}/*")),
        (format!("branch.{name}.remote"),remote.into()),(format!("branch.{name}.merge"),current.into())];
    let mut expected=Vec::new();
    for pair in allowed.chunks(2) {
        let values:Vec<_>=rows.iter().filter(|v|v.key==pair[0].0||v.key==pair[1].0).collect();
        if !values.is_empty(){if values.len()!=2{return false} expected.extend(pair.iter().cloned());}
    }
    let identity:Vec<_>=rows.iter().filter(|v|v.key.starts_with("user.")).collect();
    if !identity.is_empty() {
        if identity.len()!=2||identity[0].key!="user.name"||identity[1].key!="user.email"
            ||!(Identity{name:identity[0].value.clone(),email:identity[1].value.clone()}).valid(){return false}
        expected.push(("user.name".into(),identity[0].value.clone()));expected.push(("user.email".into(),identity[1].value.clone()));
    }
    expected.len()==rows.len() && expected.iter().zip(rows).all(|((k,v),r)|k==&r.key&&v==&r.value)
}
pub(crate) fn appended(original:&[u8],rows:&[Addition])->Option<Vec<u8>> {
    if original.is_empty() || original.len()>CONFIG_LIMIT as usize || !original.ends_with(b"\n") || original.contains(&0) || original.contains(&b'\r'){return None}
    let mut result=original.to_vec();let mut previous=String::new();
    for r in rows {
        if r.value.is_empty() || r.value.chars().any(|c|matches!(c,'\0'|'\r'|'\n'|'"'|'\\'|'#'|';')){return None}
        let (prefix,key)=r.key.rsplit_once('.')?;
        let header=if prefix=="user" {"[user]\n".into()} else {
            let (section,name)=prefix.split_once('.')?;
            if !matches!(section,"remote"|"branch"){return None} format!("[{section} \"{name}\"]\n")
        };
        if header!=previous {result.extend_from_slice(header.as_bytes());previous=header;}
        result.extend_from_slice(format!("\t{key} = {}\n",r.value).as_bytes());
        if result.len()>CONFIG_LIMIT as usize{return None}
    }
    Some(result)
}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Working {
    pub(crate) root:read::FileIdentity,pub(crate) locks:[read::FileIdentity;3],pub(crate) scratch:String,
    pub(crate) scratch_identity:read::FileIdentity,pub(crate) index_identity:read::FileIdentity,
}
pub(crate) fn directory(d:read::FileIdentity,uid:u32)->bool {d.0>0&&d.1>0&&d.2&0o170000==0o40000&&d.2&0o7022==0&&d.3==uid&&d.5>0}
pub(crate) fn same_directory(a:read::FileIdentity,b:read::FileIdentity)->bool {(a.0,a.1,a.2,a.3,a.4)==(b.0,b.1,b.2,b.3,b.4)}
fn file(d:read::FileIdentity,uid:u32,limit:u64)->bool {d.0>0&&d.1>0&&d.2&0o170000==0o100000&&d.2&0o7022==0&&d.3==uid&&d.5==1&&d.6<=limit}
impl Working {
    pub(crate) fn valid(&self)->bool {
        let uid=self.root.3;
        directory(self.root,uid)&&directory(self.scratch_identity,uid)&&self.scratch_identity.2&0o7777==0o700
            && self.scratch.strip_prefix("mrk-git-").is_some_and(|v|v.len()==8&&v.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b==b'_'))
            && file(self.index_identity,uid,1024*1024) && self.locks.iter().all(|v|file(*v,uid,0)&&v.2==0o100600)
            && self.locks.iter().enumerate().all(|(i,a)|self.locks[..i].iter().all(|b|(a.0,a.1)!=(b.0,b.1)))
    }
}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Intent {
    pub(crate) action:Kind,pub(crate) expected_revision:String,pub(crate) expected_reference_revision:String,
    pub(crate) expected_ref:String,pub(crate) expected_head:String,pub(crate) expected_index:String,
    pub(crate) original_config:String,pub(crate) candidate_config:String,pub(crate) remote:String,pub(crate) repository:String,
    pub(crate) missing_directories:Vec<String>,pub(crate) working:Working,pub(crate) config_changed:bool,
}
impl Intent {
    pub(crate) fn valid(&self)->bool {
        let Some(t)=target(&self.remote,&self.expected_ref) else{return false};
        repository(&self.repository)&&read::oid(&self.expected_head)&&self.expected_head.bytes().any(|v|v!=b'0')
            && [&self.expected_revision,&self.expected_reference_revision,&self.expected_index,&self.original_config,&self.candidate_config].iter().all(|v|read::digest(v))
            && missing(&self.missing_directories,&t)&&self.working.valid() && (self.config_changed||!self.missing_directories.is_empty())
            && (self.config_changed||self.original_config==self.candidate_config)
    }
    pub(crate) fn matches(&self,r:&Review)->bool {
        self.valid()&&r.valid()&&!r.unchanged&&self.expected_revision==r.expected_revision&&self.expected_reference_revision==r.expected_reference_revision
            && self.expected_ref==r.branch&&self.expected_head==r.head&&self.expected_index==r.expected_index&&self.original_config==r.original_config
            && self.remote==r.remote&&self.repository==r.repository&&self.missing_directories==r.missing_directories&&self.config_changed==!r.additions.is_empty()
    }
}
#[derive(Clone,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase")]
pub(crate) struct Parent {pub(crate) name:String,pub(crate) identity:read::FileIdentity,pub(crate) names:Vec<String>}
#[derive(Clone,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase")]
pub(crate) struct Sources {pub(crate) parents:Vec<Parent>,pub(crate) missing:Vec<String>,pub(crate) reference:Option<read::Snapshot>,pub(crate) log:Option<read::Snapshot>}
fn upstream_target(a:&Action)->Option<String>{target(&a.remote,&a.branch)}
impl Sources {
    fn paths_match(&self,t:&str)->bool {
        for name in paths(t).iter().filter(|p|p.as_str()!=".") {
            let (parent,leaf)=name.rsplit_once('/').unwrap_or((".",name));
            if self.missing.iter().any(|v|v==parent) {
                if !self.missing.contains(name){return false}
            }else{
                let Some(p)=self.parents.iter().find(|p|p.name==parent) else{return false};
                if p.names.iter().any(|v|v.eq_ignore_ascii_case(leaf)&&v!=leaf)
                    || p.names.iter().any(|v|v==leaf)==self.missing.contains(name){return false}
            }
        }
        for (name,value) in [(t,self.reference.as_ref()),(format!("logs/{t}").as_str(),self.log.as_ref())] {
            let (parent,leaf)=name.rsplit_once('/').unwrap_or((".",name));
            if let Some(p)=self.parents.iter().find(|p|p.name==parent) {
                if p.names.iter().any(|v|v.eq_ignore_ascii_case(leaf)&&v!=leaf)
                    || p.names.iter().any(|v|v==leaf)!=value.is_some(){return false}
            }else if value.is_some(){return false}
        }
        true
    }
    pub(crate) fn valid(&self,n:&local::Native,a:&Action)->bool {
        let Some(t)=target(&a.remote,&a.branch) else{return false}; let p=paths(&t);
        a.valid()&&n.valid()&&missing(&self.missing,&t)&&self.parents.iter().map(|v|v.name.clone()).collect::<Vec<_>>()==p.into_iter().filter(|v|!self.missing.contains(v)).collect::<Vec<_>>()
            && self.parents.first().is_some_and(|v|v.name=="."&&same_directory(v.identity,(n.directories.git.0,n.directories.git.1,n.directories.git.2,n.directories.git.3,n.directories.git.4,1,0,0,0)))
            && self.parents.iter().all(|v|directory(v.identity,n.uid)&&v.names.len()<=MAX_NAMES
                && v.names.windows(2).all(|p|p[0]<p[1])&&v.names.iter().all(|n|!n.is_empty()&&n!="."&&n!=".."&&n.len()<=255&&!n.contains(['\0','/'])))
            && self.parents.iter().map(|v|v.names.len()).sum::<usize>()<=MAX_NAMES
            && self.parents.iter().flat_map(|v|&v.names).map(String::len).sum::<usize>()<=MAX_NAME_BYTES
            && self.reference.as_ref().is_none_or(|s|file(s.identity,n.uid,65)&&read::digest(&s.sha256))
            && self.log.as_ref().is_none_or(|s|file(s.identity,n.uid,128*1024)&&read::digest(&s.sha256))
            && self.paths_match(&upstream_target(a).unwrap_or_default())
            && n.files.index.is_some()
    }
}
pub(crate) fn directory_digest(i:&Intent,before:&[Parent],after:&[Parent])->Result<String,BridgeError> {
    let rows=|v:&[Parent]|v.iter().map(|p|serde_json::json!([p.name,p.identity,p.names])).collect::<Vec<_>>();
    let w=&i.working;
    let value=serde_json::json!(["mrk-git-upstream-directories/1",
        [i.expected_revision,i.expected_reference_revision,i.expected_ref,i.expected_head,i.expected_index,i.original_config,i.candidate_config,
         i.remote,i.repository,i.missing_directories,i.config_changed,[w.root,w.locks,w.scratch,w.scratch_identity,w.index_identity]],rows(before),rows(after)]);
    Ok(hash(&serde_json::to_vec(&value).map_err(|_|BridgeError::protocol())?))
}
pub(crate) fn effect(p:local::Publication)->Option<&'static str> {match p {local::Publication::NotReported=>Some("not-published"),
    local::Publication::UpstreamDirectoriesReturned=>Some("directories-returned"),local::Publication::UpstreamConfigReturned=>Some("config-returned"),_=>None}}
#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct FinalData {pub(crate) effect_phase:String,pub(crate) retained_paths:Vec<String>}
impl FinalData {
    pub(crate) fn valid(&self,i:&Intent)->bool {
        let Some(t)=target(&i.remote,&i.expected_ref) else{return false};
        let scratch=format!(".git/{}",i.working.scratch);
        let index=format!("{scratch}/index");
        let allowed=paths(&t).into_iter().filter(|n|n!=".").map(|n|format!(".git/{n}"))
            .chain([".git/config".into(),scratch.clone(),index.clone()]).collect::<Vec<_>>();
        matches!(self.effect_phase.as_str(),"not-published"|"directories-returned"|"config-returned")
            && (self.effect_phase!="config-returned"||i.config_changed)&&self.retained_paths.len()<=MAX_MISSING+3
            && self.retained_paths.windows(2).all(|p|p[0]<p[1])&&self.retained_paths.iter().all(|n|allowed.contains(n))
            && self.retained_paths.contains(&scratch)==self.retained_paths.contains(&index)
    }
    pub(crate) fn successful(&self,i:&Intent)->bool {self.valid(i)&&self.retained_paths.is_empty()&&self.effect_phase==if i.config_changed{"config-returned"}else{"directories-returned"}}
}
pub(crate) fn final_data(t:&local::Terminal,i:&Intent)->Result<FinalData,BridgeError> {
    let d=FinalData{effect_phase:t.result["effectPhase"].as_str().ok_or_else(BridgeError::protocol)?.into(),
        retained_paths:serde_json::from_value(t.result["retainedPaths"].clone()).map_err(|_|BridgeError::protocol())?};
    need(d.valid(i)&&effect(t.publication)==Some(d.effect_phase.as_str()))?;Ok(d)
}
pub(crate) fn validate_applied(r:&local::Request,t:&local::Terminal,c:Option<&local::Candidate>)->Result<(),BridgeError> {
    let value=&t.result;need(value["observation"].is_null())?;
    let Some(c)=c else {return need(t.publication==local::Publication::NotReported&&value["intent"].is_null()
        &&value["state"]=="failed"&&value["effectPhase"]=="not-published"&&value["retainedPaths"]==serde_json::json!([]))};
    let i=c.intent.upstream_details().ok_or_else(BridgeError::protocol)?;
    need(serde_json::from_value::<local::Intent>(value["intent"].clone()).map_err(|_|BridgeError::protocol())?==c.intent)?;let d=final_data(t,i)?;
    if value["state"]=="succeeded" {need(d.successful(i)&&value["reason"].is_null()&&t.first_failure_ns.is_none()&&t.cleanup_end_ns==r.clock.hard_end_ns)}
    else {need(value["state"]=="recovery-required"&&value["reason"].as_str().is_some_and(|v|read::reason(v)||reason(v))&&t.first_failure_ns.is_some())}
}

/// Display-only projection from the already validated original terminal.
/// Raw working-file identities stay in the retained journal/SourceBook. A
/// digest is not a new source, review, directory or closure permission.
pub(crate) fn public_result(kind:local::Kind,phase:local::Phase,mut value:serde_json::Value)->serde_json::Value {
    if kind!=local::Kind::SetUpstream||phase!=local::Phase::Apply||value.is_null(){return value}
    let mut retained=false;
    if let Some(i)=value.get_mut("intent").and_then(serde_json::Value::as_object_mut) {
        let Some(w)=i.remove("working") else{return serde_json::Value::Null};
        let Ok(raw)=serde_json::to_vec(&w) else{return serde_json::Value::Null};
        i.insert("workingSha256".into(),serde_json::Value::String(hash(&raw)));
    }
    if let Some(paths)=value.get_mut("retainedPaths").and_then(serde_json::Value::as_array_mut) {
        paths.retain(|p|{let private=p.as_str().is_some_and(|p|p.starts_with(".git/mrk-git-"));retained|=private;!private});
    }
    value["retainedCandidate"]=serde_json::Value::Bool(retained);value
}

#[cfg(test)]
#[path="git_upstream_protocol_tests.rs"]
pub(crate) mod tests;
