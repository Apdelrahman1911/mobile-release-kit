//! Schema9-only optional field in the original GitOperations row. No second
//! namespace, counter, ACK or permission. Old schema1–8 omit this field.
use crate::git_upstream_protocol::{FinalData, Intent, Review};
use serde::{Deserialize, Serialize};

#[derive(Clone,Deserialize,Serialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(crate) struct Journal {
    review:Review,
    pub(crate) candidate:Option<Intent>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub(crate) final_state:Option<FinalData>,
}
impl Journal {
    pub(crate) fn preparing(review:&Review)->Self {Self {review:review.clone(),candidate:None,final_state:None}}
    pub(crate) fn valid(&self,revision:&str,head:Option<&str>,reference:Option<&str>,index:&str,digest:&str)->bool {
        self.review.valid()&&!self.review.unchanged&&self.review.expected_revision==revision&&Some(self.review.head.as_str())==head
            &&Some(self.review.branch.as_str())==reference&&self.review.expected_index==index&&self.review.review_digest==digest
            &&self.candidate.as_ref().is_none_or(|i|i.matches(&self.review))
            &&self.final_state.as_ref().is_none_or(|d|self.candidate.as_ref().is_some_and(|i|d.valid(i)))
    }
    pub(crate) fn same_original(&self,old:&Self)->bool {self.review==old.review}
    pub(crate) fn accepts(&self,intent:&Intent)->bool {self.candidate.is_none()&&self.final_state.is_none()&&intent.matches(&self.review)}
    pub(crate) fn candidate(&mut self,intent:&Intent){self.candidate=Some(intent.clone());}
}
