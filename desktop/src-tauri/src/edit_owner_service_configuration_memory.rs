//! Config-CLI-only accounting of the ORIGINAL Edit registry. No snapshots,
//! serialization, buffers, resource receipts or ownership credit are created.
use super::*;
use crate::{
    edit_protocol as c, github_workflow_edit_protocol as w, metadata_images_edit_protocol as i,
    metadata_text_edit_protocol as t, project_identity_edit_protocol as a,
    project_initialization_edit_protocol as n, release_version_edit_protocol as v,
    saved_text_recovery_protocol as r,
};
use std::mem::size_of;

// SAME Seed's fixed pre-allocation limits. Three TOTAL frames are checked by
// the original reader before decode (not merely a channel with three slots).
// A whole current Config projection is checked against ONE representation
// before adoption, including checkout AND prepared preview. Thus two native
// Status callers add two whole representations, not two encoded-size guesses.
pub(super) const REPRESENTATION: usize = crate::protocol::CONFIGURATION_AGENT_FRAME_NODES * 512
    + 2 * crate::protocol::CONFIGURATION_AGENT_FRAME_BYTES;
pub(super) const FUTURE: usize = 6 * REPRESENTATION
    + 2 * c::REQUEST_LIMIT // original one-slot command queue plus writer
    + 2 * c::STATUS_LIMIT // two separately encoded native Status results
    + 1024 * 1024; // raw LF Vec growth, IO buffers, session/channel/type cells

struct Usage {
    bytes: usize,
    nodes: usize,
}
impl Usage {
    fn add(&mut self, bytes: usize) -> Result<(), BridgeError> {
        self.bytes = self.bytes.checked_add(bytes).ok_or_else(invalid_owner)?;
        if self.bytes > 64 * 1024 * 1024 {
            return Err(invalid_owner());
        }
        Ok(())
    }
    fn cells<T>(&mut self, count: usize) -> Result<(), BridgeError> {
        self.add(
            count
                .checked_mul(size_of::<T>())
                .ok_or_else(invalid_owner)?,
        )
    }
}
// Closed borrowed type roster of the existing EditProjection. This is not a
// serializer or a general Document census. Inline cells live in their parent;
// Vec/String capacities and all recursive Value backing are counted here.
trait Heap {
    fn heap(&self, n: &mut Usage) -> Result<(), BridgeError>;
}
impl Heap for String {
    fn heap(&self, n: &mut Usage) -> Result<(), BridgeError> {
        n.add(self.capacity())
    }
}
impl<T: Heap> Heap for Option<T> {
    fn heap(&self, n: &mut Usage) -> Result<(), BridgeError> {
        if let Some(v) = self {
            v.heap(n)?;
        }
        Ok(())
    }
}
impl<T: Heap> Heap for Vec<T> {
    fn heap(&self, n: &mut Usage) -> Result<(), BridgeError> {
        n.cells::<T>(self.capacity())?;
        for v in self {
            v.heap(n)?;
        }
        Ok(())
    }
}
impl Heap for Value {
    fn heap(&self, n: &mut Usage) -> Result<(), BridgeError> {
        value(self, n, 0)
    }
}
fn value(v: &Value, n: &mut Usage, depth: usize) -> Result<(), BridgeError> {
    n.nodes = n.nodes.checked_add(1).ok_or_else(invalid_owner)?;
    // Old ordinary projections retain their original (larger) grammar. A
    // refused census leaves that exact last projection untouched.
    if depth > crate::protocol::DEPTH_LIMIT || n.nodes > 3 * crate::protocol::NODE_LIMIT {
        return Err(invalid_owner());
    }
    match v {
        Value::String(s) => s.heap(n)?,
        Value::Array(a) => {
            n.cells::<Value>(a.capacity())?;
            for v in a {
                value(v, n, depth + 1)?;
            }
        }
        Value::Object(m) => {
            // Conservative actual BTree backing, including sparsely occupied
            // single-entry roots; no len*Value-only tiny-map undercount.
            n.add(m.len().checked_mul(1024).ok_or_else(invalid_owner)?)?;
            for (k, v) in m {
                k.heap(n)?;
                value(v, n, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
macro_rules! fields {
    ($ty:ty: $($field:ident),* $(,)?) => {
        impl Heap for $ty {
            fn heap(&self, n: &mut Usage) -> Result<(), BridgeError> {
                $(self.$field.heap(n)?;)* Ok(())
            }
        }
    };
}
fields!(c::Checkout: revision,base);
fields!(c::Prepared: revision,plan_token,view);
fields!(c::FileView: path,action);
fields!(c::PreparedConfigView: files,ignore_additions,preview);
fields!(c::RecoverySummary: sha256);
fields!(c::RecoveryFile: id,path,before,after);
fields!(c::RecoveryCleanup: scope);
fields!(c::RecoveryView: kind,transaction_id,files,private_cleanup);
fields!(c::RecoveryCheckout: revision,view);
fields!(c::RecoveryPrepared: revision,plan_token,view);
fields!(c::RecoveryDetails: checkout,prepared);
fields!(w::Generated: content,sha256);
fields!(w::FileView: path,observed,generated,previous);
fields!(w::TemplateSet: core_version,resource_sha256);
fields!(w::Tooling: repository,sha,schema_reference,state);
fields!(w::PreparedView: files,create_directories,template_set,tooling);
fields!(w::ConflictFile: observed);
fields!(w::ConflictView: reason,conflicts);
fields!(w::RecoverySummary: sha256);
fields!(w::RecoveryFile: path,before,after);
fields!(w::RecoveryCleanup: scope);
fields!(w::RecoveryView: kind,transaction_id,files,private_cleanup);
fields!(w::RecoveryCheckout: revision,view);
fields!(w::RecoveryPrepared: revision,plan_token,view);
fields!(w::RecoveryDetails: checkout,prepared);
fields!(w::Checkout: revision,observed);
fields!(w::Prepared: revision,plan_token,view);
fields!(w::Details: checkout,prepared,conflict,recovery);
impl Heap for w::Observation {
    fn heap(&self, n: &mut Usage) -> Result<(), BridgeError> {
        if let Self::Present { sha256, .. } = self {
            sha256.heap(n)?;
        }
        Ok(())
    }
}
impl Heap for w::ObservedFile {
    fn heap(&self, n: &mut Usage) -> Result<(), BridgeError> {
        if let Self::Present { sha256, .. } = self {
            sha256.heap(n)?;
        }
        Ok(())
    }
}
fields!(t::ContentDigest: sha256);
fields!(t::Baseline: config,fields);
fields!(t::TextField: text);
fields!(t::TextContent: text,sha256);
fields!(t::FileView: path,before,after);
fields!(t::Assurance: basis,release_readiness);
fields!(t::TextIssue: code,status,message);
fields!(t::ValidatedField: issues);
fields!(t::ValidationResult: fields,assurance);
fields!(t::PreparedView: locale,metadata_root,files,create_directories,validation);
fields!(t::Submission: expected_baseline,fields);
fields!(t::Checkout: revision,metadata_root,baseline);
fields!(t::Prepared: revision,plan_token,view);
fields!(t::Details: locale,checkout,prepared,submission,recovery);
impl Heap for t::BaselineField {
    fn heap(&self, n: &mut Usage) -> Result<(), BridgeError> {
        if let Self::Present { sha256, .. } = self {
            sha256.heap(n)?;
        }
        Ok(())
    }
}
impl Heap for t::Before {
    fn heap(&self, n: &mut Usage) -> Result<(), BridgeError> {
        if let Self::Present { text, sha256, .. } = self {
            text.heap(n)?;
            sha256.heap(n)?;
        }
        Ok(())
    }
}
fields!(v::Values: name,build);
fields!(v::ContentDigest: sha256);
fields!(v::Baseline: saved_config,saved_version);
fields!(v::TextContent: text,sha256);
fields!(v::FileView: path,before,after);
fields!(v::LineEndings: before,after);
fields!(v::Validation: state,issues);
fields!(v::PreparedView: source,name_key,build_key,values,file,create_directories,line_endings,validation);
fields!(v::Submission: expected_baseline,values);
fields!(v::Checkout: revision,source,name_key,build_key,values,baseline);
fields!(v::Prepared: revision,plan_token,view);
fields!(v::Details: checkout,prepared,submission,recovery);
impl Heap for v::LineStyle {
    fn heap(&self, _: &mut Usage) -> Result<(), BridgeError> {
        Ok(())
    }
}
impl Heap for v::BaselineFile {
    fn heap(&self, n: &mut Usage) -> Result<(), BridgeError> {
        if let Self::Present { sha256, .. } = self {
            sha256.heap(n)?;
        }
        Ok(())
    }
}
impl Heap for v::Before {
    fn heap(&self, n: &mut Usage) -> Result<(), BridgeError> {
        if let Self::Present { text, sha256, .. } = self {
            text.heap(n)?;
            sha256.heap(n)?;
        }
        Ok(())
    }
}
fields!(r::TextSelection: locale,metadata_root);
fields!(r::VersionSelection: source,name_key,build_key);
fields!(r::Digest: sha256);
fields!(r::File: path,before,after);
fields!(r::Cleanup: scope);
fields!(r::View: kind,transaction_id,selection,files,private_cleanup);
fields!(r::Checkout: revision,view);
fields!(r::Prepared: revision,plan_token,view);
fields!(r::Details: checkout,prepared);
impl Heap for r::Selection {
    fn heap(&self, n: &mut Usage) -> Result<(), BridgeError> {
        match self {
            Self::Text(v) => v.heap(n),
            Self::Version(v) => v.heap(n),
        }
    }
}
fields!(i::Context: locale,asset_type);
fields!(i::SelectedItem: item_id,display_name,sha256);
fields!(i::ContentDigest: sha256);
fields!(i::Baseline: config,ignore,inventory_sha256);
fields!(i::Choice: item_id);
fields!(i::Submission: expected_baseline,choices);
fields!(i::Checkout: revision,baseline,view);
fields!(i::Prepared: revision,plan_token,view);
fields!(i::Details: checkout,prepared,context,selected,submission);
fields!(n::FileView: path);
fields!(n::WorkflowView: path,content,sha256);
fields!(n::InitializationView: kind,files,create_directories,configuration_preview,workflows,ignore_additions,template_set,tooling);
fields!(n::Summary: sha256);
fields!(n::RecoveryFile: path,before,after);
fields!(n::ConfigurationBinding: sha256);
fields!(n::Context: configuration,template_set,tooling);
fields!(n::PrivateCleanup: scope);
fields!(n::RecoveryView: kind,transaction_id,context,files,private_cleanup);
fields!(n::ConflictFile: path);
fields!(n::ConflictView: reason,files);
fields!(n::Details: checkout,prepared,conflict);
impl Heap for n::Checkout {
    fn heap(&self, n: &mut Usage) -> Result<(), BridgeError> {
        match self {
            Self::Initialize { revision, .. } => revision.heap(n),
            Self::Recover { revision, recovery } => {
                revision.heap(n)?;
                recovery.heap(n)
            }
        }
    }
}
impl Heap for n::Prepared {
    fn heap(&self, n: &mut Usage) -> Result<(), BridgeError> {
        match self {
            Self::Initialize {
                revision,
                plan_token,
                view,
                ..
            } => {
                revision.heap(n)?;
                plan_token.heap(n)?;
                view.heap(n)
            }
            Self::Recover {
                revision,
                plan_token,
                recovery,
            } => {
                revision.heap(n)?;
                plan_token.heap(n)?;
                recovery.heap(n)
            }
        }
    }
}
fields!(a::Checkout: revision,view);
fields!(a::Prepared: revision,plan_token,view);
fields!(a::Diagnostic: code,path,help);
impl Heap for a::Details {
    fn heap(&self, n: &mut Usage) -> Result<(), BridgeError> {
        self.checkout.heap(n)?;
        self.prepared.heap(n)?;
        self.diagnostic.heap(n)?;
        // Private expected Selection and requested Submission are not exposed
        // here. Their two original <=16KiB closed requests contain only bounded
        // identity/target/project strings; conservatively retain BOTH full wire
        // capacities. No private getters or copied selection are introduced.
        n.add(2 * a::REQUEST_LIMIT)
    }
}
fields!(EditProjection: project_id,session_id,owner_generation,checkout,prepared,recovery,
    workflow,metadata_text,release_version,metadata_images,initialization,identity);

fn projection(p: &EditProjection) -> Result<usize, BridgeError> {
    let mut n = Usage {
        bytes: size_of::<EditProjection>(),
        nodes: 0,
    };
    p.heap(&mut n)?;
    Ok(n.bytes)
}
pub(super) fn prospective(p: &EditProjection, frame: &ChildFrame) -> Result<(), BridgeError> {
    let mut n = Usage {
        bytes: size_of::<EditProjection>(),
        nodes: 0,
    };
    p.heap(&mut n)?;
    match frame {
        ChildFrame::Opened(o) => {
            o.revision.heap(&mut n)?;
            o.base.heap(&mut n)?;
        }
        ChildFrame::Prepared(p) => {
            p.revision.heap(&mut n)?;
            p.plan_token.heap(&mut n)?;
            p.view.heap(&mut n)?;
        }
        ChildFrame::Terminal(_, _) => {}
        _ => return Err(invalid_owner()),
    }
    if n.bytes > REPRESENTATION {
        return Err(invalid_owner());
    }
    Ok(())
}
impl EditOwner {
    pub(crate) fn configuration_agent_edit_backing(&self) -> Result<usize, BridgeError> {
        let r = self
            .inner
            .registry
            .try_lock()
            .map_err(|_| invalid_owner())?;
        if self.inner.poisoned.load(Ordering::SeqCst) || r.exhausted {
            return Err(edit_unknown());
        }
        let mut n = Usage {
            bytes: size_of::<Registry>(),
            nodes: 0,
        };
        r.generation.heap(&mut n)?;
        r.loss_generation.heap(&mut n)?;
        r.window.heap(&mut n)?;
        // Registry bookkeeping remains present even with no active operation.
        for keys in [
            &r.blocked_projects,
            &r.image_recovery_projects,
            &r.workflow_recovery_projects,
        ] {
            n.add(keys.len().checked_mul(1024).ok_or_else(invalid_owner)?)?;
            for key in keys {
                key.heap(&mut n)?;
            }
        }
        n.add(
            r.domain_blocks
                .0
                .len()
                .checked_mul(4096)
                .ok_or_else(invalid_owner)?,
        )?;
        for key in r.domain_blocks.0.keys() {
            key.heap(&mut n)?;
        }
        if let Some(p) = &r.last {
            let bytes = projection(p)?;
            // Config Status can hold two extra independent last clones. Other
            // domains are filtered out, but their ORIGINAL full backing stays.
            n.add(
                bytes
                    .checked_mul(if p.domain == EditDomain::Configuration {
                        3
                    } else {
                        1
                    })
                    .ok_or_else(invalid_owner)?,
            )?;
        }
        if let Some(a) = &r.active {
            if a.session.agent_configuration.is_none()
                || projection(&a.projection)? > REPRESENTATION
            {
                return Err(invalid_owner());
            }
            // The linked active is already in FUTURE's bounded six copies.
            // A simultaneous ordinary Edit is refused, never credited as idle.
        }
        n.add(FUTURE)?;
        Ok(n.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn data() -> EditProjection {
        EditProjection {
            domain: EditDomain::Configuration,
            workflow: None,
            metadata_text: None,
            release_version: None,
            metadata_images: None,
            initialization: None,
            identity: None,
            project_id: "p".into(),
            session_id: "s".into(),
            owner_generation: "g".into(),
            phase: Phase::Unknown,
            review_remaining_ms: 0,
            checkout: None,
            prepared: None,
            recovery: None,
            apply_submitted: false,
            core_outcome: None,
            native_reason: Reason::None,
            native_finality: NativeFinality::Pending,
            late_settled: false,
        }
    }
    #[test]
    fn original_last_capacity_and_private_other_domain_submission_are_not_status_credit() {
        let owner = EditOwner::new(RuntimeConfig::packaged(PathBuf::from(
            "/never-opened-config-memory",
        )));
        let initial = owner.configuration_agent_edit_backing().unwrap();
        let mut p = data();
        let mut text = String::with_capacity(1024 * 1024);
        text.push('x');
        let capacity = text.capacity();
        p.checkout = Some(c::Checkout {
            revision: "b".repeat(32),
            base: Value::String(text),
        });
        {
            owner.inner.lock().last = Some(p);
        }
        let held = owner
            .inner
            .lock()
            .last
            .as_ref()
            .unwrap()
            .checkout
            .as_ref()
            .unwrap()
            .base
            .as_str()
            .unwrap()
            .as_ptr();
        assert!(owner.configuration_agent_edit_backing().unwrap() >= initial + 3 * capacity);
        assert_eq!(
            owner
                .inner
                .lock()
                .last
                .as_ref()
                .unwrap()
                .checkout
                .as_ref()
                .unwrap()
                .base
                .as_str()
                .unwrap()
                .as_ptr(),
            held
        );
        let mut p = data();
        p.domain = EditDomain::MetadataText;
        let mut text = String::with_capacity(1024 * 1024);
        text.push('y');
        p.metadata_text = Some(t::Details {
            platform: None,
            locale: None,
            checkout: None,
            prepared: None,
            recovery: None,
            submission: Some(t::Submission {
                expected_baseline: t::Baseline {
                    config: t::ContentDigest {
                        byte_length: 0,
                        sha256: String::new(),
                    },
                    fields: Vec::new(),
                },
                fields: vec![t::TextField {
                    id: t::FieldId::Title,
                    text,
                }],
            }),
        });
        owner.inner.lock().last = Some(p);
        assert!(owner.configuration_agent_edit_backing().unwrap() >= initial + 1024 * 1024);
        assert!(owner
            .inner
            .lock()
            .last
            .as_ref()
            .unwrap()
            .metadata_text
            .as_ref()
            .unwrap()
            .submission
            .is_some());
    }
    #[test]
    fn entire_active_checkout_plus_prepared_is_bounded_before_status_clone() {
        let mut p = data();
        p.checkout = Some(c::Checkout {
            revision: "b".repeat(32),
            base: Value::String(String::with_capacity(REPRESENTATION - 4096)),
        });
        let reply = ChildFrame::Prepared(c::PreparedReply {
            revision: "b".repeat(32),
            plan_token: "c".repeat(32),
            scope_resources: ResourceState::Settled,
            view: c::PreparedConfigView {
                schema_version: 1,
                files: Vec::new(),
                create_release_directory: false,
                rewrites_config_formatting: false,
                ignore_additions: Vec::new(),
                preview: Value::String(String::with_capacity(8192)),
            },
        });
        assert!(projection(&p).unwrap() < REPRESENTATION);
        assert!(prospective(&p, &reply).is_err());
        assert!(p.prepared.is_none()); // original is neither discarded nor replaced
        assert_eq!(
            FUTURE,
            6 * REPRESENTATION + 2 * c::REQUEST_LIMIT + 2 * c::STATUS_LIMIT + 1024 * 1024
        );
    }
}
