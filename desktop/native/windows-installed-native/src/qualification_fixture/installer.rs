//! Fixed native preparation/observation for five same-controller app cases.
//! This module exists only in native libtest, never in its app dependency.
//! No payload/vendor execution, replacement owner, cleanup/deletion or arbitrary
//! path/action entry exists. Root's existing original-process owner must bind
//! exact compiler inputs, argv, real exits and private output before invoking it.
use super::*;
#[cfg(feature = "installer-selection-fixture")]
mod selection;
use super::super::installer_fixture_data::{
    installer_fixture_inputs, installer_fixture_process, InstallerFixtureCase as Case,
    InstallerFixtureInputs as Inputs, INSTALLER_FIXTURE_PROFILE,
};
use super::super::installer_primitives::exact_security;
use super::super::installer_input_data::{InputLayout, INPUTS, TARGET};

const PRE: &str = "retained-shell-precheck.private.txt";
const PRE_HEADER: &str = "MRK_WINDOWS_RETAINED_SHELL_PRECHECK_V1";
const PRE_KEYS: &[&str] = &[
    "profile", "sourceSha", "sourceTree", "runId", "attempt",
    "sourceInventorySha256", "profilesSha256", "rosterSha256",
    "nativeArtifact", "nativeArtifactBytes", "nativeArtifactSha256", "nativeArtifactIdentity",
    "nativeCompileMessagesSha256", "nativeCompileArgvSha256",
    "appArtifact", "appArtifactBytes", "appArtifactSha256", "appArtifactIdentity",
    "appCompileMessagesSha256", "appCompileArgvSha256", "preparedRuntimeSha256",
];
const EXIT_HEADER: &str = "MRK_WINDOWS_RETAINED_SHELL_ORIGINAL_EXIT_V1";
const EXIT_KEYS: &[&str] = &[
    "profile", "sourceSha", "sourceTree", "runId", "attempt", "role",
    "artifactSha256", "precheckSha256", "commandSha256", "resultBytes", "resultSha256",
    "originalWaitReturned", "exitCode", "writerCloseGate",
];
const SNAP_HEADER: &str = "MRK_WINDOWS_RETAINED_SHELL_SNAPSHOT_V1";
const SNAP_KEYS: &[&str] = &[
    "profile", "sourceSha", "sourceTree", "runId", "attempt", "case", "phase",
    "precheckSha256", "profilesSha256", "rosterSha256", "image", "manifest",
    "candidate", "freshMrkAbsent", "objects", "fileOriginals", "fileOriginalsClosed",
    "parentBookSettled", "unknown", "resultCloseGate",
];
const APP_PREFIX: &str = "MRK_WINDOWS_RETAINED_SHELL_CASE_V1=";
const APP_KEYS: &[&str] = &["case", "rows", "sourceRead", "confirmedWritten", "readbackRead",
    "prerequisite", "runtime", "activation", "roles", "transitions", "originalWatchdogJoined", "nativeSettled"];

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase { Stage, Observe, Corrupt }
fn phase_label(phase: Phase) -> &'static str { match phase { Phase::Stage=>"stage", Phase::Observe=>"observe", Phase::Corrupt=>"corrupt" } }
fn test(case: Case, phase: Phase) -> &'static str {
    match (case, phase) {
        (Case::Fresh, Phase::Stage) => "qualification_fixture::installer::stage_fresh",
        (Case::Reuse, Phase::Stage) => "qualification_fixture::installer::stage_reuse",
        (Case::StopCopy, Phase::Stage) => "qualification_fixture::installer::stage_stop_copy",
        (Case::WrongCaller, Phase::Stage) => "qualification_fixture::installer::stage_wrong_caller",
        (Case::BadManifest, Phase::Stage) => "qualification_fixture::installer::stage_bad_manifest",
        (Case::Fresh, Phase::Observe) => "qualification_fixture::installer::observe_fresh",
        (Case::Reuse, Phase::Observe) => "qualification_fixture::installer::observe_reuse",
        (Case::StopCopy, Phase::Observe) => "qualification_fixture::installer::observe_stop_copy",
        (Case::WrongCaller, Phase::Observe) => "qualification_fixture::installer::observe_wrong_caller",
        (Case::BadManifest, Phase::Observe) => "qualification_fixture::installer::observe_bad_manifest",
        (Case::BadManifest, Phase::Corrupt) => "qualification_fixture::installer::corrupt_owned_manifest_last",
        _ => "not-an-admitted-fixture-test",
    }
}
fn file(case: Case, role: &str) -> String { format!("retained-{}-{role}.private.txt", case.label()) }
fn relative(base: &Path, path: &str) -> Result<PathBuf> {
    if path.is_empty() { return Ok(base.to_path_buf()); }
    let mut result = base.to_path_buf();
    for component in path.split('/') { need(decode::component(component))?; result.push(component); }
    Ok(result)
}
fn parent(path: &str) -> (&str, &str) { path.rsplit_once('/').unwrap_or(("", path)) }
fn sd(raw: &[u8], directory: bool, image: bool, public: bool) -> Result<()> {
    let kind = if directory { FileKind::Directory } else { FileKind::File };
    let facts = security::descriptor(raw, kind, AuthorityScope::ImmutableVersion)?;
    exact_security(&facts, kind, image, public)?;
    let at = decode::u32_at(raw, 8)? as usize;
    need(security::sid_at(raw, at, raw.len())?.bytes() == builtin(544))
}
fn own_dir(inputs: &Inputs, path: &str) -> bool {
    ["runtime-input", "installer-input"].iter().any(|branch| {
        let prefix = format!("{branch}/{TARGET}/{}", inputs.image);
        path == prefix || path.starts_with(&(prefix + "/"))
    })
}
fn image_public(inputs: &Inputs, path: &str, active: bool) -> bool {
    active && (path == format!("installer-input/{TARGET}/{}", inputs.image)
        || path == format!("installer-input/{TARGET}/{}/shell", inputs.image))
}
fn object_role(case: Case, directory: bool, i: usize) -> String {
    format!("i{}/{}/{}", case.index(), if directory { "d" } else { "f" }, i)
}
fn public_role(directory: bool, i: usize) -> String { format!("d/{}/{}", if directory { "d" } else { "f" }, i) }

impl Fixture {
    fn retained_input(&mut self, name: &str, limit: usize) -> Result<Vec<u8>> {
        need(!name.contains('/') && !name.contains('\\'))?;
        let (index, bytes) = self.input(&self.root.join(name), limit)?;
        self.recheck(index)?; self.close(index)?; self.pop_closed(index)?; Ok(bytes)
    }
    fn retained_precheck(&mut self) -> Result<(Wire, Vec<u8>)> {
        self.retained_precheck_for(INSTALLER_FIXTURE_PROFILE)
    }
    fn retained_precheck_for(&mut self, expected_profile: &str) -> Result<(Wire, Vec<u8>)> {
        need(expected_profile == active_profile()?)?;
        self.root_inputs()?;
        let raw = self.retained_input(PRE, TEXT_LIMIT)?;
        let pre = Wire::parse(&raw, PRE_HEADER, PRE_KEYS, TEXT_LIMIT)?;
        pre.binding()?; pre.equal("profile", expected_profile)?;
        pre.equal("profilesSha256", env!("MRK_WINDOWS_RETAINED_FIXTURE_PROFILES_SHA256"))?;
        pre.equal("rosterSha256", env!("MRK_WINDOWS_RETAINED_FIXTURE_ROSTER_SHA256"))?;
        for role in ["native", "app"] {
            let path = fixed_path(pre.get(&format!("{role}Artifact"))?)?;
            need(path.parent() == Some(fixed_directories(&self.root)[3].1.as_path()))?;
            let prefix = if role == "native" { "mrk_windows_installed_native-" } else { "mobile_release_desktop-" };
            need(path.file_name().and_then(|s| s.to_str()).and_then(|s| s.strip_prefix(prefix))
                .and_then(|s| s.strip_suffix(".exe")).is_some_and(|s| is_hex(s, 16)))?;
            original_epoch(pre.get(&format!("{role}ArtifactIdentity"))?, pre.get(&format!("{role}ArtifactIdentity"))?)?;
            let limit = if role == "native" { PAYLOAD_LIMIT } else { APP_ARTIFACT_LIMIT };
            need(pre.number(&format!("{role}ArtifactBytes"), limit as u64)? > 0)?;
        }
        need(self.image.to_str() == Some(pre.get("nativeArtifact")?))?;
        let (image, bytes) = self.input(&self.image.clone(), PAYLOAD_LIMIT)?;
        need(bytes.len() as u64 == pre.number("nativeArtifactBytes", PAYLOAD_LIMIT as u64)?
            && digest(&bytes)? == pre.get("nativeArtifactSha256")?
            && self.snapshots.get(&image).ok_or(Error::State)?.wire() == pre.get("nativeArtifactIdentity")?)?;
        self.recheck(image)?; self.close(image)?; self.pop_closed(image)?;
        Ok((pre, raw))
    }
    fn retained_exit(&mut self, pre: &Wire, pre_raw: &[u8], case: Case, role: &str,
        command: &'static str, result: &[u8], app: bool) -> Result<()> {
        let raw = self.retained_input(&file(case, &format!("{role}-exit")), LIMIT)?;
        let exit = Wire::parse(&raw, EXIT_HEADER, EXIT_KEYS, LIMIT)?;
        exit.binding()?; exit.equal("profile", INSTALLER_FIXTURE_PROFILE)?;
        exit.equal("role", &format!("{}-{role}", case.label()))?;
        let artifact = if app { "app" } else { "native" };
        exit.equal("artifactSha256", pre.get(&format!("{artifact}ArtifactSha256"))?)?;
        exit.equal("precheckSha256", &digest(pre_raw)?)?;
        exit.equal("commandSha256", &command_sha(pre.get(&format!("{artifact}Artifact"))?, command)?)?;
        exit.equal("resultSha256", &digest(result)?)?;
        need(exit.number("resultBytes", OWNER_LIMIT as u64)? == result.len() as u64)?;
        exit.equal("originalWaitReturned", "true")?; exit.equal("exitCode", "0")?;
        exit.equal("writerCloseGate", "original-owner-closed-output")?;
        Ok(())
    }
    fn retained_app(&mut self, pre: &Wire, raw: &[u8], case: Case) -> Result<Wire> {
        let output = self.retained_input(&file(case, "app"), OWNER_LIMIT)?;
        self.retained_exit(pre, raw, case, "app", case.app_test(), &output, true)?;
        let text = std::str::from_utf8(&output).map_err(|_| Error::Unsafe)?;
        let mut matching = text.lines().filter_map(|line| line.strip_prefix(APP_PREFIX));
        let fields = matching.next().ok_or(Error::Unsafe)?;
        need(matching.next().is_none())?;
        let lines = format!("MRK_WINDOWS_RETAINED_SHELL_CASE_DATA_V1\n{}\n", fields.replace(';', "\n"));
        let proof = Wire::parse(lines.as_bytes(), "MRK_WINDOWS_RETAINED_SHELL_CASE_DATA_V1", APP_KEYS, LIMIT)?;
        proof.equal("case", case.label())?;
        proof.equal("originalWatchdogJoined", "true")?; proof.equal("nativeSettled", "true")?;
        let inputs = installer_fixture_inputs(case)?;
        let total: u64 = inputs.sizes.iter().sum();
        let stopped = case == Case::StopCopy;
        proof.equal("rows", if stopped { "0" } else { "54" })?;
        if stopped {
            let written = proof.number("confirmedWritten", inputs.sizes[0])?;
            need(written > 0 && proof.number("sourceRead", total)? == inputs.sizes[52] + inputs.sizes[53] + written)?;
            proof.equal("readbackRead", "0")?;
        } else {
            for key in ["sourceRead", "confirmedWritten", "readbackRead"] {
                need(proof.number(key, total)? == total)?;
            }
        }
        let active = matches!(case, Case::Fresh | Case::Reuse);
        proof.equal("activation", if active { "true" } else { "false" })?;
        proof.equal("roles", if active { "63" } else { "0" })?;
        proof.equal("transitions", match case { Case::Fresh=>"63", Case::Reuse=>"56", _=>"0" })?;
        proof.equal("prerequisite", if matches!(case, Case::StopCopy | Case::WrongCaller) { "not-started" } else { "already-present" })?;
        proof.equal("runtime", match case {
            Case::Fresh=>"published-new", Case::Reuse=>"reused-existing", Case::StopCopy=>"not-started",
            Case::WrongCaller=>"caller-refused", Case::BadManifest=>"own-manifest-refused",
        })?;
        Ok(proof)
    }
    fn retained_record(&self, pre: &Wire, pre_raw: &[u8], inputs: &Inputs, phase: Phase,
        absent: bool, count: usize) -> Result<Wire> {
        let mut result = Wire { values: BTreeMap::new() };
        result.copy(pre, &["profile", "sourceSha", "sourceTree", "runId", "attempt", "profilesSha256", "rosterSha256"])?;
        result.put("case", inputs.case().label()); result.put("phase", phase_label(phase));
        result.put("precheckSha256", digest(pre_raw)?); result.put("image", inputs.image); result.put("manifest", inputs.manifest);
        let candidate = Path::new(&self.location.as_ref().ok_or(Error::State)?.path).join(inputs.source_leaf());
        result.put("candidate", candidate.to_str().ok_or(Error::Unsafe)?); result.put("freshMrkAbsent", absent);
        result.put("objects", count); result.put("fileOriginals", self.opened); result.put("fileOriginalsClosed", self.closed);
        result.put("parentBookSettled", "true"); result.put("unknown", "false");
        result.put("resultCloseGate", "original-fixture-exit-zero-required");
        Ok(result)
    }
    fn retained_snapshot(&mut self, pre: &Wire, pre_raw: &[u8], case: Case, phase: Phase)
        -> Result<Vec<ObservedObject>> {
        let raw = self.retained_input(&file(case, phase_label(phase)), OWNER_LIMIT)?;
        self.retained_exit(pre, pre_raw, case, phase_label(phase), test(case, phase), &raw, false)?;
        let (record, objects) = parse_snapshot(&raw)?;
        record.binding()?; record.equal("case", case.label())?; record.equal("phase", phase_label(phase))?;
        record.equal("precheckSha256", &digest(pre_raw)?)?;
        record.equal("profilesSha256", pre.get("profilesSha256")?)?;
        record.equal("rosterSha256", pre.get("rosterSha256")?)?;
        let inputs = installer_fixture_inputs(case)?;
        record.equal("image", inputs.image)?; record.equal("manifest", inputs.manifest)?;
        let candidate = Path::new(&self.location.as_ref().ok_or(Error::State)?.path).join(inputs.source_leaf());
        record.equal("candidate", candidate.to_str().ok_or(Error::Unsafe)?)?;
        record.equal("freshMrkAbsent", if case == Case::Fresh && phase == Phase::Stage { "true" } else { "false" })?;
        let expected = snapshot_members(&inputs, phase)?;
        need(objects.len() == expected.len())?;
        for (object, (role, directory, size, hash)) in objects.iter().zip(expected) {
            need(object.role == role && object.directory == directory)?;
            if let Some(size) = size { need(object.stamp.size == size as i64)?; }
            if let Some(hash) = hash { need(object.sha == hash)?; }
        }
        Ok(objects)
    }
    fn retained_tree_census(&mut self, directories: &BTreeMap<String, usize>,
        leaves: &BTreeMap<String, Stamp>, strict: impl Fn(&str) -> bool) -> Result<BTreeMap<String, String>> {
        let mut inventory = BTreeMap::new();
        for (path, index) in directories {
            let mut expected = BTreeMap::new();
            for (child, at) in directories {
                if !child.is_empty() && parent(child).0 == path {
                    expected.insert(parent(child).1.to_owned(), self.snapshots.get(at).ok_or(Error::State)?.clone());
                }
            }
            for (leaf, stamp) in leaves { if parent(leaf).0 == path { expected.insert(parent(leaf).1.to_owned(), stamp.clone()); } }
            self.recheck(*index)?;
            let rows = self.entries(*index, None)?;
            let own = self.snapshots.get(index).ok_or(Error::State)?;
            let up = if path.is_empty() { None } else { directories.get(parent(path).0).and_then(|i| self.snapshots.get(i)) };
            if strict(path) { exact_entries(&rows, &expected, own, up)?; }
            else {
                // Shared ancestors are readonly and may contain other owned I/D.
                // Every selected child still binds exact name/kind/id/attributes.
                for (name, stamp) in &expected {
                    let candidates: Vec<_> = rows.iter().filter(|r| r.name.eq_ignore_ascii_case(name)).collect();
                    need(candidates.len() == 1 && candidates[0].name == *name && candidates[0].file_id == stamp.id
                        && candidates[0].attributes == stamp.attributes
                        && (candidates[0].kind == FileKind::Directory) == (stamp.attributes & FS::FILE_ATTRIBUTE_DIRECTORY != 0))?;
                }
            }
            self.recheck(*index)?; inventory.insert(path.clone(), inventory_sha(&expected)?);
        }
        Ok(inventory)
    }
    fn retained_close_from(&mut self, begin: usize) -> Result<()> {
        while self.files.len() > begin {
            let index = self.files.len() - 1;
            self.recheck(index)?; self.close(index)?; self.pop_closed(index)?;
        }
        Ok(())
    }
    fn retained_stage(&mut self, inputs: &Inputs, pf: usize) -> Result<Vec<ObservedObject>> {
        let layout = inputs.layout()?;
        need(layout.source_directories.len() == 9)?;
        // The actual index returned by this Fixture\'s os_location, not a copied path grant.
        need(self.paths.get(pf).and_then(|p| p.to_str()) == self.location.as_ref().map(|l| l.path.as_str()))?;
        let rows = self.entries(pf, None)?;
        let leaf = inputs.source_leaf();
        need(!rows.iter().any(|r| r.name.eq_ignore_ascii_case(&leaf)))?;
        let mrk_absent = !rows.iter().any(|r| r.name.eq_ignore_ascii_case("Mobile Release Kit"));
        need(mrk_absent == (inputs.case() == Case::Fresh))?;
        let source = Path::new(&self.location.as_ref().ok_or(Error::State)?.path).join(&leaf);
        let local = self.root.join("installer-fixtures").join(inputs.case().label());
        let initial = self.files.len();
        self.directory(&self.root.join("installer-fixtures"), 0, None, None)?;
        for relative_dir in &layout.source_directories {
            self.directory(&relative(&local, relative_dir)?, 0, None, None)?;
        }
        let mut dirs = BTreeMap::new();
        for path in &layout.source_directories {
            let at = if path.is_empty() { pf } else { *dirs.get(parent(path).0).ok_or(Error::State)? };
            let destination = relative(&source, path)?;
            self.recheck(at)?;
            let pair = self.mutate(MutationKind::Directory, &destination, true, None)?;
            mutation_return(pair.0, pair.1)?; self.update_parent(at)?;
            let index = self.directory(&destination, 0, Some(AuthorityScope::ImmutableVersion), Some(false))?;
            dirs.insert(path.clone(), index);
        }
        let mut leaves = BTreeMap::new(); let mut objects = Vec::new();
        for i in 0..INPUTS {
            let path = &layout.paths[i].source;
            let (reader, bytes) = self.input(&relative(&local, path)?, PAYLOAD_LIMIT)?;
            self.source_readers += 1;
            need(bytes.len() as u64 == inputs.sizes[i] && digest(&bytes)? == inputs.hashes[i])?;
            let at = *dirs.get(parent(path).0).ok_or(Error::State)?;
            self.recheck(at)?;
            let destination = relative(&source, path)?;
            let writer = self.create_file(&destination)?; self.update_parent(at)?;
            let (created, before_sd) = self.checked(writer, Some(AuthorityScope::ImmutableVersion), Some(false))?;
            need(created.size == 0)?;
            self.files[writer].write_fixture_payload(&bytes)?; self.gate()?;
            let (written, written_sd) = self.checked(writer, Some(AuthorityScope::ImmutableVersion), Some(false))?;
            need(payload_change(&created, &written, bytes.len()) && before_sd == written_sd)?;
            self.close(writer)?; self.pop_closed(writer)?;
            let (readback, actual) = self.input(&destination, PAYLOAD_LIMIT)?; self.postcheck_readers += 1;
            let (stamp, descriptor) = self.checked(readback, Some(AuthorityScope::ImmutableVersion), Some(false))?;
            need(payload_change(&written, &stamp, bytes.len()) && stamp.allocation == written.allocation
                && descriptor == written_sd && actual == bytes)?;
            leaves.insert(path.clone(), stamp.clone());
            objects.push(ObservedObject { role: format!("s/f/{i}"), directory: false, stamp,
                security: digest(&descriptor)?, sha: inputs.hashes[i].to_owned(), inventory: "-".to_owned() });
            self.recheck(readback)?; self.close(readback)?; self.pop_closed(readback)?;
            self.recheck(reader)?; self.close(reader)?; self.pop_closed(reader)?;
        }
        let inventories = self.retained_tree_census(&dirs, &leaves, |_| true)?;
        for (i, path) in layout.source_directories.iter().enumerate() {
            let at = *dirs.get(path).ok_or(Error::State)?;
            let mut object = self.observed_directory(at, &format!("s/d/{i}"))?;
            object.inventory = inventories.get(path).ok_or(Error::State)?.clone(); objects.push(object);
        }
        let after = self.entries_at(pf, None, 1)?;
        let root = self.snapshots.get(dirs.get("").ok_or(Error::State)?).ok_or(Error::State)?;
        let selected: Vec<_> = after.iter().filter(|r| r.name.eq_ignore_ascii_case(&leaf)).collect();
        need(selected.len() == 1 && selected[0].name == leaf && selected[0].file_id == root.id
            && selected[0].attributes == root.attributes)?;
        self.recheck(pf)?;
        need(self.source_readers == 54 && self.writers == 54 && self.postcheck_readers == 54)?;
        self.retained_close_from(initial)?;
        Ok(objects)
    }
    fn retained_image(&mut self, inputs: &Inputs, active: bool, partial: Option<u64>) -> Result<Vec<ObservedObject>> {
        self.retained_image_checked(inputs, active, partial, None)
    }
    fn retained_image_checked(&mut self, inputs: &Inputs, active: bool, partial: Option<u64>,
        damaged_shell: Option<&ObservedObject>) -> Result<Vec<ObservedObject>> {
        if let Some(expected) = damaged_shell {
            need(cfg!(feature = "installer-selection-fixture") && inputs.case() == Case::BadManifest
                && active && partial.is_none() && expected.role == object_role(Case::BadManifest, false, 48)
                && !expected.directory && expected.stamp.size == inputs.sizes[48] as i64
                && expected.sha != inputs.hashes[48] && is_hex(&expected.sha, 64))?;
        }
        let layout = inputs.layout()?;
        let base = Path::new(&self.location.as_ref().ok_or(Error::State)?.path).join("Mobile Release Kit");
        let initial = self.files.len();
        let mut dirs = BTreeMap::new(); let mut objects = Vec::new(); let mut leaves = BTreeMap::new();
        for path in &layout.output_directories {
            let index = self.directory(&relative(&base, path)?, 0, Some(AuthorityScope::ImmutableVersion), None)?;
            let public = if own_dir(inputs, path) { image_public(inputs, path, active) }
                else { path.is_empty() || path == "installer-input" || path == format!("installer-input/{TARGET}") };
            sd(&self.descriptor(index)?, true, false, public)?; dirs.insert(path.clone(), index);
        }
        for i in 0..if partial.is_some() { 1 } else { INPUTS } {
            let path = &layout.paths[i].output;
            let (reader, bytes) = self.input(&relative(&base, path)?, PAYLOAD_LIMIT)?; self.postcheck_readers += 1;
            let (stamp, descriptor) = self.checked(reader, Some(AuthorityScope::ImmutableVersion), None)?;
            sd(&descriptor, false, layout.paths[i].image(), active && i == 48)?;
            if let Some(count) = partial {
                need(i == 0 && count > 0 && bytes.len() as u64 == count && count <= inputs.sizes[0])?;
                let source = Path::new(&self.location.as_ref().ok_or(Error::State)?.path).join(inputs.source_leaf());
                let (input, original) = self.input(&relative(&source, &layout.paths[0].source)?, PAYLOAD_LIMIT)?;
                need(original.len() as u64 == inputs.sizes[0] && digest(&original)? == inputs.hashes[0]
                    && original.get(..bytes.len()) == Some(bytes.as_slice()))?;
                self.recheck(input)?; self.close(input)?; self.pop_closed(input)?;
            } else if let Some(expected) = damaged_shell.filter(|_| i == 48) {
                // Only the exact bound fourth-profile row48 postwrite original,
                // from the immediately preceding owned setup proof. Every other
                // row keeps its original compile-bound hash and metadata checks.
                need(stamp == expected.stamp && digest(&descriptor)? == expected.security
                    && bytes.len() as u64 == inputs.sizes[i] && digest(&bytes)? == expected.sha)?;
            } else { need(bytes.len() as u64 == inputs.sizes[i] && digest(&bytes)? == inputs.hashes[i])?; }
            leaves.insert(path.clone(), stamp.clone());
            objects.push(ObservedObject { role: object_role(inputs.case(), false, i), directory: false,
                stamp, security: digest(&descriptor)?, sha: digest(&bytes)?, inventory: "-".to_owned() });
            self.recheck(reader)?; self.close(reader)?; self.pop_closed(reader)?;
        }
        let inventories = self.retained_tree_census(&dirs, &leaves, |path| own_dir(inputs, path))?;
        for (i, path) in layout.output_directories.iter().filter(|p| own_dir(inputs, p)).enumerate() {
            let at = *dirs.get(path).ok_or(Error::State)?;
            let mut object = self.observed_directory(at, &object_role(inputs.case(), true, i))?;
            object.inventory = inventories.get(path).ok_or(Error::State)?.clone(); objects.push(object);
        }
        self.retained_close_from(initial)?; Ok(objects)
    }
    fn retained_public(&mut self, inputs: &Inputs) -> Result<Vec<ObservedObject>> {
        let base = Path::new(&self.location.as_ref().ok_or(Error::State)?.path).join("Mobile Release Kit");
        let version = format!("versions/{TARGET}/{}", inputs.manifest);
        let names = [String::new(), "versions".to_owned(), format!("versions/{TARGET}"), version.clone(), format!("{version}/python")];
        let initial = self.files.len();
        let mut dirs = BTreeMap::new(); let mut leaves = BTreeMap::new(); let mut objects = Vec::new();
        for path in &names {
            let at = self.directory(&relative(&base, path)?, 0, Some(AuthorityScope::ImmutableVersion), None)?;
            sd(&self.descriptor(at)?, true, false, true)?; dirs.insert(path.clone(), at);
        }
        for (i, name) in PAYLOAD_NAMES.iter().enumerate() {
            let path = format!("{version}/{name}");
            let (reader, bytes) = self.input(&relative(&base, &path)?, PAYLOAD_LIMIT)?; self.postcheck_readers += 1;
            let (stamp, descriptor) = self.checked(reader, Some(AuthorityScope::ImmutableVersion), None)?;
            sd(&descriptor, false, name.ends_with(".exe") || name.ends_with(".dll") || name.ends_with(".pyd"), true)?;
            need(bytes.len() as u64 == inputs.sizes[i] && digest(&bytes)? == inputs.hashes[i])?;
            leaves.insert(path, stamp.clone());
            objects.push(ObservedObject { role: public_role(false, i), directory: false, stamp,
                security: digest(&descriptor)?, sha: inputs.hashes[i].to_owned(), inventory: "-".to_owned() });
            self.recheck(reader)?; self.close(reader)?; self.pop_closed(reader)?;
        }
        let inventories = self.retained_tree_census(&dirs, &leaves, |path| path == version || path == format!("{version}/python"))?;
        for (i, path) in names[3..].iter().enumerate() {
            let at = *dirs.get(path).ok_or(Error::State)?;
            let mut object = self.observed_directory(at, &public_role(true, i))?;
            object.inventory = inventories.get(path).ok_or(Error::State)?.clone(); objects.push(object);
        }
        self.retained_close_from(initial)?; Ok(objects)
    }
    fn retained_owned_baseline(&mut self, pre: &Wire, pre_raw: &[u8]) -> Result<Vec<ObservedObject>> {
        // No path/hash adoption: actual A fresh stage, A PublishNew+activation,
        // A snapshot and B unchanged observation each have original owner exits.
        self.retained_snapshot(pre, pre_raw, Case::Fresh, Phase::Stage)?;
        self.retained_app(pre, pre_raw, Case::Fresh)?;
        let before = self.retained_snapshot(pre, pre_raw, Case::Fresh, Phase::Observe)?;
        self.retained_app(pre, pre_raw, Case::Reuse)?;
        let after = self.retained_snapshot(pre, pre_raw, Case::Reuse, Phase::Observe)?;
        for object in &before { need(observed(&after, &object.role)? == object)?; }
        need(before.len() == 110 && after.len() == 171)?;
        Ok(after)
    }
    fn retained_corrupt_last(&mut self, pre: &Wire, pre_raw: &[u8], inputs: &Inputs) -> Result<Vec<ObservedObject>> {
        need(inputs.case() == Case::BadManifest)?;
        let baseline = self.retained_owned_baseline(pre, pre_raw)?;
        for earlier in [Case::StopCopy, Case::WrongCaller] {
            self.retained_app(pre, pre_raw, earlier)?;
            self.retained_snapshot(pre, pre_raw, earlier, Phase::Observe)?;
        }
        self.retained_snapshot(pre, pre_raw, Case::BadManifest, Phase::Stage)?;
        // Actual earlier app AND observer exits precede the last mutation.
        // The outer owner must not schedule another namespace user after E.
        let current = self.retained_public(inputs)?;
        for object in &current { need(observed(&baseline, &object.role)? == object)?; }
        let expected = observed(&current, &public_role(false, 7))?.clone();
        let path = Path::new(&self.location.as_ref().ok_or(Error::State)?.path)
            .join("Mobile Release Kit").join("versions").join(TARGET).join(inputs.manifest).join("manifest.json");
        let (reader, mut bytes) = self.input(&path, PAYLOAD_LIMIT)?;
        let (before, security) = self.checked(reader, Some(AuthorityScope::ImmutableVersion), None)?;
        sd(&security, false, false, true)?;
        need(before == expected.stamp && digest(&security)? == expected.security
            && !bytes.is_empty() && bytes.len() as u64 == inputs.sizes[7] && digest(&bytes)? == inputs.hashes[7])?;
        self.recheck(reader)?; self.close(reader)?; self.pop_closed(reader)?;
        bytes[0] ^= 1; // fixed same-length corruption, once; never repair/reset
        let writer = self.open(&path, false, FS::FILE_GENERIC_READ | FS::FILE_GENERIC_WRITE)?;
        let (opened, writer_sd) = self.checked(writer, Some(AuthorityScope::ImmutableVersion), None)?;
        need(opened == before && writer_sd == security)?;
        self.files[writer].write_fixture_payload(&bytes)?; self.gate()?;
        let (written, written_sd) = self.checked(writer, Some(AuthorityScope::ImmutableVersion), None)?;
        need(same_object(&opened, &written) && written.size == opened.size
            && written.allocation == opened.allocation && written.write >= opened.write
            && written.change >= opened.change && written_sd == writer_sd)?;
        self.close(writer)?; self.pop_closed(writer)?;
        let (readback, actual) = self.input(&path, PAYLOAD_LIMIT)?; self.postcheck_readers += 1;
        let (stamp, readback_sd) = self.checked(readback, Some(AuthorityScope::ImmutableVersion), None)?;
        need(same_object(&written, &stamp) && stamp.size == written.size && stamp.allocation == written.allocation
            && stamp.write >= written.write && stamp.change >= written.change && readback_sd == written_sd
            && actual == bytes && digest(&actual)? != inputs.hashes[7])?;
        let result = ObservedObject { role: public_role(false, 7), directory: false, stamp,
            security: digest(&readback_sd)?, sha: digest(&actual)?, inventory: "-".to_owned() };
        self.recheck(readback)?; self.close(readback)?; self.pop_closed(readback)?;
        Ok(vec![result])
    }
    fn retained_observe(&mut self, pre: &Wire, pre_raw: &[u8], inputs: &Inputs) -> Result<Vec<ObservedObject>> {
        self.retained_snapshot(pre, pre_raw, inputs.case(), Phase::Stage)?;
        let proof = self.retained_app(pre, pre_raw, inputs.case())?;
        let objects = match inputs.case() {
            Case::Fresh => {
                let mut out = self.retained_public(inputs)?;
                out.extend(self.retained_image(inputs, true, None)?); out
            },
            Case::Reuse => {
                self.retained_app(pre, pre_raw, Case::Fresh)?;
                let before = self.retained_snapshot(pre, pre_raw, Case::Fresh, Phase::Observe)?;
                let mut out = self.retained_public(inputs)?;
                let old = installer_fixture_inputs(Case::Fresh)?;
                out.extend(self.retained_image(&old, true, None)?);
                need(out == before)?; // complete D47/IA54, exact original Facts/hash/ACL
                out.extend(self.retained_image(inputs, true, None)?); out
            },
            Case::StopCopy => self.retained_image(inputs, false, Some(proof.number("confirmedWritten", inputs.sizes[0])?))?,
            Case::WrongCaller => self.retained_image(inputs, false, None)?,
            Case::BadManifest => {
                let corrupted = self.retained_snapshot(pre, pre_raw, Case::BadManifest, Phase::Corrupt)?;
                need(corrupted.len() == 1)?;
                let path = Path::new(&self.location.as_ref().ok_or(Error::State)?.path)
                    .join("Mobile Release Kit").join("versions").join(TARGET).join(inputs.manifest).join("manifest.json");
                let (reader, bytes) = self.input(&path, PAYLOAD_LIMIT)?;
                let (stamp, descriptor) = self.checked(reader, Some(AuthorityScope::ImmutableVersion), None)?;
                let actual = ObservedObject { role: public_role(false, 7), directory: false, stamp,
                    security: digest(&descriptor)?, sha: digest(&bytes)?, inventory: "-".to_owned() };
                need(corrupted[0] == actual && actual.sha != inputs.hashes[7])?;
                self.recheck(reader)?; self.close(reader)?; self.pop_closed(reader)?;
                let mut out = self.retained_image(inputs, false, None)?; out.push(actual); out
            },
        };
        Ok(objects)
    }
}

type SnapshotMember = (String, bool, Option<u64>, Option<&'static str>);
fn snapshot_members(inputs: &Inputs, phase: Phase) -> Result<Vec<SnapshotMember>> {
    let mut members = Vec::new();
    if phase == Phase::Stage {
        for i in 0..INPUTS { members.push((format!("s/f/{i}"), false, Some(inputs.sizes[i]), Some(inputs.hashes[i]))); }
        for i in 0..9 { members.push((format!("s/d/{i}"), true, None, None)); }
        return Ok(members);
    }
    if phase == Phase::Corrupt {
        need(inputs.case() == Case::BadManifest)?;
        return Ok(vec![(public_role(false, 7), false, Some(inputs.sizes[7]), None)]);
    }
    if matches!(inputs.case(), Case::Fresh | Case::Reuse) {
        for i in 0..47 { members.push((public_role(false, i), false, Some(inputs.sizes[i]), Some(inputs.hashes[i]))); }
        for i in 0..2 { members.push((public_role(true, i), true, None, None)); }
    }
    let selected = inputs.case();
    let cases: &[Case] = if selected == Case::Reuse { &[Case::Fresh, Case::Reuse] }
        else { std::slice::from_ref(&selected) };
    for case in cases {
        let row = installer_fixture_inputs(*case)?;
        let partial = *case == Case::StopCopy;
        for i in 0..if partial { 1 } else { INPUTS } {
            members.push((object_role(*case, false, i), false,
                if partial { None } else { Some(row.sizes[i]) },
                if partial { None } else { Some(row.hashes[i]) }));
        }
        let own = row.layout()?.output_directories.iter().filter(|p| own_dir(&row, p)).count();
        need(own == 7)?;
        for i in 0..own { members.push((object_role(*case, true, i), true, None, None)); }
    }
    if inputs.case() == Case::BadManifest {
        members.push((public_role(false, 7), false, Some(inputs.sizes[7]), None));
    }
    Ok(members)
}

fn parse_snapshot(raw: &[u8]) -> Result<(Wire, Vec<ObservedObject>)> {
    need(!raw.is_empty() && raw.len() <= OWNER_LIMIT && raw.is_ascii() && raw.ends_with(b"\n")
        && !raw.contains(&b'\r'))?;
    let lines: Vec<_> = std::str::from_utf8(raw).map_err(|_| Error::Unsafe)?.lines().collect();
    let prefix = 1 + SNAP_KEYS.len();
    need(lines.len() >= prefix)?;
    let header = lines[..prefix].join("\n") + "\n";
    let record = Wire::parse(header.as_bytes(), SNAP_HEADER, SNAP_KEYS, OWNER_LIMIT)?;
    record.equal("profile", INSTALLER_FIXTURE_PROFILE)?;
    record.equal("parentBookSettled", "true")?; record.equal("unknown", "false")?;
    record.equal("resultCloseGate", "original-fixture-exit-zero-required")?;
    need(record.number("objects", 192)? == (lines.len() - prefix) as u64
        && record.number("fileOriginals", 256)? > 0
        && record.get("fileOriginals")? == record.get("fileOriginalsClosed")?)?;
    let mut objects = Vec::new(); let mut identities = BTreeSet::new(); let mut roles = BTreeSet::new();
    for line in &lines[prefix..] {
        let parts: Vec<_> = line.strip_prefix("observed=").ok_or(Error::Unsafe)?.split('|').collect();
        need(parts.len() == 6 && parts[0].len() <= 24 && roles.insert(parts[0])
            && matches!(parts[1], "directory" | "file") && is_hex(parts[3], 64))?;
        let stamp = parse_stamp(parts[2])?; let directory = parts[1] == "directory";
        need((stamp.attributes & FS::FILE_ATTRIBUTE_DIRECTORY != 0) == directory
            && identities.insert((stamp.volume, stamp.id)))?;
        need(if directory { parts[4] == "-" && is_hex(parts[5], 64) }
            else { is_hex(parts[4], 64) && parts[5] == "-" })?;
        objects.push(ObservedObject { role: parts[0].to_owned(), directory, stamp,
            security: parts[3].to_owned(), sha: parts[4].to_owned(), inventory: parts[5].to_owned() });
    }
    Ok((record, objects))
}
fn run(case: Case, phase: Phase) -> Result<()> {
    let start = Instant::now();
    let name = test(case, phase);
    let root = installer_fixture_process(name)?;
    let image = std::env::current_exe().map_err(|_| Error::Unavailable)?;
    let inputs = installer_fixture_inputs(case)?; // existing pure sha2 DATA, no native digest
    let mut original = Fixture::new(start, root, image)?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (pre, pre_raw) = original.retained_precheck()?;
        let program_files = original.os_location()?;
        let objects = match phase {
            Phase::Stage => original.retained_stage(&inputs, program_files)?,
            Phase::Observe => original.retained_observe(&pre, &pre_raw, &inputs)?,
            Phase::Corrupt => original.retained_corrupt_last(&pre, &pre_raw, &inputs)?,
        };
        original.final_inputs()?;
        Ok((pre, pre_raw, objects))
    })).unwrap_or(Err(Error::Unknown));
    if matches!(result, Err(Error::Unknown)) || original.unknown() {
        diagnostic_data("retained-fixture-original-operation", None, true, None);
        loop { std::thread::park(); std::hint::black_box(&mut original); }
    }
    let settled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| original.settle())).unwrap_or(Err(Error::Unknown));
    if matches!(settled, Err(Error::Unknown)) || original.unknown() {
        diagnostic_data("retained-fixture-original-close", None, true, None);
        loop { std::thread::park(); std::hint::black_box(&mut original); }
    }
    let (pre, pre_raw, objects) = result?; settled?;
    let record = original.retained_record(&pre, &pre_raw, &inputs, phase,
        case == Case::Fresh && phase == Phase::Stage, objects.len())?;
    let mut raw = record.encoded(SNAP_HEADER, SNAP_KEYS, OWNER_LIMIT)?;
    for object in &objects { raw.extend(object.line().as_bytes()); }
    parse_snapshot(&raw)?;
    original.gate()?;
    write_fixture_record(&original.root.join(file(case, phase_label(phase))), &raw, OWNER_LIMIT, original.end)?;
    original.gate()
}
#[test] #[ignore = "fixed owned native preparation, no payload execution"] fn stage_fresh() -> Result<()> { run(Case::Fresh, Phase::Stage) }
#[test] #[ignore = "fixed owned native preparation, no payload execution"] fn stage_reuse() -> Result<()> { run(Case::Reuse, Phase::Stage) }
#[test] #[ignore = "fixed owned native preparation, no payload execution"] fn stage_stop_copy() -> Result<()> { run(Case::StopCopy, Phase::Stage) }
#[test] #[ignore = "fixed owned native preparation, no payload execution"] fn stage_wrong_caller() -> Result<()> { run(Case::WrongCaller, Phase::Stage) }
#[test] #[ignore = "fixed owned native preparation, no payload execution"] fn stage_bad_manifest() -> Result<()> { run(Case::BadManifest, Phase::Stage) }
#[test] #[ignore = "actual original-owned A exit required"] fn observe_fresh() -> Result<()> { run(Case::Fresh, Phase::Observe) }
#[test] #[ignore = "actual original-owned A and B exits required"] fn observe_reuse() -> Result<()> { run(Case::Reuse, Phase::Observe) }
#[test] #[ignore = "actual original-owned first-copy STOP exit required"] fn observe_stop_copy() -> Result<()> { run(Case::StopCopy, Phase::Observe) }
#[test] #[ignore = "actual original-owned wrong-caller exit required"] fn observe_wrong_caller() -> Result<()> { run(Case::WrongCaller, Phase::Observe) }
#[test] #[ignore = "last namespace user; actual corrupted-original refusal required"] fn observe_bad_manifest() -> Result<()> { run(Case::BadManifest, Phase::Observe) }
#[test] #[ignore = "A PublishNew and actual A/B owned snapshots required; one same-length write, never restore"]
fn corrupt_owned_manifest_last() -> Result<()> { run(Case::BadManifest, Phase::Corrupt) }
