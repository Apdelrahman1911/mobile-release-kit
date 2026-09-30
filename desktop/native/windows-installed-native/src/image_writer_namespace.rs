//! Finite image-only namespace DATA. No Windows call, owner, HANDLE or transaction.
//! Acquisition edges and entered canonical claims never change or disappear.
#![forbid(unsafe_code)]
use std::mem::size_of;

pub(super) const MAX_ROWS: usize = 38;
pub(super) const MAX_MOVES: usize = 16;
pub(super) const MAX_DELETES: usize = MAX_ROWS;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Fault { Bounds, State, Unsafe }
type Result<T> = std::result::Result<T, Fault>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Edge { pub parent: usize, pub name: String }
#[derive(Clone, Debug)]
pub(super) struct Node {
    pub parent: Option<usize>,
    pub name: String,
    pub directory: bool,
    pub mutation_parent: bool,
    pub movable: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Move {
    pub row: usize,
    pub from: Edge,
    pub to: Edge,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Delete { pub row: usize, pub edge: Edge }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MoveState { Planned, Entered, Latched, Complete }
#[derive(Clone, Copy)]
pub(super) struct Epoch(u64);
struct Claim { row: usize, name: String }

pub(super) struct PreparedMove {
    step: usize,
    epoch: Epoch,
    edges: Vec<Option<Edge>>,
    names: Vec<String>,
    claims: Vec<Claim>,
    entered: bool,
}
impl PreparedMove {
    pub fn step(&self) -> usize { self.step }
    pub fn heap_bytes(&self) -> Option<usize> {
        edge_bytes(&self.edges)?.checked_add(string_bytes(&self.names)?)?
            .checked_add(claim_bytes(&self.claims)?)
    }
}
pub(super) struct Namespace {
    nodes: Vec<Node>,                 // immutable acquisition facts
    edges: Vec<Option<Edge>>,         // current edge facts only
    moves: Vec<Move>,                 // immutable one-use operation declarations
    deletes: Vec<Delete>,
    states: [MoveState; MAX_MOVES],
    delete_entered: [bool; MAX_ROWS],
    attempted: [bool; MAX_ROWS],
    original_slots: [Option<usize>; MAX_ROWS], // DATA identity, never a HANDLE
    parents: [u64; MAX_ROWS],         // frozen union, not just current parents
    retire: [usize; MAX_ROWS],        // reverse topological union order
    names: Vec<String>,
    claims: Vec<Claim>,
    epoch: u64,
    name_limit: usize,
    bound: bool,
}
impl Namespace {
    pub fn new(nodes: &[Node], moves: &[Move], deletes: &[Delete], name_limit: usize) -> Result<Self> {
        if nodes.is_empty() || nodes.len() > MAX_ROWS || moves.len() > MAX_MOVES
            || deletes.len() > MAX_DELETES || name_limit < 2 { return Err(Fault::Bounds); }
        let mut parents = [0u64; MAX_ROWS];
        for (row, node) in nodes.iter().enumerate() {
            if node.mutation_parent && !node.directory { return Err(Fault::Unsafe); }
            match node.parent {
                None if row == 0 && node.name.is_empty() && node.directory && !node.movable => {},
                Some(parent) if parent < row && nodes[parent].directory && leaf(&node.name) => {
                    parents[row] |= 1u64 << parent;
                },
                _ => return Err(Fault::Unsafe),
            }
        }
        for (step, movement) in moves.iter().enumerate() {
            if movement.row >= nodes.len() || !nodes[movement.row].movable
                || moves[..step].contains(movement) { return Err(Fault::State); }
            for edge in [&movement.from, &movement.to] {
                if edge.parent >= nodes.len() || !nodes[edge.parent].directory || !nodes[edge.parent].mutation_parent
                    || edge.parent == movement.row || !leaf(&edge.name) { return Err(Fault::Unsafe); }
                parents[movement.row] |= 1u64 << edge.parent;
            }
            if movement.from.parent == movement.to.parent
                && movement.from.name.eq_ignore_ascii_case(&movement.to.name) { return Err(Fault::Unsafe); }
        }
        for (step, deletion) in deletes.iter().enumerate() {
            if deletion.row >= nodes.len() || !nodes[deletion.row].movable
                || deletion.edge.parent >= nodes.len() || !nodes[deletion.edge.parent].mutation_parent
                || !leaf(&deletion.edge.name)
                || deletes[..step].iter().any(|prior| prior.row == deletion.row) {
                return Err(Fault::Unsafe);
            }
            // A deletion can only be declared at acquisition or a frozen move edge.
            let acquired = nodes[deletion.row].parent == Some(deletion.edge.parent)
                && nodes[deletion.row].name == deletion.edge.name;
            if !acquired && !moves.iter().any(|movement| movement.row == deletion.row
                && (movement.from == deletion.edge || movement.to == deletion.edge)) {
                return Err(Fault::State);
            }
        }
        let retire = retirement_order(&parents, nodes.len())?;
        let mut owned = Vec::new();
        owned.try_reserve_exact(nodes.len()).map_err(|_| Fault::Bounds)?;
        owned.extend_from_slice(nodes);
        let mut edges = Vec::new();
        edges.try_reserve_exact(nodes.len()).map_err(|_| Fault::Bounds)?;
        for node in nodes {
            edges.push(node.parent.map(|parent| Edge { parent, name: node.name.clone() }));
        }
        let mut declared = Vec::new();
        declared.try_reserve_exact(moves.len()).map_err(|_| Fault::Bounds)?;
        declared.extend_from_slice(moves);
        let mut deletion_slots = Vec::new();
        deletion_slots.try_reserve_exact(deletes.len()).map_err(|_| Fault::Bounds)?;
        deletion_slots.extend_from_slice(deletes);
        let mut claims = Vec::new();
        claims.try_reserve_exact((MAX_MOVES + 1) * nodes.len()).map_err(|_| Fault::Bounds)?;
        Ok(Self { nodes: owned, edges, moves: declared, deletes: deletion_slots,
            states: [MoveState::Planned; MAX_MOVES], delete_entered: [false; MAX_ROWS],
            attempted: [false; MAX_ROWS], original_slots: [None; MAX_ROWS], parents, retire, names: Vec::new(), claims,
            epoch: 0, name_limit, bound: false })
    }
    pub fn bind_volume(&mut self, device: &str) -> Result<()> {
        if self.bound || self.attempted.iter().any(|attempted| *attempted)
            || !device.starts_with("\\Device\\") || !device.is_ascii()
            || device.contains('\0') || device.ends_with('\\') { return Err(Fault::State); }
        let base = format!("{device}\\");
        let names = paths(&self.edges, &base, self.name_limit)?;
        for (row, name) in names.iter().enumerate() {
            if names[..row].iter().any(|prior| prior.eq_ignore_ascii_case(name)) { return Err(Fault::Unsafe); }
        }
        for (row, name) in names.iter().enumerate() {
            self.claims.push(Claim { row, name: name.clone() });
        }
        self.names = names;
        self.bound = true;
        Ok(())
    }
    pub fn epoch(&self) -> u64 { self.epoch }
    pub fn next_epoch(&self) -> Result<Epoch> {
        if !self.bound { return Err(Fault::State); }
        self.epoch.checked_add(1).map(Epoch).ok_or(Fault::Bounds)
    }
    // Only a pre-entry checked token reaches this allocation-free latch.
    pub fn latch_epoch(&mut self, epoch: Epoch) { self.epoch = epoch.0; }
    pub fn name(&self, row: usize, epoch: u64) -> Result<&str> {
        if !self.bound || epoch != self.epoch { return Err(Fault::State); }
        self.names.get(row).map(String::as_str).ok_or(Fault::State)
    }
    pub fn edge(&self, row: usize) -> Result<Option<&Edge>> {
        self.edges.get(row).map(Option::as_ref).ok_or(Fault::State)
    }
    pub fn parent(&self, row: usize) -> Result<Option<usize>> { Ok(self.edge(row)?.map(|edge| edge.parent)) }
    pub fn leaf(&self, row: usize) -> Result<&str> { Ok(self.edge(row)?.map_or("", |edge| edge.name.as_str())) }
    pub fn move_plan(&self, step: usize) -> Result<&Move> { self.moves.get(step).ok_or(Fault::State) }
    pub fn delete_plan(&self, step: usize) -> Result<&Delete> { self.deletes.get(step).ok_or(Fault::State) }
    pub fn move_count(&self) -> usize { self.moves.len() }
    pub fn delete_count(&self) -> usize { self.deletes.len() }
    pub fn state(&self, step: usize) -> Result<MoveState> {
        self.move_plan(step)?;
        Ok(self.states[step])
    }
    pub fn claim_acquisition(&mut self, row: usize) -> Result<String> {
        let name = self.name(row, self.epoch)?;
        if self.attempted[row] || self.claims.iter().any(|claim|
            claim.name.eq_ignore_ascii_case(name) && (claim.row != row || claim.name != name)) {
            return Err(Fault::State);
        }
        let name = name.to_owned(); // allocation belongs to pre-entry acquisition
        self.attempted[row] = true;
        Ok(name)
    }
    pub fn bind_original(&mut self, row: usize, slot: usize) -> Result<()> {
        if row >= self.nodes.len() || !self.attempted[row] || self.original_slots[row].is_some()
            || self.original_slots.iter().any(|bound| *bound == Some(slot)) { return Err(Fault::State); }
        self.original_slots[row] = Some(slot);
        Ok(())
    }
    pub fn original_is(&self, row: usize, slot: usize) -> bool {
        row < self.nodes.len() && self.original_slots[row] == Some(slot)
    }
    pub fn prepare_move(&self, step: usize) -> Result<PreparedMove> {
        let movement = self.move_plan(step)?;
        if !self.bound || self.states[step] != MoveState::Planned || !self.attempted[movement.row]
            || self.edge(movement.row)? != Some(&movement.from) { return Err(Fault::State); }
        let epoch = self.next_epoch()?;
        let mut edges = self.edges.clone();
        edges[movement.row] = Some(movement.to.clone());
        let names = paths(&edges, &self.names[0], self.name_limit)?;
        let mut claims = Vec::new();
        claims.try_reserve_exact(self.nodes.len()).map_err(|_| Fault::Bounds)?;
        for (row, name) in names.iter().enumerate() {
            if name != &self.names[row] && !self.claims.iter().any(|claim| claim.row == row && claim.name == *name) {
                claims.push(Claim { row, name: name.clone() });
            }
        }
        if self.claims.len().checked_add(claims.len()).is_none_or(|n| n > (MAX_MOVES + 1) * self.nodes.len()) {
            return Err(Fault::Bounds);
        }
        Ok(PreparedMove { step, epoch, edges, names, claims, entered: false })
    }
    pub fn enter_move(&mut self, prepared: &mut PreparedMove) -> Result<()> {
        let step = prepared.step;
        let movement = self.move_plan(step)?;
        if prepared.entered || self.states[step] != MoveState::Planned
            || self.edge(movement.row)? != Some(&movement.from)
            || prepared.epoch.0 != self.epoch.checked_add(1).ok_or(Fault::Bounds)?
            || self.claims.len().checked_add(prepared.claims.len()).is_none_or(|n| n > self.claims.capacity()) {
            return Err(Fault::State);
        }
        // Claims survive an actual entered failure; no retry can reacquire an alias.
        self.claims.extend(prepared.claims.drain(..)); // fixed pre-reserved capacity
        self.states[step] = MoveState::Entered;
        prepared.entered = true;
        Ok(())
    }
    // No allocation, Result, native call or stop/recheck occurs inside the latch.
    // The serialized owner passes its EXACT entered pending plan, never caller DATA.
    pub fn latch_move(&mut self, prepared: PreparedMove) {
        self.edges = prepared.edges;
        self.names = prepared.names;
        self.epoch = prepared.epoch.0;
        self.states[prepared.step] = MoveState::Latched;
    }
    pub fn finish_move(&mut self, step: usize) -> Result<()> {
        if self.state(step)? != MoveState::Latched { return Err(Fault::State); }
        self.states[step] = MoveState::Complete;
        Ok(())
    }
    pub fn enter_delete(&mut self, step: usize) -> Result<Epoch> {
        let deletion = self.delete_plan(step)?;
        let row = deletion.row;
        if !self.attempted[row] || self.delete_entered[row] || self.edge(row)? != Some(&deletion.edge) {
            return Err(Fault::State);
        }
        let epoch = self.next_epoch()?;
        self.delete_entered[row] = true;
        Ok(epoch)
    }
    pub fn retirement(&self) -> &[usize] { &self.retire[..self.nodes.len()] }
    pub fn has_live_dependency(&self, parent: usize, live: u64) -> bool {
        self.parents[..self.nodes.len()].iter().enumerate()
            .any(|(child, parents)| live & (1u64 << child) != 0 && parents & (1u64 << parent) != 0)
    }
    pub fn dependency_closure(&self, mut needed: u64) -> u64 {
        loop {
            let before = needed;
            for (row, parents) in self.parents[..self.nodes.len()].iter().enumerate() {
                if needed & (1u64 << row) != 0 { needed |= parents; }
            }
            if needed == before { return needed; }
        }
    }
    pub fn heap_bytes(&self) -> Option<usize> {
        let mut bytes = self.nodes.capacity().checked_mul(size_of::<Node>())?
            .checked_add(edge_bytes(&self.edges)?)?
            .checked_add(self.moves.capacity().checked_mul(size_of::<Move>())?)?
            .checked_add(self.deletes.capacity().checked_mul(size_of::<Delete>())?)?
            .checked_add(string_bytes(&self.names)?)?
            .checked_add(claim_bytes(&self.claims)?)?;
        for node in &self.nodes { bytes = bytes.checked_add(node.name.capacity())?; }
        for movement in &self.moves {
            bytes = bytes.checked_add(movement.from.name.capacity())?.checked_add(movement.to.name.capacity())?;
        }
        for deletion in &self.deletes { bytes = bytes.checked_add(deletion.edge.name.capacity())?; }
        Some(bytes)
    }
}
fn leaf(name: &str) -> bool {
    !name.is_empty() && name.len() <= 255 && name.is_ascii() && name != "." && name != ".."
        && !name.bytes().any(|byte| byte == 0 || byte == b'\\' || byte == b'/' || byte == b':')
}
// Union order is frozen once; even a currently acyclic ancestry rotation refuses.
fn retirement_order(parents: &[u64; MAX_ROWS], count: usize) -> Result<[usize; MAX_ROWS]> {
    let mut output = [0usize; MAX_ROWS];
    let mut done = 0u64;
    for ordinal in 0..count {
        let row = (0..count).find(|row| done & (1u64 << row) == 0 && parents[*row] & !done == 0)
            .ok_or(Fault::Unsafe)?;
        output[count - 1 - ordinal] = row;
        done |= 1u64 << row;
    }
    Ok(output)
}
fn paths(edges: &[Option<Edge>], base: &str, limit: usize) -> Result<Vec<String>> {
    if edges.is_empty() || edges.len() > MAX_ROWS || edges[0].is_some() { return Err(Fault::State); }
    let mut result = Vec::new();
    result.try_reserve_exact(edges.len()).map_err(|_| Fault::Bounds)?;
    for row in 0..edges.len() {
        let mut chain = [0usize; MAX_ROWS];
        let mut count = 0usize;
        let mut cursor = row;
        let mut length = base.len();
        while let Some(edge) = edges.get(cursor).ok_or(Fault::State)?.as_ref() {
            if count == MAX_ROWS { return Err(Fault::Unsafe); }
            chain[count] = cursor;
            count += 1;
            length = length.checked_add(edge.name.len()).and_then(|n| n.checked_add(1)).ok_or(Fault::Bounds)?;
            cursor = edge.parent;
        }
        if cursor != 0 || length >= limit { return Err(Fault::Bounds); }
        let mut path = String::new();
        path.try_reserve_exact(length).map_err(|_| Fault::Bounds)?;
        path.push_str(base);
        for node in chain[..count].iter().rev() {
            let edge = edges[*node].as_ref().ok_or(Fault::State)?;
            if !path.ends_with('\\') { path.push('\\'); }
            path.push_str(&edge.name);
        }
        if path.len() >= limit { return Err(Fault::Bounds); }
        result.push(path);
    }
    Ok(result)
}
fn edge_bytes(edges: &Vec<Option<Edge>>) -> Option<usize> {
    let mut bytes = edges.capacity().checked_mul(size_of::<Option<Edge>>())?;
    for edge in edges.iter().flatten() { bytes = bytes.checked_add(edge.name.capacity())?; }
    Some(bytes)
}
fn string_bytes(names: &Vec<String>) -> Option<usize> {
    let mut bytes = names.capacity().checked_mul(size_of::<String>())?;
    for name in names { bytes = bytes.checked_add(name.capacity())?; }
    Some(bytes)
}
fn claim_bytes(claims: &Vec<Claim>) -> Option<usize> {
    let mut bytes = claims.capacity().checked_mul(size_of::<Claim>())?;
    for claim in claims { bytes = bytes.checked_add(claim.name.capacity())?; }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn node(parent: Option<usize>, name: &str, directory: bool, movable: bool) -> Node {
        Node { parent, name: name.to_owned(), directory, mutation_parent: directory, movable }
    }
    fn edge(parent: usize, name: &str) -> Edge { Edge { parent, name: name.to_owned() } }
    fn fixture() -> Vec<Node> {
        vec![node(None, "", true, false), node(Some(0), "project", true, false),
            node(Some(1), "journal", true, true), node(Some(2), "stage", true, true),
            node(Some(3), "leaf", false, true), node(Some(1), "destination", true, false)]
    }
    fn moves() -> Vec<Move> {
        vec![Move { row: 3, from: edge(2, "stage"), to: edge(5, "published") },
            Move { row: 3, from: edge(5, "published"), to: edge(2, "stage") }]
    }
    #[test]
    fn moved_parent_updates_unacquired_descendant_and_inverse_keeps_claims() {
        let mut graph = Namespace::new(&fixture(), &moves(), &[], 8192).unwrap();
        graph.bind_volume(r"\Device\HarddiskVolume1").unwrap();
        graph.claim_acquisition(3).unwrap();
        let old = graph.name(4, 0).unwrap().to_owned();
        let mut forward = graph.prepare_move(0).unwrap();
        graph.enter_move(&mut forward).unwrap();
        graph.latch_move(forward);
        assert_eq!(graph.epoch(), 1);
        assert!(graph.name(4, 1).unwrap().ends_with(r"\destination\published\leaf"));
        assert!(graph.claim_acquisition(4).unwrap().ends_with(r"\published\leaf"));
        assert!(graph.name(4, 0).is_err());
        graph.finish_move(0).unwrap();
        let mut inverse = graph.prepare_move(1).unwrap();
        graph.enter_move(&mut inverse).unwrap();
        graph.latch_move(inverse);
        assert_eq!(graph.name(4, 2).unwrap(), old);
        assert!(graph.claim_acquisition(4).is_err());
    }
    #[test]
    fn union_order_keeps_both_parents_after_the_moved_child() {
        let graph = Namespace::new(&fixture(), &moves(), &[], 8192).unwrap();
        let order = graph.retirement();
        let position = |row| order.iter().position(|value| *value == row).unwrap();
        assert!(position(4) < position(3) && position(3) < position(2) && position(3) < position(5));
        assert!(graph.has_live_dependency(5, 1 << 3));
        assert_eq!(graph.dependency_closure(1 << 3) & ((1 << 2) | (1 << 5)), (1 << 2) | (1 << 5));
    }
    #[test]
    fn cycle_rotation_root_duplicate_and_overbound_plans_refuse() {
        let nodes = fixture();
        let cycle = [Move { row: 2, from: edge(1, "journal"), to: edge(3, "cycle") }];
        assert!(Namespace::new(&nodes, &cycle, &[], 8192).is_err());
        let root = [Move { row: 1, from: edge(0, "project"), to: edge(2, "project") }];
        assert!(Namespace::new(&nodes, &root, &[], 8192).is_err());
        let movement = moves()[0].clone();
        assert!(Namespace::new(&nodes, &[movement.clone(), movement.clone()], &[], 8192).is_err());
        assert!(Namespace::new(&nodes, &vec![movement; MAX_MOVES + 1], &[], 8192).is_err());
    }
    #[test]
    fn entered_failure_is_one_use_and_keeps_future_alias_claims() {
        let mut nodes = fixture();
        nodes.push(node(Some(5), "published", true, true));
        let mut graph = Namespace::new(&nodes, &moves(), &[], 8192).unwrap();
        graph.bind_volume(r"\Device\HarddiskVolume1").unwrap();
        graph.claim_acquisition(3).unwrap();
        let mut pending = graph.prepare_move(0).unwrap();
        graph.enter_move(&mut pending).unwrap();
        drop(pending); // a definite failed native attempt would preserve these DATA claims
        assert_eq!(graph.state(0).unwrap(), MoveState::Entered);
        assert_eq!(graph.epoch(), 0);
        assert!(graph.prepare_move(0).is_err());
        assert!(graph.claim_acquisition(6).is_err());
    }
    #[test]
    fn declared_transfer_does_not_mean_reacquisition_or_path_authority() {
        let nodes = vec![node(None, "", true, false), node(Some(0), "project", true, false),
            node(Some(1), "journal", true, true), node(Some(1), "target", false, true),
            node(Some(2), "stage", false, true)];
        let declared = [Move { row: 3, from: edge(1, "target"), to: edge(2, "old-0") },
            Move { row: 4, from: edge(2, "stage"), to: edge(1, "target") }];
        let mut graph = Namespace::new(&nodes, &declared, &[], 8192).unwrap();
        graph.bind_volume(r"\Device\HarddiskVolume1").unwrap();
        graph.claim_acquisition(3).unwrap(); graph.claim_acquisition(4).unwrap();
        for step in 0..2 {
            let mut pending = graph.prepare_move(step).unwrap();
            graph.enter_move(&mut pending).unwrap(); graph.latch_move(pending); graph.finish_move(step).unwrap();
        }
        assert!(graph.name(4, 2).unwrap().ends_with(r"\project\target"));
        assert!(graph.claim_acquisition(3).is_err() && graph.claim_acquisition(4).is_err());
    }
    #[test]
    fn delete_edge_epoch_and_attempt_are_not_acquisition_spelling() {
        let declarations = [Delete { row: 3, edge: edge(5, "published") }];
        let mut graph = Namespace::new(&fixture(), &moves(), &declarations, 8192).unwrap();
        graph.bind_volume(r"\Device\HarddiskVolume1").unwrap();
        graph.claim_acquisition(3).unwrap();
        assert!(graph.enter_delete(0).is_err());
        let mut pending = graph.prepare_move(0).unwrap();
        graph.enter_move(&mut pending).unwrap(); graph.latch_move(pending); graph.finish_move(0).unwrap();
        let epoch = graph.enter_delete(0).unwrap(); graph.latch_epoch(epoch);
        assert_eq!(graph.epoch(), 2);
        assert_eq!(graph.delete_plan(0).unwrap().edge.parent, 5);
        assert!(graph.enter_delete(0).is_err());
    }
    #[test]
    fn prepared_names_and_claim_storage_are_bounded_before_entry() {
        let mut graph = Namespace::new(&fixture(), &moves(), &[], 8192).unwrap();
        graph.bind_volume(r"\Device\HarddiskVolume1").unwrap();
        graph.claim_acquisition(3).unwrap();
        let pending = graph.prepare_move(0).unwrap();
        assert!(graph.heap_bytes().unwrap() > 0 && pending.heap_bytes().unwrap() > 0);
        graph.epoch = u64::MAX;
        assert!(graph.next_epoch().is_err() && graph.prepare_move(0).is_err());
        let mut short = Namespace::new(&fixture(), &moves(), &[], 12).unwrap();
        assert!(short.bind_volume(r"\Device\HarddiskVolume1").is_err());
    }
}
