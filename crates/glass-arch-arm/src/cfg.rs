//! Control-flow graph construction for a single function.
//!
//! Splits a function's bytes at every direct-branch target and after
//! every terminator, yielding a `FunctionCfg` of basic blocks plus
//! edges between them. Calls (`bl`/`blr`) do *not* split blocks —
//! they're attached to their call-site instruction as a `CallSite`
//! so the UI can render call annotations without exploding block
//! count.
//!
//! Layout is a small Sugiyama-ish layered pass: rank each block by
//! BFS distance from the entry over forward edges, then place left
//! to right within each rank. Edge-crossing minimisation is a v2
//! polish item — the data model carries enough information for the
//! caller to swap in a better placer later.

use std::collections::{BTreeMap, HashMap, VecDeque};

use armv8_encode::container::Container;
use armv8_encode::isa::aarch64::{decode_instruction, DecodedInstruction};

use crate::format;
use crate::symbol_map::SymbolMap;

/// Stable identifier for a basic block within a single `FunctionCfg`.
/// Just an index into `FunctionCfg.blocks` — the CFG's block list is
/// stable from construction onward, so referring to blocks by index
/// is safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockId(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockEdgeKind {
    /// Unconditional `B <imm>` (or fall-through to the only successor).
    Unconditional,
    /// `B.cond` / `CBZ` / `CBNZ` / `TBZ` / `TBNZ` taken edge.
    TakenConditional,
    /// The not-taken side of a conditional branch.
    NotTakenConditional,
    /// Implicit edge from a non-branching block to the next address.
    Fallthrough,
}

#[derive(Debug, Clone, Copy)]
pub struct BlockEdge {
    pub from: BlockId,
    pub to: BlockId,
    pub kind: BlockEdgeKind,
}

/// A call instruction inside a basic block. Recorded separately from
/// the block's intra-function edges because calls don't change the
/// flow inside the current function — they're rendered as annotations
/// and (optionally) clickable links to the callee's CFG.
#[derive(Debug, Clone)]
pub struct CallSite {
    /// Address of the `bl` / `blr` instruction.
    pub site_addr: u64,
    /// Resolved call target. `None` for register-indirect calls
    /// (`blr`) where we don't know the target statically.
    pub target_addr: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct InstructionEntry {
    pub address: u64,
    /// Raw 4-byte word, little-endian.
    pub bytes: [u8; 4],
    /// Mnemonic text. Empty when the word didn't decode (kept as
    /// `.word 0x...` for the UI to render).
    pub mnemonic: String,
    /// Comma-separated operand text in display form (registers,
    /// immediates, branch targets — same shape the listing renders).
    /// Empty for instructions with no operands and for undecoded
    /// words (in that case the `.word 0x...` goes in `mnemonic`).
    pub operands: String,
    /// Whether the decoder couldn't make sense of this word.
    pub undecoded: bool,
}

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: BlockId,
    /// Address of the first instruction in the block.
    pub start_addr: u64,
    /// Address one past the last instruction (i.e. start of the next
    /// block, when one follows in memory).
    pub end_addr: u64,
    pub instructions: Vec<InstructionEntry>,
    pub calls: Vec<CallSite>,
    /// True when the block's terminator leaves the function (return,
    /// branch outside the function span, `brk`, etc.). Used by the
    /// renderer to draw an exit stub instead of a successor edge.
    pub exits_function: bool,
}

/// Computed screen-space coordinates for a block. World-space units —
/// the caller (a `Camera`) maps these into pixels.
///
/// `x` and `y` are the top-left corner. Width/height are derived from
/// the block's contents at the renderer's chosen LOD, so layout only
/// commits to *positions*, not sizes.
#[derive(Debug, Clone, Copy)]
pub struct BlockLayout {
    pub block: BlockId,
    pub x: f32,
    pub y: f32,
    /// Rank index (0 = entry rank, larger = deeper). The renderer can
    /// use this for collapsing/expanding sub-ranges.
    pub rank: usize,
}

#[derive(Debug, Clone)]
pub struct FunctionCfg {
    pub entry_addr: u64,
    pub end_addr: u64,
    pub blocks: Vec<BasicBlock>,
    pub edges: Vec<BlockEdge>,
    pub layout: Vec<BlockLayout>,
}

/// Build a CFG for the function whose entry point is `entry_addr`.
///
/// The function's extent is taken from the symbol map: prefer the
/// covering symbol's `size`. When `size == 0` (common on stripped
/// binaries), walk to the next symbol address as a fallback. Returns
/// `None` when `entry_addr` doesn't fall inside any code section.
pub fn build_function_cfg(
    container: &Container,
    symbols: &SymbolMap,
    entry_addr: u64,
) -> Option<FunctionCfg> {
    use armv8_encode::container::{Architecture, SectionKind};

    // ARMv7 path: defer to the upstream recursive-descent
    // disassembler and the neutral `mc::build_cfg` builder.
    if matches!(container.architecture, Architecture::Arm) {
        return build_function_cfg_armv7(container, symbols, entry_addr);
    }

    // x86/x86_64 path: linear-sweep decode the function's byte range,
    // then feed the instructions through the same neutral insns->CFG
    // builder the ARMv7 path uses (it operates purely through the
    // `InstructionInfo` trait, so it is ISA-agnostic). The `& !1`
    // mode-bit mask inside that builder is a no-op for x86's even
    // entry addresses.
    if matches!(
        container.architecture,
        Architecture::X86_64 | Architecture::X86
    ) {
        return build_function_cfg_x86(container, symbols, entry_addr);
    }

    // Locate the text section containing `entry_addr`.
    let text_sec = container
        .sections
        .iter()
        .find(|s| {
            matches!(s.kind, SectionKind::Text)
                && entry_addr >= s.address
                && entry_addr < s.address.saturating_add(s.size)
        })?;
    build_function_cfg_from_bytes(
        text_sec.address,
        &text_sec.bytes,
        symbols,
        entry_addr,
    )
}

/// x86/x86_64-specific CFG construction. Linear-sweeps the function's
/// byte range — clamped to the covering symbol's extent (or the next
/// symbol / section end when the size is unknown), mirroring the
/// AArch64 byte path — then reuses the neutral insns->CFG builder.
fn build_function_cfg_x86(
    container: &Container,
    symbols: &SymbolMap,
    entry_addr: u64,
) -> Option<FunctionCfg> {
    use armv8_encode::container::SectionKind;

    let text_sec = container.sections.iter().find(|s| {
        matches!(s.kind, SectionKind::Text)
            && entry_addr >= s.address
            && entry_addr < s.address.saturating_add(s.size)
    })?;
    let section_end = text_sec.address.saturating_add(text_sec.size);

    // Function extent: covering symbol size, else next symbol address,
    // else section end — always clamped to the section end.
    let end_addr = {
        let from_sym = symbols.covering(entry_addr).and_then(|s| {
            if s.size > 0 {
                Some(s.address + s.size)
            } else {
                None
            }
        });
        let from_next = symbols
            .iter()
            .filter(|s| s.address > entry_addr)
            .map(|s| s.address)
            .min();
        from_sym.or(from_next).unwrap_or(section_end).min(section_end)
    };
    if end_addr <= entry_addr {
        return None;
    }

    // Sweep the whole reachable tail, then trim to the function extent.
    let mut insns = crate::disasm::disassemble_function_at(container, entry_addr)?;
    insns.retain(|i| {
        use armv8_encode::mc::InstructionInfo;
        i.address() < end_addr
    });
    build_function_cfg_armv7_from_insns(&insns, entry_addr)
}

/// ARMv7-specific CFG construction. Reuses the upstream
/// recursive-descent disassembler to obtain a `Vec<DecodedInsn>`
/// covering the function, then feeds that into the architecture-
/// neutral `armv8_encode::mc::build_cfg` and projects the resulting
/// generic graph into Glass's `FunctionCfg` shape.
fn build_function_cfg_armv7(
    container: &Container,
    _symbols: &SymbolMap,
    entry_addr: u64,
) -> Option<FunctionCfg> {
    let insns = crate::disasm::disassemble_function_at(container, entry_addr)?;
    build_function_cfg_armv7_from_insns(&insns, entry_addr)
}

/// Construct an ARMv7 CFG from a pre-computed `Vec<DecodedInsn>`
/// covering the function. Used by the GUI, which already holds the
/// recursive-descent result on `TextSectionBytes::precomputed` and
/// doesn't carry a full `Container`. Pass the slice of instructions
/// for the function in source order (e.g. obtained by trimming the
/// section's precomputed vector to the symbol's extent); `entry_addr`
/// is the function entry point (with or without the Thumb mode-bit
/// — the function masks it off internally).
pub fn build_function_cfg_armv7_from_insns(
    insns: &[crate::DecodedInsn],
    entry_addr: u64,
) -> Option<FunctionCfg> {
    use armv8_encode::mc::{self, EdgeKind as McEdgeKind, EdgeTarget, InstructionInfo};

    if insns.is_empty() {
        return None;
    }
    let real_entry = entry_addr & !1u64;
    let last = insns.last()?;
    let end_addr = last.address() + last.size();

    let mc_cfg = mc::build_cfg(insns);
    // Map from upstream BlockId to Glass BlockId (same index).
    let mut blocks: Vec<BasicBlock> = Vec::with_capacity(mc_cfg.blocks.len());
    for b in &mc_cfg.blocks {
        let mut entries = Vec::with_capacity(b.instructions.end - b.instructions.start);
        let mut calls = Vec::new();
        for idx in b.instructions.clone() {
            let insn = &insns[idx];
            let raw = insn.raw_bytes();
            let mut bytes4 = [0u8; 4];
            let copy_len = raw.len().min(4);
            bytes4[..copy_len].copy_from_slice(&raw[..copy_len]);
            let line = insn.format_text();
            let (mnemonic, operands) = match line.split_once(' ') {
                Some((m, rest)) => (m.to_string(), rest.to_string()),
                None => (line, String::new()),
            };
            entries.push(InstructionEntry {
                address: insn.address(),
                bytes: bytes4,
                mnemonic,
                operands,
                undecoded: false,
            });
            // Recognise calls so the UI's call-site annotations
            // continue to work.
            match insn.control_flow() {
                armv8_encode::mc::ControlFlow::Call { target, .. } => {
                    calls.push(CallSite {
                        site_addr: insn.address(),
                        target_addr: Some(target),
                    });
                }
                armv8_encode::mc::ControlFlow::IndirectCall { .. } => {
                    calls.push(CallSite {
                        site_addr: insn.address(),
                        target_addr: None,
                    });
                }
                _ => {}
            }
        }
        let exits = b.successors.is_empty();
        blocks.push(BasicBlock {
            id: BlockId(b.id.0),
            start_addr: b.start,
            end_addr: b.end,
            instructions: entries,
            calls,
            exits_function: exits,
        });
    }

    let mut edges: Vec<BlockEdge> = Vec::new();
    for b in &mc_cfg.blocks {
        for e in &b.successors {
            let to = match e.target {
                EdgeTarget::Block(id) => BlockId(id.0),
                _ => continue, // skip indirect / external for now
            };
            let kind = match e.kind {
                McEdgeKind::Fallthrough => BlockEdgeKind::Fallthrough,
                McEdgeKind::Jump => BlockEdgeKind::Unconditional,
                McEdgeKind::BranchTaken => BlockEdgeKind::TakenConditional,
                McEdgeKind::Call => continue, // Calls handled via CallSite annotations
            };
            edges.push(BlockEdge {
                from: BlockId(b.id.0),
                to,
                kind,
            });
        }
    }

    let layout = compute_layered_layout(&blocks, &edges);
    Some(FunctionCfg {
        entry_addr: real_entry,
        end_addr,
        blocks,
        edges,
        layout,
    })
}

/// Same as `build_function_cfg` but works against pre-extracted
/// section bytes. Used by the UI, which keeps text-section bytes on
/// `LoadedBundle` rather than holding the full `Container` after
/// load.
pub fn build_function_cfg_from_bytes(
    section_base: u64,
    section_bytes: &[u8],
    symbols: &SymbolMap,
    entry_addr: u64,
) -> Option<FunctionCfg> {
    // arm64 function entries are always 4-byte aligned. Reject misaligned
    // entries early so callers (notably random-scan probes) don't get
    // garbage decoded.
    if entry_addr % 4 != 0 {
        return None;
    }
    if entry_addr < section_base {
        return None;
    }
    let section_end = section_base + section_bytes.len() as u64;
    if entry_addr >= section_end {
        return None;
    }
    let section_start = section_base;
    // Bind the existing variable name used downstream.
    #[allow(non_snake_case)]
    let text_sec_bytes = section_bytes;

    // Function extent. Prefer the covering symbol's declared size;
    // fall back to the next symbol's address; fall back to the
    // section end. Always clamp to the section end so we never read
    // out of bounds.
    let end_addr = {
        let from_sym = symbols.covering(entry_addr).and_then(|s| {
            if s.size > 0 {
                Some(s.address + s.size)
            } else {
                None
            }
        });
        let from_next = symbols
            .iter()
            .filter(|s| s.address > entry_addr)
            .map(|s| s.address)
            .min();
        from_sym
            .or(from_next)
            .unwrap_or(section_end)
            .min(section_end)
    };
    if end_addr <= entry_addr {
        return None;
    }

    // Decode every instruction in the function. We need decoded info
    // for branch targets and terminator detection; cache decode
    // results so block construction doesn't re-decode.
    let bytes_offset = (entry_addr - section_start) as usize;
    let bytes_len = (end_addr - entry_addr) as usize;
    let func_bytes = &text_sec_bytes[bytes_offset..bytes_offset + bytes_len];
    let mut decoded: Vec<(u64, [u8; 4], Option<DecodedInstruction>)> =
        Vec::with_capacity(bytes_len / 4);
    for (i, chunk) in func_bytes.chunks_exact(4).enumerate() {
        let addr = entry_addr + (i as u64) * 4;
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let bytes = [chunk[0], chunk[1], chunk[2], chunk[3]];
        decoded.push((addr, bytes, decode_instruction(addr, word).ok()));
    }
    if decoded.is_empty() {
        return None;
    }

    // ---- Phase 1: collect block-boundary addresses --------------------
    //
    // A boundary sits at: the entry address, every direct-branch target
    // inside the function, and the address immediately after every
    // terminator. We keep them in a BTreeSet so they're sorted +
    // deduplicated for free.
    use std::collections::BTreeSet;
    let mut boundaries: BTreeSet<u64> = BTreeSet::new();
    boundaries.insert(entry_addr);
    for (addr, _bytes, insn) in &decoded {
        let Some(insn) = insn.as_ref() else { continue };
        // Calls (BL/BLR) are *not* terminators in the CFG sense —
        // control returns to the next instruction. Don't split blocks
        // at calls; they're recorded on the call-site instruction
        // instead.
        if format::is_call(insn.mnemonic) {
            continue;
        }
        if format::is_terminator(insn.mnemonic) {
            let next = addr + 4;
            if next < end_addr {
                boundaries.insert(next);
            }
        }
        // Direct-branch and conditional-branch targets that land inside
        // the function are block boundaries.
        let is_direct_branch = format::is_unconditional_direct_branch(insn.mnemonic)
            || format::is_conditional_branch(insn.mnemonic);
        if !is_direct_branch {
            continue;
        }
        let Some(target) = format::primary_address_operand(insn) else { continue };
        if target >= entry_addr && target < end_addr {
            boundaries.insert(target);
        }
    }
    let boundary_list: Vec<u64> = boundaries.into_iter().collect();

    // ---- Phase 2: build blocks ----------------------------------------
    //
    // Walk the function instruction-by-instruction; whenever we hit a
    // boundary, close out the previous block and start a new one. The
    // block ends at the next boundary or at the function's end.
    let mut blocks: Vec<BasicBlock> = Vec::with_capacity(boundary_list.len());
    let mut addr_to_block: HashMap<u64, BlockId> = HashMap::new();
    let mut boundary_iter = boundary_list.iter().peekable();
    let mut current_start = *boundary_iter.next()?; // entry_addr by construction
    let mut current = BasicBlock {
        id: BlockId(0),
        start_addr: current_start,
        end_addr: current_start, // updated as we go
        instructions: Vec::new(),
        calls: Vec::new(),
        exits_function: false,
    };
    addr_to_block.insert(current_start, BlockId(0));

    for (addr, bytes, insn) in &decoded {
        let addr = *addr;
        // Is this address the start of a new block (and not the very
        // first instruction)? Close the current block first.
        if addr != current_start && boundary_iter.peek().map(|&&b| b == addr).unwrap_or(false) {
            current.end_addr = addr;
            let new_id = BlockId(blocks.len() + 1);
            let next = BasicBlock {
                id: new_id,
                start_addr: addr,
                end_addr: addr,
                instructions: Vec::new(),
                calls: Vec::new(),
                exits_function: false,
            };
            blocks.push(std::mem::replace(&mut current, next));
            addr_to_block.insert(addr, new_id);
            current_start = addr;
            boundary_iter.next();
        }

        // Append this instruction.
        let (mnemonic, operands, undecoded) = match insn.as_ref() {
            Some(i) => {
                let mnem = format::mnemonic_chunk(i).text;
                let ops_text: String = format::operands_chunks(i)
                    .into_iter()
                    .map(|c| c.text)
                    .collect();
                (mnem, ops_text, false)
            }
            None => {
                let word = u32::from_le_bytes(*bytes);
                (format!(".word 0x{word:08x}"), String::new(), true)
            }
        };
        current.instructions.push(InstructionEntry {
            address: addr,
            bytes: *bytes,
            mnemonic,
            operands,
            undecoded,
        });

        // Calls are recorded inline, not as edges.
        if let Some(insn) = insn.as_ref() {
            if format::is_call(insn.mnemonic) {
                let target = format::primary_address_operand(insn);
                current.calls.push(CallSite {
                    site_addr: addr,
                    target_addr: target,
                });
            }
        }
    }
    // Close the last block.
    current.end_addr = end_addr;
    blocks.push(current);

    // Default for empty/all-undecoded blocks: mark as exit. The edge
    // pass below upgrades the marker once it inspects terminators.
    for block in &mut blocks {
        if block.instructions.is_empty() {
            block.exits_function = true;
        }
    }

    // ---- Phase 3: build edges -----------------------------------------
    let mut edges: Vec<BlockEdge> = Vec::new();
    // Build a lookup once: address -> decoded insn (used for the last
    // instruction of each block).
    let decoded_by_addr: BTreeMap<u64, &Option<DecodedInstruction>> =
        decoded.iter().map(|(a, _b, i)| (*a, i)).collect();

    let block_count = blocks.len();
    for i in 0..block_count {
        let block_id = blocks[i].id;
        let last_addr = match blocks[i].instructions.last() {
            Some(last) => last.address,
            None => continue,
        };
        let last_insn = decoded_by_addr.get(&last_addr).and_then(|d| d.as_ref());

        let fallthrough_block = if i + 1 < block_count {
            Some(blocks[i + 1].id)
        } else {
            None
        };

        let Some(insn) = last_insn else {
            // Undecoded tail — treat as a fallthrough if there's a
            // next block, else mark as exit.
            if let Some(next) = fallthrough_block {
                edges.push(BlockEdge {
                    from: block_id,
                    to: next,
                    kind: BlockEdgeKind::Fallthrough,
                });
            } else {
                blocks[i].exits_function = true;
            }
            continue;
        };

        let target = format::primary_address_operand(insn);
        let target_in_func = target
            .map(|t| t >= entry_addr && t < end_addr)
            .unwrap_or(false);

        if format::is_unconditional_direct_branch(insn.mnemonic) {
            if target_in_func {
                let target_id = addr_to_block[&target.unwrap()];
                edges.push(BlockEdge {
                    from: block_id,
                    to: target_id,
                    kind: BlockEdgeKind::Unconditional,
                });
            } else {
                blocks[i].exits_function = true;
            }
        } else if format::is_conditional_branch(insn.mnemonic) {
            if target_in_func {
                let target_id = addr_to_block[&target.unwrap()];
                edges.push(BlockEdge {
                    from: block_id,
                    to: target_id,
                    kind: BlockEdgeKind::TakenConditional,
                });
            }
            if let Some(next) = fallthrough_block {
                edges.push(BlockEdge {
                    from: block_id,
                    to: next,
                    kind: BlockEdgeKind::NotTakenConditional,
                });
            }
            // Conditional that leaves the function on the taken side
            // is still rendered as a partial exit; the not-taken edge
            // covers the fallthrough.
            if !target_in_func {
                blocks[i].exits_function = true;
            }
        } else if format::is_call(insn.mnemonic) {
            // Calls return to the next address; treat as fall-through.
            if let Some(next) = fallthrough_block {
                edges.push(BlockEdge {
                    from: block_id,
                    to: next,
                    kind: BlockEdgeKind::Fallthrough,
                });
            }
        } else if format::is_terminator(insn.mnemonic) {
            // Anything else terminator-shaped (RET, BR, BRK, …): the
            // function exits here.
            blocks[i].exits_function = true;
        } else {
            // Non-terminator: implicit fall-through.
            if let Some(next) = fallthrough_block {
                edges.push(BlockEdge {
                    from: block_id,
                    to: next,
                    kind: BlockEdgeKind::Fallthrough,
                });
            }
        }
    }

    // ---- Phase 4: layered layout --------------------------------------
    let layout = compute_layered_layout(&blocks, &edges);

    Some(FunctionCfg {
        entry_addr,
        end_addr,
        blocks,
        edges,
        layout,
    })
}

/// Sugiyama-ish layered layout. Rank each block by BFS distance from
/// the entry; within each rank, place blocks left-to-right in the
/// stable order they were discovered.
///
/// World units: rank height is 1.0, intra-rank stride is 1.0. The
/// renderer scales these into pixels via the camera so the same
/// layout works at every zoom.
fn compute_layered_layout(
    blocks: &[BasicBlock],
    edges: &[BlockEdge],
) -> Vec<BlockLayout> {
    if blocks.is_empty() {
        return Vec::new();
    }
    // Build the successor adjacency list, but exclude back-edges from
    // ranking (heuristic: a successor whose id ≤ predecessor's id is
    // most likely a loop back-edge in the discovery order).
    let mut succ: Vec<Vec<BlockId>> = vec![Vec::new(); blocks.len()];
    for e in edges {
        if e.to.0 > e.from.0 {
            succ[e.from.0].push(e.to);
        }
    }
    // BFS from block 0 (entry).
    let mut rank: Vec<Option<usize>> = vec![None; blocks.len()];
    let mut queue: VecDeque<BlockId> = VecDeque::new();
    rank[0] = Some(0);
    queue.push_back(BlockId(0));
    while let Some(BlockId(i)) = queue.pop_front() {
        let r = rank[i].unwrap();
        for &BlockId(j) in &succ[i] {
            // Take the longest path so blocks land below all of their
            // predecessors (better-looking layout than shortest path).
            let new = r + 1;
            if rank[j].map(|prev| new > prev).unwrap_or(true) {
                rank[j] = Some(new);
                queue.push_back(BlockId(j));
            }
        }
    }
    // Any block we didn't reach (back-edge-only successors): place at
    // the lowest rank we've seen, +1, so it still appears.
    let max_rank = rank.iter().filter_map(|r| *r).max().unwrap_or(0);
    for r in rank.iter_mut() {
        if r.is_none() {
            *r = Some(max_rank + 1);
        }
    }

    // Group blocks by rank, preserving discovery order within a rank.
    let mut by_rank: BTreeMap<usize, Vec<BlockId>> = BTreeMap::new();
    for (i, r) in rank.iter().enumerate() {
        by_rank.entry(r.unwrap()).or_default().push(BlockId(i));
    }
    let ranks: Vec<usize> = by_rank.keys().copied().collect();

    // Bidirectional adjacency for cross-rank edges. We use these in
    // the barycenter passes below to pick the position for each
    // block as the average of its neighbours in the adjacent rank.
    let mut preds: Vec<Vec<BlockId>> = vec![Vec::new(); blocks.len()];
    let mut succs: Vec<Vec<BlockId>> = vec![Vec::new(); blocks.len()];
    // Per-parent "primary child" — the child this parent prefers to
    // sit directly under, eliminating an elbow on that edge. Pick
    // the unconditional / fallthrough successor when one exists
    // (the implicit straight-line flow), else the first cross-rank
    // successor in discovery order. Each block can therefore be a
    // primary-child of at most one parent.
    let mut primary_child: Vec<Option<BlockId>> = vec![None; blocks.len()];
    // Same-rank edges aren't used for primary-child / rank-ordering
    // — but we still want them to *attract* their endpoints in the
    // relaxation phase, so jump-table-style functions (where all
    // cases sit at the same rank) get some structure rather than
    // being spread out as a uniform row.
    let mut same_rank_neighbours: Vec<Vec<BlockId>> = vec![Vec::new(); blocks.len()];
    for e in edges {
        let r_from = rank[e.from.0].unwrap_or(0);
        let r_to = rank[e.to.0].unwrap_or(0);
        if r_to > r_from {
            preds[e.to.0].push(e.from);
            succs[e.from.0].push(e.to);
            // Primary child = the linearly-sequential continuation
            // of this block. For a conditional branch (`B.cond`,
            // `CBZ`, etc.) that's the *not-taken* edge — control
            // falls through to the next address. For unconditional
            // branches and plain fall-throughs the only edge IS the
            // primary one. The taken side of a conditional is the
            // off-spine branch and gets the elbow.
            let is_primary = matches!(
                e.kind,
                BlockEdgeKind::Unconditional
                    | BlockEdgeKind::Fallthrough
                    | BlockEdgeKind::NotTakenConditional
            );
            if is_primary {
                // A primary edge always wins, even if we previously
                // marked a non-primary edge as the placeholder.
                primary_child[e.from.0] = Some(e.to);
            } else if primary_child[e.from.0].is_none() {
                primary_child[e.from.0] = Some(e.to);
            }
        } else if r_to == r_from && e.to.0 != e.from.0 {
            // Same-rank attraction goes both ways.
            same_rank_neighbours[e.to.0].push(e.from);
            same_rank_neighbours[e.from.0].push(e.to);
        }
    }
    // A block is a "primary child" of its parent when it's the
    // marked primary_child target. We use this in the fine-tune
    // pass to give those blocks the parent's exact x.
    let mut is_primary_of: Vec<Option<BlockId>> = vec![None; blocks.len()];
    for (parent_idx, child) in primary_child.iter().enumerate() {
        if let Some(c) = child {
            is_primary_of[c.0] = Some(BlockId(parent_idx));
        }
    }

    // Initial position of each block within its rank — start with
    // the discovery order so the first iteration has something to
    // sort against. Stored as the block's index within
    // `by_rank[rank]` so barycenter averaging is dimensionless.
    let mut pos: Vec<usize> = vec![0; blocks.len()];
    for ids in by_rank.values() {
        for (i, &BlockId(id)) in ids.iter().enumerate() {
            pos[id] = i;
        }
    }

    // Barycenter sweeps: top-down then bottom-up, repeating until
    // the order stabilises or a small iteration cap is reached.
    // Each pass reorders blocks within a rank by the average
    // position of their neighbours in the adjacent rank. This is
    // the standard Sugiyama crossing-reduction heuristic — cheap
    // and good enough in practice.
    let avg_position = |of_ids: &[BlockId], pos: &[usize]| -> f32 {
        if of_ids.is_empty() {
            return f32::INFINITY;
        }
        let sum: f32 = of_ids.iter().map(|b| pos[b.0] as f32).sum();
        sum / of_ids.len() as f32
    };
    for _ in 0..8 {
        let mut changed = false;
        // Top-down: each rank ordered by predecessor positions.
        for &r in ranks.iter().skip(1) {
            if let Some(ids) = by_rank.get_mut(&r) {
                let mut keyed: Vec<(f32, BlockId)> = ids
                    .iter()
                    .map(|&b| (avg_position(&preds[b.0], &pos), b))
                    .collect();
                keyed.sort_by(|a, b| {
                    a.0
                        .partial_cmp(&b.0)
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| a.1 .0.cmp(&b.1 .0))
                });
                let new_ids: Vec<BlockId> = keyed.iter().map(|(_, b)| *b).collect();
                if &new_ids != ids {
                    changed = true;
                    *ids = new_ids;
                    for (i, &BlockId(id)) in ids.iter().enumerate() {
                        pos[id] = i;
                    }
                }
            }
        }
        // Bottom-up: each rank ordered by successor positions.
        for &r in ranks.iter().rev().skip(1) {
            if let Some(ids) = by_rank.get_mut(&r) {
                let mut keyed: Vec<(f32, BlockId)> = ids
                    .iter()
                    .map(|&b| (avg_position(&succs[b.0], &pos), b))
                    .collect();
                keyed.sort_by(|a, b| {
                    a.0
                        .partial_cmp(&b.0)
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| a.1 .0.cmp(&b.1 .0))
                });
                let new_ids: Vec<BlockId> = keyed.iter().map(|(_, b)| *b).collect();
                if &new_ids != ids {
                    changed = true;
                    *ids = new_ids;
                    for (i, &BlockId(id)) in ids.iter().enumerate() {
                        pos[id] = i;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }

    // Fine-tune x positions so each block lines up with the average
    // of its predecessors (or successors when no preds in adjacent
    // ranks). Then enforce a minimum gap between consecutive blocks
    // in each rank so they don't overlap. Centre each rank on x = 0.
    //
    // This gives single-predecessor blocks a perfectly-aligned x,
    // turning the parent→child edge into a single vertical with no
    // elbows.
    const MIN_GAP: f32 = 1.0; // world units between consecutive block centres
    let mut block_x: Vec<f32> = vec![0.; blocks.len()];
    // Seed the entry rank with even spacing.
    if let Some(first_rank) = ranks.first() {
        if let Some(ids) = by_rank.get(first_rank) {
            let count = ids.len() as f32;
            let start_x = -((count - 1.0) / 2.0) * MIN_GAP;
            for (i, &BlockId(id)) in ids.iter().enumerate() {
                block_x[id] = start_x + i as f32 * MIN_GAP;
            }
        }
    }
    // Top-down pass: each block's x = average of its predecessors' x,
    // *except* when it's the primary child of some parent — then it
    // sits at exactly that parent's x so the edge has no elbow.
    for &r in ranks.iter().skip(1) {
        if let Some(ids) = by_rank.get(&r) {
            let mut prefs: Vec<(f32, BlockId)> = ids
                .iter()
                .map(|&b| {
                    let p = &preds[b.0];
                    let x = if let Some(parent) = is_primary_of[b.0] {
                        // Inherit the parent's x exactly.
                        block_x[parent.0]
                    } else if p.is_empty() {
                        let idx = ids.iter().position(|&x| x == b).unwrap_or(0);
                        (idx as f32 - (ids.len() as f32 - 1.) / 2.) * MIN_GAP
                    } else {
                        let sum: f32 = p.iter().map(|b| block_x[b.0]).sum();
                        sum / p.len() as f32
                    };
                    (x, b)
                })
                .collect();
            // Preserve the rank's existing order (already barycenter-
            // sorted) by sorting prefs by current ordering position
            // instead of by preferred x — then we enforce non-
            // overlap left-to-right.
            prefs.sort_by_key(|(_, b)| {
                ids.iter().position(|&x| x == *b).unwrap_or(0)
            });
            // Enforce monotonic non-decreasing x with at least
            // MIN_GAP between centres.
            for i in 1..prefs.len() {
                if prefs[i].0 < prefs[i - 1].0 + MIN_GAP {
                    prefs[i].0 = prefs[i - 1].0 + MIN_GAP;
                }
            }
            // Centre the rank.
            let lo = prefs.first().map(|(x, _)| *x).unwrap_or(0.);
            let hi = prefs.last().map(|(x, _)| *x).unwrap_or(0.);
            let shift = -(lo + hi) / 2.;
            for (x, BlockId(id)) in prefs {
                block_x[id] = x + shift;
            }
        }
    }
    // Bottom-up pass: pull each block toward its primary child's x
    // (so the parent-primary-child edge has no elbow), else average
    // with all successors.
    for &r in ranks.iter().rev().skip(1) {
        if let Some(ids) = by_rank.get(&r) {
            let mut prefs: Vec<(f32, BlockId)> = ids
                .iter()
                .map(|&b| {
                    let s = &succs[b.0];
                    let x = if let Some(pc) = primary_child[b.0] {
                        // Align with the primary child's x exactly.
                        block_x[pc.0]
                    } else if s.is_empty() {
                        block_x[b.0]
                    } else {
                        let avg: f32 =
                            s.iter().map(|b| block_x[b.0]).sum::<f32>() / s.len() as f32;
                        (avg + block_x[b.0]) / 2.
                    };
                    (x, b)
                })
                .collect();
            prefs.sort_by_key(|(_, b)| {
                ids.iter().position(|&x| x == *b).unwrap_or(0)
            });
            for i in 1..prefs.len() {
                if prefs[i].0 < prefs[i - 1].0 + MIN_GAP {
                    prefs[i].0 = prefs[i - 1].0 + MIN_GAP;
                }
            }
            let lo = prefs.first().map(|(x, _)| *x).unwrap_or(0.);
            let hi = prefs.last().map(|(x, _)| *x).unwrap_or(0.);
            let shift = -(lo + hi) / 2.;
            for (x, BlockId(id)) in prefs {
                block_x[id] = x + shift;
            }
        }
    }

    // ---- Gauss-Seidel relaxation -----------------------------------
    //
    // The top-down / bottom-up passes give each block a sensible x
    // *given its current parent's / child's x*, but neither pass
    // sees the whole graph at once. Relaxation drives toward a
    // global minimum of `Σ (a.x - b.x)²` over every cross-rank edge
    // — the natural energy function for elbow length. Each iteration
    // sets every block's x to the weighted mean of its neighbours,
    // then enforces non-overlap per rank.
    //
    // Primary edges (the chosen straight-line flow from each fork)
    // get a higher weight so they don't get pulled away by ordinary
    // edges. Convergence is fast in practice — small functions
    // settle in 4-5 passes, large ones in 10-15.
    const PRIMARY_WEIGHT: f32 = 4.0;
    const NORMAL_WEIGHT: f32 = 1.0;
    for _iter in 0..16 {
        let mut max_move = 0.0_f32;
        // Compute new x's into a buffer then commit — so within a
        // single iteration each block sees the previous iteration's
        // positions for all neighbours (the standard Jacobi step;
        // Gauss-Seidel would use the freshest in-iteration values,
        // but Jacobi is more stable for this).
        let mut new_x = block_x.clone();
        for (b_idx, _block) in blocks.iter().enumerate() {
            let bid = BlockId(b_idx);
            let mut sum = 0.0_f32;
            let mut weight = 0.0_f32;
            // Predecessors.
            for &p in &preds[b_idx] {
                let w = if is_primary_of[b_idx] == Some(p) {
                    PRIMARY_WEIGHT
                } else {
                    NORMAL_WEIGHT
                };
                sum += w * block_x[p.0];
                weight += w;
            }
            // Successors.
            for &s in &succs[b_idx] {
                let w = if primary_child[b_idx] == Some(s) {
                    PRIMARY_WEIGHT
                } else {
                    NORMAL_WEIGHT
                };
                sum += w * block_x[s.0];
                weight += w;
            }
            // Same-rank neighbours pull this block toward the
            // x of its peer (one block apart in the same rank
            // ideally sits next to the other along the natural
            // flow). Light weight so it can't override real
            // parent/child alignment.
            const SAME_RANK_WEIGHT: f32 = 0.5;
            for &n in &same_rank_neighbours[b_idx] {
                sum += SAME_RANK_WEIGHT * block_x[n.0];
                weight += SAME_RANK_WEIGHT;
            }
            if weight > 0. {
                new_x[b_idx] = sum / weight;
            }
            let _ = bid;
        }
        // Enforce non-overlap per rank *preserving the existing
        // left-to-right ordering*. We do NOT sort by `new_x` here:
        // doing that would let the relaxation re-order blocks
        // within a rank, which causes edges that used to be parallel
        // to cross. The barycenter sweeps already chose the
        // crossing-minimising order; the relaxation only refines
        // positions, never permutes them.
        for ids in by_rank.values() {
            let mut ordered: Vec<(f32, BlockId)> =
                ids.iter().map(|&b| (new_x[b.0], b)).collect();
            // `ids` is already in the barycenter-chosen left-to-
            // right order, so iterate it directly.
            for i in 1..ordered.len() {
                if ordered[i].0 < ordered[i - 1].0 + MIN_GAP {
                    ordered[i].0 = ordered[i - 1].0 + MIN_GAP;
                }
            }
            // Recentre the rank on x = 0.
            let lo = ordered.first().map(|(x, _)| *x).unwrap_or(0.);
            let hi = ordered.last().map(|(x, _)| *x).unwrap_or(0.);
            let shift = -(lo + hi) / 2.;
            for (x, BlockId(id)) in ordered {
                let final_x = x + shift;
                max_move = max_move.max((final_x - block_x[id]).abs());
                new_x[id] = final_x;
            }
        }
        block_x = new_x;
        // Early exit when the iteration moved nothing meaningful.
        if max_move < 0.01 {
            break;
        }
    }

    let mut layout = Vec::with_capacity(blocks.len());
    for (r, ids) in by_rank {
        for id in ids {
            layout.push(BlockLayout {
                block: id,
                x: block_x[id.0],
                y: r as f32,
                rank: r,
            });
        }
    }
    layout.sort_by_key(|l| l.block.0);
    layout
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests use the public `build_function_cfg` against a synthetic
    // text section. We can't easily build a real Container in unit
    // scope without dragging in armv8-encode's writer machinery, so
    // we exercise the smaller helpers and the layout pass directly.

    #[test]
    fn layout_places_entry_at_top() {
        let blocks = vec![
            BasicBlock {
                id: BlockId(0),
                start_addr: 0,
                end_addr: 4,
                instructions: vec![],
                calls: vec![],
                exits_function: false,
            },
            BasicBlock {
                id: BlockId(1),
                start_addr: 4,
                end_addr: 8,
                instructions: vec![],
                calls: vec![],
                exits_function: true,
            },
        ];
        let edges = vec![BlockEdge {
            from: BlockId(0),
            to: BlockId(1),
            kind: BlockEdgeKind::Unconditional,
        }];
        let layout = compute_layered_layout(&blocks, &edges);
        assert_eq!(layout.len(), 2);
        assert_eq!(layout[0].rank, 0);
        assert_eq!(layout[1].rank, 1);
        assert!(layout[1].y > layout[0].y);
    }

    #[test]
    fn layout_handles_diamond() {
        // 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3.
        let blocks: Vec<BasicBlock> = (0..4)
            .map(|i| BasicBlock {
                id: BlockId(i),
                start_addr: (i as u64) * 4,
                end_addr: (i as u64 + 1) * 4,
                instructions: vec![],
                calls: vec![],
                exits_function: false,
            })
            .collect();
        let edges = vec![
            BlockEdge {
                from: BlockId(0),
                to: BlockId(1),
                kind: BlockEdgeKind::TakenConditional,
            },
            BlockEdge {
                from: BlockId(0),
                to: BlockId(2),
                kind: BlockEdgeKind::NotTakenConditional,
            },
            BlockEdge {
                from: BlockId(1),
                to: BlockId(3),
                kind: BlockEdgeKind::Unconditional,
            },
            BlockEdge {
                from: BlockId(2),
                to: BlockId(3),
                kind: BlockEdgeKind::Unconditional,
            },
        ];
        let layout = compute_layered_layout(&blocks, &edges);
        // 0 at rank 0, 1 and 2 at rank 1, 3 at rank 2.
        assert_eq!(layout[0].rank, 0);
        assert_eq!(layout[1].rank, 1);
        assert_eq!(layout[2].rank, 1);
        assert_eq!(layout[3].rank, 2);
        // 1 and 2 should sit on either side of x = 0.
        assert!(layout[1].x < layout[2].x);
    }

    #[test]
    fn layout_handles_back_edge() {
        // Simple loop: 0 -> 1 -> 2 -> 1 (back-edge).
        let blocks: Vec<BasicBlock> = (0..3)
            .map(|i| BasicBlock {
                id: BlockId(i),
                start_addr: (i as u64) * 4,
                end_addr: (i as u64 + 1) * 4,
                instructions: vec![],
                calls: vec![],
                exits_function: false,
            })
            .collect();
        let edges = vec![
            BlockEdge {
                from: BlockId(0),
                to: BlockId(1),
                kind: BlockEdgeKind::Fallthrough,
            },
            BlockEdge {
                from: BlockId(1),
                to: BlockId(2),
                kind: BlockEdgeKind::NotTakenConditional,
            },
            BlockEdge {
                from: BlockId(2),
                to: BlockId(1),
                kind: BlockEdgeKind::TakenConditional,
            },
        ];
        let layout = compute_layered_layout(&blocks, &edges);
        // Back-edge is excluded from ranking so 1 ends up at rank 1
        // and 2 at rank 2. Without that exclusion 1 would oscillate
        // back to rank 3 forever.
        assert_eq!(layout[0].rank, 0);
        assert_eq!(layout[1].rank, 1);
        assert_eq!(layout[2].rank, 2);
    }
}
