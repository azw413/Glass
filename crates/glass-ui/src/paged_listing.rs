//! Paged row cache for the disassembly listing view.
//!
//! Same shape as `paged_hex`: divide the section into fixed-instruction
//! pages, build them on demand, LRU-cache them under a page-count cap.
//! The win is bigger than hex because each `ListingRow::Instruction`
//! carries a `SharedString` mnemonic, an `Arc<Vec<Chunk>>` of resolved
//! operands, a `SharedString` comment, plus the `Arc<Vec<ArrowSegment>>`
//! for gutter arrows. On a 1 M-instruction `.text` the row vector
//! easily runs to 50 MB+ before the per-row sub-allocations.
//!
//! ## How a page is built
//!
//! A page builder runs the existing per-instruction disassembly +
//! formatting + ADRP/ADD resolution logic over a slice of the
//! section's bytes. Most of `build_listing_rows`'s logic still
//! applies — the formatting and operand resolution are the same.
//!
//! The two things we lose at page boundaries:
//!
//!   * **ADRP+ADD pairs that straddle a boundary.** The ADRP lives
//!     in page N-1, the ADD in page N. We carry per-register page-
//!     base state across page builds by re-initialising the
//!     `PageBaseTracker` at the *start* of each page from a
//!     precomputed snapshot. Snapshots are taken once at construction
//!     time by replaying the section through the tracker with no
//!     formatting. So the second-instruction-of-page-N still
//!     resolves correctly when its partner ADRP is at the end of
//!     page N-1.
//!   * **The cross-section ADRP retro-label** (`__got+0x...` →
//!     `__cstring-0x...`) — when an ADRP in page N-1 fuses with an
//!     ADD in page N to point at a different section. The retro-
//!     label mutates a prior row, which is per-page-N-1 work that
//!     the page-N build doesn't get to do. We accept that the
//!     occasional cross-page-boundary ADRP keeps its raw page-
//!     address label. Disassembly is still readable; only a
//!     cosmetic label is lost.
//!
//! ## Arrows
//!
//! Arrows are computed once at construction time over the entire
//! section, using a lightweight pre-pass that needs only raw bytes
//! and symbol-header positions (no formatting). Each page picks up
//! the arrow segments whose source row falls inside it; arrows that
//! cross page boundaries appear correctly on both pages.
//!
//! ## Row index space
//!
//! Total rows = `n_insns + n_symbol_headers + n_terminators` (the
//! last is the count of BasicBlockSeparator rows). All three are
//! known after the pre-pass — symbol headers from the symbol map,
//! terminators from a single decode-only walk of the bytes.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use armv8_encode::mc::InstructionInfo;
use glass_arch_arm::format as fmt;
use gpui::SharedString;

use crate::listing_model::{
    ArrowDirection, ArrowRole, ArrowSegment, ArrowStyle, DataPeek, ListingRow,
    ARROW_MAX_LANES, STRING_PEEK_CAP,
};
use crate::TextSectionBytes;

/// Number of instructions per page. 2048 instructions = 8 KB of
/// AArch64 code per page; ARMv7 stores precomputed instructions
/// so the byte-equivalent doesn't matter. With ~3 rows per insn
/// average (symbol headers + BB separators) that's ~6k rows per
/// page; ~150 KB per page materialised.
pub const PAGE_INSNS: u32 = 2048;

/// Default LRU cap. 64 pages × ~150 KB ≈ 9.6 MB per tab. Sized
/// to absorb fast scrolling across ~128k instructions without
/// rebuilding, while still capping per-tab memory in single-
/// digit MB.
pub const DEFAULT_MAX_PAGES: usize = 64;

/// Page-aware row cache for one disassembly section.
pub struct PagedListing {
    text: TextSectionBytes,
    symbols: Arc<glass_arch_arm::SymbolMap>,
    data: Arc<DataPeek>,
    /// Instruction count. AArch64 = `bytes.len() / 4`; ARMv7 =
    /// precomputed Vec length.
    n_insns: u32,
    /// Number of pages.
    n_pages: u32,
    /// Global row index where each page's first row lives.
    /// `page_row_starts[i]` is row 0 of page `i`;
    /// `page_row_starts[n_pages]` = `total_rows`.
    page_row_starts: Vec<u32>,
    /// Instruction index where each page begins. Same length
    /// convention as `page_row_starts`.
    page_insn_starts: Vec<u32>,
    /// Snapshot of the `PageBaseTracker` state at each page
    /// boundary. The page builder seeds its tracker from
    /// `page_tracker_states[page_idx]` so ADRP+ADD pairs that
    /// straddle a page boundary still fuse. `None` entry means
    /// "fresh tracker" (which is also the right thing for the
    /// first page).
    page_tracker_states: Vec<Option<PageBaseSnapshot>>,
    /// All section arrows, grouped by source row. The page
    /// builder copies the entries for its rows into the
    /// resulting `ListingRow::Instruction::arrows` field.
    arrows_by_row: Arc<HashMap<u32, Vec<ArrowSegment>>>,
    state: Arc<Mutex<PagedListingState>>,
}

struct PagedListingState {
    pages: HashMap<u32, Arc<Vec<ListingRow>>>,
    lru: VecDeque<u32>,
    max_pages: usize,
}

/// Snapshot of `PageBaseTracker` state at a page boundary. We
/// just keep the per-register page-base words — that's all
/// `observe` consults to fuse a later ADD.
#[derive(Clone, Default)]
struct PageBaseSnapshot {
    /// For each X register (0..32), the page base loaded by the
    /// most recent ADRP into that register, or `None` if the
    /// slot has been invalidated.
    x_pages: [Option<u64>; 32],
}

impl PagedListing {
    /// Build the page index. Runs a single decode-only pass over
    /// the section bytes to identify terminators (BB separators)
    /// and snapshot the `PageBaseTracker` at page boundaries.
    /// O(n_insns) with a small constant — much cheaper than the
    /// full formatting pass that previously ran at tab open.
    pub fn new(
        text: TextSectionBytes,
        symbols: Arc<glass_arch_arm::SymbolMap>,
        data: Arc<DataPeek>,
        max_pages: usize,
    ) -> Self {
        let n_insns = text.instruction_count() as u32;
        let n_pages = n_insns.div_ceil(PAGE_INSNS).max(1);

        // Prepass: walk every insn once. For each:
        //   - Count symbol headers (1 if symbols.at(addr).is_some()).
        //   - Decode + check is_terminator (1 if BB ends here).
        //   - Maintain PageBaseTracker for ADRP+ADD across pages.
        // Sample tracker state + cumulative row count at each
        // page boundary.
        let mut page_row_starts = Vec::with_capacity(n_pages as usize + 1);
        let mut page_insn_starts = Vec::with_capacity(n_pages as usize + 1);
        let mut page_tracker_states = Vec::with_capacity(n_pages as usize + 1);
        let mut tracker = glass_arch_arm::PageBaseTracker::new();
        let mut x_pages: [Option<u64>; 32] = [None; 32];
        let mut cum_rows: u32 = 0;
        let is_precomputed = text.precomputed.is_some();

        for insn_idx in 0..n_insns {
            // Page boundary: snapshot state.
            if insn_idx % PAGE_INSNS == 0 {
                page_row_starts.push(cum_rows);
                page_insn_starts.push(insn_idx);
                page_tracker_states.push(
                    if x_pages.iter().any(|p| p.is_some()) {
                        Some(PageBaseSnapshot { x_pages })
                    } else {
                        None
                    },
                );
            }
            let addr = text.addr_of(insn_idx as usize);
            // Header row — count it iff the *builder* would emit one.
            // Both builders emit a header only for a symbol that starts
            // exactly at this instruction's address (`symbols.at(addr)`,
            // plus the Thumb `|1` marker form). Symbols elsewhere — in
            // other sections, or between instructions — never produce a
            // header here, so they must NOT be counted. Counting the
            // whole global symbol map (every later-section symbol, e.g.
            // all of `.text` when viewing a code section that sits
            // below `.rodata`) is what previously inflated the row
            // total and panicked the listing on x86.
            if symbols.at(addr).or_else(|| symbols.at(addr | 1)).is_some() {
                cum_rows += 1;
            }
            // The instruction row itself.
            cum_rows += 1;
            // Decode for ADRP page-base tracking (AArch64 only) plus
            // the AArch64 terminator classification.
            let (aarch64_terminates, dest_x, is_adrp, adrp_page) =
                decode_for_prepass(&text, insn_idx);
            let decoded = decoded_at(&text, insn_idx);
            // Mirror tracker state into `x_pages` so the page builder's
            // tracker resumes from the same snapshot at each boundary.
            if let Some(insn_w) = &decoded {
                tracker.observe(insn_w);
            }
            if is_adrp {
                if let Some(d) = dest_x {
                    if (d as usize) < x_pages.len() {
                        x_pages[d as usize] = adrp_page;
                    }
                }
            } else if let Some(d) = dest_x {
                if (d as usize) < x_pages.len() {
                    x_pages[d as usize] = None;
                }
            }
            // Basic-block separator row — match whichever builder runs.
            // The precomputed builder keys on
            // `control_flow().is_terminator()`; the AArch64 word builder
            // uses `fmt::is_terminator(mnemonic)` (via
            // `decode_for_prepass`, which can only classify 4-byte
            // AArch64 words — hence the facade read for x86/ARMv7).
            let terminates = if is_precomputed {
                decoded
                    .as_ref()
                    .map(|i| {
                        use armv8_encode::mc::InstructionInfo;
                        i.control_flow().is_terminator()
                    })
                    .unwrap_or(false)
            } else {
                aarch64_terminates
            };
            if terminates {
                cum_rows += 1;
            }
        }
        // No trailing-symbol drain: symbols past the last instruction
        // (later sections, padding) never produce a header row, so
        // counting them would over-shoot the builder's row total.
        // Sentinel.
        page_row_starts.push(cum_rows);
        page_insn_starts.push(n_insns);
        page_tracker_states.push(
            if x_pages.iter().any(|p| p.is_some()) {
                Some(PageBaseSnapshot { x_pages })
            } else {
                None
            },
        );

        // Section-wide arrow computation.
        let arrows_by_row =
            build_section_arrows(&text, &symbols, &page_row_starts);

        Self {
            text,
            symbols,
            data,
            n_insns,
            n_pages,
            page_row_starts,
            page_insn_starts,
            page_tracker_states,
            arrows_by_row: Arc::new(arrows_by_row),
            state: Arc::new(Mutex::new(PagedListingState {
                pages: HashMap::new(),
                lru: VecDeque::new(),
                max_pages,
            })),
        }
    }

    pub fn total_rows(&self) -> u32 {
        *self.page_row_starts.last().unwrap_or(&0)
    }

    pub fn n_pages(&self) -> u32 {
        self.n_pages
    }

    /// Map a global row index to its containing page.
    pub fn page_of(&self, idx: u32) -> Option<u32> {
        if idx >= self.total_rows() {
            return None;
        }
        let pos = self.page_row_starts.partition_point(|&start| start <= idx);
        Some((pos as u32).saturating_sub(1))
    }

    /// Blocking page lookup. Builds the containing page if not
    /// cached. Used by the renderer until step 3 swaps it for
    /// the non-blocking variant + background build.
    pub fn page_for_row_blocking(
        &self,
        idx: u32,
    ) -> Option<(Arc<Vec<ListingRow>>, usize)> {
        let page_idx = self.page_of(idx)?;
        let page = self.ensure_page_built(page_idx);
        let off = (idx - self.page_row_starts[page_idx as usize]) as usize;
        Some((page, off))
    }

    /// Non-blocking variant — returns `None` when the page isn't
    /// cached. Used by step-3 renderer integration; safe to call
    /// from any thread.
    pub fn page_for_row_if_cached(
        &self,
        idx: u32,
    ) -> Option<(Arc<Vec<ListingRow>>, usize)> {
        let page_idx = self.page_of(idx)?;
        let mut state = self.state.lock().ok()?;
        let page = state.pages.get(&page_idx).cloned()?;
        if let Some(pos) = state.lru.iter().position(|&p| p == page_idx) {
            state.lru.remove(pos);
        }
        state.lru.push_back(page_idx);
        let off = (idx - self.page_row_starts[page_idx as usize]) as usize;
        Some((page, off))
    }

    /// Idempotent page build: returns the cached page if present,
    /// otherwise builds it (outside the lock) and inserts it
    /// under the LRU policy.
    pub fn ensure_page_built(&self, page_idx: u32) -> Arc<Vec<ListingRow>> {
        {
            let mut state = self.state.lock().expect("poisoned");
            if let Some(p) = state.pages.get(&page_idx).cloned() {
                if let Some(pos) = state.lru.iter().position(|&p| p == page_idx) {
                    state.lru.remove(pos);
                }
                state.lru.push_back(page_idx);
                return p;
            }
        }
        let rows = self.build_page(page_idx);
        let rows = Arc::new(rows);
        let mut state = self.state.lock().expect("poisoned");
        if let Some(existing) = state.pages.get(&page_idx).cloned() {
            if let Some(pos) = state.lru.iter().position(|&p| p == page_idx) {
                state.lru.remove(pos);
            }
            state.lru.push_back(page_idx);
            return existing;
        }
        state.pages.insert(page_idx, rows.clone());
        state.lru.push_back(page_idx);
        while state.lru.len() > state.max_pages {
            if let Some(victim) = state.lru.pop_front() {
                state.pages.remove(&victim);
            } else {
                break;
            }
        }
        rows
    }

    /// Look up the global row index containing the instruction
    /// at `addr`. Returns `None` if no instruction has that
    /// address. Materialises the containing page so the row count
    /// inside it can be measured exactly (symbol headers + BB
    /// separators above the target insn).
    pub fn row_for_addr(&self, addr: u64) -> Option<u32> {
        // First find the instruction index for this address. For
        // AArch64 that's `(addr - base) / 4`; for ARMv7 a binary
        // search of the precomputed insn list.
        let insn_idx = self.insn_idx_of_addr(addr)?;
        let page_idx = (insn_idx / PAGE_INSNS).min(self.n_pages - 1);
        let page = self.ensure_page_built(page_idx);
        // Walk the page rows looking for the Instruction with the
        // matching address.
        for (off, row) in page.iter().enumerate() {
            if let ListingRow::Instruction { address, .. } = row {
                if *address == addr {
                    return Some(self.page_row_starts[page_idx as usize] + off as u32);
                }
            }
        }
        None
    }

    /// Address of the instruction row at the given global row
    /// index, or `None` when the row is a symbol header or BB
    /// separator (or out of range). Blocking: materialises the
    /// containing page.
    pub fn addr_at(&self, idx: u32) -> Option<u64> {
        let (page, off) = self.page_for_row_blocking(idx)?;
        match &page[off] {
            ListingRow::Instruction { address, .. } => Some(*address),
            _ => None,
        }
    }

    /// Non-blocking variant of `addr_at` — returns `None` when
    /// the row's page isn't cached. Used by persistence at
    /// shutdown.
    pub fn addr_at_if_cached(&self, idx: u32) -> Option<u64> {
        let (page, off) = self.page_for_row_if_cached(idx)?;
        match &page[off] {
            ListingRow::Instruction { address, .. } => Some(*address),
            _ => None,
        }
    }

    /// Find the first instruction row at or after `idx`. Skips
    /// symbol headers and BB separators. Used by listing
    /// navigation (J/K, arrow keys). Walks pages from `idx`
    /// forward; blocks on a page build per crossed page.
    pub fn next_instruction_at_or_after(&self, idx: u32) -> Option<u32> {
        let total = self.total_rows();
        if idx >= total {
            return None;
        }
        let mut page_idx = self.page_of(idx)?;
        loop {
            let page = self.ensure_page_built(page_idx);
            let page_base = self.page_row_starts[page_idx as usize];
            let start_off = if idx > page_base {
                (idx - page_base) as usize
            } else {
                0
            };
            for (off, row) in page.iter().enumerate().skip(start_off) {
                if matches!(row, ListingRow::Instruction { .. }) {
                    return Some(page_base + off as u32);
                }
            }
            page_idx += 1;
            if page_idx >= self.n_pages {
                return None;
            }
        }
    }

    /// Sibling of `next_instruction_at_or_after`. Walks pages
    /// from `idx` backwards.
    pub fn prev_instruction_at_or_before(&self, idx: u32) -> Option<u32> {
        let total = self.total_rows();
        if idx >= total {
            return None;
        }
        let mut page_idx = self.page_of(idx)?;
        loop {
            let page = self.ensure_page_built(page_idx);
            let page_base = self.page_row_starts[page_idx as usize];
            let last_off = ((idx - page_base) as usize).min(page.len() - 1);
            for off in (0..=last_off).rev() {
                if matches!(&page[off], ListingRow::Instruction { .. }) {
                    return Some(page_base + off as u32);
                }
            }
            if page_idx == 0 {
                return None;
            }
            page_idx -= 1;
        }
    }

    fn insn_idx_of_addr(&self, addr: u64) -> Option<u32> {
        if let Some(p) = &self.text.precomputed {
            // ARMv7: binary-search the precomputed insns.
            let idx = p.binary_search_by(|i| i.address().cmp(&addr)).ok()?;
            Some(idx as u32)
        } else {
            if addr < self.text.base {
                return None;
            }
            let off = (addr - self.text.base) as u64;
            if off as usize >= self.text.bytes.len() {
                return None;
            }
            if off % 4 != 0 {
                return None;
            }
            Some((off / 4) as u32)
        }
    }

    /// Build a page's rows. Pure — no cache mutation. Reuses the
    /// monolithic builder by slicing the section into a windowed
    /// `TextSectionBytes` and running the per-instruction logic
    /// over it; the windowed slice provides exactly the bytes the
    /// page needs, no more.
    fn build_page(&self, page_idx: u32) -> Vec<ListingRow> {
        let first_insn = self.page_insn_starts[page_idx as usize];
        let end_insn = self.page_insn_starts[page_idx as usize + 1];
        if first_insn >= end_insn {
            return Vec::new();
        }
        let n_page_insns = end_insn - first_insn;
        // For now: build by invoking the existing per-insn logic
        // through a private helper that takes a tracker snapshot
        // as input. This keeps the formatting / resolution paths
        // identical to the monolithic build so a paged page is
        // byte-identical (except for arrows + cross-page retro-
        // labels) to the corresponding slice of the unpaged build.
        let mut rows = Vec::with_capacity((n_page_insns as usize) * 3 / 2);
        let snapshot = self.page_tracker_states[page_idx as usize].clone();
        crate::listing_model::build_listing_rows_for_range(
            &self.text,
            &self.symbols,
            &self.data,
            first_insn,
            end_insn,
            snapshot.map(|s| s.x_pages),
            &mut rows,
        );
        // Attach arrows: walk rows; for each Instruction look up
        // its global row index in arrows_by_row.
        let page_base = self.page_row_starts[page_idx as usize];
        for (off, row) in rows.iter_mut().enumerate() {
            if let ListingRow::Instruction { arrows, .. } = row {
                let global = page_base + off as u32;
                if let Some(segs) = self.arrows_by_row.get(&global) {
                    *arrows = Arc::new(segs.clone());
                }
            } else if let ListingRow::BasicBlockSeparator { arrows } = row {
                let global = page_base + off as u32;
                if let Some(segs) = self.arrows_by_row.get(&global) {
                    *arrows = Arc::new(segs.clone());
                }
            }
        }
        rows
    }
}

/// Compute the entire section's arrows in one pass, keyed by the
/// global row index of the source / target / passing rows. The
/// per-page builder uses this map to attach arrow segments to its
/// rows.
fn build_section_arrows(
    text: &TextSectionBytes,
    symbols: &glass_arch_arm::SymbolMap,
    page_row_starts: &[u32],
) -> HashMap<u32, Vec<ArrowSegment>> {
    // We need address → row-index for every instruction across
    // the section. Reconstruct it from the same arithmetic the
    // prepass used. For AArch64 this is: walk instructions in
    // order, counting symbol headers + BB separators, and emit
    // `addr_to_row` entries for each instruction row.
    let n_insns = text.instruction_count() as u32;
    // Per-instruction row index — `insn_to_row[i]` is the global
    // row index where insn `i`'s Instruction row sits. Indexed
    // by insn_idx (cheap O(1) lookup) instead of a 5M-entry
    // HashMap keyed by address (which would cost ~160 MB and
    // ~500 ms to populate on a big .text).
    let mut insn_to_row: Vec<u32> = Vec::with_capacity(n_insns as usize);
    let mut header_rows: Vec<u32> = Vec::new();
    let mut row_idx: u32 = 0;
    for insn_idx in 0..n_insns {
        let addr = text.addr_of(insn_idx as usize);
        // Header row iff a symbol starts *exactly* at this instruction —
        // identical to the builder's `symbols.at(addr)` emission and to
        // PagedListing's prepass. Counting symbols that fall *between*
        // instruction addresses (non-4-aligned symbols such as `$d`/`$x`
        // mapping symbols or data labels) would advance `row_idx` for
        // rows the builder never emits, so every following arrow's
        // source/target would render a few rows below the real one.
        if symbols.at(addr).or_else(|| symbols.at(addr | 1)).is_some() {
            header_rows.push(row_idx);
            row_idx += 1;
        }
        // Instruction row.
        insn_to_row.push(row_idx);
        row_idx += 1;
        let (terminates, _, _, _) = decode_for_prepass(text, insn_idx);
        if terminates {
            row_idx += 1;
        }
    }
    let _ = page_row_starts; // currently unused — page boundaries
                              // don't affect the global row index
                              // mapping. Kept on signature so step 3
                              // prefetch can use the same map.

    // Function ranges: [header[k], header[k+1]) plus prefix /
    // suffix. Same shape as `assign_arrows`.
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    let mut prev: u32 = 0;
    for &h in &header_rows {
        if h > prev {
            ranges.push((prev, h));
        }
        prev = h;
    }
    let total_rows = row_idx;
    if prev < total_rows {
        ranges.push((prev, total_rows));
    }

    // Collect candidate arrows. AArch64 path only — ARMv7 ships
    // its own per-row branch info via the precomputed
    // `Vec<DecodedInsn>`; we keep its arrow logic in
    // `build_listing_rows_armv7` and don't page ARMv7 for now.
    #[derive(Clone)]
    struct PendingArrow {
        src_row: u32,
        tgt_row: u32,
        style: ArrowStyle,
    }
    let mut pending: Vec<PendingArrow> = Vec::new();
    if text.precomputed.is_some() {
        // ARMv7 — skip section-wide arrows; per-row arrows fall
        // out of the per-page build via the existing path. Empty
        // map; pages compute their own arrows.
        return HashMap::new();
    }
    // Walk insns in order; for each, derive its row via
    // `insn_to_row[i]` and reject ones outside any function
    // range. AArch64 is fixed 4-byte, so we go straight from
    // address to insn idx via `(target - base) / 4` when
    // resolving branch targets — no hash lookup.
    let mut current_range_idx: usize = 0;
    for insn_idx in 0..n_insns {
        let src_row = insn_to_row[insn_idx as usize];
        // Advance to the function range whose [lo, hi) contains
        // src_row. ranges are sorted by row.
        while current_range_idx < ranges.len()
            && ranges[current_range_idx].1 <= src_row
        {
            current_range_idx += 1;
        }
        if current_range_idx >= ranges.len() {
            break;
        }
        let (lo, hi) = ranges[current_range_idx];
        if src_row < lo {
            continue;
        }
        let addr = text.addr_of(insn_idx as usize);
        let Some(word) = text
            .bytes
            .get((insn_idx as usize) * 4..)
            .and_then(|s| s.first_chunk::<4>())
            .map(|w| u32::from_le_bytes(*w))
        else {
            continue;
        };
        let Ok(insn) =
            armv8_encode::isa::aarch64::decode_instruction(addr, word)
        else {
            continue;
        };
        let style = if fmt::is_unconditional_direct_branch(insn.mnemonic) {
            ArrowStyle::Solid
        } else if fmt::is_conditional_branch(insn.mnemonic) {
            ArrowStyle::Dotted
        } else {
            continue;
        };
        let Some(target) = fmt::primary_address_operand(&insn) else { continue };
        // Resolve target address → insn idx via fixed-stride
        // arithmetic. Skip if the target's outside the section.
        if target < text.base {
            continue;
        }
        let target_off = (target - text.base) as u64;
        if target_off % 4 != 0 {
            continue;
        }
        let target_insn = (target_off / 4) as u32;
        if target_insn >= n_insns {
            continue;
        }
        let tgt_row = insn_to_row[target_insn as usize];
        if tgt_row < lo || tgt_row >= hi {
            continue;
        }
        if tgt_row == src_row {
            continue;
        }
        pending.push(PendingArrow { src_row, tgt_row, style });
    }

    // Sweepline lane assignment, same algorithm as `assign_arrows`.
    pending.sort_by_key(|a| a.src_row);
    let mut lane_free_at: Vec<u32> = Vec::new();
    let mut out: HashMap<u32, Vec<ArrowSegment>> = HashMap::new();
    for a in &pending {
        let (lo, hi) = if a.src_row <= a.tgt_row {
            (a.src_row, a.tgt_row)
        } else {
            (a.tgt_row, a.src_row)
        };
        let mut lane = None;
        for (idx, free_at) in lane_free_at.iter_mut().enumerate() {
            if *free_at <= lo {
                lane = Some(idx);
                *free_at = hi + 1;
                break;
            }
        }
        let lane = match lane {
            Some(l) => l,
            None => {
                lane_free_at.push(hi + 1);
                lane_free_at.len() - 1
            }
        };
        if (lane as u8) >= ARROW_MAX_LANES {
            continue;
        }
        let dir = if a.src_row < a.tgt_row {
            ArrowDirection::Down
        } else {
            ArrowDirection::Up
        };
        let seg_at = |role: ArrowRole| ArrowSegment {
            lane: lane as u8,
            style: a.style,
            direction: dir,
            role,
        };
        // Source row.
        out.entry(a.src_row).or_default().push(seg_at(ArrowRole::Source));
        // Target row.
        out.entry(a.tgt_row).or_default().push(seg_at(ArrowRole::Target));
        // Passing rows.
        for r in (lo + 1)..hi {
            if r == a.src_row || r == a.tgt_row {
                continue;
            }
            out.entry(r).or_default().push(seg_at(ArrowRole::Pass));
        }
    }
    out
}

/// Decode-only inspection of an instruction. Returns:
///   - terminates: whether the insn ends a basic block (BB
///     separator row follows).
///   - dest_x: destination X-register index, if any.
///   - is_adrp: whether the insn is ADRP.
///   - adrp_page: the page base loaded by ADRP, if applicable.
fn decode_for_prepass(
    text: &TextSectionBytes,
    insn_idx: u32,
) -> (bool, Option<u8>, bool, Option<u64>) {
    use armv8_encode::isa::aarch64::{
        Aarch64Mnemonic, DecodedOperand, RegisterClass,
    };
    let Some((addr, _bytes, word)) = text.word_at(insn_idx as usize) else {
        return (false, None, false, None);
    };
    let Ok(insn) = armv8_encode::isa::aarch64::decode_instruction(addr, word) else {
        return (false, None, false, None);
    };
    let terminates = fmt::is_terminator(insn.mnemonic);
    let dest_x = insn.operands.iter().find_map(|op| match op {
        DecodedOperand::Register(r)
            if matches!(r.class, RegisterClass::X | RegisterClass::XOrSp) =>
        {
            Some(r.index)
        }
        _ => None,
    });
    let is_adrp = matches!(insn.mnemonic, Aarch64Mnemonic::Adrp);
    let adrp_page = if is_adrp {
        insn.operands.iter().find_map(|op| match op {
            DecodedOperand::BranchTarget(a) => Some(*a),
            _ => None,
        })
    } else {
        None
    };
    (terminates, dest_x, is_adrp, adrp_page)
}

fn decoded_at(
    text: &TextSectionBytes,
    insn_idx: u32,
) -> Option<glass_arch_arm::DecodedInsn> {
    if let Some(p) = &text.precomputed {
        return p.get(insn_idx as usize).cloned();
    }
    let (addr, _bytes, word) = text.word_at(insn_idx as usize)?;
    let insn = armv8_encode::isa::aarch64::decode_instruction(addr, word).ok()?;
    Some(glass_arch_arm::DecodedInsn::Aarch64(insn))
}

// Silence unused-import warnings for items referenced only by
// the future async / step-3 path.
#[allow(dead_code)]
fn _keep_imports_alive() {
    let _ = SharedString::from("");
    let _ = STRING_PEEK_CAP;
}

#[cfg(test)]
mod tests {
    use super::*;
    use glass_arch_arm::{Symbol, SymbolKind, SymbolMap, SymbolSources};

    fn syms(addrs: &[(u64, &str)]) -> Arc<SymbolMap> {
        let vec: Vec<Symbol> = addrs
            .iter()
            .map(|(a, n)| Symbol {
                address: *a,
                size: 4,
                kind: SymbolKind::Function,
                display_name: n.to_string(),
                name: n.to_string(),
                sources: SymbolSources::default(),
            })
            .collect();
        Arc::new(SymbolMap::from_symbols(vec))
    }

    fn empty_peek() -> Arc<DataPeek> {
        Arc::new(DataPeek {
            sections: Vec::new(),
            code_sections: Vec::new(),
            section_meta: Vec::new(),
        })
    }

    /// Build a section of `n` AArch64 NOP instructions starting at
    /// `base`. NOP is `0xD503201F` (little-endian: 1F 20 03 D5).
    fn nop_section(base: u64, n: usize) -> TextSectionBytes {
        let nop_le = 0xD503201Fu32.to_le_bytes();
        let mut bytes = Vec::with_capacity(n * 4);
        for _ in 0..n {
            bytes.extend_from_slice(&nop_le);
        }
        TextSectionBytes {
            base,
            bytes: Arc::new(bytes),
            precomputed: None,
            arch: armv8_encode::container::Architecture::Aarch64,
        }
    }

    #[test]
    fn empty_section_zero_rows() {
        let text = nop_section(0x1000, 0);
        let p = PagedListing::new(text, syms(&[]), empty_peek(), 4);
        assert_eq!(p.total_rows(), 0);
    }

    #[test]
    fn single_page_no_symbols_no_terminators() {
        let text = nop_section(0x1000, 8);
        let p = PagedListing::new(text, syms(&[]), empty_peek(), 4);
        // NOP isn't a terminator and there are no symbols, so
        // total_rows = 8.
        assert_eq!(p.total_rows(), 8);
        assert_eq!(p.n_pages, 1);
    }

    #[test]
    fn symbol_at_first_insn_adds_header_row() {
        let text = nop_section(0x1000, 4);
        let p = PagedListing::new(
            text,
            syms(&[(0x1000, "foo")]),
            empty_peek(),
            4,
        );
        // 1 header + 4 insns = 5.
        assert_eq!(p.total_rows(), 5);
    }

    #[test]
    fn arrows_align_with_instruction_rows_past_off_boundary_symbols() {
        // Regression: control-flow arrows are positioned by a row count
        // independent of the row builder. A symbol that does NOT start
        // at an instruction address (here 0x1002) must not advance that
        // count — the builder emits no header for it, so counting it
        // would render the arrow a row below the real branch.
        // Section: nop; b .+12; nop; nop; nop(target).
        let words: [u32; 5] = [
            0xD503201F, // nop            @0x1000
            0x14000003, // b 0x1010       @0x1004  (imm26=3 ⇒ +12)
            0xD503201F, // nop            @0x1008
            0xD503201F, // nop            @0x100c
            0xD503201F, // nop (target)   @0x1010
        ];
        let mut bytes = Vec::new();
        for w in words {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let text = TextSectionBytes {
            base: 0x1000,
            bytes: Arc::new(bytes),
            precomputed: None,
            arch: armv8_encode::container::Architecture::Aarch64,
        };
        // A symbol wedged between two instructions (non-4-aligned).
        let p = PagedListing::new(text, syms(&[(0x1002, "between")]), empty_peek(), 4);

        // Actual global row that holds the branch instruction.
        let page = p.build_page(0);
        let base_row = p.page_row_starts[0];
        let branch_row = page
            .iter()
            .enumerate()
            .find_map(|(off, row)| match row {
                ListingRow::Instruction { address, .. } if *address == 0x1004 => {
                    Some(base_row + off as u32)
                }
                _ => None,
            })
            .expect("branch instruction row present");

        // The arrow's Source segment must land on exactly that row.
        let segs = p
            .arrows_by_row
            .get(&branch_row)
            .expect("an arrow segment on the branch row");
        assert!(
            segs.iter().any(|s| matches!(s.role, ArrowRole::Source)),
            "Source arrow must sit on the branch row {branch_row}, not be shifted"
        );
    }

    #[test]
    fn x86_precomputed_paging_is_consistent() {
        // Regression for two coupled bugs that crashed the x86 listing:
        //   1. the paged row builder used the fixed-4-byte `word_at`
        //      path, which `break`s at the first >4-byte instruction
        //      (lea/call below) → short page;
        //   2. the prepass counted every global symbol (incl. later
        //      sections) as a header → inflated row total.
        // Either makes `sum(page rows) != total_rows()` and panics the
        // renderer with an out-of-bounds page offset.
        use armv8_encode::isa::x86::{disassemble_bytes, Bitness};
        let bytes = vec![
            0x48, 0x89, 0xd8, // mov rax, rbx            (3 bytes)
            0x48, 0x8d, 0x05, 0x00, 0x01, 0x00, 0x00, // lea rax,[rip+0x100] (7)
            0xe8, 0x10, 0x00, 0x00, 0x00, // call rel32  (5 bytes)
            0xc3, // ret                                 (1 byte)
        ];
        let base = 0x1000u64;
        let decoded = disassemble_bytes(base, &bytes, Bitness::Bits64).expect("decode");
        let precomputed: Vec<glass_arch_arm::DecodedInsn> =
            decoded.into_iter().map(glass_arch_arm::DecodedInsn::X86).collect();
        let n_insns = precomputed.len();

        let make = |far_symbol: bool| {
            let text = TextSectionBytes {
                base,
                bytes: Arc::new(bytes.clone()),
                precomputed: Some(Arc::new(precomputed.clone())),
                arch: armv8_encode::container::Architecture::X86_64,
            };
            let mut sym_list = vec![(0x1000u64, "start")];
            if far_symbol {
                // A symbol from a *later section* — must not add rows.
                sym_list.push((0x9000, "other_section"));
            }
            PagedListing::new(text, syms(&sym_list), empty_peek(), 4)
        };

        let p = make(false);
        // The >4-byte lea/call did not truncate the page: every
        // instruction yields a row (plus the header for "start").
        let summed: u32 = (0..p.n_pages()).map(|pi| p.build_page(pi).len() as u32).sum();
        assert_eq!(summed, p.total_rows(), "page rows must sum to total_rows");
        assert!(
            p.total_rows() as usize >= n_insns + 1,
            "expected all {n_insns} insns + header, got {}",
            p.total_rows()
        );
        // No row index underflows or runs past its page.
        for r in 0..p.total_rows() {
            let (page, off) = p.page_for_row_blocking(r).expect("row resolves");
            assert!(off < page.len(), "row {r}: off {off} >= len {}", page.len());
        }
        // An out-of-section symbol must not change the row total.
        assert_eq!(
            make(true).total_rows(),
            p.total_rows(),
            "out-of-section symbol must not inflate row count"
        );
    }

    #[test]
    fn page_of_inverts_page_row_starts() {
        let text = nop_section(0x1000, (PAGE_INSNS * 3) as usize);
        let p = PagedListing::new(text, syms(&[]), empty_peek(), 4);
        assert_eq!(p.n_pages, 3);
        // No symbols, no terminators ⇒ rows == insns.
        assert_eq!(p.total_rows(), PAGE_INSNS * 3);
        assert_eq!(p.page_of(0), Some(0));
        assert_eq!(p.page_of(PAGE_INSNS - 1), Some(0));
        assert_eq!(p.page_of(PAGE_INSNS), Some(1));
        assert_eq!(p.page_of(PAGE_INSNS * 2 - 1), Some(1));
        assert_eq!(p.page_of(PAGE_INSNS * 2), Some(2));
        assert_eq!(p.page_of(PAGE_INSNS * 3), None);
    }

    #[test]
    fn row_for_addr_finds_instruction() {
        let text = nop_section(0x1000, 8);
        let p = PagedListing::new(
            text,
            syms(&[(0x1004, "mid")]),
            empty_peek(),
            4,
        );
        // Layout: row 0 = insn at 0x1000; row 1 = header "mid";
        // row 2 = insn at 0x1004; …
        assert_eq!(p.row_for_addr(0x1000), Some(0));
        assert_eq!(p.row_for_addr(0x1004), Some(2));
        assert_eq!(p.row_for_addr(0x1008), Some(3));
        assert_eq!(p.row_for_addr(0x999), None);
    }

    #[test]
    fn lru_evicts_oldest_under_cap() {
        let text = nop_section(0x1000, (PAGE_INSNS * 5) as usize);
        let p = PagedListing::new(text, syms(&[]), empty_peek(), 2);
        let _ = p.ensure_page_built(0);
        let _ = p.ensure_page_built(1);
        let _ = p.ensure_page_built(2);
        let state = p.state.lock().unwrap();
        assert!(state.pages.contains_key(&1));
        assert!(state.pages.contains_key(&2));
        assert!(!state.pages.contains_key(&0));
    }

    #[test]
    fn page_for_row_blocking_returns_correct_offset() {
        let text = nop_section(0x1000, (PAGE_INSNS * 2 + 5) as usize);
        let p = PagedListing::new(text, syms(&[]), empty_peek(), 4);
        // Row 0 → page 0, off 0.
        let (page0, off0) = p.page_for_row_blocking(0).expect("row 0");
        assert_eq!(off0, 0);
        assert!(matches!(page0[0], ListingRow::Instruction { .. }));
        // Row PAGE_INSNS → page 1, off 0.
        let (_, off1) = p.page_for_row_blocking(PAGE_INSNS).expect("row PAGE_INSNS");
        assert_eq!(off1, 0);
    }
}
