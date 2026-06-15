//! Paged row cache for the hex view.
//!
//! The hex view scrolls a `Vec<HexRow>` covering every 16-byte chunk
//! of the section's data, interleaved with symbol headers. On a large
//! native artifact (e.g. a 100 MB rodata or data section) this vec
//! is the largest single allocation per tab — easily hundreds of MB
//! including the per-row `Vec<u8>` allocations. On a 16 GB Mac that
//! blows the working set very quickly when more than one big tab is
//! open.
//!
//! Solution: lazy page-based materialisation. The section is divided
//! into fixed-byte-row pages (`PAGE_BYTE_ROWS` byte rows = 16 KB of
//! source bytes per page). Pages are built on demand and held in an
//! LRU cache bounded by `max_pages`. The renderer's row callback
//! looks up the page containing each visible row; if the page is
//! cached the row renders normally, otherwise the renderer falls
//! back to a height-correct placeholder and the page is built (the
//! plumbing for *how* — background task vs. inline — lives in the
//! caller; this module is sync-only).
//!
//! ## Row → page mapping
//!
//! Symbol headers are interleaved with byte rows: zero or more
//! headers may appear *before* each byte row. The global row index
//! therefore depends on the cumulative header count at each byte
//! row. We precompute, for each page, the global row index of its
//! first byte row's first header (i.e. the first row that "belongs"
//! to the page). The precomputation walks the symbol map once at
//! construction — O(symbols), independent of byte row count — so
//! even the largest sections cost only a few KB.
//!
//! ## Address → row mapping
//!
//! For navigation (jump-to-address), we map address → byte row via
//! arithmetic (`addr / 16 - base / 16`), then byte row → global row
//! index via the same per-page precomputed offsets plus the page's
//! local header count for the byte row in question. The page must
//! be materialised to know the local header offset, but only the
//! *containing* page — cheap.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use crate::hex::{build_hex_rows, HexRow};
use crate::DataSectionBytes;

/// Number of 16-byte byte rows in a single page. 1024 byte rows =
/// 16 KB of source bytes per page. With ~50 bytes per HexRow that
/// works out to ~50 KB of materialised state per page — small
/// enough that we can keep dozens cached and large enough that
/// scroll-by-line doesn't bounce between pages on every row.
pub const PAGE_BYTE_ROWS: u32 = 1024;

/// Default maximum number of materialised pages held in cache.
/// 64 pages × ~50 KB = ~3.2 MB per tab. Chosen to absorb fast scroll
/// across ~64k byte rows (~1 MB of source) without rebuild thrash,
/// while still capping per-tab memory in the low MB range. Caller
/// can override via `PagedHex::new` for narrow / wide cache trade-
/// offs.
pub const DEFAULT_MAX_PAGES: usize = 64;

/// Page-aware row cache for one hex section.
pub struct PagedHex {
    data: DataSectionBytes,
    symbols: Arc<glass_arch_arm::SymbolMap>,
    /// How many 16-byte byte rows are in this section.
    n_byte_rows: u32,
    /// Number of pages. The last page may have fewer than
    /// `PAGE_BYTE_ROWS` byte rows.
    n_pages: u32,
    /// `page_starts[i]` = global row index of the *first row* that
    /// belongs to page `i`. The first row may be a symbol header
    /// or the first byte row, depending on whether any headers
    /// fall at the page boundary. `page_starts[n_pages]` =
    /// `total_rows`.
    page_starts: Vec<u32>,
    state: Arc<Mutex<PagedHexState>>,
}

struct PagedHexState {
    pages: HashMap<u32, Arc<Vec<HexRow>>>,
    /// Most-recently-used at the back. Eviction pops the front.
    /// Re-touching a cached page moves it to the back.
    lru: VecDeque<u32>,
    max_pages: usize,
}

impl PagedHex {
    /// Build the page index. Cheap — walks the symbol map once;
    /// does not materialise any rows.
    pub fn new(
        data: DataSectionBytes,
        symbols: Arc<glass_arch_arm::SymbolMap>,
        max_pages: usize,
    ) -> Self {
        let n_byte_rows = data.row_count() as u32;
        let n_pages = n_byte_rows.div_ceil(PAGE_BYTE_ROWS).max(1);

        // For each page boundary, count the symbol headers that
        // belong to its first byte row. We need the cumulative
        // header count *up to but not including* each page's first
        // byte row, so the page's starting global row index is:
        //
        //     page_starts[i] = (first_byte_row_of_page_i)
        //                    + (header_count_strictly_before_page_i)
        //
        // We iterate symbols in address order — `SymbolMap`
        // already exposes that.
        // Header rows are only emitted for symbols whose address falls
        // *inside this section's byte range* — `build_hex_rows` filters
        // with `symbols.in_range(row_addr, row_end)`, and the section
        // spans `[base, base + len)`. The accounting here must use the
        // same bound: a global `SymbolMap` also contains symbols from
        // other sections (e.g. every `.text` function sits *below*
        // `.rodata` on x86_64), and counting those would push
        // `page_starts[0]` above 0 — making low row indices underflow
        // the `idx - page_starts[page]` subtraction in
        // `page_for_row_blocking`.
        let section_base = data.base;
        let section_end = data.base + data.bytes.len() as u64;
        let mut page_starts = Vec::with_capacity(n_pages as usize + 1);
        {
            let mut cum_headers: u32 = 0;
            let mut sym_iter = symbols.iter().peekable();
            // Skip — without counting — every symbol that lives before
            // this section. They never produce a header row here.
            while let Some(s) = sym_iter.peek() {
                if s.address < section_base {
                    sym_iter.next();
                } else {
                    break;
                }
            }
            for page_idx in 0..n_pages {
                let first_byte_row = page_idx * PAGE_BYTE_ROWS;
                let first_byte_row_addr =
                    data.row_addr(first_byte_row as usize);
                // Advance past every in-section symbol whose address is
                // before this page — those are headers for earlier
                // pages.
                while let Some(s) = sym_iter.peek() {
                    if s.address < first_byte_row_addr {
                        cum_headers += 1;
                        sym_iter.next();
                    } else {
                        break;
                    }
                }
                page_starts.push(first_byte_row + cum_headers);
            }
            // Sentinel: total_rows. Count the remaining symbols that
            // still fall *inside* the section (headers for the final
            // page); symbols at/after `section_end` belong to later
            // sections and never emit a header here.
            while let Some(s) = sym_iter.peek() {
                if s.address < section_end {
                    cum_headers += 1;
                    sym_iter.next();
                } else {
                    break;
                }
            }
            page_starts.push(n_byte_rows + cum_headers);
        }

        Self {
            data,
            symbols,
            n_byte_rows,
            n_pages,
            page_starts,
            state: Arc::new(Mutex::new(PagedHexState {
                pages: HashMap::new(),
                lru: VecDeque::new(),
                max_pages,
            })),
        }
    }

    pub fn total_rows(&self) -> u32 {
        *self.page_starts.last().unwrap_or(&0)
    }

    pub fn n_pages(&self) -> u32 {
        self.n_pages
    }

    /// Map a global row index to its containing page. Returns
    /// `None` if `idx` is past the end.
    pub fn page_of(&self, idx: u32) -> Option<u32> {
        if idx >= self.total_rows() {
            return None;
        }
        // Binary search: greatest page i with page_starts[i] <= idx.
        let pos = self.page_starts.partition_point(|&start| start <= idx);
        Some((pos as u32).saturating_sub(1))
    }

    /// Synchronous page lookup. Builds the page in-place if it's
    /// missing and returns the (page, row-within-page) pair.
    /// Returns `None` if `idx` is out of range.
    ///
    /// The async / background-build variant lives in the caller —
    /// see the renderer in `two_pane.rs`. This method exists for
    /// navigation paths (jump-to-address, copy-row-text) where
    /// blocking inline for a single page build is acceptable.
    pub fn page_for_row_blocking(
        &self,
        idx: u32,
    ) -> Option<(Arc<Vec<HexRow>>, usize)> {
        let page_idx = self.page_of(idx)?;
        let page = self.ensure_page_built(page_idx);
        // `page_of` guarantees `page_starts[page_idx] <= idx`, so this
        // never underflows in practice; `checked_sub` degrades a future
        // accounting bug to a blank row instead of a panic.
        let off = idx.checked_sub(self.page_starts[page_idx as usize])? as usize;
        Some((page, off))
    }

    /// Returns the cached page when it's already materialised;
    /// otherwise `None` *without* triggering a build. The renderer
    /// uses this on the hot path so it never blocks on a build;
    /// schedules a build via `request_page_build` instead.
    pub fn page_for_row_if_cached(
        &self,
        idx: u32,
    ) -> Option<(Arc<Vec<HexRow>>, usize)> {
        let page_idx = self.page_of(idx)?;
        let mut state = self.state.lock().ok()?;
        let page = state.pages.get(&page_idx).cloned()?;
        // Touch LRU.
        if let Some(pos) = state.lru.iter().position(|&p| p == page_idx) {
            state.lru.remove(pos);
        }
        state.lru.push_back(page_idx);
        let off = idx.checked_sub(self.page_starts[page_idx as usize])? as usize;
        Some((page, off))
    }

    /// Build a page now (synchronously, no caching policy beyond
    /// the LRU). Idempotent — if cached, returns the cached Arc.
    /// Public so background tasks can drive builds.
    pub fn ensure_page_built(&self, page_idx: u32) -> Arc<Vec<HexRow>> {
        // Fast path under the lock.
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
        // Slow path: build outside the lock to avoid blocking the
        // renderer (or any concurrent lookup) for the duration of
        // the build.
        let rows = self.build_page(page_idx);
        let rows = Arc::new(rows);
        let mut state = self.state.lock().expect("poisoned");
        // Re-check: another thread may have built it concurrently.
        // First writer wins; we discard our build.
        if let Some(existing) = state.pages.get(&page_idx).cloned() {
            if let Some(pos) = state.lru.iter().position(|&p| p == page_idx) {
                state.lru.remove(pos);
            }
            state.lru.push_back(page_idx);
            return existing;
        }
        state.pages.insert(page_idx, rows.clone());
        state.lru.push_back(page_idx);
        // Evict oldest pages until we're back under cap.
        while state.lru.len() > state.max_pages {
            if let Some(victim) = state.lru.pop_front() {
                state.pages.remove(&victim);
            } else {
                break;
            }
        }
        rows
    }

    /// Build a page's rows by slicing the source bytes + the
    /// symbol map. Pure — no cache mutation, safe to call from
    /// any thread.
    fn build_page(&self, page_idx: u32) -> Vec<HexRow> {
        let first_byte_row = page_idx * PAGE_BYTE_ROWS;
        let last_byte_row = ((page_idx + 1) * PAGE_BYTE_ROWS).min(self.n_byte_rows);
        if first_byte_row >= last_byte_row {
            return Vec::new();
        }

        // Slice the source bytes for this page. We rebuild a tiny
        // `DataSectionBytes` over the slice so we can reuse
        // `build_hex_rows`. The Arc<Vec<u8>> on the original
        // section is shared and not cloned; we copy out only this
        // page's window. Window-copying keeps the page rows
        // self-contained — the cache doesn't pin the section's
        // bytes alive beyond what `data` already does.
        let start_byte = (first_byte_row as usize) * 16;
        let end_byte = (last_byte_row as usize * 16).min(self.data.bytes.len());
        let window_bytes: Vec<u8> = self.data.bytes[start_byte..end_byte].to_vec();
        let window_base = self.data.base + start_byte as u64;
        let window_section = DataSectionBytes {
            base: window_base,
            bytes: Arc::new(window_bytes),
            kind: self.data.kind,
        };

        // The header lookup in `build_hex_rows` consults the full
        // symbol map — `symbols.in_range(addr, end)` — so we pass
        // the same symbol map; it'll naturally only emit headers
        // whose address falls in the window.
        build_hex_rows(&window_section, &self.symbols)
    }

    /// Address-of-byte at the given global row index, or `None`
    /// if the row isn't a byte row (i.e. it's a symbol header).
    /// Blocking: materialises the page if not cached.
    pub fn addr_at(&self, idx: u32) -> Option<u64> {
        let (page, off) = self.page_for_row_blocking(idx)?;
        match &page[off] {
            HexRow::Bytes { address, .. } => Some(*address),
            HexRow::SymbolHeader { .. } => None,
        }
    }

    /// Non-blocking variant of `addr_at` — returns `None` when
    /// the row's containing page isn't cached. Used by persistence
    /// at shutdown so closing a session doesn't trigger page
    /// builds.
    pub fn addr_at_if_cached(&self, idx: u32) -> Option<u64> {
        let (page, off) = self.page_for_row_if_cached(idx)?;
        match &page[off] {
            HexRow::Bytes { address, .. } => Some(*address),
            HexRow::SymbolHeader { .. } => None,
        }
    }

    /// Find the first byte row at or after `idx`. Used by hex
    /// navigation (cursor movement, j/k traversal). Walks pages
    /// from `idx` forward until a byte row is found, or returns
    /// `None` if all remaining rows are headers (impossible in
    /// practice — every page ends with byte rows).
    pub fn next_byte_row_at_or_after(&self, idx: u32) -> Option<u32> {
        let total = self.total_rows();
        if idx >= total {
            return None;
        }
        let mut page_idx = self.page_of(idx)?;
        loop {
            let page = self.ensure_page_built(page_idx);
            let page_base = self.page_starts[page_idx as usize];
            let start_off = if idx > page_base {
                (idx - page_base) as usize
            } else {
                0
            };
            for (off, row) in page.iter().enumerate().skip(start_off) {
                if matches!(row, HexRow::Bytes { .. }) {
                    return Some(page_base + off as u32);
                }
            }
            page_idx += 1;
            if page_idx >= self.n_pages {
                return None;
            }
        }
    }

    /// Find the last byte row at or before `idx`. Sibling of
    /// `next_byte_row_at_or_after`; used by upward cursor
    /// movement.
    pub fn prev_byte_row_at_or_before(&self, idx: u32) -> Option<u32> {
        let total = self.total_rows();
        if idx >= total {
            return None;
        }
        let mut page_idx = self.page_of(idx)?;
        loop {
            let page = self.ensure_page_built(page_idx);
            let page_base = self.page_starts[page_idx as usize];
            let last_off = ((idx - page_base) as usize).min(page.len() - 1);
            for off in (0..=last_off).rev() {
                if matches!(&page[off], HexRow::Bytes { .. }) {
                    return Some(page_base + off as u32);
                }
            }
            if page_idx == 0 {
                return None;
            }
            page_idx -= 1;
        }
    }

    /// Find the global row index of the byte row at `addr` (the
    /// row that contains the byte at the given address). Returns
    /// `None` if the address is outside the section, or `Some(idx)`
    /// where `idx` is the global row index of the byte-row
    /// (skipping any leading symbol headers for that row).
    ///
    /// Blocking: builds the containing page if not cached. We need
    /// the page to find the symbol-header count *within* the page
    /// up to the target byte row.
    pub fn row_for_addr(&self, addr: u64) -> Option<u32> {
        if addr < self.data.base {
            return None;
        }
        let off = (addr - self.data.base) as usize;
        if off >= self.data.bytes.len() {
            return None;
        }
        let byte_row = (off / 16) as u32;
        let page_idx = byte_row / PAGE_BYTE_ROWS;
        let page = self.ensure_page_built(page_idx);
        // Walk the page and count rows up to the target byte row.
        // `byte_row_in_page` is which byte-row within the page we
        // want; we need to count how many global rows precede it.
        let target_byte_row_in_page = byte_row % PAGE_BYTE_ROWS;
        let mut byte_rows_seen: u32 = 0;
        for (off_in_page, row) in page.iter().enumerate() {
            if let HexRow::Bytes { .. } = row {
                if byte_rows_seen == target_byte_row_in_page {
                    return Some(
                        self.page_starts[page_idx as usize] + off_in_page as u32,
                    );
                }
                byte_rows_seen += 1;
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use glass_arch_arm::{Symbol, SymbolKind, SymbolMap, SymbolSources};
    use std::sync::Arc;

    fn data_section(base: u64, bytes_len: usize) -> DataSectionBytes {
        DataSectionBytes {
            base,
            bytes: Arc::new(vec![0u8; bytes_len]),
            kind: crate::NativeSectionKind::Data,
        }
    }

    fn sym(addr: u64, name: &str) -> Symbol {
        Symbol {
            address: addr,
            size: 4,
            kind: SymbolKind::Object,
            display_name: name.to_string(),
            name: name.to_string(),
            sources: SymbolSources::default(),
        }
    }

    fn symbol_map(syms: Vec<Symbol>) -> Arc<SymbolMap> {
        Arc::new(SymbolMap::from_symbols(syms))
    }

    #[test]
    fn empty_section_yields_one_page_zero_rows() {
        let data = data_section(0x1000, 0);
        let p = PagedHex::new(data, symbol_map(vec![]), 4);
        assert_eq!(p.n_pages, 1);
        assert_eq!(p.total_rows(), 0);
    }

    #[test]
    fn single_page_no_symbols() {
        // 32 bytes = 2 byte rows.
        let data = data_section(0x1000, 32);
        let p = PagedHex::new(data, symbol_map(vec![]), 4);
        assert_eq!(p.n_pages, 1);
        assert_eq!(p.total_rows(), 2);
        let (page, off) = p.page_for_row_blocking(0).expect("row 0");
        assert_eq!(off, 0);
        assert_eq!(page.len(), 2);
    }

    #[test]
    fn single_page_with_symbol_at_start() {
        // 32 bytes = 2 byte rows; a symbol at the section's base.
        let data = data_section(0x1000, 32);
        let p = PagedHex::new(data, symbol_map(vec![sym(0x1000, "first")]), 4);
        assert_eq!(p.total_rows(), 3); // 1 header + 2 byte rows
    }

    #[test]
    fn symbols_before_section_do_not_shift_page_starts() {
        // Regression: a global SymbolMap contains symbols from earlier
        // sections (e.g. every `.text` function sits below `.rodata` on
        // x86_64). Those must not be counted as headers for this
        // section, or `page_starts[0]` becomes > 0 and the first rows
        // underflow `idx - page_starts[page]` in page_for_row_blocking.
        let data = data_section(0x1000, 32); // 2 byte rows
        let before = vec![
            sym(0x10, "text_fn_a"),
            sym(0x20, "text_fn_b"),
            sym(0x30, "text_fn_c"),
        ];
        let p = PagedHex::new(data, symbol_map(before), 4);
        assert_eq!(p.page_starts[0], 0, "leading symbols must not shift page 0");
        assert_eq!(p.total_rows(), 2, "no in-section headers expected");
        // Row 0 must resolve to offset 0, not underflow.
        let (_page, off) = p.page_for_row_blocking(0).expect("row 0");
        assert_eq!(off, 0);
    }

    #[test]
    fn symbols_after_section_do_not_inflate_total_rows() {
        // Symbols at/after the section end belong to later sections and
        // must not be counted into total_rows.
        let data = data_section(0x1000, 32); // ends at 0x1020
        let after = vec![sym(0x1020, "next_sec_a"), sym(0x2000, "next_sec_b")];
        let p = PagedHex::new(data, symbol_map(after), 4);
        assert_eq!(p.total_rows(), 2, "out-of-section symbols must not add rows");
    }

    #[test]
    fn page_boundary_byte_row_addresses_are_correct() {
        // 3 pages: 1024 byte rows each (= 16 KB each) plus a few
        // more.  Total 3*1024 + 7 = 3079 byte rows.
        let bytes_len = (PAGE_BYTE_ROWS as usize * 3 + 7) * 16;
        let data = data_section(0x1000, bytes_len);
        let p = PagedHex::new(data, symbol_map(vec![]), 4);
        assert_eq!(p.n_pages, 4);
        assert_eq!(p.total_rows(), (PAGE_BYTE_ROWS * 3 + 7));
        // Page 0 starts at row 0; page 1 at row 1024 (since no
        // headers); page 2 at 2048; page 3 at 3072.
        assert_eq!(p.page_starts[0], 0);
        assert_eq!(p.page_starts[1], PAGE_BYTE_ROWS);
        assert_eq!(p.page_starts[2], PAGE_BYTE_ROWS * 2);
        assert_eq!(p.page_starts[3], PAGE_BYTE_ROWS * 3);
        assert_eq!(p.page_starts[4], PAGE_BYTE_ROWS * 3 + 7);
    }

    #[test]
    fn symbol_in_middle_shifts_following_page_starts() {
        // 3 pages worth, with one symbol in the middle of page 0.
        let bytes_len = (PAGE_BYTE_ROWS as usize * 3) * 16;
        let data = data_section(0x1000, bytes_len);
        let mid_addr = 0x1000 + (PAGE_BYTE_ROWS as u64 / 2) * 16;
        let p = PagedHex::new(data, symbol_map(vec![sym(mid_addr, "mid")]), 4);
        // Page 0 still starts at row 0.
        assert_eq!(p.page_starts[0], 0);
        // Page 1 starts after PAGE_BYTE_ROWS byte rows + 1 header.
        assert_eq!(p.page_starts[1], PAGE_BYTE_ROWS + 1);
        assert_eq!(p.page_starts[2], PAGE_BYTE_ROWS * 2 + 1);
        assert_eq!(p.page_starts[3], PAGE_BYTE_ROWS * 3 + 1);
    }

    #[test]
    fn page_of_inverts_page_starts() {
        let bytes_len = (PAGE_BYTE_ROWS as usize * 3) * 16;
        let data = data_section(0x1000, bytes_len);
        let p = PagedHex::new(data, symbol_map(vec![]), 4);
        assert_eq!(p.page_of(0), Some(0));
        assert_eq!(p.page_of(PAGE_BYTE_ROWS - 1), Some(0));
        assert_eq!(p.page_of(PAGE_BYTE_ROWS), Some(1));
        assert_eq!(p.page_of(PAGE_BYTE_ROWS * 2), Some(2));
        assert_eq!(p.page_of(PAGE_BYTE_ROWS * 3 - 1), Some(2));
        assert_eq!(p.page_of(PAGE_BYTE_ROWS * 3), None);
    }

    #[test]
    fn lru_evicts_oldest_under_cap() {
        let bytes_len = (PAGE_BYTE_ROWS as usize * 5) * 16;
        let data = data_section(0x1000, bytes_len);
        let p = PagedHex::new(data, symbol_map(vec![]), 2); // 2-page cap
        let _ = p.ensure_page_built(0);
        let _ = p.ensure_page_built(1);
        let _ = p.ensure_page_built(2);
        let state = p.state.lock().unwrap();
        // Page 0 should have been evicted to make room for page 2.
        assert!(state.pages.contains_key(&1));
        assert!(state.pages.contains_key(&2));
        assert!(!state.pages.contains_key(&0));
    }

    #[test]
    fn next_and_prev_byte_row_traverse_pages() {
        // Three pages, one symbol straddling the page-1/page-2
        // boundary at byte row PAGE_BYTE_ROWS.
        let bytes_len = (PAGE_BYTE_ROWS as usize * 3) * 16;
        let data = data_section(0x1000, bytes_len);
        let boundary_addr = 0x1000 + PAGE_BYTE_ROWS as u64 * 16;
        let p = PagedHex::new(
            data,
            symbol_map(vec![sym(boundary_addr, "boundary")]),
            4,
        );
        // Row indices (page 0): 0..PAGE_BYTE_ROWS (all byte rows).
        // Row indices (page 1): first row is header for `boundary`,
        // then PAGE_BYTE_ROWS byte rows.
        // Total: PAGE_BYTE_ROWS*3 byte rows + 1 header = 3073.
        assert_eq!(p.total_rows(), PAGE_BYTE_ROWS * 3 + 1);
        // Next byte row at PAGE_BYTE_ROWS: that's the symbol header.
        // The next byte row is at PAGE_BYTE_ROWS + 1.
        assert_eq!(
            p.next_byte_row_at_or_after(PAGE_BYTE_ROWS),
            Some(PAGE_BYTE_ROWS + 1)
        );
        // From byte row 5 forward.
        assert_eq!(p.next_byte_row_at_or_after(5), Some(5));
        // Prev byte row at PAGE_BYTE_ROWS (the symbol header): the
        // last byte row of page 0.
        assert_eq!(
            p.prev_byte_row_at_or_before(PAGE_BYTE_ROWS),
            Some(PAGE_BYTE_ROWS - 1)
        );
        // Last row is a byte row.
        assert_eq!(
            p.prev_byte_row_at_or_before(p.total_rows() - 1),
            Some(p.total_rows() - 1)
        );
    }

    #[test]
    fn addr_at_returns_address_for_byte_rows_only() {
        let data = data_section(0x1000, 64);
        let p = PagedHex::new(data, symbol_map(vec![sym(0x1010, "x")]), 4);
        // Row 0: first byte row at 0x1000.
        assert_eq!(p.addr_at(0), Some(0x1000));
        // Row 1: symbol header — no byte addr.
        assert_eq!(p.addr_at(1), None);
        // Row 2: second byte row at 0x1010.
        assert_eq!(p.addr_at(2), Some(0x1010));
    }

    #[test]
    fn row_for_addr_finds_byte_row_after_header() {
        // 16 bytes per row; section base 0x1000; one symbol at
        // 0x1010 (the second byte row).
        let data = data_section(0x1000, 64);
        let p = PagedHex::new(data, symbol_map(vec![sym(0x1010, "x")]), 4);
        // Total rows: 4 byte rows + 1 header = 5.
        assert_eq!(p.total_rows(), 5);
        // Byte row containing 0x1010 is the second byte row. Its
        // global row index is 2 (one byte row before it + one
        // header that precedes it).
        assert_eq!(p.row_for_addr(0x1010), Some(2));
        // Byte at 0x1018 is in the same byte row.
        assert_eq!(p.row_for_addr(0x1018), Some(2));
        // First byte row (0x1000) is row 0.
        assert_eq!(p.row_for_addr(0x1000), Some(0));
        // Out of range.
        assert_eq!(p.row_for_addr(0x0fff), None);
        assert_eq!(p.row_for_addr(0x1040), None);
    }
}
