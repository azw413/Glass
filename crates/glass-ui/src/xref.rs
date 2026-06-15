//! Cross-reference indices.
//!
//! Three indices, each built on a background thread after the
//! foreground bundle load completes so first paint stays responsive:
//!
//!   * `native` — for every native (AArch64) artifact, a map from
//!     `target_addr` → list of caller-site addresses. Caller sites
//!     are direct branch instructions plus resolved ADRP+ADD pairs.
//!   * `dex_callers` — inverse of `bundle.method_calls`. Methods
//!     that invoke each key.
//!   * `dex_field_refs` — for every field reference seen in any
//!     smali body, the list of method keys that touch it
//!     (iget/iput/sget/sput).
//!
//! Each index is wrapped in an `XrefIndexState` so the UI can show a
//! progress bar while the build is in flight. The store is owned by
//! `LoadedBundle` and shared into the build tasks via Arc.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

/// One in-flight xref index. The Shell renders a progress chip when
/// `state == Building` and the real results panel when `state ==
/// Ready`. `Failed` is defensive — none of the builders are
/// fallible today but the state machine accommodates them.
#[derive(Clone)]
#[derive(Default)]
pub enum XrefIndexState<T> {
    /// Build hasn't started yet. The Shell shouldn't see this in
    /// practice (the loader fires builders immediately after bundle
    /// hand-off), but it's the cheap initial value.
    #[default]
    Pending,
    /// Build is running. The `XrefProgress` is shared with the
    /// worker so the UI can render `current / total`.
    Building(Arc<parking_lot::Mutex<XrefProgress>>),
    /// Build finished; result is Arc'd so cloning is cheap.
    Ready(Arc<T>),
    /// Build failed. Stores a short message for diagnostics.
    #[allow(dead_code)]
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct XrefProgress {
    /// Free-text label rendered above the progress bar.
    pub label: String,
    /// Items processed so far.
    pub current: usize,
    /// Total items the build will process. May be approximate; the
    /// bar clamps so it never overflows visually.
    pub total: usize,
}

impl XrefProgress {
    pub fn fraction(&self) -> f32 {
        if self.total == 0 {
            return 0.;
        }
        (self.current as f32 / self.total as f32).clamp(0., 1.)
    }
}

/// Inverse call graph for a native artifact: target addr →
/// caller-site addrs.
pub type NativeXrefMap = HashMap<u64, Vec<u64>>;

/// Per-artifact native xref maps. Same keying as `LoadedBundle.symbol_maps`.
pub type NativeXrefs = HashMap<glass_db::ArtifactId, NativeXrefMap>;

/// `caller_key` + the line offset within that method body where
/// the `invoke-*` lives, for each `callee_key`. Multiple entries
/// per caller when one method invokes the same callee on several
/// lines. Sorted on `(caller_key, line_offset)` for stable order.
pub type DexCallers = HashMap<String, Vec<(String, u32)>>;

/// For each smali field reference (`Lcom/Foo;->name:Ltype;`), the
/// `(method_key, line_offset)` pairs that touch it. Same sort
/// shape as `DexCallers`.
pub type DexFieldRefs = HashMap<String, Vec<(String, u32)>>;

/// What an in-flight scoped palette is querying. Stored on the
/// scope so the poller can rebuild entries deterministically when
/// the underlying index transitions to Ready.
#[derive(Clone, Debug)]
pub enum PaletteScopeSource {
    /// `target_addr` references in the native xref index for
    /// `artifact`.
    NativeXrefs { artifact: glass_db::ArtifactId, target_addr: u64 },
    /// Callers of a DEX method.
    DexCallers { method_key: String },
    /// Touchers of a DEX field.
    DexFieldRefs { field_ref: String },
}

/// A scoped palette query — populates the palette with a fixed set
/// of `SearchEntry` results instead of the bundle-wide index.
///
/// The header chip reads "Label — N results" (or "Label — indexing
/// …" while the underlying index is still building). The Shell
/// constructs one of these when the user picks "References to X" or
/// "Callers of X" from a right-click menu.
#[derive(Clone)]
pub struct PaletteScope {
    /// Free-text label rendered in the chip above the palette input.
    pub label: String,
    /// Pre-computed entries the palette filters within. May be
    /// empty while `progress` is still in flight; the Shell refreshes
    /// when the underlying index becomes Ready.
    pub entries: Arc<Vec<crate::SearchEntry>>,
    /// `Some` while the producing index is still building. The
    /// palette polls this to render a bar; when None, the scope is
    /// terminal (results are final).
    pub progress: Option<Arc<parking_lot::Mutex<XrefProgress>>>,
    /// What this scope is querying. Used by the background poller
    /// to rebuild `entries` once the source index transitions to
    /// Ready.
    pub source: PaletteScopeSource,
}

/// The full xref store. Owned by `LoadedBundle`; cloning is cheap
/// because everything is Arc'd.
#[derive(Clone, Default)]
pub struct XrefStore {
    pub native: Arc<RwLock<XrefIndexState<NativeXrefs>>>,
    pub dex_callers: Arc<RwLock<XrefIndexState<DexCallers>>>,
    pub dex_field_refs: Arc<RwLock<XrefIndexState<DexFieldRefs>>>,
}

impl XrefStore {
    pub fn new() -> Self {
        Self::default()
    }
}


impl<T> XrefIndexState<T> {
    /// Convenience: whether any consumer has the finished index in
    /// hand. Used by the Shell to enable / disable right-click menu
    /// items.
    #[allow(dead_code)]
    pub fn is_ready(&self) -> bool {
        matches!(self, XrefIndexState::Ready(_))
    }
}

// ---- AArch64 builder -------------------------------------------------------

/// Walk every native text section, decode every instruction, and
/// build the per-artifact `target_addr → caller_sites` index.
/// Handles direct branches via `primary_address_operand` plus
/// resolved ADRP+ADD pairs via the same page-base tracker used in
/// `build_listing_rows`.
pub fn build_native_xrefs(
    text_sections: &std::collections::HashMap<
        (glass_db::ArtifactId, String),
        crate::TextSectionBytes,
    >,
    data_sections: &std::collections::HashMap<
        (glass_db::ArtifactId, String),
        crate::DataSectionBytes,
    >,
    progress: &Arc<parking_lot::Mutex<XrefProgress>>,
) -> NativeXrefs {
    use armv8_encode::isa::aarch64;
    use armv8_encode::mc::InstructionInfo;
    use glass_arch_arm::{DecodedInsn, PageBaseTracker};
    let mut out: NativeXrefs = HashMap::new();
    let mut processed_total = 0usize;
    // Per-artifact DataPeek cache so the ARMv7 literal-pool
    // dereference can read 4-byte pointer words out of rodata
    // without rebuilding the lookup per instruction. Keyed by
    // ArtifactId; built lazily on first use for each artifact
    // we encounter in text_sections.
    let mut data_peek_cache: HashMap<
        glass_db::ArtifactId,
        crate::listing_model::DataPeek,
    > = HashMap::new();
    let build_peek = |aid: &glass_db::ArtifactId| -> crate::listing_model::DataPeek {
        use crate::listing_model::{DataPeek, DataSectionMeta};
        let mut sections = Vec::new();
        let mut section_meta = Vec::new();
        for ((other_aid, name), ds) in data_sections.iter() {
            if other_aid != aid {
                continue;
            }
            // Skip BSS / debug / zero-base sections — they can't
            // hold useful pointer values. Mirrors the filter
            // `build_listing_rows` uses when populating DataPeek.
            if matches!(
                ds.kind,
                crate::NativeSectionKind::Bss | crate::NativeSectionKind::Debug
            ) {
                continue;
            }
            if ds.base == 0 {
                continue;
            }
            sections.push((ds.base, ds.bytes.clone()));
            section_meta.push(DataSectionMeta {
                name: name.clone(),
                base: ds.base,
                size: ds.bytes.len() as u64,
            });
        }
        // Code sections — needed by `peek_u32_le` for Thumb
        // literal-pool dereferences (the pool word lives inside
        // `.text`). Same artifact filter as the data side.
        let mut code_sections = Vec::new();
        for ((other_aid, _name), ts) in text_sections.iter() {
            if other_aid != aid {
                continue;
            }
            code_sections.push((ts.base, ts.bytes.clone()));
        }
        DataPeek { sections, code_sections, section_meta }
    };
    for ((aid, _name), section) in text_sections {
        let base = section.base;
        let bytes: &[u8] = section.bytes.as_ref();
        let per_artifact = out.entry(aid.clone()).or_default();
        // Shared fusion tracker — same idioms as `build_listing_rows`.
        let mut tracker = PageBaseTracker::new();
        // Lazily materialise the per-artifact data peek; ARMv7
        // text sections use it for literal-pool pointer
        // dereferencing.
        let peek = data_peek_cache
            .entry(aid.clone())
            .or_insert_with(|| build_peek(aid));
        // ARMv7 sections carry a precomputed `Vec<DecodedInsn>`
        // because Thumb / ARM-mode mixed code has variable
        // instruction widths and literal-pool dropouts that the
        // fixed-4-byte AArch64 walk can't honour. Route those
        // through a dedicated loop that re-uses the same tracker
        // abstraction for movw+movt fusion.
        if let Some(precomputed) = section.precomputed.as_ref() {
            let n = precomputed.len();
            for (i, insn) in precomputed.iter().enumerate() {
                let addr = insn.address();
                // Direct branch target → xref. Strip the Thumb
                // mode-bit so the recorded address matches what
                // the rest of the listing / symbol-map machinery
                // uses (the listing's `symbols.at` already
                // dual-checks `t` and `t | 1`, but the xref index
                // is keyed by a single canonical address).
                if let Some(t) = insn.branch_target() {
                    per_artifact.entry(t & !1u64).or_default().push(addr);
                }
                // Fusion via the shared tracker. Covers movw+movt
                // (fused 32-bit constant, typically a pointer) and
                // the Rust PIC idiom `ldr Rt, [pc, #imm] ; add Rt,
                // pc` (target = (add_insn_pc + 4) + signed pool
                // value). Pass the per-artifact data peek so the
                // tracker can read the pool slot.
                let pool_peek = |a: u64| peek.peek_u32_le(a);
                if let Some(ft) = tracker.observe_with_pool_peek(insn, pool_peek) {
                    per_artifact.entry(ft.target).or_default().push(addr);
                }
                // Thumb literal-pool loads (`ldr Rt, [pc, #imm]`)
                // resolve to the pool word's address; record that
                // as an xref so the user can navigate from the
                // load site to the pool slot. The pool word's
                // bytes are typically a pointer into rodata —
                // dereference one level so the xref also fires
                // on the *real* destination ("References to
                // 0x{string_addr}" finds the load site, not just
                // the pool slot).
                if let Some(pool_addr) = insn.pcrel_target() {
                    per_artifact.entry(pool_addr).or_default().push(addr);
                    if let Some(deref) = peek.peek_u32_le(pool_addr) {
                        // 0 is the common "no relocation applied
                        // yet" filler — skip so we don't pollute
                        // the index with a giant null-target
                        // entry. Also reject pointers that don't
                        // land in any known section (likely
                        // uninitialised heap addresses, GOT
                        // resolver thunks, etc.).
                        if deref != 0
                            && peek.section_containing(deref as u64).is_some()
                        {
                            per_artifact
                                .entry(deref as u64)
                                .or_default()
                                .push(addr);
                        }
                    }
                }
                if i % 1024 == 0 {
                    let mut p = progress.lock();
                    p.current = processed_total + i;
                }
            }
            processed_total += n;
            let mut p = progress.lock();
            p.current = processed_total;
            continue;
        }
        let n = bytes.len() / 4;
        for i in 0..n {
            let addr = base + (i as u64) * 4;
            let word = u32::from_le_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ]);
            let Ok(insn) = aarch64::decode_instruction(addr, word) else {
                if i % 1024 == 0 {
                    let mut p = progress.lock();
                    p.current = processed_total + i;
                }
                continue;
            };
            // Direct branch target → xref.
            if let Some(target) =
                glass_arch_arm::format::primary_address_operand(&insn)
            {
                per_artifact.entry(target).or_default().push(addr);
            }
            // ADRP+ADD fusion via the shared tracker.
            let wrapped = DecodedInsn::Aarch64(insn);
            if let Some(ft) = tracker.observe(&wrapped) {
                per_artifact.entry(ft.target).or_default().push(addr);
            }
            // Progress at 1024-insn cadence to keep lock contention low.
            if i % 1024 == 0 {
                let mut p = progress.lock();
                p.current = processed_total + i;
            }
        }
        processed_total += n;
        let mut p = progress.lock();
        p.current = processed_total;
    }
    // Make caller lists deterministic for stable display ordering.
    for v in out.values_mut() {
        for sites in v.values_mut() {
            sites.sort_unstable();
            sites.dedup();
        }
    }
    out
}

// ---- DEX field refs builder -----------------------------------------------

/// Scan every smali class body for field accesses
/// (`iget*/iput*/sget*/sput*`) and build `field_ref → method_keys`.
/// The method key is the same `Class;->name(sig)ret` form used by
/// `method_calls`. The field ref is the last whitespace-separated
/// token on the instruction line, in the same form as smali source
/// (`Lcom/Foo;->name:Ltype;`).
pub fn build_dex_field_refs(
    bodies: &[gpui::SharedString],
    kinds: &[crate::LeafKind],
    progress: &Arc<parking_lot::Mutex<XrefProgress>>,
) -> DexFieldRefs {
    let mut out: DexFieldRefs = HashMap::new();
    let mut processed = 0usize;
    for (i, k) in kinds.iter().enumerate() {
        let crate::LeafKind::SmaliClass { class_jni } = k else { continue };
        processed += 1;
        let Some(body) = bodies.get(i) else { continue };
        // Track current `.method` so we can record the line offset
        // relative to its header (matches the MethodLine annotation
        // key convention).
        let mut current_method: Option<String> = None;
        let mut method_line_idx: usize = 0;
        for (line_no, raw) in body.lines().enumerate() {
            let trimmed = raw.trim_start();
            if let Some(after) = trimmed.strip_prefix(".method ") {
                if let Some(decl) = after.split_whitespace().last() {
                    current_method = Some(format!("{class_jni}->{decl}"));
                    method_line_idx = line_no;
                }
                continue;
            }
            if trimmed.starts_with(".end method") {
                current_method = None;
                continue;
            }
            // Looking for iget*/iput*/sget*/sput*. All start with
            // one of those four prefixes followed by a possible
            // type suffix (-boolean, -wide, etc.).
            let is_field_op = trimmed.starts_with("iget")
                || trimmed.starts_with("iput")
                || trimmed.starts_with("sget")
                || trimmed.starts_with("sput");
            if !is_field_op {
                continue;
            }
            let Some(method_key) = current_method.as_ref() else { continue };
            let Some(field_ref) = trimmed.split_whitespace().last() else {
                continue;
            };
            if !field_ref.contains("->") || !field_ref.contains(':') {
                continue;
            }
            let offset = (line_no - method_line_idx) as u32;
            out.entry(field_ref.to_string())
                .or_default()
                .push((method_key.clone(), offset));
        }
        if processed % 64 == 0 {
            let mut p = progress.lock();
            p.current = processed;
        }
    }
    for sites in out.values_mut() {
        sites.sort_unstable();
        sites.dedup();
    }
    let mut p = progress.lock();
    p.current = processed;
    out
}

/// Build the DEX callers index by scanning smali bodies. Captures
/// the line offset of each `invoke-*` so the palette entry can
/// jump to the exact call site. Replaces the cheaper-but-line-
/// less inverse-of-method_calls path that lived in app.rs.
pub fn build_dex_callers(
    bodies: &[gpui::SharedString],
    kinds: &[crate::LeafKind],
    progress: &Arc<parking_lot::Mutex<XrefProgress>>,
) -> DexCallers {
    let mut out: DexCallers = HashMap::new();
    let mut processed = 0usize;
    for (i, k) in kinds.iter().enumerate() {
        let crate::LeafKind::SmaliClass { class_jni } = k else { continue };
        processed += 1;
        let Some(body) = bodies.get(i) else { continue };
        let mut current_method: Option<String> = None;
        let mut method_line_idx: usize = 0;
        for (line_no, raw) in body.lines().enumerate() {
            let trimmed = raw.trim_start();
            if let Some(after) = trimmed.strip_prefix(".method ") {
                if let Some(decl) = after.split_whitespace().last() {
                    current_method = Some(format!("{class_jni}->{decl}"));
                    method_line_idx = line_no;
                }
                continue;
            }
            if trimmed.starts_with(".end method") {
                current_method = None;
                continue;
            }
            if !trimmed.starts_with("invoke-") {
                continue;
            }
            let Some(caller_key) = current_method.as_ref() else { continue };
            // Smali invoke syntax: `invoke-... {regs}, Callee;->name(sig)ret`.
            // The callee is the last whitespace-separated token.
            let Some(callee_key) = trimmed.split_whitespace().last() else {
                continue;
            };
            if !callee_key.contains("->") {
                continue;
            }
            let offset = (line_no - method_line_idx) as u32;
            out.entry(callee_key.to_string())
                .or_default()
                .push((caller_key.clone(), offset));
        }
        if processed % 64 == 0 {
            let mut p = progress.lock();
            p.current = processed;
        }
    }
    for sites in out.values_mut() {
        sites.sort_unstable();
        sites.dedup();
    }
    let mut p = progress.lock();
    p.current = processed;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use armv8_encode::container::{Container, SectionKind};
    use parking_lot::Mutex;
    use std::path::PathBuf;

    fn libtool_checker_bytes() -> Vec<u8> {
        // Vendored alongside glass-arch-arm's armv7_smoke.rs.
        let manifest = env!("CARGO_MANIFEST_DIR");
        let path = PathBuf::from(manifest)
            .join("..")
            .join("glass-arch-arm")
            .join("tests")
            .join("libtool-checker.so");
        std::fs::read(&path).expect("read libtool-checker.so")
    }

    fn make_armv7_text_section(
        bytes: &[u8],
    ) -> std::collections::HashMap<
        (glass_db::ArtifactId, String),
        crate::TextSectionBytes,
    > {
        let container = Container::from_bytes(bytes).expect("parse container");
        let entries: Vec<u64> = container
            .symbols
            .iter()
            .filter(|s| !s.is_undefined)
            .map(|s| s.address)
            .collect();
        let mut out = std::collections::HashMap::new();
        for (idx, sec) in container.sections.iter().enumerate() {
            if !matches!(sec.kind, SectionKind::Text) {
                continue;
            }
            let precomputed =
                glass_arch_arm::precompute_section_insns(&container, idx, &entries)
                    .expect("precompute");
            let aid = glass_db::ArtifactId::from_raw([0u8; 32]);
            out.insert(
                (aid, sec.name.clone()),
                crate::TextSectionBytes {
                    base: sec.address,
                    bytes: Arc::new(sec.bytes.clone()),
                    precomputed: Some(Arc::new(precomputed)),
                    arch: container.architecture,
                },
            );
        }
        out
    }

    #[test]
    fn build_native_xrefs_armv7_libtool_checker_nonempty() {
        let bytes = libtool_checker_bytes();
        let sections = make_armv7_text_section(&bytes);
        assert!(!sections.is_empty(), "expected at least one text section");
        let progress = Arc::new(Mutex::new(XrefProgress {
            label: "test".into(),
            current: 0,
            total: 0,
        }));
        let data: std::collections::HashMap<
            (glass_db::ArtifactId, String),
            crate::DataSectionBytes,
        > = std::collections::HashMap::new();
        let xrefs = build_native_xrefs(&sections, &data, &progress);
        let aid = glass_db::ArtifactId::from_raw([0u8; 32]);
        let per_artifact = xrefs.get(&aid).expect("artifact entry");
        assert!(
            !per_artifact.is_empty(),
            "expected ARMv7 xref builder to record at least one target"
        );
        let in_section = |addr: u64| {
            sections.values().any(|t| {
                addr >= t.base && addr < t.base + (t.bytes.len() as u64)
            })
        };
        for sites in per_artifact.values() {
            for s in sites {
                assert!(
                    in_section(*s),
                    "caller-site 0x{s:x} outside any text section"
                );
            }
        }
    }

    #[test]
    fn build_native_xrefs_armv7_branch_targets_have_mode_bit_stripped() {
        let bytes = libtool_checker_bytes();
        let sections = make_armv7_text_section(&bytes);
        let progress = Arc::new(Mutex::new(XrefProgress {
            label: "test".into(),
            current: 0,
            total: 0,
        }));
        let data: std::collections::HashMap<
            (glass_db::ArtifactId, String),
            crate::DataSectionBytes,
        > = std::collections::HashMap::new();
        let xrefs = build_native_xrefs(&sections, &data, &progress);
        let aid = glass_db::ArtifactId::from_raw([0u8; 32]);
        let per_artifact = xrefs.get(&aid).expect("artifact entry");
        let mut expected_targets: std::collections::HashSet<u64> =
            std::collections::HashSet::new();
        for section in sections.values() {
            let Some(p) = section.precomputed.as_ref() else { continue };
            for insn in p.iter() {
                if let Some(t) = insn.branch_target() {
                    expected_targets.insert(t & !1u64);
                }
            }
        }
        assert!(!expected_targets.is_empty(), "no branch targets in fixture");
        for t in &expected_targets {
            assert!(
                per_artifact.contains_key(t),
                "branch target 0x{t:x} (mode-bit stripped) missing from xref index"
            );
            assert_eq!(t & 1, 0);
        }
    }
}
