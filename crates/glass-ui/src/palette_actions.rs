//! Palette state-mutation methods.
//!
//! Lifted out of `shell_actions.rs` so the file stays under the
//! module-size discipline. The methods are still defined on
//! `Shell` via a sibling `impl Shell` block — Rust allows
//! multiple `impl Shell` blocks across files in the same crate,
//! so the existing call sites continue to work without renames.
//!
//! Scope: the palette proper — toggle/open/close, mode switching,
//! scope management, asm autocomplete, key/move/activate
//! handlers, bin-search execution, list refresh, and the
//! background search-index build. Rendering lives in
//! `palette.rs`; context menus, the annotation editor and the
//! various navigation helpers that historically sat under the
//! `// ---- search palette ----` banner still live in
//! `shell_actions.rs` pending future extractions.

use std::sync::Arc;
use std::time::Duration;

use gpui::{px, Context, ListAlignment, ListState, Window};

use crate::search::SearchJump;
use crate::shell_actions::{
    build_dex_caller_entries, build_dex_field_entries, build_native_xref_entries,
};
use crate::SearchEntry;
use crate::Shell;

impl Shell {
    pub(crate) fn toggle_palette(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.palette_open {
            self.palette_open = false;
        } else {
            self.palette_open = true;
            self.palette_focused = true;
            self.refresh_palette_list();
            self.spawn_search_index_build_if_needed(cx);
            // Default (or refresh) the binary-search artifact to
            // an artifact id that actually has text sections in
            // the loaded bundle. `artifact_ids` lists everything
            // (including DEX artifacts that have no native bytes
            // to scan); using a DEX id here would give zero hits
            // and look like a broken search.
            let valid = match (&self.palette_bin_artifact, self.bundle()) {
                (Some(aid), Some(b)) => {
                    b.text_sections.keys().any(|(x, _)| x == aid)
                        || b.data_sections.keys().any(|(x, _)| x == aid)
                }
                _ => false,
            };
            if !valid {
                self.palette_bin_artifact = self.bundle().and_then(|b| {
                    b.text_sections
                        .keys()
                        .next()
                        .map(|(aid, _)| aid.clone())
                        .or_else(|| {
                            b.data_sections.keys().next().map(|(aid, _)| aid.clone())
                        })
                });
            }
            // Pull keyboard focus onto our root so typing reaches the
            // palette without the user clicking it first.
            window.focus(&self.focus_handle, cx);
        }
        cx.notify();
    }

    /// Switch palette to text mode (⌘1). State for the other
    /// mode is preserved so toggling back doesn't lose it.
    pub(crate) fn palette_set_mode_text(&mut self, cx: &mut Context<Self>) {
        if self.palette_mode != crate::PaletteMode::Text {
            self.palette_mode = crate::PaletteMode::Text;
            self.palette_selected = 0;
            self.refresh_palette_list();
            cx.notify();
        }
    }

    /// Switch palette to binary mode (⌘2).
    pub(crate) fn palette_set_mode_binary(&mut self, cx: &mut Context<Self>) {
        if self.palette_mode != crate::PaletteMode::Binary {
            self.palette_mode = crate::PaletteMode::Binary;
            self.palette_selected = 0;
            cx.notify();
        }
    }

    /// Toggle the "Code only" filter for bin/insn-search.
    /// Re-runs the last search if results were on screen so the
    /// table updates immediately without the user re-pressing
    /// Enter.
    pub(crate) fn palette_toggle_bin_code_only(&mut self, cx: &mut Context<Self>) {
        self.palette_bin_code_only = !self.palette_bin_code_only;
        if self.palette_bin_results.is_some() && !self.palette_bin_query.text().is_empty() {
            self.run_palette_bin_search(cx);
        }
        cx.notify();
    }

    /// Toggle the binary-mode sub-grammar between Bytes and Asm.
    pub(crate) fn palette_toggle_bin_grammar(&mut self, cx: &mut Context<Self>) {
        self.palette_bin_grammar = match self.palette_bin_grammar {
            crate::BinaryGrammar::Bytes => crate::BinaryGrammar::Asm,
            crate::BinaryGrammar::Asm => crate::BinaryGrammar::Bytes,
        };
        self.palette_bin_results = None;
        self.palette_bin_match_sources.clear();
        self.palette_bin_error = None;
        self.refresh_palette_asm_candidates();
        cx.notify();
    }

    pub(crate) fn palette_set_bin_grammar(
        &mut self,
        grammar: crate::BinaryGrammar,
        cx: &mut Context<Self>,
    ) {
        if self.palette_bin_grammar != grammar {
            self.palette_bin_grammar = grammar;
            self.palette_bin_results = None;
            self.palette_bin_match_sources.clear();
            self.palette_bin_error = None;
            self.refresh_palette_asm_candidates();
            cx.notify();
        }
    }

    /// Rebuild the asm-mode autocomplete candidate list. Cheap —
    /// just walks the variants index. Active instruction = text
    /// after the last `;` in the input.
    pub(crate) fn refresh_palette_asm_candidates(&mut self) {
        if self.palette_bin_grammar != crate::BinaryGrammar::Asm {
            self.palette_asm_candidates.clear();
            self.palette_asm_selected = 0;
            return;
        }
        let active = self
            .palette_bin_query
            .text()
            .rsplit(';')
            .next()
            .unwrap_or("")
            .trim_start();
        self.palette_asm_candidates = glass_api::match_insn_variants(active, 12);
        self.palette_asm_selected = self
            .palette_asm_selected
            .min(self.palette_asm_candidates.len().saturating_sub(1));
    }

    /// Tab inside asm mode: commit the highlighted variant's
    /// template into the current instruction, replacing whatever
    /// the user has half-typed.
    pub(crate) fn palette_asm_commit_template(&mut self, cx: &mut Context<Self>) {
        if self.palette_bin_grammar != crate::BinaryGrammar::Asm {
            return;
        }
        let Some(cand) = self
            .palette_asm_candidates
            .get(self.palette_asm_selected)
            .cloned()
        else {
            return;
        };
        // Split off the current instruction (everything after the
        // last `;`); replace it with the variant's template.
        let mut prefix = String::new();
        let current = self.palette_bin_query.text();
        if let Some(idx) = current.rfind(';') {
            prefix.push_str(&current[..=idx]);
            prefix.push(' ');
        }
        prefix.push_str(&cand.variant.template);
        self.palette_bin_query.set_text(prefix);
        self.palette_bin_results = None;
        self.palette_bin_match_sources.clear();
        self.palette_bin_error = None;
        self.refresh_palette_asm_candidates();
        cx.notify();
    }

    /// Up/Down within the asm dropdown.
    pub(crate) fn palette_asm_move(&mut self, delta: i32, cx: &mut Context<Self>) {
        if self.palette_asm_candidates.is_empty() {
            return;
        }
        let max = self.palette_asm_candidates.len() - 1;
        let next =
            (self.palette_asm_selected as i32 + delta).clamp(0, max as i32) as usize;
        if next != self.palette_asm_selected {
            self.palette_asm_selected = next;
            cx.notify();
        }
    }

    pub(crate) fn close_palette(&mut self, cx: &mut Context<Self>) {
        if self.palette_open {
            self.palette_open = false;
            // Reset scope on close so the next cmd-F opens a clean
            // bundle-wide search.
            self.palette_scope = None;
            // Closing the palette also bails any in-progress
            // annotation edit — the editor lives inside it.
            self.annotation_edit = None;
            cx.notify();
        }
    }

    /// Open the palette in scoped mode. The header chip shows
    /// `label`, the list shows `scope.entries` (refined by typing).
    /// Esc clears the scope rather than closing the palette
    /// outright.
    pub(crate) fn open_scoped_palette(
        &mut self,
        scope: crate::PaletteScope,
        cx: &mut Context<Self>,
    ) {
        let was_pending = scope.progress.is_some();
        self.palette_scope = Some(scope);
        self.palette_open = true;
        self.palette_focused = true;
        self.palette_query.clear();
        self.palette_selected = 0;
        self.refresh_palette_list();
        cx.notify();
        if was_pending {
            self.spawn_xref_scope_poller(cx);
        }
    }

    /// Tick at ~30 fps while the open scoped palette is still
    /// waiting on a building xref index. Each tick re-checks the
    /// XrefStore and rebuilds the scope's entries when the index
    /// transitions to Ready. Stops once the scope is gone, closed,
    /// or the index is done.
    fn spawn_xref_scope_poller(&self, cx: &mut Context<Self>) {
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(120))
                    .await;
                let stop = this
                    .update(cx, |shell, cx| {
                        shell.refresh_xref_scope_if_pending(cx)
                    })
                    .unwrap_or(true);
                if stop {
                    return;
                }
            }
        })
        .detach();
    }

    /// If the current palette scope is waiting on a building xref
    /// index, peek at the underlying state and rebuild entries when
    /// the index has become Ready. Returns true when the poller
    /// should stop.
    pub(crate) fn refresh_xref_scope_if_pending(
        &mut self,
        cx: &mut Context<Self>,
    ) -> bool {
        use crate::xref::{PaletteScopeSource, XrefIndexState};
        if !self.palette_open {
            return true;
        }
        let Some(scope) = self.palette_scope.as_ref() else { return true };
        if scope.progress.is_none() {
            return true;
        }
        // Nudge the renderer so the progress meter advances even if
        // no transition is happening yet.
        cx.notify();
        let bundle = match self.bundle().cloned() {
            Some(b) => b,
            None => return true,
        };
        let source = scope.source.clone();
        // Pull the relevant slot. Returns (Some(rebuilt_entries),
        // _) on transition to Ready, (None, false) while still
        // building, (None, true) on Failed.
        let (new_entries, failed) = match source {
            PaletteScopeSource::NativeXrefs { artifact, target_addr } => {
                match bundle.xrefs.native.read().clone() {
                    XrefIndexState::Ready(idx) => (
                        Some(build_native_xref_entries(
                            &bundle,
                            &artifact,
                            target_addr,
                            &idx,
                        )),
                        false,
                    ),
                    XrefIndexState::Failed(_) => (None, true),
                    _ => (None, false),
                }
            }
            PaletteScopeSource::DexCallers { method_key } => {
                match bundle.xrefs.dex_callers.read().clone() {
                    XrefIndexState::Ready(idx) => (
                        Some(build_dex_caller_entries(&bundle, &method_key, &idx)),
                        false,
                    ),
                    XrefIndexState::Failed(_) => (None, true),
                    _ => (None, false),
                }
            }
            PaletteScopeSource::DexFieldRefs { field_ref } => {
                match bundle.xrefs.dex_field_refs.read().clone() {
                    XrefIndexState::Ready(idx) => (
                        Some(build_dex_field_entries(&bundle, &field_ref, &idx)),
                        false,
                    ),
                    XrefIndexState::Failed(_) => (None, true),
                    _ => (None, false),
                }
            }
        };
        if let Some(entries) = new_entries {
            if let Some(scope) = self.palette_scope.as_mut() {
                scope.entries = Arc::new(entries);
                scope.progress = None;
            }
            self.refresh_palette_list();
            cx.notify();
            return true;
        }
        if failed {
            if let Some(scope) = self.palette_scope.as_mut() {
                scope.progress = None;
            }
            cx.notify();
            return true;
        }
        false
    }

    /// Clear the current scope without closing the palette. Used as
    /// the first effect of Esc when scoped — Esc on a non-scoped
    /// palette closes it.
    pub(crate) fn clear_palette_scope(&mut self, cx: &mut Context<Self>) {
        if self.palette_scope.is_some() {
            self.palette_scope = None;
            self.palette_query.clear();
            self.palette_selected = 0;
            self.refresh_palette_list();
            cx.notify();
        }
    }

    /// Forward a key event to the appropriate palette TextInput
    /// and run any side-effects (search refresh, result-set
    /// invalidation). Returns `true` if handled.
    pub(crate) fn palette_handle_key(
        &mut self,
        k: &gpui::Keystroke,
        cx: &mut Context<Self>,
    ) -> bool {
        let shift = k.modifiers.shift;
        let cmd = k.modifiers.platform || k.modifiers.control;
        let alt = k.modifiers.alt;
        let key_char = k.key_char.as_deref();
        // In Text mode the same input drives bundle search AND
        // the annotation-edit chip (which keeps annotation_edit
        // set while typing); the differentiating logic happens
        // at commit time.
        let target_is_text = self.palette_mode == crate::PaletteMode::Text
            || self.annotation_edit.is_some();
        let app: &mut gpui::App = &mut *cx;
        let handled = if target_is_text {
            self.palette_query
                .handle_key(&k.key, shift, cmd, alt, key_char, app)
        } else {
            self.palette_bin_query
                .handle_key(&k.key, shift, cmd, alt, key_char, app)
        };
        // Side-effects on real text mutations.
        if target_is_text {
            self.palette_selected = 0;
            self.refresh_palette_list();
        } else {
            self.palette_bin_results = None;
            self.palette_bin_match_sources.clear();
            self.palette_bin_error = None;
            self.palette_selected = 0;
            self.refresh_palette_asm_candidates();
        }
        cx.notify();
        handled
    }

    pub(crate) fn palette_move(&mut self, delta: i32, cx: &mut Context<Self>) {
        // In Binary+Asm mode with no results table yet, Up/Down
        // navigates the autocomplete dropdown instead.
        if self.palette_mode == crate::PaletteMode::Binary
            && self.palette_bin_grammar == crate::BinaryGrammar::Asm
            && self.palette_bin_results.is_none()
            && !self.palette_asm_candidates.is_empty()
        {
            self.palette_asm_move(delta, cx);
            return;
        }
        let len = match self.palette_mode {
            crate::PaletteMode::Text => self.palette_list_len,
            crate::PaletteMode::Binary => self
                .palette_bin_results
                .as_ref()
                .map(|r| r.matches.len())
                .unwrap_or(0),
        };
        if len == 0 {
            return;
        }
        let max = len.saturating_sub(1);
        let next = (self.palette_selected as i32 + delta).clamp(0, max as i32) as usize;
        if next != self.palette_selected {
            self.palette_selected = next;
            match self.palette_mode {
                crate::PaletteMode::Text => {
                    self.palette_list_state.scroll_to_reveal_item(next);
                }
                crate::PaletteMode::Binary => {
                    self.palette_bin_list_state.scroll_to_reveal_item(next);
                }
            }
            cx.notify();
        }
    }

    /// Run the binary-search pattern against the currently
    /// selected artifact. Results land in `palette_bin_results`,
    /// errors in `palette_bin_error`. Always called from the
    /// foreground thread; the scan typically runs in milliseconds
    /// for the kind of pattern a user types interactively.
    pub(crate) fn run_palette_bin_search(&mut self, cx: &mut Context<Self>) {
        use glass_arch_arm::SymbolMap;
        let _ = SymbolMap::default; // touch import for future use
        self.palette_bin_error = None;
        let pattern = self.palette_bin_query.text().to_string();
        // Build per-architecture atom sets. Bytes-grammar
        // patterns are byte-literal so they apply to every
        // architecture uniformly. Asm-grammar patterns may parse
        // as AArch64, ARMv7, or both — we compile against each
        // and only scan the artifacts that match.
        use armv8_encode::container::Architecture;
        let atoms_per_arch: Vec<(Option<Architecture>, Vec<glass_api::Atom>)> =
            match self.palette_bin_grammar {
                crate::BinaryGrammar::Bytes => match glass_api::parse_pattern(&pattern) {
                    Ok(a) => vec![(None, a)],
                    Err(e) => {
                        self.palette_bin_error = Some(format!("{e:#}"));
                        cx.notify();
                        return;
                    }
                },
                crate::BinaryGrammar::Asm => {
                    match glass_api::compile_insn_atoms_for_all_arches(&pattern) {
                        Ok(per_arch) => per_arch
                            .into_iter()
                            .map(|(a, atoms)| (Some(a), atoms))
                            .collect(),
                        Err(e) => {
                            self.palette_bin_error = Some(format!("{e:#}"));
                            cx.notify();
                            return;
                        }
                    }
                }
            };
        let atoms_for_arch = |arch: Architecture| -> Option<&[glass_api::Atom]> {
            atoms_per_arch.iter().find_map(|(a, atoms)| match a {
                None => Some(atoms.as_slice()),
                Some(ar) if *ar == arch => Some(atoms.as_slice()),
                _ => None,
            })
        };
        // Atoms for data-section scans (arch-agnostic byte hits).
        // Use the first compiled set; in the Asm-grammar case
        // that's whichever arch parsed first (typically AArch64
        // when both worked). Data hits are best-effort and the
        // preview always renders as hex, so the choice is fine.
        let data_atoms: &[glass_api::Atom] = atoms_per_arch
            .first()
            .map(|(_, a)| a.as_slice())
            .unwrap_or(&[]);
        let Some(bundle) = self.bundle().cloned() else {
            self.palette_bin_error = Some("no bundle loaded".to_string());
            cx.notify();
            return;
        };
        // Scan every native artifact in the bundle, not just the
        // currently-selected one. Android apps routinely ship the
        // same library for arm64-v8a + armeabi-v7a; a "global"
        // search across both is what users want by default. The
        // `palette_bin_artifact` field stays around as a future
        // filter hook but no longer scopes the scan.
        let mut matches: Vec<glass_api::BinMatch> = Vec::new();
        // Parallel vector: each entry pairs with `matches[i]` and
        // carries the typed `(artifact, section)` so the activate
        // path can route the click back to a real tab even when
        // multiple artifacts have the same section name.
        let mut sources: Vec<(glass_db::ArtifactId, String)> = Vec::new();
        let mut scanned_sections = 0usize;
        let mut total_bytes_scanned = 0usize;
        // Text sections — across every artifact.
        for ((aid, name), text) in bundle.text_sections.iter() {
            // Each text section now carries its artifact's real
            // architecture, so we no longer infer it from the
            // `precomputed` marker (ambiguous since x86 also populates
            // that slot).
            let arch = text.arch;
            let Some(atoms) = atoms_for_arch(arch) else {
                // No atoms compiled for this artifact's arch — skip.
                // Covers an ARMv7 pattern with no AArch64 form against
                // an arm64 lib, and x86 sections (no x86 ASM-pattern
                // compiler yet; hex byte-search still scans them via
                // the arch-agnostic atom set).
                continue;
            };
            let alabel = crate::search::short_artifact_label(&bundle, aid);
            let section_label = format!("{alabel} · {name}");
            let bytes: &[u8] = text.bytes.as_ref();
            // For ARMv7 (variable-width Thumb + literal pools
            // inline with code) raw byte scanning produces many
            // matches that don't correspond to real instruction
            // starts — they may sit mid-instruction inside a
            // Thumb-2 32-bit encoding, or inside a literal pool's
            // 4-byte pointer word. Opening any of those in the
            // listing would either land the cursor on the
            // *containing* code row (confusing) or on a
            // pre-pool branch (very confusing). Build a set of
            // real instruction-start addresses from the
            // precomputed disassembly and filter byte hits to
            // those. AArch64 doesn't need this — every 4-byte
            // aligned word is an instruction or a known data
            // hole that already excluded.
            let insn_starts: Option<std::collections::HashSet<u64>> = text
                .precomputed
                .as_ref()
                .map(|v| {
                    use armv8_encode::mc::InstructionInfo;
                    v.iter().map(|i| i.address()).collect()
                });
            scanned_sections += 1;
            total_bytes_scanned += bytes.len();
            for (start, slice_end) in glass_api::scan_section(atoms, bytes) {
                let abs_end = start + slice_end;
                let addr = text.base + start as u64;
                if let Some(starts) = insn_starts.as_ref() {
                    if !starts.contains(&addr) {
                        continue;
                    }
                }
                let preview = glass_api::build_preview(
                    true,
                    arch,
                    addr,
                    &bytes[start..abs_end.min(bytes.len())],
                );
                matches.push(glass_api::BinMatch {
                    section: section_label.clone(),
                    address: format!("0x{addr:x}"),
                    length: slice_end,
                    preview,
                });
                sources.push((aid.clone(), name.clone()));
            }
        }
        // Data sections (non-text, non-bss, non-debug, non-zero-base).
        // Skipped entirely when `Code only` is checked — the
        // common case where the user is hunting an instruction
        // shape and doesn't want stray ADRP-looking data hits.
        let scan_data = !self.palette_bin_code_only;
        for ((aid, name), data) in bundle.data_sections.iter().filter(|_| scan_data) {
            if data.base == 0 || data.bytes.is_empty() {
                continue;
            }
            if matches!(data.kind, crate::NativeSectionKind::Bss | crate::NativeSectionKind::Debug) {
                continue;
            }
            let alabel = crate::search::short_artifact_label(&bundle, aid);
            let section_label = format!("{alabel} · {name}");
            let bytes: &[u8] = data.bytes.as_ref();
            scanned_sections += 1;
            total_bytes_scanned += bytes.len();
            for (start, slice_end) in glass_api::scan_section(data_atoms, bytes) {
                let abs_end = start + slice_end;
                let addr = data.base + start as u64;
                // arch is irrelevant for non-text matches (the
                // preview always falls through to hex), but we
                // pass it through for signature consistency.
                let preview = glass_api::build_preview(
                    false,
                    armv8_encode::container::Architecture::Aarch64,
                    addr,
                    &bytes[start..abs_end.min(bytes.len())],
                );
                matches.push(glass_api::BinMatch {
                    section: section_label.clone(),
                    address: format!("0x{addr:x}"),
                    length: slice_end,
                    preview,
                });
                sources.push((aid.clone(), name.clone()));
            }
        }
        // Sort matches + sources together so they stay aligned.
        let mut order: Vec<usize> = (0..matches.len()).collect();
        order.sort_by(|&a, &b| {
            matches[a]
                .section
                .cmp(&matches[b].section)
                .then(matches[a].address.cmp(&matches[b].address))
        });
        let matches: Vec<glass_api::BinMatch> = order
            .iter()
            .map(|&i| matches[i].clone())
            .collect();
        let sources: Vec<(glass_db::ArtifactId, String)> = order
            .into_iter()
            .map(|i| sources[i].clone())
            .collect();
        // Stash for the activate path before falling through to
        // the existing post-scan plumbing.
        self.palette_bin_match_sources = sources;
        let total = matches.len();
        if scanned_sections == 0 {
            self.palette_bin_error = Some(format!(
                "no native sections to scan (bundle has {} text + {} data sections)",
                bundle.text_sections.len(),
                bundle.data_sections.len(),
            ));
        } else if total == 0 {
            self.palette_bin_error = Some(format!(
                "no matches across {scanned_sections} sections ({total_bytes_scanned} bytes scanned)"
            ));
        }
        let result = glass_api::BinSearchResult {
            // Global scan — no single artifact to report. Use a
            // placeholder so the renderer's existing field is happy.
            artifact: String::from("(all artifacts)"),
            pattern: pattern.clone(),
            total,
            shown: total,
            matches,
        };
        self.palette_bin_list_state =
            ListState::new(total, ListAlignment::Top, px(2000.));
        self.palette_bin_results = Some(std::sync::Arc::new(result));
        self.palette_selected = 0;
        cx.notify();
    }

    /// Navigate to the currently-selected bin-search result.
    /// Same dispatch as a SearchJump: text-section addresses
    /// open the listing, data-section addresses open the hex
    /// view.
    pub(crate) fn palette_bin_activate(&mut self, cx: &mut Context<Self>) {
        let Some(results) = self.palette_bin_results.clone() else { return };
        let Some(m) = results.matches.get(self.palette_selected) else { return };
        let Some(bundle) = self.bundle().cloned() else { return };
        // The palette scans globally across artifacts, so we don't
        // trust the active `palette_bin_artifact` here — look up
        // the typed `(artifact, raw_section)` we stashed when the
        // match was produced. Without this, a hit in the
        // armeabi-v7a lib would try to open against the
        // arm64-v8a lib's tab key.
        let Some((artifact, section)) =
            self.palette_bin_match_sources.get(self.palette_selected).cloned()
        else {
            return;
        };
        let Ok(addr) = u64::from_str_radix(m.address.trim_start_matches("0x"), 16) else {
            return;
        };
        self.palette_open = false;
        // Text vs data dispatch: ask the bundle which view it is.
        if bundle.text_section_for_addr(&artifact, addr).is_some() {
            self.open_listing_in_new_tab(artifact, section, addr, cx);
        } else {
            self.open_hex_in_new_tab(artifact, section, addr, cx);
        }
    }

    /// Currently-displayed palette entries, taking the scope into
    /// account. When scoped, filter within `scope.entries`; else
    /// query the bundle-wide index. Returned vector is sized to the
    /// palette's display cap.
    pub(crate) fn palette_visible_entries(&self) -> Vec<SearchEntry> {
        const CAP: usize = 50;
        if let Some(scope) = self.palette_scope.as_ref() {
            // Scoped: fixed entry set + fuzzy refinement via the
            // same matching tiers the bundle search uses.
            let q = self.palette_query.text().to_lowercase();
            let mut scored: Vec<(u8, usize, &SearchEntry)> = Vec::new();
            for e in scope.entries.iter() {
                let hay = e.display.to_lowercase();
                let tier = if q.is_empty() {
                    0
                } else if hay.starts_with(&q) {
                    0
                } else if hay.contains(&q) {
                    1
                } else {
                    continue;
                };
                scored.push((tier, e.display.len(), e));
            }
            scored.sort_by_key(|&(tier, len, _)| (tier, len));
            scored
                .into_iter()
                .take(CAP)
                .map(|(_, _, e)| e.clone())
                .collect()
        } else if let Some(idx) = self.search_index.as_ref() {
            idx.filter(self.palette_query.text(), CAP)
                .into_iter()
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    pub(crate) fn palette_activate(&mut self, cx: &mut Context<Self>) {
        // Annotation edit hijacks Enter: commit the typed value as
        // the new rename / comment.
        if self.annotation_edit.is_some() {
            self.commit_annotation_edit(cx);
            return;
        }
        // Binary mode: Enter on the input row runs the scan;
        // Enter on a result row navigates. The render closure
        // calls palette_bin_activate directly on result clicks,
        // so this branch only handles the input-row case (no
        // results yet) by running the search.
        if self.palette_mode == crate::PaletteMode::Binary {
            if self.palette_bin_results.is_some() {
                self.palette_bin_activate(cx);
            } else {
                self.run_palette_bin_search(cx);
            }
            return;
        }
        let results = self.palette_visible_entries();
        let Some(entry) = results.get(self.palette_selected).cloned() else {
            return;
        };
        let jump = entry.jump.clone();
        self.palette_open = false;
        self.palette_scope = None;
        match jump {
            SearchJump::Listing { artifact, section, addr } => {
                self.open_listing_in_new_tab(artifact, section, addr, cx);
            }
            SearchJump::Hex { artifact, section, addr } => {
                self.open_hex_in_new_tab(artifact, section, addr, cx);
            }
            SearchJump::SmaliClass { class_jni } => {
                // Find the leaf with that class JNI and open it.
                let leaf = self.bundle().and_then(|b| {
                    b.resolve(&glass_db::TabState::SmaliClass {
                        class_jni: class_jni.clone(),
                        scroll_line: 0,
                    })
                });
                if let Some(leaf) = leaf {
                    self.open_leaf(leaf, cx);
                }
            }
            SearchJump::SmaliMethodLine { class_jni, line } => {
                // Open the class then scroll to the absolute line.
                let leaf = self.bundle().and_then(|b| {
                    b.resolve(&glass_db::TabState::SmaliClass {
                        class_jni: class_jni.clone(),
                        scroll_line: 0,
                    })
                });
                if let Some(leaf) = leaf {
                    self.goto_smali_method(leaf, line, cx);
                }
            }
            SearchJump::SectionMap { artifact } => {
                let leaf = self.bundle().and_then(|b| {
                    b.resolve(&glass_db::TabState::SectionMap {
                        artifact: artifact.clone(),
                    })
                });
                if let Some(leaf) = leaf {
                    self.open_leaf(leaf, cx);
                }
            }
        }
        cx.notify();
    }

    /// Recompute `palette_list_len` so up/down navigation knows the
    /// number of currently-displayed rows. Takes the scope into
    /// account.
    pub(crate) fn refresh_palette_list(&mut self) {
        let len = self.palette_visible_entries().len();
        if len != self.palette_list_len {
            self.palette_list_state = ListState::new(len, ListAlignment::Top, px(800.));
            self.palette_list_len = len;
        }
        if self.palette_selected >= len {
            self.palette_selected = 0;
        }
    }

    /// Kick off the background index build on first palette open.
    /// Idempotent — does nothing if already built or in progress.
    pub(crate) fn spawn_search_index_build_if_needed(&mut self, cx: &mut Context<Self>) {
        if self.search_index.is_some() || self.search_indexing {
            return;
        }
        let Some(bundle) = self.bundle().cloned() else { return };
        self.search_indexing = true;
        let task = cx.background_executor().spawn(async move {
            crate::search::build_search_index(&bundle)
        });
        cx.spawn(async move |this, cx| {
            let idx = task.await;
            let _ = this.update(cx, |shell, cx| {
                shell.search_index = Some(Arc::new(idx));
                shell.search_indexing = false;
                shell.refresh_palette_list();
                cx.notify();
            });
        })
        .detach();
    }
}
