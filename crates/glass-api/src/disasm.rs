//! Disassembly verbs — linear sweep, per-function, single-word decode.

use anyhow::{Context, Result};
use armv8_encode::container::{Architecture, Container, SectionKind};
use armv8_encode::isa::aarch64;
use armv8_encode::isa::x86;
use glass_arch_arm::{format as fmt, DecodedInsn, SymbolMap};
use serde::Serialize;

use crate::bundle::Bundle;

#[derive(Serialize, Debug, Clone)]
pub struct DisasmListing {
    pub artifact: String,
    pub section: String,
    pub base_address: String,
    pub total_instructions: usize,
    pub shown: usize,
    pub rows: Vec<DisasmRow>,
}

#[derive(Serialize, Debug, Clone)]
pub struct DisasmRow {
    pub address: String,
    pub bytes: String,
    pub mnemonic: String,
    pub operands: String,
    /// Only populated when the row's address starts a known symbol.
    pub symbol: Option<String>,
    /// Resolved branch / ADRP target text — e.g. "foo+0x4" or `None`.
    pub comment: Option<String>,
    pub undecoded: bool,
}

impl Bundle {
    /// Linear sweep over a text section. Picks the first text
    /// section in `artifact_ref` when `section_filter` is None.
    /// `limit` caps the number of rows; subsequent rows are
    /// dropped silently (the `shown` field carries the actual
    /// count and `total_instructions` the section's instruction
    /// count).
    pub fn disasm(
        &self,
        artifact_ref: &str,
        section_filter: Option<&str>,
        limit: Option<usize>,
    ) -> Result<DisasmListing> {
        let art = self
            .artifacts
            .iter()
            .find(|a| {
                a.label == artifact_ref
                    || a.id.to_string().starts_with(artifact_ref)
            })
            .with_context(|| format!("no artifact matches {artifact_ref:?}"))?;
        let container = &art.binary.container;
        // The AArch64 sweep decodes fixed 4-byte words; ARMv7 and x86
        // need their own paths. Anything the ISA layer can't decode
        // (`Other`) has no meaningful linear-sweep listing — refuse it
        // and point at the byte view, mirroring the GUI's hex routing.
        if matches!(container.architecture, Architecture::Other) {
            anyhow::bail!(
                "artifact {:?} is an architecture Glass can't disassemble \
                 (supported: AArch64, ARMv7, x86, x86_64). Inspect its \
                 bytes with `sections` / the GUI hex viewer instead.",
                art.label,
            );
        }
        let section = pick_text_section(container, section_filter)
            .with_context(|| {
                if let Some(name) = section_filter {
                    format!("section {name:?} not found / not text")
                } else {
                    "no text section in this artifact".to_string()
                }
            })?;
        let symbols = SymbolMap::build(container);
        let cap = limit.unwrap_or(usize::MAX);
        // x86/x86_64 is variable-length: decode the stream rather than
        // chunking by 4. ARM-family stays on the fixed-width sweep.
        let (total_instructions, rows) = match container.architecture {
            Architecture::X86_64 | Architecture::X86 => {
                sweep_section_x86(container.architecture, section, &symbols, cap)
            }
            _ => {
                let total = section.bytes.len() / 4;
                (total, sweep_section(section, &symbols, cap))
            }
        };
        let shown = rows.len();
        Ok(DisasmListing {
            artifact: art.id.to_string(),
            section: section.name.clone(),
            base_address: format!("0x{:x}", section.address),
            total_instructions,
            shown,
            rows,
        })
    }
}

fn pick_text_section<'a>(
    container: &'a Container,
    name: Option<&str>,
) -> Option<&'a armv8_encode::container::Section> {
    container
        .sections
        .iter()
        .find(|s| matches!(s.kind, SectionKind::Text) && name.is_none_or(|n| s.name == n))
}

fn sweep_section(
    section: &armv8_encode::container::Section,
    symbols: &SymbolMap,
    cap: usize,
) -> Vec<DisasmRow> {
    let base = section.address;
    let bytes: &[u8] = &section.bytes;
    let n = bytes.len() / 4;
    let mut rows = Vec::with_capacity(n.min(cap));
    for i in 0..n {
        if rows.len() >= cap {
            break;
        }
        let addr = base + (i as u64) * 4;
        let word = u32::from_le_bytes([
            bytes[i * 4],
            bytes[i * 4 + 1],
            bytes[i * 4 + 2],
            bytes[i * 4 + 3],
        ]);
        let symbol = symbols
            .at(addr)
            .map(|s| s.display_name.clone());
        match aarch64::decode_instruction(addr, word) {
            Ok(insn) => {
                let mnemonic = fmt::mnemonic_chunk(&insn).text;
                let operands = fmt::operands_chunks(&insn)
                    .iter()
                    .map(|c| c.text.as_str())
                    .collect::<Vec<_>>()
                    .join("");
                let comment = fmt::primary_address_operand(&insn).and_then(|t| {
                    let sym = symbols.covering(t)?;
                    let off = t - sym.address;
                    Some(if off == 0 {
                        sym.display_name.clone()
                    } else {
                        format!("{}+0x{off:x}", sym.display_name)
                    })
                });
                rows.push(DisasmRow {
                    address: format!("0x{:016x}", addr),
                    bytes: format!(
                        "{:02x} {:02x} {:02x} {:02x}",
                        bytes[i * 4],
                        bytes[i * 4 + 1],
                        bytes[i * 4 + 2],
                        bytes[i * 4 + 3],
                    ),
                    mnemonic,
                    operands,
                    symbol,
                    comment,
                    undecoded: false,
                });
            }
            Err(_) => {
                rows.push(DisasmRow {
                    address: format!("0x{:016x}", addr),
                    bytes: format!(
                        "{:02x} {:02x} {:02x} {:02x}",
                        bytes[i * 4],
                        bytes[i * 4 + 1],
                        bytes[i * 4 + 2],
                        bytes[i * 4 + 3],
                    ),
                    mnemonic: ".word".to_string(),
                    operands: format!("0x{word:08x}"),
                    symbol,
                    comment: None,
                    undecoded: true,
                });
            }
        }
    }
    rows
}

/// Variable-length sweep for x86/x86_64. Returns `(total_instruction
/// count, capped rows)`. iced decodes the section as one contiguous
/// stream; if a mid-section byte fails to decode (data/padding mixed
/// into `.text`), we keep the valid prefix rather than dropping the
/// whole listing. Branch and RIP-relative targets are resolved through
/// the symbol map for the comment column.
fn sweep_section_x86(
    arch: Architecture,
    section: &armv8_encode::container::Section,
    symbols: &SymbolMap,
    cap: usize,
) -> (usize, Vec<DisasmRow>) {
    let Some(bitness) = x86::bitness_for_architecture(arch) else {
        return (0, Vec::new());
    };
    let base = section.address;
    let bytes: &[u8] = &section.bytes;
    let decoded = match x86::disassemble_bytes(base, bytes, bitness) {
        Ok(d) => d,
        // `disassemble_bytes` errors on the first invalid byte; re-decode
        // the valid prefix [base, failure) so we still show real code.
        Err(x86::DisassembleError::DecodeFailed { address, .. }) => {
            let off = address.saturating_sub(base) as usize;
            x86::disassemble_bytes(base, &bytes[..off.min(bytes.len())], bitness)
                .unwrap_or_default()
        }
    };
    let total = decoded.len();
    let mut rows = Vec::with_capacity(total.min(cap));
    for insn in decoded.into_iter().take(cap) {
        let addr = insn.address;
        let off = (addr - base) as usize;
        let end = (off + insn.size_bytes() as usize).min(bytes.len());
        let bytes_str = bytes[off..end]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let symbol = symbols.at(addr).map(|s| s.display_name.clone());
        let di = DecodedInsn::X86(insn);
        // Resolve a direct branch target first, else a RIP-relative
        // data reference, into a "sym+0xNN" comment.
        let comment = di.branch_target().or_else(|| di.pcrel_target()).and_then(|t| {
            let sym = symbols.covering(t)?;
            let off = t - sym.address;
            Some(if off == 0 {
                sym.display_name.clone()
            } else {
                format!("{}+0x{off:x}", sym.display_name)
            })
        });
        let line = di.format_text();
        let (mnemonic, operands) = match line.split_once(' ') {
            Some((m, rest)) => (m.to_string(), rest.to_string()),
            None => (line, String::new()),
        };
        rows.push(DisasmRow {
            address: format!("0x{addr:016x}"),
            bytes: bytes_str,
            mnemonic,
            operands,
            symbol,
            comment,
            undecoded: false,
        });
    }
    (total, rows)
}

// ---- single-word decode ----------------------------------------------------

#[derive(Serialize, Debug, Clone)]
pub struct DecodeResult {
    pub word: String,
    pub mnemonic: String,
    pub operands: String,
    pub undecoded: bool,
}

/// Decode one 32-bit AArch64 instruction word. `addr` is the
/// instruction's address — affects PC-relative branch decoding.
pub fn decode_word(word: u32, addr: u64) -> DecodeResult {
    match aarch64::decode_instruction(addr, word) {
        Ok(insn) => DecodeResult {
            word: format!("0x{word:08x}"),
            mnemonic: fmt::mnemonic_chunk(&insn).text,
            operands: fmt::operands_chunks(&insn)
                .iter()
                .map(|c| c.text.as_str())
                .collect::<Vec<_>>()
                .join(""),
            undecoded: false,
        },
        Err(_) => DecodeResult {
            word: format!("0x{word:08x}"),
            mnemonic: ".word".to_string(),
            operands: format!("0x{word:08x}"),
            undecoded: true,
        },
    }
}
