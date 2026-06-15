//! Byte-level pattern search across native artifact sections.
//!
//! Pattern grammar (full reference in `docs/BinSearch.md`):
//!
//!   - `c0`, `0xc0`         — exact byte literal.
//!   - `e?`, `?f`, `??`     — nibble-level wildcards.
//!   - `*`                  — gap of 0..=32 bytes (default).
//!   - `*(min..max)`        — explicit gap bounds.
//!   - `*(min..)` / `*(..max)` — partial bounds; the other side
//!     defaults to 0 / 32 respectively.
//!
//! Matches don't span sections. The engine runs once per text /
//! data section (excluding bss / debug / zero-base sections, the
//! same filter the listing builder applies). Each match carries
//! a short `preview` string — two decoded instructions joined
//! with " ; " for text sections, the first 8 bytes as hex for
//! data sections — so a table renderer has useful context
//! without a follow-up call.

use anyhow::{anyhow, Context, Result};
use armv8_encode::isa::aarch64;
use serde::Serialize;

use crate::bundle::Bundle;

/// Default upper bound for an unannotated `*` gap atom. Chosen
/// to comfortably cover a basic block (~16 insns × 4 bytes = 64
/// bytes) without making the matcher pathological. Override with
/// `*(0..N)` when you need a longer window.
pub const DEFAULT_GAP_MAX: u32 = 32;

/// Defensive cap on total atom count per pattern. A user
/// pasting a multi-kilobyte hex blob would otherwise quietly
/// turn the matcher into a long-running scan.
const MAX_ATOMS: usize = 1024;

/// One element of a compiled pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Atom {
    /// One byte, masked: a candidate byte `b` matches when
    /// `b & mask == value`.
    Mask { mask: u8, value: u8 },
    /// Bounded gap. Inclusive on both ends.
    Gap { min: u32, max: u32 },
}

#[derive(Serialize, Debug, Clone)]
pub struct BinSearchResult {
    pub artifact: String,
    pub pattern: String,
    pub total: usize,
    pub shown: usize,
    pub matches: Vec<BinMatch>,
}

#[derive(Serialize, Debug, Clone)]
pub struct BinMatch {
    pub section: String,
    /// Match start address as `0x...`.
    pub address: String,
    /// Number of bytes the match consumed.
    pub length: usize,
    /// Pre-formatted preview suitable for a table column:
    /// "mov w0, #1 ; ret" for text sections, "de ad be ef …"
    /// for data sections. Empty when the section bytes are
    /// fully outside this artifact (shouldn't happen).
    pub preview: String,
}

// ---- Parser ---------------------------------------------------

/// Parse a pattern string into a sequence of atoms. Whitespace
/// is the only separator; atoms must be syntactically complete
/// tokens. Errors are user-readable.
pub fn parse_pattern(input: &str) -> Result<Vec<Atom>> {
    let mut atoms = Vec::new();
    for tok in input.split_whitespace() {
        let tok = tok.trim_start_matches("0x");
        if tok.is_empty() {
            continue;
        }
        if let Some(rest) = tok.strip_prefix('*') {
            atoms.push(parse_gap(rest)?);
        } else {
            atoms.push(parse_byte_mask(tok)?);
        }
        if atoms.len() > MAX_ATOMS {
            anyhow::bail!("pattern has more than {MAX_ATOMS} atoms");
        }
    }
    if atoms.is_empty() {
        anyhow::bail!("pattern is empty");
    }
    Ok(atoms)
}

fn parse_byte_mask(tok: &str) -> Result<Atom> {
    if tok.len() != 2 {
        anyhow::bail!(
            "expected a 2-character byte token, got {:?} (use `??` for any \
             byte and `e?` / `?f` for nibble wildcards)",
            tok
        );
    }
    let hi = tok.as_bytes()[0];
    let lo = tok.as_bytes()[1];
    let (hi_mask, hi_val) = nibble_spec(hi)
        .with_context(|| format!("bad high nibble in {tok:?}"))?;
    let (lo_mask, lo_val) = nibble_spec(lo)
        .with_context(|| format!("bad low nibble in {tok:?}"))?;
    Ok(Atom::Mask {
        mask: (hi_mask << 4) | lo_mask,
        value: (hi_val << 4) | lo_val,
    })
}

fn nibble_spec(b: u8) -> Result<(u8, u8)> {
    Ok(match b {
        b'?' => (0x0, 0x0),
        b'0'..=b'9' => (0xf, b - b'0'),
        b'a'..=b'f' => (0xf, 10 + (b - b'a')),
        b'A'..=b'F' => (0xf, 10 + (b - b'A')),
        _ => anyhow::bail!("bad hex character {:?}", b as char),
    })
}

fn parse_gap(rest: &str) -> Result<Atom> {
    if rest.is_empty() {
        return Ok(Atom::Gap { min: 0, max: DEFAULT_GAP_MAX });
    }
    let inner = rest
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .ok_or_else(|| anyhow!("gap must be `*` or `*(min..max)`, got `*{rest}`"))?;
    let (lo_s, hi_s) = inner
        .split_once("..")
        .ok_or_else(|| anyhow!("gap range needs `..`, got `*{rest}`"))?;
    let min: u32 = if lo_s.is_empty() {
        0
    } else {
        lo_s.parse().with_context(|| format!("bad gap min `{lo_s}`"))?
    };
    let max: u32 = if hi_s.is_empty() {
        DEFAULT_GAP_MAX
    } else {
        hi_s.parse().with_context(|| format!("bad gap max `{hi_s}`"))?
    };
    if max < min {
        anyhow::bail!("gap range `{min}..{max}` has max < min");
    }
    if max > 4096 {
        // Hard upper bound — keeps the worst case bounded.
        anyhow::bail!("gap max {max} exceeds 4096; tighten the pattern");
    }
    Ok(Atom::Gap { min, max })
}

// ---- Matcher --------------------------------------------------

/// Try to match `atoms` at `bytes[0..]`. Returns the total
/// number of bytes consumed on success; `None` on failure.
fn matches_at(atoms: &[Atom], bytes: &[u8]) -> Option<usize> {
    fn go(atoms: &[Atom], bytes: &[u8], pos: usize) -> Option<usize> {
        match atoms.split_first() {
            None => Some(pos),
            Some((Atom::Mask { mask, value }, rest)) => {
                if pos < bytes.len() && bytes[pos] & mask == *value {
                    go(rest, bytes, pos + 1)
                } else {
                    None
                }
            }
            Some((Atom::Gap { min, max }, rest)) => {
                let lo = pos.saturating_add(*min as usize);
                let hi = pos
                    .saturating_add(*max as usize)
                    .min(bytes.len());
                if lo > bytes.len() {
                    return None;
                }
                (lo..=hi).find_map(|p| go(rest, bytes, p))
            }
        }
    }
    go(atoms, bytes, 0)
}

/// Scan `section_bytes` for every offset at which the pattern
/// matches. When the first atom is a literal byte (mask 0xff)
/// we use `memchr` to skip non-candidate starts cheaply.
///
/// Returned `(start, slice_end)` pairs are relative to
/// `section_bytes`; `start + slice_end` is the absolute end
/// within the section. Public so glass-ui can drive the same
/// matcher against `LoadedBundle` byte sections without going
/// through the file-loading path.
pub fn scan_section(atoms: &[Atom], section_bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    if section_bytes.is_empty() {
        return out;
    }
    let starts: Box<dyn Iterator<Item = usize>> = match atoms.first() {
        Some(Atom::Mask { mask: 0xff, value }) => {
            // Literal-byte anchor: only offsets where the first
            // byte already matches are worth probing.
            let v = *value;
            Box::new(
                section_bytes
                    .iter()
                    .enumerate()
                    .filter_map(move |(i, b)| (*b == v).then_some(i)),
            )
        }
        _ => Box::new(0..section_bytes.len()),
    };
    for start in starts {
        if let Some(end) = matches_at(atoms, &section_bytes[start..]) {
            out.push((start, end));
        }
    }
    out
}

// ---- Verb impl ------------------------------------------------

impl Bundle {
    /// Search every (or one) section of an artifact for a byte
    /// pattern. See `docs/BinSearch.md` for grammar.
    pub fn bin_search(
        &self,
        artifact_ref: &str,
        pattern: &str,
        section_filter: Option<&str>,
        limit: Option<usize>,
    ) -> Result<BinSearchResult> {
        let art = self
            .artifacts
            .iter()
            .find(|a| {
                a.label == artifact_ref || a.id.to_string().starts_with(artifact_ref)
            })
            .with_context(|| format!("no artifact matches {artifact_ref:?}"))?;
        let atoms = parse_pattern(pattern)?;
        let container = &art.binary.container;
        let arch = container.architecture;
        let mut matches = Vec::new();
        let mut total = 0usize;
        let cap = limit.unwrap_or(usize::MAX);
        for section in &container.sections {
            if let Some(name) = section_filter {
                if section.name != name {
                    continue;
                }
            }
            // Filter rules mirror data_peek / listing: ignore
            // BSS, Debug, and zero-base sections so we don't
            // spend time on file padding or DWARF blobs at
            // synthetic addresses.
            use armv8_encode::container::SectionKind;
            match section.kind {
                SectionKind::Bss | SectionKind::Debug => continue,
                _ => {}
            }
            if section.address == 0 || section.bytes.is_empty() {
                continue;
            }
            let is_text = matches!(section.kind, SectionKind::Text);
            for (start, slice_end) in scan_section(&atoms, &section.bytes) {
                // `slice_end` is relative to the match's slice
                // start; the absolute end in the section is
                // start + slice_end.
                let abs_end = start + slice_end;
                total += 1;
                if matches.len() >= cap {
                    continue;
                }
                let preview = build_preview(
                    is_text,
                    arch,
                    section.address + start as u64,
                    &section.bytes[start..abs_end.min(section.bytes.len())],
                );
                matches.push(BinMatch {
                    section: section.name.clone(),
                    address: format!("0x{:x}", section.address + start as u64),
                    length: slice_end,
                    preview,
                });
            }
        }
        Ok(BinSearchResult {
            artifact: art.id.to_string(),
            pattern: pattern.to_string(),
            total,
            shown: matches.len(),
            matches,
        })
    }
}

/// Pre-formatted preview string for a match slice. Public for
/// the same reason as `scan_section`.
///
/// AArch64 + ARM-mode A32 decode fixed 4-byte instructions; Thumb is
/// variable width and walks `armv7::read_instruction` byte-by-byte.
/// For a non-text match (or anything that doesn't decode cleanly)
/// the fallback is the first 8 bytes as space-separated hex.
pub fn build_preview(
    is_text: bool,
    arch: armv8_encode::container::Architecture,
    addr: u64,
    bytes: &[u8],
) -> String {
    use armv8_encode::container::Architecture;
    if is_text {
        match arch {
            Architecture::Aarch64 => {
                if let Some(s) = build_preview_aarch64(addr, bytes) {
                    return s;
                }
            }
            Architecture::Arm => {
                if let Some(s) = build_preview_armv7(addr, bytes) {
                    return s;
                }
            }
            Architecture::X86_64 | Architecture::X86 => {
                if let Some(s) = build_preview_x86(arch, addr, bytes) {
                    return s;
                }
            }
            Architecture::Other => {}
        }
    }
    bytes
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// AArch64 preview: two fixed-width 32-bit instructions joined with
/// ` ; `. Returns `None` when alignment / length is unusable so the
/// caller can fall through to a hex preview.
/// x86/x86_64 preview. Linear-sweep up to two instructions from
/// `bytes` at `addr` in the architecture's decode width. Falls back to
/// `None` (caller emits hex) when the slice doesn't decode cleanly.
fn build_preview_x86(
    arch: armv8_encode::container::Architecture,
    addr: u64,
    bytes: &[u8],
) -> Option<String> {
    use armv8_encode::isa::x86;
    let bitness = x86::bitness_for_architecture(arch)?;
    let decoded = x86::disassemble_bytes(addr, bytes, bitness).ok()?;
    if decoded.is_empty() {
        return None;
    }
    let parts: Vec<String> = decoded
        .into_iter()
        .take(2)
        .map(|i| glass_arch_arm::DecodedInsn::X86(i).format_text())
        .collect();
    Some(parts.join(" ; "))
}

fn build_preview_aarch64(addr: u64, bytes: &[u8]) -> Option<String> {
    if addr % 4 != 0 || bytes.len() < 4 {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    for i in 0..2 {
        let off = i * 4;
        if off + 4 > bytes.len() {
            break;
        }
        let word = u32::from_le_bytes([
            bytes[off],
            bytes[off + 1],
            bytes[off + 2],
            bytes[off + 3],
        ]);
        let formatted = match aarch64::decode_instruction(addr + off as u64, word) {
            Ok(insn) => glass_arch_arm::DecodedInsn::from(insn).format_text(),
            Err(_) => format!(".word 0x{word:08x}"),
        };
        parts.push(formatted);
    }
    Some(parts.join(" ; "))
}

/// ARMv7 preview. Decode up to two instructions from `bytes`. Thumb
/// (low-bit-set address) walks `read_instruction` for variable
/// width; ARM-mode steps in fixed 4-byte units. Falls back to
/// `None` on the first decode failure so the caller can emit hex.
fn build_preview_armv7(addr: u64, bytes: &[u8]) -> Option<String> {
    use armv8_encode::isa::armv7;
    let thumb = addr & 1 == 1;
    let base_addr = addr & !1u64;
    let mut parts: Vec<String> = Vec::new();
    let mut cursor = 0usize;
    let mut here = base_addr;
    for _ in 0..2 {
        if cursor >= bytes.len() {
            break;
        }
        if thumb {
            let (word, width) = armv7::read_instruction(bytes, cursor).ok()?;
            use armv7::table::ThumbWidth;
            let tw = if width == 4 { ThumbWidth::Word } else { ThumbWidth::Halfword };
            // Use the upstream table matcher to get a decoded row,
            // then project to a DecodedInsn for unified formatting.
            let row = armv7::table_generated::match_generated(word, tw)?;
            let (operands, _unhandled) = armv7::format_decode::decode_operands_from_format(
                row.format, word, here, width,
            );
            let insn = armv7::sweep::ThumbDecodedInstruction {
                address: here,
                word,
                width: tw,
                mnemonic: row.mnemonic,
                operands,
                row: Some(row),
                neon_row: None,
            };
            parts.push(glass_arch_arm::DecodedInsn::Thumb(insn).format_text());
            cursor += width;
            here = here.wrapping_add(width as u64);
        } else {
            if cursor + 4 > bytes.len() {
                break;
            }
            let word = u32::from_le_bytes([
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
            ]);
            let row = armv7::arm::table_generated::match_generated(word)?;
            let (operands, _unhandled) = armv7::arm::format_decode::decode_operands_from_format(
                row.format, word, here,
            );
            let insn = armv7::arm::sweep::ArmDecodedInstruction {
                address: here,
                word,
                mnemonic: row.mnemonic,
                operands,
                row: Some(row),
                neon_row: None,
            };
            parts.push(glass_arch_arm::DecodedInsn::Arm(insn).format_text());
            cursor += 4;
            here = here.wrapping_add(4);
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" ; "))
    }
}

// ---- Tests ----------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_byte_literal() {
        let a = parse_pattern("c0").unwrap();
        assert_eq!(a, vec![Atom::Mask { mask: 0xff, value: 0xc0 }]);
    }

    #[test]
    fn parse_nibble_wildcards() {
        assert_eq!(
            parse_pattern("e? ?f ??").unwrap(),
            vec![
                Atom::Mask { mask: 0xf0, value: 0xe0 },
                Atom::Mask { mask: 0x0f, value: 0x0f },
                Atom::Mask { mask: 0x00, value: 0x00 },
            ]
        );
    }

    #[test]
    fn parse_gap_default_and_bounded() {
        assert_eq!(
            parse_pattern("c0 * c0").unwrap()[1],
            Atom::Gap { min: 0, max: DEFAULT_GAP_MAX }
        );
        assert_eq!(
            parse_pattern("c0 *(2..16) c0").unwrap()[1],
            Atom::Gap { min: 2, max: 16 }
        );
        assert_eq!(
            parse_pattern("c0 *(4..) c0").unwrap()[1],
            Atom::Gap { min: 4, max: DEFAULT_GAP_MAX }
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_pattern("").is_err());
        assert!(parse_pattern("zz").is_err());
        assert!(parse_pattern("c").is_err());
        assert!(parse_pattern("*(10..5) c0").is_err());
    }

    #[test]
    fn match_literal_sequence() {
        // `end` is relative to the match's slice start, so a
        // 4-byte pattern matches with end == 4.
        let p = parse_pattern("c0 03 5f d6").unwrap();
        let bytes: &[u8] = &[0x00, 0xc0, 0x03, 0x5f, 0xd6, 0xff];
        let hits = scan_section(&p, bytes);
        assert_eq!(hits, vec![(1, 4)]);
    }

    #[test]
    fn match_with_gap() {
        let p = parse_pattern("aa * bb").unwrap();
        let bytes: &[u8] = &[0xaa, 0x00, 0x00, 0xbb];
        let hits = scan_section(&p, bytes);
        // `aa` consumes 1, then gap (2 bytes), then `bb` (1). 4 total.
        assert_eq!(hits, vec![(0, 4)]);
    }

    #[test]
    fn match_nibble_wildcard() {
        let p = parse_pattern("e?").unwrap();
        let bytes: &[u8] = &[0xe0, 0xe7, 0xef, 0xf0];
        let hits = scan_section(&p, bytes);
        // Three matches, one each for 0xe0, 0xe7, 0xef.
        assert_eq!(hits.len(), 3);
    }
}
