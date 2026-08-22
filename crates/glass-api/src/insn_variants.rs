//! Variant index for instruction autocomplete (Phase B).
//!
//! Walks `armv8_encode::iter_opcodes()` (AArch64) and the ARMv7
//! Thumb + A32 upstream tables once at first use and produces a
//! list of `Variant`s — one per opcode-table entry, filtered to
//! entries that have a usable display form.
//!
//! Each `Variant` carries enough metadata to drive the palette
//! autocomplete dropdown:
//!
//! - `isa`: which ISA the variant belongs to (AArch64, ARM Thumb,
//!   or ARM A32). The matcher uses this to gate operand-shape
//!   compatibility (a typed `r1` token kills AArch64 variants;
//!   a typed `w0` token kills ARMv7 variants).
//! - `mnemonic`: the user-facing base mnemonic.
//! - `cond_suffix_allowed`: true for ARMv7 rows that accept a
//!   condition-code suffix on the mnemonic (`bxeq`, `moveq`).
//!   The matcher uses this to grow the prefix-acceptance set;
//!   the template renders the conditional shape as `mnem<cond>`.
//! - `slots`: a `SlotSpec` per operand position — used both to
//!   render the template (`mov <Wd>, <Wm>`) and to test whether
//!   user-typed text could fit this slot.
//! - `template`: precomputed display string. Shown verbatim.
//!
//! Slot specs are deliberately coarse — autocomplete is about
//! UX, not encoding correctness. Encoding goes through the real
//! encoder once the user commits a fully-concrete pattern.

use armv8_encode::isa::aarch64::{iter_opcodes, Aarch64Opcode, Aarch64Opnd};
use armv8_encode::isa::armv7::arm::table_generated::ARM_OPCODE_TABLE_GENERATED;
use armv8_encode::isa::armv7::table_generated::THUMB_OPCODE_TABLE_GENERATED;
use std::sync::OnceLock;

/// Which ISA produced this variant. Used by the matcher to
/// reject operand-token shapes that can't possibly fit (a typed
/// `r1` rules out every AArch64 variant; a typed `w0` rules out
/// every ARMv7 variant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariantIsa {
    Aarch64,
    ArmThumb,
    ArmA32,
}

/// A user-visible instruction variant.
#[derive(Debug, Clone)]
pub struct Variant {
    pub isa: VariantIsa,
    pub mnemonic: &'static str,
    /// True iff this variant accepts an optional 2-letter
    /// condition-code suffix on its mnemonic (`bxeq`, `moveq`).
    /// Only ever true for ARMv7 variants.
    pub cond_suffix_allowed: bool,
    pub slots: Vec<SlotSpec>,
    pub template: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotSpec {
    // ---- AArch64 slot kinds ----
    /// GP register (either W- or X-class — armv8-encode picks
    /// the size at encode time from the supplied register). `sp`
    /// = true means SP / WSP is allowed in this slot.
    Gp { sp: bool },
    /// FP register, family selected by suffix in the user's input.
    FpReg,
    /// SIMD vector register (V<n>.<arr>).
    VecReg,
    /// Generic immediate (any width).
    Imm,
    /// PC-relative branch / address target — accepts a hex address.
    PcRel,
    /// Memory operand `[xN, ...]`.
    Mem,
    /// Condition code (`eq`, `ne`, …).
    Cond,
    /// System operand (sysreg name, barrier name, …).
    System,
    /// Anything else — slot is opaque, rendered as `<arg>`.
    Other,

    // ---- ARMv7 slot kinds ----
    /// Arm GP register (r0..r15, sp, lr, pc). `sp = true` flags
    /// the slot as one of the SP-permitting forms (purely
    /// informative; the matcher accepts SP/LR/PC in either kind
    /// to stay tolerant during typing).
    ArmGp { sp: bool },
    /// Arm immediate (`#imm`).
    ArmImm,
    /// Arm memory operand (`[rN, #imm]`).
    ArmMem,
    /// Arm register list (`{r4-r7, lr}`).
    ArmRegList,
    /// Arm condition code consumed as an operand (rare — most
    /// conditional Arm/Thumb forms bake the condition into the
    /// mnemonic suffix instead).
    ArmCond,
    /// Arm shifted register operand (`r0, lsl #2`).
    ArmShifted,
    /// Arm PC-relative branch target.
    ArmBranch,
}

impl SlotSpec {
    /// Placeholder text rendered in the template + dropdown.
    pub fn placeholder(self) -> &'static str {
        match self {
            SlotSpec::Gp { sp: false } => "x",
            SlotSpec::Gp { sp: true } => "x|sp",
            SlotSpec::FpReg => "<F>",
            SlotSpec::VecReg => "<V>",
            SlotSpec::Imm => "*",
            SlotSpec::PcRel => "*",
            SlotSpec::Mem => "[x]",
            SlotSpec::Cond => "<cond>",
            SlotSpec::System => "<sys>",
            SlotSpec::Other => "*",

            SlotSpec::ArmGp { sp: false } => "r",
            SlotSpec::ArmGp { sp: true } => "r|sp",
            SlotSpec::ArmImm => "#imm",
            SlotSpec::ArmMem => "[r, #imm]",
            SlotSpec::ArmRegList => "{regs}",
            SlotSpec::ArmCond => "<cond>",
            SlotSpec::ArmShifted => "r, lsl #*",
            SlotSpec::ArmBranch => "*",
        }
    }

    /// Best-effort classification of a single `Aarch64Opnd`.
    fn from_opnd(o: Aarch64Opnd, _mnem: &str) -> Self {
        use Aarch64Opnd::*;
        match o {
            Nil => SlotSpec::Other,
            Rd | Rn | Rm | Rt | Rt2 | Rs | Ra | RtSys | RmExt | RmSft | RmLow => {
                SlotSpec::Gp { sp: false }
            }
            RdSp | RnSp => SlotSpec::Gp { sp: true },
            Pairreg => SlotSpec::Other,
            Fd | Fn | Fm | Fa | Ft | Ft2 | Sd | Sn | Sm => SlotSpec::FpReg,
            Vd | Vn | Vm | VdD1 | VnD1 | Ed | En | Em | Lvn | Lvt | LvtAl | Let => {
                SlotSpec::VecReg
            }
            Cn | Cm => SlotSpec::System,
            Idx | ImmVlsl | ImmVlsr | SimdImm | SimdImmSft | SimdFpimm | ShllImm | Imm0
            | Fpimm0 | Fpimm | Immr | Imms | Width | Imm | Uimm3Op1 | Uimm3Op2 | Uimm4
            | Uimm7 | BitNum | Exc | CcmpImm | Nzcv | Limm | Aimm | Half | Fbits | ImmMov => {
                SlotSpec::Imm
            }
            Cond | Cond1 => SlotSpec::Cond,
            AddrAdrp | AddrPcrel14 | AddrPcrel19 | AddrPcrel21 | AddrPcrel26 => SlotSpec::PcRel,
            AddrSimple | AddrRegoff | AddrSimm7 | AddrSimm9 | AddrSimm92 | AddrUimm12
            | SimdAddrSimple | SimdAddrPost => SlotSpec::Mem,
            Sysreg | Pstatefield | SysregAt | SysregDc | SysregIc | SysregTlbi | Barrier
            | BarrierIsb | Prfop | BarrierPsb => SlotSpec::System,
        }
    }

    /// True for AArch64-specific slot kinds. The matcher uses
    /// this to reject ARMv7 register tokens (`r0`, `sp`, `lr`,
    /// `pc`) before they hit slot-specific predicates.
    pub fn is_aarch64(self) -> bool {
        matches!(
            self,
            SlotSpec::Gp { .. }
                | SlotSpec::FpReg
                | SlotSpec::VecReg
                | SlotSpec::Imm
                | SlotSpec::PcRel
                | SlotSpec::Mem
                | SlotSpec::Cond
                | SlotSpec::System
                | SlotSpec::Other
        )
    }

    /// True for ARMv7-specific slot kinds.
    pub fn is_armv7(self) -> bool {
        matches!(
            self,
            SlotSpec::ArmGp { .. }
                | SlotSpec::ArmImm
                | SlotSpec::ArmMem
                | SlotSpec::ArmRegList
                | SlotSpec::ArmCond
                | SlotSpec::ArmShifted
                | SlotSpec::ArmBranch
        )
    }
}

fn build_template(mnemonic: &str, cond_suffix: bool, slots: &[SlotSpec]) -> String {
    let mut out = mnemonic.to_string();
    if cond_suffix {
        out.push_str("<cond>");
    }
    for (i, s) in slots.iter().enumerate() {
        out.push(if i == 0 { ' ' } else { ',' });
        if i != 0 {
            out.push(' ');
        }
        out.push_str(s.placeholder());
    }
    out
}

fn make_aarch64_variant(op: &Aarch64Opcode) -> Variant {
    let mnemonic = op.mnemonic();
    let slots: Vec<SlotSpec> = op
        .operands()
        .into_iter()
        .filter(|o| !matches!(o, Aarch64Opnd::Nil))
        .map(|o| SlotSpec::from_opnd(o, mnemonic))
        .collect();
    let template = build_template(mnemonic, false, &slots);
    Variant {
        isa: VariantIsa::Aarch64,
        mnemonic,
        cond_suffix_allowed: false,
        slots,
        template,
    }
}

/// Classify one binutils Thumb/ARM format escape into a
/// `SlotSpec`. Returns `None` for display-only escapes (cond
/// printers, decorative chars). Mirrors
/// `insn_pattern_armv7::format_slot_kinds`, but expressed as
/// per-escape so we can build the variant slot list directly.
struct ArmFormatWalker<'a> {
    bytes: &'a [u8],
    i: usize,
    arm_mode: bool,
}

impl<'a> ArmFormatWalker<'a> {
    fn new(format: &'a str, arm_mode: bool) -> Self {
        Self {
            bytes: format.as_bytes(),
            i: 0,
            arm_mode,
        }
    }

    /// Walk the format string. Returns the operand-slot list
    /// AND a flag saying whether a bare `%c` was seen (i.e. the
    /// mnemonic accepts a conditional suffix).
    fn collect(mut self) -> (Vec<SlotSpec>, bool) {
        let mut out = Vec::new();
        let mut cond_suffix = false;
        while self.i < self.bytes.len() {
            if self.bytes[self.i] != b'%' {
                self.i += 1;
                continue;
            }
            self.i += 1;
            if self.i >= self.bytes.len() {
                break;
            }
            // Display wrappers %{X:...%} — recurse over inner.
            if self.bytes[self.i] == b'{' {
                let inner_start = self.i + 1;
                let mut j = inner_start;
                while j + 1 < self.bytes.len() {
                    if self.bytes[j] == b'%' && self.bytes[j + 1] == b'}' {
                        break;
                    }
                    j += 1;
                }
                let inner_text = if inner_start + 2 <= j {
                    std::str::from_utf8(&self.bytes[inner_start + 2..j]).unwrap_or("")
                } else {
                    ""
                };
                let (inner_slots, inner_cond) =
                    ArmFormatWalker::new(inner_text, self.arm_mode).collect();
                out.extend(inner_slots);
                cond_suffix |= inner_cond;
                self.i = j + 2;
                continue;
            }
            let bf_start = self.i;
            while self.i < self.bytes.len()
                && (self.bytes[self.i].is_ascii_digit() || self.bytes[self.i] == b'-')
            {
                self.i += 1;
            }
            let has_bf = self.i > bf_start;
            if self.i >= self.bytes.len() {
                break;
            }
            let code = self.bytes[self.i];
            self.i += 1;
            // Modifier suffixes — skip the following 1-2 chars.
            match code {
                b'\'' | b'`' => {
                    if self.i < self.bytes.len() {
                        self.i += 1;
                    }
                    continue;
                }
                b'?' => {
                    if self.i + 1 < self.bytes.len() {
                        self.i += 2;
                    }
                    continue;
                }
                _ => {}
            }
            // Bitfielded condition (e.g. %8-11c) consumes a
            // Condition slot in both modes.
            if code == b'c' && has_bf {
                out.push(SlotSpec::ArmCond);
                continue;
            }
            // Bare %c — display-only in Thumb (just prints the
            // suffix), real operand in ARM mode. Either way it
            // signals "this mnemonic accepts a conditional
            // suffix on the user-typed text".
            if code == b'c' && !has_bf {
                cond_suffix = true;
                continue;
            }
            // Pure display escapes (no bitfield).
            if !has_bf && matches!(code, b'C' | b'x' | b'X' | b'%' | b'p' | b't' | b'q') {
                continue;
            }
            if !has_bf && matches!(code, b'w' | b'W') {
                continue;
            }
            let slot = match code {
                b'r' | b'R' | b'T' | b'D' => Some(SlotSpec::ArmGp { sp: false }),
                b'S' if has_bf => Some(SlotSpec::ArmGp { sp: false }),
                // 32-bit %S (no bf) is a shifted register operand.
                b'S' => Some(SlotSpec::ArmShifted),
                b'd' | b'W' | b'H' | b'x' | b'X' | b'I' | b'J' | b'V' | b'e' | b'E' | b'U'
                | b'K' => Some(SlotSpec::ArmImm),
                b'B' | b'b' => Some(SlotSpec::ArmBranch),
                b'a' if has_bf => Some(SlotSpec::ArmBranch),
                b'M' | b'N' | b'O' => Some(SlotSpec::ArmRegList),
                b'a' | b's' | b'o' => Some(SlotSpec::ArmMem),
                b'L' | b'F' | b'm' | b'n' => Some(SlotSpec::Other),
                _ => Some(SlotSpec::Other),
            };
            if let Some(s) = slot {
                out.push(s);
            }
        }
        (out, cond_suffix)
    }
}

fn make_armv7_thumb_variants(out: &mut Vec<Variant>) {
    for row in THUMB_OPCODE_TABLE_GENERATED.iter() {
        let mnemonic = row.mnemonic.as_str();
        let (slots, cond_suffix) = ArmFormatWalker::new(row.format, false).collect();
        let template = build_template(mnemonic, cond_suffix, &slots);
        out.push(Variant {
            isa: VariantIsa::ArmThumb,
            mnemonic,
            cond_suffix_allowed: cond_suffix,
            slots,
            template,
        });
    }
}

fn make_armv7_arm_variants(out: &mut Vec<Variant>) {
    for row in ARM_OPCODE_TABLE_GENERATED.iter() {
        let mnemonic = row.mnemonic.as_str();
        let (slots, cond_suffix) = ArmFormatWalker::new(row.format, true).collect();
        let template = build_template(mnemonic, cond_suffix, &slots);
        out.push(Variant {
            isa: VariantIsa::ArmA32,
            mnemonic,
            cond_suffix_allowed: cond_suffix,
            slots,
            template,
        });
    }
}

static VARIANTS: OnceLock<Vec<Variant>> = OnceLock::new();

/// Build (or fetch) the full variant index. Built lazily on
/// first call; subsequent calls reuse the cached `Vec`.
pub fn variants() -> &'static [Variant] {
    VARIANTS
        .get_or_init(|| {
            let mut v: Vec<Variant> = iter_opcodes().map(make_aarch64_variant).collect();
            make_armv7_thumb_variants(&mut v);
            make_armv7_arm_variants(&mut v);
            v
        })
        .as_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_index_is_populated() {
        let v = variants();
        assert!(
            v.len() > 1500,
            "expected thousands of variants across ISAs, got {}",
            v.len()
        );
    }

    #[test]
    fn ret_variant_has_one_x_slot() {
        let v = variants();
        let ret = v
            .iter()
            .find(|v| v.mnemonic == "ret" && v.isa == VariantIsa::Aarch64)
            .expect("ret in table");
        assert_eq!(ret.slots.len(), 1, "ret takes exactly Rn");
        assert!(matches!(ret.slots[0], SlotSpec::Gp { .. }));
    }

    #[test]
    fn mov_variants_exist() {
        let v = variants();
        let movs: Vec<_> = v.iter().filter(|v| v.mnemonic == "mov").collect();
        assert!(!movs.is_empty(), "mov should have variants");
    }

    #[test]
    fn arm_mov_present() {
        let v = variants();
        let armv7_movs: Vec<_> = v
            .iter()
            .filter(|v| {
                v.mnemonic == "mov"
                    && matches!(v.isa, VariantIsa::ArmThumb | VariantIsa::ArmA32)
            })
            .collect();
        assert!(!armv7_movs.is_empty(), "ARMv7 mov variants should exist");
    }

    #[test]
    fn arm_push_has_reglist() {
        let v = variants();
        let pushes: Vec<_> = v
            .iter()
            .filter(|v| {
                v.mnemonic == "push"
                    && matches!(v.isa, VariantIsa::ArmThumb | VariantIsa::ArmA32)
            })
            .collect();
        assert!(!pushes.is_empty(), "ARMv7 push exists");
        assert!(
            pushes
                .iter()
                .any(|p| p.slots.iter().any(|s| matches!(s, SlotSpec::ArmRegList))),
            "push should have a register-list slot"
        );
    }
}
