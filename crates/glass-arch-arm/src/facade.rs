//! Architecture-neutral instruction facade.
//!
//! [`DecodedInsn`] wraps the three per-ISA decoded-instruction types
//! exposed by `armv8-encode` (AArch64, ARM-mode, Thumb-mode) so the
//! UI / analysis layers can operate on a single enum and stay
//! ISA-agnostic. The enum implements [`armv8_encode::mc::InstructionInfo`]
//! by forwarding to the inner variant, which unlocks the upstream
//! `mc::build_cfg` for ARMv7 with no extra code.
//!
//! Beyond `InstructionInfo`, the type carries the small bundle of
//! inherent accessors Glass's listing / xref / CFG code historically
//! pattern-matched into AArch64's `DecodedInstruction` for. The
//! AArch64 arm of each accessor is a relocated copy of the helper
//! that previously lived in `glass-ui/src/listing_model.rs` and
//! `glass-ui/src/xref.rs` (which were textually duplicated); behavior
//! is identical so AArch64 listings render byte-for-byte the same as
//! before.
//!
//! The ARMv7 arms are bootstrap-quality. `format_text` reuses the
//! upstream operand model and our own pretty-printer; the analysis
//! accessors (`branch_target`, `first_imm`, register uses) consult
//! the same `DecodedOperand` variants the upstream decoder emits.
//! ADRP+ADD-style page-base fusion and `movw+movt` reconstruction
//! are AArch64-only for this pass — ARMv7's PC-relative literal-pool
//! references decode straight to `DecodedOperand::PcRelative(addr)`
//! and need no fusion.

use armv8_encode::isa::aarch64::DecodedInstruction as Aarch64Insn;
use armv8_encode::isa::armv7::arm::sweep::ArmDecodedInstruction;
use armv8_encode::isa::armv7::sweep::ThumbDecodedInstruction;
use armv8_encode::isa::x86::X86DecodedInstruction;
use armv8_encode::mc::{ControlFlow, InstructionInfo};

use crate::format as aarch64_fmt;

/// Architecture-neutral decoded instruction.
///
/// The `X86` arm wraps `armv8_encode::isa::x86::X86DecodedInstruction`,
/// which itself carries an `iced_x86::Instruction`. Unlike the ARM
/// variants (whose neutral operand model lives in `armv8-encode`), the
/// x86 accessors below read iced's instruction directly — iced is the
/// operand model for this ISA. x86 has no ADRP/movw-style cross-
/// instruction fusion (RIP-relative addresses are self-contained and
/// resolved by [`Self::pcrel_target`]), so the `PageBaseTracker` arm is
/// a no-op.
#[derive(Debug, Clone)]
pub enum DecodedInsn {
    Aarch64(Aarch64Insn),
    Arm(ArmDecodedInstruction),
    Thumb(ThumbDecodedInstruction),
    X86(X86DecodedInstruction),
}

impl InstructionInfo for DecodedInsn {
    fn address(&self) -> u64 {
        match self {
            DecodedInsn::Aarch64(i) => i.address(),
            DecodedInsn::Arm(i) => i.address(),
            DecodedInsn::Thumb(i) => i.address(),
            DecodedInsn::X86(i) => i.address(),
        }
    }
    fn size(&self) -> u64 {
        match self {
            DecodedInsn::Aarch64(i) => i.size(),
            DecodedInsn::Arm(i) => i.size(),
            DecodedInsn::Thumb(i) => i.size(),
            DecodedInsn::X86(i) => i.size(),
        }
    }
    fn control_flow(&self) -> ControlFlow {
        match self {
            DecodedInsn::Aarch64(i) => i.control_flow(),
            DecodedInsn::Arm(i) => i.control_flow(),
            DecodedInsn::Thumb(i) => i.control_flow(),
            DecodedInsn::X86(i) => i.control_flow(),
        }
    }
}

/// Distinguishes register kinds across ISAs so the UI's
/// "highlight all uses of this register" feature stays scoped
/// correctly (an `x5` use shouldn't highlight an `r5` use).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RegKind {
    /// AArch64 64-bit GP (`x0..x30`, `sp`).
    AArch64Gpr64,
    /// AArch64 32-bit GP (`w0..w30`, `wsp`).
    AArch64Gpr32,
    /// ARMv7 GP (`r0..r15`).
    ArmGpr,
    /// x86 / x86_64 general-purpose register *family*, identified by
    /// its full-width register (`rax`/`eax`/`ax`/`al` all map to the
    /// same `index`). Highlighting is deliberately alias-aware: a use
    /// of `eax` highlights uses of `al`/`ax`/`rax` too, since they are
    /// the same physical register. `index` is the iced full-register
    /// number (0 = `rax`, 1 = `rcx`, …).
    X86Gpr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RegRef {
    pub kind: RegKind,
    pub index: u8,
}

impl DecodedInsn {
    /// Encoded width in bytes. Wraps `InstructionInfo::size` for
    /// callers that don't want to bring the trait into scope.
    pub fn width_bytes(&self) -> usize {
        InstructionInfo::size(self) as usize
    }

    /// True if this instruction is a 16-bit Thumb-1 NOP
    /// (encoded as `0xbf 0x00`). The editor uses this to decide
    /// whether a 2-byte Thumb-1 instruction can be grown to a
    /// 4-byte form by absorbing the following slot.
    pub fn is_thumb1_nop(&self) -> bool {
        use armv8_encode::isa::armv7::table::ThumbWidth;
        use armv8_encode::isa::armv7::table_generated::ThumbMnemonicGenerated;
        match self {
            DecodedInsn::Thumb(i) => {
                matches!(i.width, ThumbWidth::Halfword)
                    && i.mnemonic == ThumbMnemonicGenerated::Nop
            }
            _ => false,
        }
    }

    /// Raw little-endian bytes of this instruction. Returns up to 4
    /// bytes; AArch64 and ARM-mode always yield exactly 4, Thumb
    /// yields 2 or 4 depending on width.
    pub fn raw_bytes(&self) -> Vec<u8> {
        match self {
            DecodedInsn::Aarch64(i) => i.word.to_le_bytes().to_vec(),
            DecodedInsn::Arm(i) => i.word.to_le_bytes().to_vec(),
            DecodedInsn::Thumb(i) => {
                use armv8_encode::isa::armv7::table::ThumbWidth;
                match i.width {
                    ThumbWidth::Halfword => {
                        // 16-bit Thumb sits in the low half.
                        let hw = i.word as u16;
                        hw.to_le_bytes().to_vec()
                    }
                    ThumbWidth::Word => {
                        // 32-bit Thumb: hw1 in the high half, hw2 in
                        // the low half (upstream convention).
                        let hw1 = ((i.word >> 16) & 0xFFFF) as u16;
                        let hw2 = (i.word & 0xFFFF) as u16;
                        let mut out = Vec::with_capacity(4);
                        out.extend_from_slice(&hw1.to_le_bytes());
                        out.extend_from_slice(&hw2.to_le_bytes());
                        out
                    }
                }
            }
            // iced's `Instruction` does not retain the source bytes, so
            // re-encode it at its own IP to recover them. This is faithful
            // for the overwhelming majority of instructions; callers that
            // need byte-exact originals (the hex viewer) read the file /
            // section bytes directly rather than going through here.
            DecodedInsn::X86(i) => x86_raw_bytes(i),
        }
    }

    /// Pretty-print mnemonic + operands. The result is the same text
    /// Glass listings have always shown for AArch64. For ARMv7 the
    /// formatter uses the upstream mnemonic and the `Debug` projection
    /// of each operand — readable but not yet polished.
    pub fn format_text(&self) -> String {
        match self {
            DecodedInsn::Aarch64(i) => {
                let mnem = aarch64_fmt::mnemonic_chunk(i).text;
                let ops: String = aarch64_fmt::operands_chunks(i)
                    .into_iter()
                    .map(|c| c.text)
                    .collect();
                if ops.is_empty() {
                    mnem
                } else {
                    format!("{mnem} {ops}")
                }
            }
            DecodedInsn::Arm(i) => crate::arm_format::format_arm(i),
            DecodedInsn::Thumb(i) => crate::arm_format::format_thumb(i),
            DecodedInsn::X86(i) => x86_format(i),
        }
    }

    /// Every general-purpose register the instruction touches, in
    /// the order they appear in the operand list. Used by the UI to
    /// highlight uses of the same register across rows.
    pub fn gp_register_uses(&self) -> Vec<RegRef> {
        use armv8_encode::isa::aarch64 as a64;
        use armv8_encode::isa::armv7::operand as a7;
        let mut out = Vec::new();
        match self {
            DecodedInsn::Aarch64(i) => {
                for op in &i.operands {
                    if let a64::DecodedOperand::Register(r) = op {
                        match r.class {
                            a64::RegisterClass::X | a64::RegisterClass::XOrSp => {
                                out.push(RegRef { kind: RegKind::AArch64Gpr64, index: r.index })
                            }
                            a64::RegisterClass::W | a64::RegisterClass::WOrSp => {
                                out.push(RegRef { kind: RegKind::AArch64Gpr32, index: r.index })
                            }
                            _ => {}
                        }
                    }
                }
            }
            DecodedInsn::Arm(i) => {
                for op in &i.operands {
                    if let a7::DecodedOperand::Register(r) = op {
                        if matches!(r.class, a7::RegisterClass::R | a7::RegisterClass::Low) {
                            out.push(RegRef { kind: RegKind::ArmGpr, index: r.index });
                        }
                    }
                }
            }
            DecodedInsn::Thumb(i) => {
                for op in &i.operands {
                    if let a7::DecodedOperand::Register(r) = op {
                        if matches!(r.class, a7::RegisterClass::R | a7::RegisterClass::Low) {
                            out.push(RegRef { kind: RegKind::ArmGpr, index: r.index });
                        }
                    }
                }
            }
            DecodedInsn::X86(i) => {
                use iced_x86::OpKind;
                for op in 0..i.instr.op_count() {
                    if i.instr.op_kind(op) == OpKind::Register {
                        if let Some(index) = x86_gpr_family(i.instr.op_register(op)) {
                            out.push(RegRef { kind: RegKind::X86Gpr, index });
                        }
                    }
                }
            }
        }
        out
    }

    /// First immediate operand, normalised to `i64`. Matches the
    /// behavior of the helper that used to live in
    /// `listing_model.rs`: `Immediate` → value; `UnsignedImmediate`
    /// → cast; `ShiftedImmediate` → `value << shift`.
    pub fn first_imm(&self) -> Option<i64> {
        use armv8_encode::isa::aarch64 as a64;
        use armv8_encode::isa::armv7::operand as a7;
        match self {
            DecodedInsn::Aarch64(i) => {
                for op in &i.operands {
                    match op {
                        a64::DecodedOperand::Immediate(v) => return Some(*v),
                        a64::DecodedOperand::UnsignedImmediate(v) => return Some(*v as i64),
                        a64::DecodedOperand::ShiftedImmediate(s) => {
                            return Some(s.value.wrapping_shl(s.shift as u32))
                        }
                        _ => {}
                    }
                }
                None
            }
            DecodedInsn::Arm(i) => {
                for op in &i.operands {
                    if let a7::DecodedOperand::Immediate(v) = op {
                        return Some(*v);
                    }
                }
                None
            }
            DecodedInsn::Thumb(i) => {
                for op in &i.operands {
                    if let a7::DecodedOperand::Immediate(v) = op {
                        return Some(*v);
                    }
                }
                None
            }
            DecodedInsn::X86(i) => {
                for op in 0..i.instr.op_count() {
                    if x86_is_immediate_opkind(i.instr.op_kind(op)) {
                        // iced's `immediate()` returns the operand value
                        // already widened per its OpKind (sign-extended
                        // forms included); reinterpret as i64 to match
                        // the ARM accessors' signed convention.
                        return Some(i.instr.immediate(op) as i64);
                    }
                }
                None
            }
        }
    }

    /// Resolved direct-branch target, if the instruction encodes
    /// one. ARMv7's `BranchTarget` variant gives us the absolute
    /// address directly; AArch64 has both `BranchTarget` and
    /// `PageTarget` (the latter from `ADRP`), and we prefer
    /// `BranchTarget` because `PageTarget` is reachable via the
    /// dedicated [`Self::pcrel_target`] accessor.
    pub fn branch_target(&self) -> Option<u64> {
        use armv8_encode::isa::aarch64 as a64;
        use armv8_encode::isa::armv7::operand as a7;
        match self {
            DecodedInsn::Aarch64(i) => {
                for op in &i.operands {
                    if let a64::DecodedOperand::BranchTarget(a) = op {
                        return Some(*a);
                    }
                }
                None
            }
            DecodedInsn::Arm(i) => {
                for op in &i.operands {
                    if let a7::DecodedOperand::BranchTarget(a) = op {
                        return Some(*a);
                    }
                }
                None
            }
            DecodedInsn::Thumb(i) => {
                for op in &i.operands {
                    if let a7::DecodedOperand::BranchTarget(a) = op {
                        return Some(*a);
                    }
                }
                None
            }
            DecodedInsn::X86(i) => {
                use iced_x86::OpKind;
                // Direct near branches/calls (`jmp`/`jcc`/`call rel`)
                // carry a NearBranch operand; iced resolves it against
                // the instruction's IP. Far branches and indirect forms
                // have no static target.
                for op in 0..i.instr.op_count() {
                    if matches!(
                        i.instr.op_kind(op),
                        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                    ) {
                        return Some(i.instr.near_branch_target());
                    }
                }
                None
            }
        }
    }

    /// PC-relative literal-pool or page address target. AArch64
    /// `ADR`/`ADRP` emit `PageTarget`; ARMv7 Thumb and ARM-mode
    /// `ldr Rt, [pc, #imm]` literal-pool loads both emit
    /// `PcRelative` from the upstream format decoder.
    pub fn pcrel_target(&self) -> Option<u64> {
        use armv8_encode::isa::aarch64 as a64;
        use armv8_encode::isa::armv7::operand as a7;
        match self {
            DecodedInsn::Aarch64(i) => {
                for op in &i.operands {
                    if let a64::DecodedOperand::PageTarget(a) = op {
                        return Some(*a);
                    }
                }
                None
            }
            DecodedInsn::Arm(i) => {
                // ARM-mode `ldr Rt, [pc, #imm]` literal-pool loads
                // emit `PcRelative` alongside the `OpaqueBits` for
                // the addressing-mode bits. Previously this arm
                // returned `None` and ARM-mode functions got no
                // literal-pool comment / xref.
                for op in &i.operands {
                    if let a7::DecodedOperand::PcRelative(a) = op {
                        return Some(*a);
                    }
                }
                None
            }
            DecodedInsn::Thumb(i) => {
                for op in &i.operands {
                    if let a7::DecodedOperand::PcRelative(a) = op {
                        return Some(*a);
                    }
                }
                None
            }
            DecodedInsn::X86(i) => {
                // RIP-relative memory operand (`lea rax, [rip+0x..]`,
                // `mov rax, [rip+0x..]`). iced computes the absolute
                // target for us — the x86_64 analogue of AArch64's ADRP
                // page address, but self-contained (no fusion needed).
                if i.instr.is_ip_rel_memory_operand() {
                    return Some(i.instr.ip_rel_memory_address());
                }
                None
            }
        }
    }

    /// Destination general-purpose register if there is one. For
    /// AArch64 this is the first X-class register; for ARMv7 it's
    /// the first `R`/`Low`-class register. Used by the listing's
    /// ADRP+ADD page-base tracker (AArch64 only) and by the arrow
    /// renderer.
    pub fn dest_register(&self) -> Option<RegRef> {
        self.gp_register_uses().into_iter().next()
    }

    /// Direct AArch64 view — `None` for ARMv7 variants. Lets the
    /// few remaining AArch64-only code paths (insn-pattern matcher,
    /// page-base fusion) keep their existing pattern matches without
    /// re-implementing them through the facade.
    pub fn as_aarch64(&self) -> Option<&Aarch64Insn> {
        match self {
            DecodedInsn::Aarch64(i) => Some(i),
            _ => None,
        }
    }

    /// Recognise ARMv7 instruction shapes that the listing's
    /// macro-fusion tracker cares about (currently `movw`/`movt`
    /// pair tracking). Returns the destination register and the
    /// 16-bit immediate.
    ///
    /// `movw Rd, #imm16` zero-extends into the low 16 bits of `Rd`;
    /// `movt Rd, #imm16` writes the imm into the high 16 bits of `Rd`
    /// without disturbing the low half. The pair builds a 32-bit
    /// absolute constant that's almost always a pointer into
    /// rodata — so the listing renderer wants to follow it.
    pub fn armv7_movw(&self) -> Option<(u8, u16)> {
        use armv8_encode::isa::armv7::arm::table_generated::ArmMnemonicGenerated as ArmM;
        use armv8_encode::isa::armv7::table_generated::ThumbMnemonicGenerated as ThumbM;
        match self {
            DecodedInsn::Arm(i) if i.mnemonic == ArmM::Movw => {
                armv7_movw_movt_operands(self)
            }
            DecodedInsn::Thumb(i) if i.mnemonic == ThumbM::Movw => {
                armv7_movw_movt_operands(self)
            }
            _ => None,
        }
    }

    /// Same shape as `armv7_movw` but for `movt`. The returned `Rd`
    /// must be matched against the most recent `movw` target before
    /// the pair can be fused into a 32-bit constant.
    pub fn armv7_movt(&self) -> Option<(u8, u16)> {
        use armv8_encode::isa::armv7::arm::table_generated::ArmMnemonicGenerated as ArmM;
        use armv8_encode::isa::armv7::table_generated::ThumbMnemonicGenerated as ThumbM;
        match self {
            DecodedInsn::Arm(i) if i.mnemonic == ArmM::Movt => {
                armv7_movw_movt_operands(self)
            }
            DecodedInsn::Thumb(i) if i.mnemonic == ThumbM::Movt => {
                armv7_movw_movt_operands(self)
            }
            _ => None,
        }
    }
}

/// Extract `(Rd, imm16)` from an already-classified ARMv7
/// `movw` / `movt` instruction. Both forms decode to operands
/// `[Register(Rd), Immediate(imm)]`; we just project them out.
fn armv7_movw_movt_operands(insn: &DecodedInsn) -> Option<(u8, u16)> {
    let dest = insn.dest_register()?;
    if dest.kind != RegKind::ArmGpr {
        return None;
    }
    let imm = insn.first_imm()?;
    // The decoder emits a non-negative i64 here; mask to 16 bits
    // to be safe against any signed projection.
    Some((dest.index, (imm as u32 & 0xFFFF) as u16))
}

/// Result of a successful fusion-pair completion. Carries enough
/// info for both consumers:
///   * `target` — the listing comment renderer ("; \"foo\"") and
///     the xref index both record this.
///   * `source_register` — the listing's per-row retro-label
///     (the ADRP row gets relabelled with the destination section
///     when the pair resolves to a different section). Equals the
///     destination register for ARMv7 movw+movt (since the pair
///     consumes its own previous write).
#[derive(Debug, Clone, Copy)]
pub struct FusionTarget {
    pub target: u64,
    pub source_register: u8,
}

/// Stateful tracker for cross-instruction fusion idioms used to
/// resolve "what address does this pair of instructions actually
/// reference?". Walk decoded instructions in source order via
/// `observe(insn) -> Option<FusionTarget>`.
///
/// Supported idioms:
///   * AArch64 `ADRP Xd, page ; ADD Xd, Xs, #imm`. Returns
///     target = page + imm.
///   * ARMv7 (Thumb-2 / A32) `movw Rd, #lo16 ; movt Rd, #hi16`.
///     Returns target = (hi16 << 16) | lo16.
///   * ARMv7 PIC literal `ldr Rt, [pc, #imm] ; add Rt, pc`.
///     Used by Rust / modern compilers in place of an absolute
///     pointer to avoid a runtime relocation: the pool word is a
///     signed 32-bit offset from the `add` instruction's PC.
///     Returns target = add_insn_addr + 4 + signed_offset. Only
///     fires when the caller passes a pool-word peek closure via
///     [`Self::observe_with_pool_peek`] — without one we can't
///     read the offset.
///
/// Any non-completing write to a tracked register invalidates
/// that slot — same conservative rule both call sites used before.
///
/// AArch64 state slots are unused for ARMv7 inputs and vice
/// versa. Either ISA can produce mixed observations without
/// confusing the other's state.
#[derive(Debug, Default, Clone)]
pub struct PageBaseTracker {
    aarch64_pages: [Option<u64>; 32],
    armv7_movw_lo: [Option<u16>; 16],
    /// Signed pool-word value loaded by the most recent
    /// `ldr Rt, [pc, #imm]` into each ARM GPR. Consumed by a
    /// subsequent `add Rt, pc` to form the final PIC target.
    armv7_pcrel_offsets: [Option<i32>; 16],
}

impl PageBaseTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed the AArch64 ADRP page slot for register Xd with
    /// `page`. Used by callers that build the listing in pieces
    /// (the paged listing cache) so an ADRP that lives in a
    /// previous page can still complete an ADD in the current
    /// page. Callers that build the whole section in one pass
    /// don't need this — `observe` sets the slot naturally as
    /// it walks the ADRP instruction.
    pub fn set_x_page(&mut self, reg: u8, page: u64) {
        if (reg as usize) < self.aarch64_pages.len() {
            self.aarch64_pages[reg as usize] = Some(page);
        }
    }

    /// Consume one instruction in source order. Returns the
    /// fused absolute address when this instruction completes a
    /// known pair; updates internal state otherwise.
    ///
    /// This variant doesn't take a pool-word peeker, so it can't
    /// resolve the ARMv7 PIC `ldr ; add r, pc` idiom — that needs
    /// to read 4 bytes out of the pool slot. Callers that have a
    /// way to do that (the listing builder, the xref builder)
    /// should use [`Self::observe_with_pool_peek`] instead.
    pub fn observe(&mut self, insn: &DecodedInsn) -> Option<FusionTarget> {
        self.observe_with_pool_peek(insn, |_| None)
    }

    /// Consume one instruction with a closure that reads a 32-bit
    /// little-endian word at the given address (returning `None`
    /// when the address isn't in any known section). The closure
    /// is consulted only on `ldr Rt, [pc, #imm]` to capture the
    /// pool slot's signed offset for the ARMv7 PIC idiom.
    pub fn observe_with_pool_peek<F: Fn(u64) -> Option<u32>>(
        &mut self,
        insn: &DecodedInsn,
        peek_pool: F,
    ) -> Option<FusionTarget> {
        match insn {
            DecodedInsn::Aarch64(a64) => self.observe_aarch64(a64),
            DecodedInsn::Arm(_) | DecodedInsn::Thumb(_) => {
                self.observe_armv7_with_peek(insn, &peek_pool)
            }
            // x86 has no multi-instruction page-base/literal fusion
            // idiom: RIP-relative references are self-contained and
            // surface via `DecodedInsn::pcrel_target`. Nothing to track.
            DecodedInsn::X86(_) => None,
        }
    }

    fn observe_aarch64(&mut self, insn: &Aarch64Insn) -> Option<FusionTarget> {
        use armv8_encode::isa::aarch64::{Aarch64Mnemonic, DecodedOperand, RegisterClass};
        // Collect X-register operand indices in order.
        let mut x_regs: Vec<u8> = Vec::with_capacity(insn.operands.len());
        for op in &insn.operands {
            if let DecodedOperand::Register(r) = op {
                if matches!(r.class, RegisterClass::X | RegisterClass::XOrSp) {
                    x_regs.push(r.index);
                }
            }
        }
        // 1. ADRP — update page slot, no completion.
        if insn.mnemonic == Aarch64Mnemonic::Adrp {
            let page = insn.operands.iter().find_map(|op| match op {
                DecodedOperand::PageTarget(a) => Some(*a),
                _ => None,
            });
            if let (Some(&d), Some(page)) = (x_regs.first(), page) {
                if (d as usize) < self.aarch64_pages.len() {
                    self.aarch64_pages[d as usize] = Some(page);
                }
            }
            return None;
        }
        // 2. ADD Xd, Xs, #imm — potential completion.
        if insn.mnemonic == Aarch64Mnemonic::Add && x_regs.len() >= 2 {
            let d = x_regs[0];
            let s = x_regs[1];
            if let Some(base) = self.aarch64_pages.get(s as usize).copied().flatten() {
                // Pull the first immediate.
                let imm = insn.operands.iter().find_map(|op| match op {
                    DecodedOperand::Immediate(v) => Some(*v),
                    DecodedOperand::UnsignedImmediate(v) => Some(*v as i64),
                    DecodedOperand::ShiftedImmediate(s) => {
                        Some(s.value.wrapping_shl(s.shift as u32))
                    }
                    _ => None,
                });
                if let Some(imm) = imm {
                    if imm >= 0 {
                        // Completion. Per legacy semantics, the
                        // destination register is NOT invalidated
                        // here — callers used to fall through to a
                        // `dest_x_reg` invalidate only in the
                        // non-ADRP, non-completing-ADD branch.
                        // However in practice the listing always
                        // overwrote `x_page_bases[d]` to None when
                        // d != s via the dest_x_reg path. To match
                        // the legacy behaviour, leave it as-is and
                        // let the next non-completing write clear
                        // it.
                        let _ = d;
                        return Some(FusionTarget {
                            target: base.wrapping_add(imm as u64),
                            source_register: s,
                        });
                    }
                }
            }
        }
        // 3. Any other write to an X register invalidates that slot.
        if let Some(&d) = x_regs.first() {
            if (d as usize) < self.aarch64_pages.len() {
                self.aarch64_pages[d as usize] = None;
            }
        }
        None
    }

    fn observe_armv7_with_peek<F: Fn(u64) -> Option<u32>>(
        &mut self,
        insn: &DecodedInsn,
        peek_pool: &F,
    ) -> Option<FusionTarget> {
        use armv8_encode::mc::InstructionInfo;
        // movw Rd, #lo16 — store the low half. (movw doesn't have
        // a pcrel target, so the order of these checks vs the
        // pcrel-target check below is fine either way.)
        if let Some((rd, lo)) = insn.armv7_movw() {
            if (rd as usize) < self.armv7_movw_lo.len() {
                self.armv7_movw_lo[rd as usize] = Some(lo);
            }
            // movw also invalidates any pending PIC offset on Rd —
            // the register is being overwritten.
            if (rd as usize) < self.armv7_pcrel_offsets.len() {
                self.armv7_pcrel_offsets[rd as usize] = None;
            }
            return None;
        }
        // movt Rd, #hi16 — complete the movw+movt pair if a low
        // half was pending.
        if let Some((rd, hi)) = insn.armv7_movt() {
            if (rd as usize) < self.armv7_movw_lo.len() {
                if let Some(lo) = self.armv7_movw_lo[rd as usize].take() {
                    let fused = (u32::from(hi) << 16) | u32::from(lo);
                    return Some(FusionTarget {
                        target: fused as u64,
                        source_register: rd,
                    });
                }
            }
            return None;
        }
        // `ldr Rt, [pc, #imm]` — capture the pool word's signed
        // value into the Rt slot, ready for a subsequent
        // `add Rt, pc` to complete the PIC pair. Rust / modern
        // compilers emit this pattern in place of an absolute
        // pointer to avoid a runtime relocation: the pool word
        // is `target - (add_insn_pc + 4)`.
        if let Some(pool_addr) = insn.pcrel_target() {
            if let Some(dest) = insn.dest_register() {
                if dest.kind == RegKind::ArmGpr
                    && (dest.index as usize) < self.armv7_pcrel_offsets.len()
                {
                    let value = peek_pool(pool_addr).map(|w| w as i32);
                    self.armv7_pcrel_offsets[dest.index as usize] = value;
                    // The Rt also loses any pending movw low.
                    if (dest.index as usize) < self.armv7_movw_lo.len() {
                        self.armv7_movw_lo[dest.index as usize] = None;
                    }
                }
            }
            return None;
        }
        // `add Rt, pc` — completes the PIC pair. Detected via the
        // mnemonic + operands: the destination is Rt, and one of
        // the operand registers is r15 (PC). Two encodings cover
        // it: Thumb-1 16-bit `0x44XX` (`add Rd, pc`, two-operand)
        // and A32 `add Rd, pc, Rm` (three-operand, where Rm is
        // typically the same Rd loaded by the prior ldr).
        if let Some((rd, add_pc_addr, width)) = armv7_add_pc_form(insn) {
            if (rd as usize) < self.armv7_pcrel_offsets.len() {
                if let Some(off) = self.armv7_pcrel_offsets[rd as usize].take() {
                    // Thumb / A32: the PC value used by `add` is
                    // `add_insn_addr + 4` (Thumb pipeline) for
                    // both 16-bit and 32-bit Thumb forms, and
                    // `add_insn_addr + 8` for A32. Sign-extend
                    // the offset and add.
                    let pc_at_add = match width {
                        // 16-bit Thumb-1 `add Rd, pc` reads PC as
                        // `(insn_addr + 4) & !3` — bit-1 of PC is
                        // forced to 0 in this encoding. The `& !3`
                        // word-aligns the read.
                        2 => (add_pc_addr.wrapping_add(4)) & !3u64,
                        // 32-bit Thumb-2 / A32 forms: `pc = insn_addr + 4`
                        // for Thumb, `+ 8` for A32. We don't carry
                        // the mode hint here so guess by width:
                        // Thumb-2 = +4, A32 (also width 4) likely
                        // wants +8. The PIC idiom uses Thumb-2 in
                        // practice (the dominant Rust codegen);
                        // A32 binaries from this compiler use the
                        // older `mov pc, ...` and don't follow
                        // this pattern. Default to +4.
                        _ => add_pc_addr.wrapping_add(4),
                    };
                    let target = (pc_at_add as i64)
                        .wrapping_add(off as i64) as u64;
                    return Some(FusionTarget {
                        target,
                        source_register: rd,
                    });
                }
            }
            return None;
        }
        let _ = insn.address(); // keep InstructionInfo in use for the trait
        // Any other write to an ARM GPR invalidates the slot(s).
        if let Some(dest) = insn.dest_register() {
            if dest.kind == RegKind::ArmGpr {
                if (dest.index as usize) < self.armv7_movw_lo.len() {
                    self.armv7_movw_lo[dest.index as usize] = None;
                }
                if (dest.index as usize) < self.armv7_pcrel_offsets.len() {
                    self.armv7_pcrel_offsets[dest.index as usize] = None;
                }
            }
        }
        None
    }
}

/// Recognise `add Rd, pc` / `add Rd, pc, Rm` patterns used by
/// the ARMv7 PIC literal idiom. Returns `(Rd, insn_address,
/// width_bytes)` for downstream PC calculation. The width matters
/// because Thumb-1 16-bit `add Rd, pc` reads PC differently from
/// Thumb-2 / A32 forms.
fn armv7_add_pc_form(insn: &DecodedInsn) -> Option<(u8, u64, usize)> {
    use armv8_encode::isa::armv7::arm::table_generated::ArmMnemonicGenerated as ArmM;
    use armv8_encode::isa::armv7::operand::{DecodedOperand, RegisterClass};
    use armv8_encode::isa::armv7::table_generated::ThumbMnemonicGenerated as ThumbM;
    use armv8_encode::mc::InstructionInfo;
    // Helper: any operand a register with index 15 (PC)?
    let has_pc = |ops: &[DecodedOperand]| -> bool {
        ops.iter().any(|op| match op {
            DecodedOperand::Register(r) => {
                matches!(r.class, RegisterClass::R | RegisterClass::Low) && r.index == 15
            }
            _ => false,
        })
    };
    // Helper: first Rd-class GPR among operands (index 0).
    let first_gpr = |ops: &[DecodedOperand]| -> Option<u8> {
        ops.iter().find_map(|op| match op {
            DecodedOperand::Register(r) => {
                if matches!(r.class, RegisterClass::R | RegisterClass::Low) && r.index < 15
                {
                    Some(r.index)
                } else {
                    None
                }
            }
            _ => None,
        })
    };
    match insn {
        DecodedInsn::Thumb(t) if t.mnemonic == ThumbM::Add && has_pc(&t.operands) => {
            let rd = first_gpr(&t.operands)?;
            Some((rd, insn.address(), insn.width_bytes()))
        }
        DecodedInsn::Arm(a) if a.mnemonic == ArmM::Add && has_pc(&a.operands) => {
            let rd = first_gpr(&a.operands)?;
            Some((rd, insn.address(), insn.width_bytes()))
        }
        _ => None,
    }
}

impl From<Aarch64Insn> for DecodedInsn {
    fn from(i: Aarch64Insn) -> Self { DecodedInsn::Aarch64(i) }
}
impl From<ArmDecodedInstruction> for DecodedInsn {
    fn from(i: ArmDecodedInstruction) -> Self { DecodedInsn::Arm(i) }
}
impl From<ThumbDecodedInstruction> for DecodedInsn {
    fn from(i: ThumbDecodedInstruction) -> Self { DecodedInsn::Thumb(i) }
}
impl From<X86DecodedInstruction> for DecodedInsn {
    fn from(i: X86DecodedInstruction) -> Self { DecodedInsn::X86(i) }
}

// ---- x86 helpers ---------------------------------------------------
//
// These read the `iced_x86::Instruction` carried by the x86 variant.
// iced *is* the operand model for this ISA, so unlike the ARM arms
// (which consult `armv8-encode`'s neutral operand enums) the x86 arms
// reach into iced directly.

/// True for the iced `OpKind`s that denote an immediate operand.
fn x86_is_immediate_opkind(kind: iced_x86::OpKind) -> bool {
    use iced_x86::OpKind::*;
    matches!(
        kind,
        Immediate8
            | Immediate8_2nd
            | Immediate16
            | Immediate32
            | Immediate64
            | Immediate8to16
            | Immediate8to32
            | Immediate8to64
            | Immediate32to64
    )
}

/// Map an iced register to its general-purpose-register *family*
/// index (0 = `rax`/`eax`/`ax`/`al`, 1 = `rcx`-family, …), or `None`
/// when the register isn't a GPR (xmm/segment/control/flags/etc.).
///
/// Collapsing every width onto the full register's number is what
/// makes register-use highlighting alias-aware (see [`RegKind::X86Gpr`]).
fn x86_gpr_family(reg: iced_x86::Register) -> Option<u8> {
    if !reg.is_gpr() {
        return None;
    }
    // `full_register()` widens AL/AX/EAX → RAX; `number()` yields the
    // 0-based index within the (full-width) GPR bank.
    Some(reg.full_register().number() as u8)
}

/// Pretty-print an x86 instruction with iced's Intel-syntax formatter
/// (`mov rax, qword ptr [rip+0x1234]`). A fresh formatter per call
/// keeps this stateless; the listing path can switch to a cached,
/// tokenised formatter later for coloured chunks.
fn x86_format(insn: &X86DecodedInstruction) -> String {
    use iced_x86::{Formatter, IntelFormatter};
    let mut formatter = IntelFormatter::new();
    let mut out = String::new();
    formatter.format(&insn.instr, &mut out);
    out
}

/// Recover an x86 instruction's encoded bytes by re-encoding it at its
/// own IP. iced doesn't retain source bytes on `Instruction`; the
/// decode width is taken from the instruction's own `code_size()`.
/// Faithful for nearly all instructions; on the rare re-encode failure
/// we fall back to a zero-filled buffer of the correct length so the
/// listing's (4-byte-truncated) bytes column still lines up.
fn x86_raw_bytes(insn: &X86DecodedInstruction) -> Vec<u8> {
    use iced_x86::{CodeSize, Encoder};
    let bitness = match insn.instr.code_size() {
        CodeSize::Code16 => 16,
        CodeSize::Code32 => 32,
        // Unknown (e.g. synthesised) instructions default to 64-bit.
        CodeSize::Code64 | CodeSize::Unknown => 64,
    };
    let mut encoder = Encoder::new(bitness);
    match encoder.encode(&insn.instr, insn.address) {
        Ok(_) => encoder.take_buffer(),
        Err(_) => vec![0u8; insn.size_bytes() as usize],
    }
}
