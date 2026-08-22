//! Human-readable formatting for decoded AArch64 instructions.
//!
//! Produces a typed `Vec<Chunk>` per operand so the UI can paint each
//! piece with its own colour, rather than the `Debug` dump we had before.

use armv8_encode::isa::aarch64::{
    Aarch64Mnemonic, AddressingMode, DecodedInstruction, DecodedOperand, ExtendKind,
    ExtendedRegister, MemoryOffset, MemoryOperand, Register, RegisterClass, Shift,
    ShiftKind, VectorElement, VectorList, VectorRegister,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkKind {
    Plain,
    Mnemonic,
    Register,
    Immediate,
    Address,
    Shift,
    Condition,
    Punct,
    /// Smali top-level directives: `.class`, `.method`, `.field`, …
    Directive,
    /// Java access modifiers: `public`, `static`, `final`, …
    Modifier,
    /// Smali labels referenced by control flow: `:cond_0`, `:goto_1`.
    Label,
    /// Trailing `# comment` text.
    Comment,
    /// Java type / class signatures: `Lcom/example/Foo;`, primitive
    /// `I`/`Z`/`V`, array `[I`.
    Type,
    /// Quoted string literal in smali.
    String,
    /// A method name + signature within a smali method reference.
    /// e.g. `doIt(II)V` in `Lcom/Foo;->doIt(II)V`. The full ref is
    /// stored on the chunk's `target_text` for navigation lookup.
    MethodName,
    /// A field name + signature within a smali field reference.
    /// e.g. `count:I` in `Lcom/Foo;->count:I`. The full ref is
    /// stored on the chunk's `target_text` for the "References
    /// to field" navigation lookup.
    FieldName,
}

#[derive(Clone, Debug)]
pub struct Chunk {
    pub text: String,
    pub kind: ChunkKind,
    /// For `ChunkKind::Address` chunks, the raw target address. Used
    /// by the UI for click-to-goto navigation.
    pub target: Option<u64>,
    /// String-keyed navigation target. Used by smali `MethodName`
    /// chunks to carry the full `Class;->name(sig)` form so the UI
    /// can deep-link to that method's source line.
    pub target_text: Option<String>,
}

impl Chunk {
    fn plain(s: impl Into<String>) -> Self {
        Self { text: s.into(), kind: ChunkKind::Plain, target: None, target_text: None }
    }
    fn punct(s: impl Into<String>) -> Self {
        Self { text: s.into(), kind: ChunkKind::Punct, target: None, target_text: None }
    }
    fn reg(s: impl Into<String>) -> Self {
        Self { text: s.into(), kind: ChunkKind::Register, target: None, target_text: None }
    }
    fn imm(s: impl Into<String>) -> Self {
        Self { text: s.into(), kind: ChunkKind::Immediate, target: None, target_text: None }
    }
    fn addr(s: impl Into<String>, target: u64) -> Self {
        Self {
            text: s.into(),
            kind: ChunkKind::Address,
            target: Some(target),
            target_text: None,
        }
    }
    fn shift(s: impl Into<String>) -> Self {
        Self { text: s.into(), kind: ChunkKind::Shift, target: None, target_text: None }
    }
    fn cond(s: impl Into<String>) -> Self {
        Self { text: s.into(), kind: ChunkKind::Condition, target: None, target_text: None }
    }
    fn mnemonic(s: impl Into<String>) -> Self {
        Self { text: s.into(), kind: ChunkKind::Mnemonic, target: None, target_text: None }
    }
}

pub fn mnemonic_chunk(insn: &DecodedInstruction) -> Chunk {
    Chunk::mnemonic(mnemonic_text(insn.mnemonic))
}

fn mnemonic_text(m: Aarch64Mnemonic) -> String {
    match m {
        Aarch64Mnemonic::Other(s) => s.to_string(),
        _ => format!("{m:?}").to_lowercase(),
    }
}

pub fn operands_chunks(insn: &DecodedInstruction) -> Vec<Chunk> {
    let mut out = Vec::new();
    for (i, op) in insn.operands.iter().enumerate() {
        if i > 0 {
            out.push(Chunk::punct(", "));
        }
        format_operand(op, &mut out);
    }
    out
}

fn format_operand(op: &DecodedOperand, out: &mut Vec<Chunk>) {
    use DecodedOperand::*;
    match op {
        Register(r) => out.push(Chunk::reg(register_name(r))),
        VectorRegister(v) => out.push(Chunk::reg(vector_register_name(v))),
        VectorElement(v) => out.push(Chunk::reg(vector_element_name(v))),
        VectorList(v) => out.push(Chunk::reg(vector_list_name(v))),
        ShiftedRegister(s) => {
            out.push(Chunk::reg(register_name(&s.register)));
            push_shift(&s.shift, out);
        }
        ExtendedRegister(e) => {
            out.push(Chunk::reg(register_name(&e.register)));
            push_extend(e, out);
        }
        Immediate(i) => out.push(Chunk::imm(format_imm(*i))),
        UnsignedImmediate(u) => out.push(Chunk::imm(format_uimm(*u))),
        ShiftedImmediate(s) => {
            out.push(Chunk::imm(format_imm(s.value)));
            if s.shift != 0 {
                out.push(Chunk::punct(", "));
                out.push(Chunk::shift(format!("lsl #{}", s.shift)));
            }
        }
        Memory(m) => push_memory(m, out),
        BranchTarget(addr) => out.push(Chunk::addr(format!("0x{addr:x}"), *addr)),
        PageTarget(addr) => out.push(Chunk::addr(format!("0x{addr:x}"), *addr)),
        System(s) => out.push(Chunk::plain(s.clone())),
        Condition(c) => out.push(Chunk::cond((*c).to_string())),
        FloatImmediate(s) => out.push(Chunk::imm(s.clone())),
        Unimplemented { kind } => out.push(Chunk::plain(format!("<{kind}>"))),
    }
}

fn register_name(r: &Register) -> String {
    let n = r.index;
    match r.class {
        RegisterClass::W => zero_or(n, 31, "wzr", || format!("w{n}")),
        RegisterClass::X => zero_or(n, 31, "xzr", || format!("x{n}")),
        RegisterClass::WOrSp => zero_or(n, 31, "wsp", || format!("w{n}")),
        RegisterClass::XOrSp => zero_or(n, 31, "sp", || format!("x{n}")),
        RegisterClass::B => format!("b{n}"),
        RegisterClass::H => format!("h{n}"),
        RegisterClass::S => format!("s{n}"),
        RegisterClass::D => format!("d{n}"),
        RegisterClass::Q => format!("q{n}"),
    }
}

fn zero_or(n: u8, marker: u8, special: &str, otherwise: impl FnOnce() -> String) -> String {
    if n == marker {
        special.to_string()
    } else {
        otherwise()
    }
}

fn vector_register_name(v: &VectorRegister) -> String {
    format!("v{}.{}", v.index, vector_arr(v.arrangement))
}

fn vector_element_name(v: &VectorElement) -> String {
    use armv8_encode::isa::aarch64::VectorElementSize as Sz;
    let lane = match v.size {
        Sz::B => "b",
        Sz::H => "h",
        Sz::S => "s",
        Sz::D => "d",
    };
    format!("v{}.{}[{}]", v.index, lane, v.element)
}

fn vector_list_name(v: &VectorList) -> String {
    let arr = vector_arr(v.arrangement);
    let last = v.first + v.count.saturating_sub(1);
    let mut s = if v.count <= 1 {
        format!("{{v{}.{arr}}}", v.first)
    } else {
        format!("{{v{}.{arr} - v{last}.{arr}}}", v.first)
    };
    if let Some(e) = v.element {
        s.push_str(&format!("[{e}]"));
    }
    s
}

fn vector_arr(a: armv8_encode::isa::aarch64::VectorArrangement) -> &'static str {
    use armv8_encode::isa::aarch64::VectorArrangement::*;
    match a {
        B8 => "8b",
        B16 => "16b",
        H4 => "4h",
        H8 => "8h",
        S2 => "2s",
        S4 => "4s",
        D1 => "1d",
        D2 => "2d",
    }
}

fn push_shift(s: &Shift, out: &mut Vec<Chunk>) {
    if s.amount == 0 && matches!(s.kind, ShiftKind::Lsl) {
        return;
    }
    let kind = match s.kind {
        ShiftKind::Lsl => "lsl",
        ShiftKind::Lsr => "lsr",
        ShiftKind::Asr => "asr",
        ShiftKind::Ror => "ror",
    };
    out.push(Chunk::punct(", "));
    out.push(Chunk::shift(format!("{kind} #{}", s.amount)));
}

fn push_extend(e: &ExtendedRegister, out: &mut Vec<Chunk>) {
    let kind = match e.extend {
        ExtendKind::Uxtb => "uxtb",
        ExtendKind::Uxth => "uxth",
        ExtendKind::Uxtw => "uxtw",
        ExtendKind::Uxtx => "uxtx",
        ExtendKind::Sxtb => "sxtb",
        ExtendKind::Sxth => "sxth",
        ExtendKind::Sxtw => "sxtw",
        ExtendKind::Sxtx => "sxtx",
    };
    out.push(Chunk::punct(", "));
    if e.amount == 0 {
        out.push(Chunk::shift(kind.to_string()));
    } else {
        out.push(Chunk::shift(format!("{kind} #{}", e.amount)));
    }
}

fn push_memory(m: &MemoryOperand, out: &mut Vec<Chunk>) {
    match m.mode {
        AddressingMode::Offset | AddressingMode::PreIndex => {
            out.push(Chunk::punct("["));
            out.push(Chunk::reg(register_name(&m.base)));
            push_memory_offset(&m.offset, out);
            out.push(Chunk::punct("]"));
            if matches!(m.mode, AddressingMode::PreIndex) {
                out.push(Chunk::punct("!"));
            }
        }
        AddressingMode::PostIndex => {
            out.push(Chunk::punct("["));
            out.push(Chunk::reg(register_name(&m.base)));
            out.push(Chunk::punct("]"));
            if !matches!(m.offset, MemoryOffset::None) {
                out.push(Chunk::punct(", "));
                push_memory_offset_value(&m.offset, out);
            }
        }
    }
}

fn push_memory_offset(off: &MemoryOffset, out: &mut Vec<Chunk>) {
    match off {
        MemoryOffset::None => {}
        MemoryOffset::Immediate(0) => {}
        MemoryOffset::Immediate(i) => {
            out.push(Chunk::punct(", "));
            out.push(Chunk::imm(format_imm(*i)));
        }
        MemoryOffset::Register { register, shift } => {
            out.push(Chunk::punct(", "));
            out.push(Chunk::reg(register_name(register)));
            if let Some(s) = shift {
                push_shift(s, out);
            }
        }
    }
}

fn push_memory_offset_value(off: &MemoryOffset, out: &mut Vec<Chunk>) {
    match off {
        MemoryOffset::None => {}
        MemoryOffset::Immediate(i) => out.push(Chunk::imm(format_imm(*i))),
        MemoryOffset::Register { register, shift } => {
            out.push(Chunk::reg(register_name(register)));
            if let Some(s) = shift {
                push_shift(s, out);
            }
        }
    }
}

fn format_imm(i: i64) -> String {
    if i.is_negative() {
        // wrapping_neg() handles i64::MIN — its absolute value doesn't
        // fit in i64, but cast-to-u64 keeps the magnitude bits correct.
        format!("#-0x{:x}", (i.wrapping_neg() as u64))
    } else if (0..=0x1000).contains(&i) {
        format!("#{i}")
    } else {
        format!("#0x{:x}", i)
    }
}

fn format_uimm(u: u64) -> String {
    if u <= 0x1000 {
        format!("#{u}")
    } else {
        format!("#0x{u:x}")
    }
}

/// True for any AArch64 mnemonic that ends a basic block.
pub fn is_terminator(m: Aarch64Mnemonic) -> bool {
    use Aarch64Mnemonic::*;
    matches!(
        m,
        B | Br | Bl | Blr | Ret | Eret | Drps
        | Beq | Bne | Bcs | Bcc | Bmi | Bpl | Bvs | Bvc | Bhi | Bls
        | Bge | Blt | Bgt | Ble
        | Cbz | Cbnz | Tbz | Tbnz
        | Hvc | Smc | Svc | Brk | Hlt
    )
}

/// True for the call-like terminators (Bl/Blr).
pub fn is_call(m: Aarch64Mnemonic) -> bool {
    matches!(m, Aarch64Mnemonic::Bl | Aarch64Mnemonic::Blr)
}

/// True for conditional direct branches (`B.cond`, `CBZ`, `CBNZ`,
/// `TBZ`, `TBNZ`). Used by the listing's control-flow arrow renderer
/// to pick between dotted (conditional) and solid (unconditional)
/// lines.
pub fn is_conditional_branch(m: Aarch64Mnemonic) -> bool {
    use Aarch64Mnemonic::*;
    matches!(
        m,
        Beq | Bne | Bcs | Bcc | Bmi | Bpl | Bvs | Bvc | Bhi | Bls
        | Bge | Blt | Bgt | Ble
        | Cbz | Cbnz | Tbz | Tbnz
    )
}

/// True for unconditional direct branches (`B <imm>`). Excludes `Bl`
/// (call) and indirect/register-based branches.
pub fn is_unconditional_direct_branch(m: Aarch64Mnemonic) -> bool {
    matches!(m, Aarch64Mnemonic::B)
}

/// Pull the absolute branch / ADRP target out of an instruction, if any.
pub fn primary_address_operand(insn: &DecodedInstruction) -> Option<u64> {
    for op in &insn.operands {
        match op {
            DecodedOperand::BranchTarget(a) | DecodedOperand::PageTarget(a) => {
                return Some(*a)
            }
            _ => {}
        }
    }
    None
}
