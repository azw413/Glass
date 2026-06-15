//! x86_64 decode smoke test.
//!
//! Exercises the `DecodedInsn::X86` facade arms end-to-end against
//! hand-assembled byte sequences: formatting, instruction width,
//! register-use extraction, direct-branch targets, and RIP-relative
//! target resolution. Mirrors `armv7_smoke.rs` for the ARM path.

use armv8_encode::isa::x86::{disassemble_bytes, Bitness};
use armv8_encode::mc::InstructionInfo;
use glass_arch_arm::DecodedInsn;

/// `mov rax, rbx ; ret` — formatting, width, and register families.
#[test]
fn decode_mov_ret_x86_64() {
    // 48 89 d8 = mov rax, rbx (REX.W MOV r/m64, r64)
    // c3       = ret
    let bytes = [0x48, 0x89, 0xd8, 0xc3];
    let insns = disassemble_bytes(0x1000, &bytes, Bitness::Bits64).expect("decode");
    assert_eq!(insns.len(), 2, "expected two instructions");

    let mov = DecodedInsn::X86(insns[0]);
    assert_eq!(mov.address(), 0x1000);
    assert_eq!(mov.width_bytes(), 3);
    let txt = mov.format_text().to_lowercase();
    assert!(txt.starts_with("mov"), "unexpected mnemonic: {txt}");
    assert!(txt.contains("rax") && txt.contains("rbx"), "operands: {txt}");

    // Alias-aware GPR families: rax = 0, rbx = 3.
    let fams: Vec<u8> = mov.gp_register_uses().iter().map(|r| r.index).collect();
    assert!(fams.contains(&0), "missing rax family in {fams:?}");
    assert!(fams.contains(&3), "missing rbx family in {fams:?}");

    let ret = DecodedInsn::X86(insns[1]);
    assert_eq!(ret.width_bytes(), 1);
    assert_eq!(ret.format_text().to_lowercase(), "ret");
    assert_eq!(ret.branch_target(), None);
}

/// `call rel32` resolves to an absolute near-branch target.
#[test]
fn branch_target_call_rel32() {
    // e8 10 00 00 00 = call rel32(+0x10) at 0x1000.
    // next IP = 0x1005, target = 0x1005 + 0x10 = 0x1015.
    let bytes = [0xe8, 0x10, 0x00, 0x00, 0x00];
    let insns = disassemble_bytes(0x1000, &bytes, Bitness::Bits64).expect("decode");
    let call = DecodedInsn::X86(insns[0]);
    assert_eq!(call.width_bytes(), 5);
    assert_eq!(call.branch_target(), Some(0x1015));
    // A direct call has no RIP-relative data operand.
    assert_eq!(call.pcrel_target(), None);
}

/// `lea rax, [rip+disp]` resolves to an absolute RIP-relative target.
#[test]
fn rip_relative_pcrel_target() {
    // 48 8d 05 00 01 00 00 = lea rax, [rip+0x100] at 0x2000.
    // instruction length = 7, next IP = 0x2007, target = 0x2107.
    let bytes = [0x48, 0x8d, 0x05, 0x00, 0x01, 0x00, 0x00];
    let insns = disassemble_bytes(0x2000, &bytes, Bitness::Bits64).expect("decode");
    let lea = DecodedInsn::X86(insns[0]);
    assert_eq!(lea.width_bytes(), 7);
    assert_eq!(lea.pcrel_target(), Some(0x2107));
}

/// 32-bit decode width is honored (i386 / `Architecture::X86`).
#[test]
fn decode_32bit_push_ret() {
    // 53 = push ebx ; c3 = ret  (decoded in 32-bit mode)
    let bytes = [0x53, 0xc3];
    let insns = disassemble_bytes(0x8048000, &bytes, Bitness::Bits32).expect("decode");
    assert_eq!(insns.len(), 2);
    let push = DecodedInsn::X86(insns[0]);
    let txt = push.format_text().to_lowercase();
    assert!(txt.starts_with("push"), "unexpected: {txt}");
    assert!(txt.contains("ebx"), "operands: {txt}");
}
