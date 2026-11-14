use alloc::vec::Vec;

pub const JRPD_VM_MAX_STACK_DEPTH: usize = 64;
pub const JRPD_VM_MAX_LOCALS: usize = 16;
pub const JRPD_VM_MAX_BYTECODE_LEN: usize = 2048;
pub const JRPD_VM_DEFAULT_GAS_BUDGET: u32 = 1024;
pub const JRPD_VM_EPSILON_F64: f64 = 1e-15;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmOpcode {
    Halt = 0x00,
    Nop = 0x01,
    Jmp = 0x02,
    JmpIfFalse = 0x03,
    JmpIfTrue = 0x04,
    PushU64 = 0x10,
    PushF64 = 0x11,
    Pop = 0x12,
    Dup = 0x13,
    Swap = 0x14,
    LoadLocal = 0x15,
    StoreLocal = 0x16,
    AddF64 = 0x20,
    SubF64 = 0x21,
    MulF64 = 0x22,
    DivSafe = 0x23,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmTrap {
    InvalidOpcode = 0x01,
    StackOverflow = 0x02,
    StackUnderflow = 0x03,
    DivZero = 0x04,
    OutOfGas = 0x05,
    PcOutOfBounds = 0x06,
    NonFiniteFloat = 0x07,
    InvalidLocal = 0x09,
    EmptyReturn = 0x0A,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmExecOutcome {
    pub result_bits: u64,
    pub gas_used: u32,
    pub final_pc: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmFault {
    pub trap: VmTrap,
    pub fault_pc: u16,
    pub gas_used: u32,
}

impl VmOpcode {
    pub const fn decode(byte: u8) -> Result<Self, VmTrap> {
        match byte {
            0x00 => Ok(Self::Halt),
            0x01 => Ok(Self::Nop),
            0x02 => Ok(Self::Jmp),
            0x03 => Ok(Self::JmpIfFalse),
            0x04 => Ok(Self::JmpIfTrue),
            0x10 => Ok(Self::PushU64),
            0x11 => Ok(Self::PushF64),
            0x12 => Ok(Self::Pop),
            0x13 => Ok(Self::Dup),
            0x14 => Ok(Self::Swap),
            0x15 => Ok(Self::LoadLocal),
            0x16 => Ok(Self::StoreLocal),
            0x20 => Ok(Self::AddF64),
            0x21 => Ok(Self::SubF64),
            0x22 => Ok(Self::MulF64),
            0x23 => Ok(Self::DivSafe),
            _ => Err(VmTrap::InvalidOpcode),
        }
    }

    pub const fn gas_cost(self) -> u32 {
        match self {
            Self::Halt | Self::Nop => 1,
            Self::PushU64 | Self::PushF64 | Self::Pop | Self::Dup | Self::Swap
            | Self::LoadLocal | Self::StoreLocal => 2,
            Self::Jmp | Self::JmpIfFalse | Self::JmpIfTrue | Self::AddF64 | Self::SubF64 => 4,
            Self::MulF64 => 6,
            Self::DivSafe => 10,
        }
    }

    pub const fn immediate_len(self) -> usize {
        match self {
            Self::PushU64 | Self::PushF64 => 8,
            Self::Jmp | Self::JmpIfFalse | Self::JmpIfTrue => 2,
            Self::LoadLocal | Self::StoreLocal => 1,
            _ => 0,
        }
    }
}

pub fn div_safe_f64(num: f64, den: f64) -> Result<f64, VmTrap> {
    if !num.is_finite() || !den.is_finite() {
        return Err(VmTrap::NonFiniteFloat);
    }
    if den.abs() < JRPD_VM_EPSILON_F64 {
        return Err(VmTrap::DivZero);
    }
    let q = num / den;
    if !q.is_finite() {
        return Err(VmTrap::NonFiniteFloat);
    }
    Ok(q)
}

pub fn verify_bytecode_strict_alignment(code: &[u8]) -> Result<[u8; JRPD_VM_MAX_BYTECODE_LEN / 8], VmFault> {
    if code.is_empty() || code.len() > JRPD_VM_MAX_BYTECODE_LEN {
        return Err(VmFault { trap: VmTrap::PcOutOfBounds, fault_pc: 0, gas_used: 0 });
    }
    let mut valid_op_starts = [0u8; JRPD_VM_MAX_BYTECODE_LEN / 8];
    let mut jump_targets = Vec::new();
    let mut pc = 0usize;

    while pc < code.len() {
        valid_op_starts[pc >> 3] |= 1u8 << (pc & 7);
        let fault_pc = pc as u16;
        let op = VmOpcode::decode(code[pc]).map_err(|trap| VmFault { trap, fault_pc, gas_used: 0 })?;
        let imm = op.immediate_len();
        if pc + 1 + imm > code.len() {
            return Err(VmFault { trap: VmTrap::PcOutOfBounds, fault_pc, gas_used: 0 });
        }
        match op {
            VmOpcode::Jmp | VmOpcode::JmpIfFalse | VmOpcode::JmpIfTrue => {
                let target = u16::from_be_bytes([code[pc + 1], code[pc + 2]]) as usize;
                if target >= code.len() {
                    return Err(VmFault { trap: VmTrap::PcOutOfBounds, fault_pc, gas_used: 0 });
                }
                jump_targets.push((target, fault_pc));
            }
            VmOpcode::LoadLocal | VmOpcode::StoreLocal => {
                if (code[pc + 1] as usize) >= JRPD_VM_MAX_LOCALS {
                    return Err(VmFault { trap: VmTrap::InvalidLocal, fault_pc, gas_used: 0 });
                }
            }
            VmOpcode::PushF64 => {
                let bits = u64::from_be_bytes([
                    code[pc + 1], code[pc + 2], code[pc + 3], code[pc + 4],
                    code[pc + 5], code[pc + 6], code[pc + 7], code[pc + 8],
                ]);
                if !f64::from_bits(bits).is_finite() {
                    return Err(VmFault { trap: VmTrap::NonFiniteFloat, fault_pc, gas_used: 0 });
                }
            }
            _ => {}
        }
        pc += 1 + imm;
    }

    for (target, fault_pc) in jump_targets {
        if (valid_op_starts[target >> 3] & (1u8 << (target & 7))) == 0 {
            return Err(VmFault { trap: VmTrap::PcOutOfBounds, fault_pc, gas_used: 0 });
        }
    }
    Ok(valid_op_starts)
}

pub fn execute_sandboxed_vm(code: &[u8], init_locals: &[u64], gas_budget: u32) -> Result<VmExecOutcome, VmFault> {
    verify_bytecode_strict_alignment(code)?;
    let max_gas = if gas_budget == 0 || gas_budget > JRPD_VM_DEFAULT_GAS_BUDGET {
        JRPD_VM_DEFAULT_GAS_BUDGET
    } else {
        gas_budget
    };

    let mut stack = [0u64; JRPD_VM_MAX_STACK_DEPTH];
    let mut locals = [0u64; JRPD_VM_MAX_LOCALS];
    let copy_n = init_locals.len().min(JRPD_VM_MAX_LOCALS);
    locals[..copy_n].copy_from_slice(&init_locals[..copy_n]);

    let mut sp = 0usize;
    let mut pc = 0usize;
    let mut gas_used = 0u32;

    while pc < code.len() {
        let fault_pc = pc as u16;
        let op = VmOpcode::decode(code[pc]).map_err(|trap| VmFault { trap, fault_pc, gas_used })?;
        pc += 1;
        let cost = op.gas_cost();
        if gas_used + cost > max_gas {
            return Err(VmFault { trap: VmTrap::OutOfGas, fault_pc, gas_used });
        }
        gas_used += cost;
        let fail = |trap: VmTrap| VmFault { trap, fault_pc, gas_used };

        match op {
            VmOpcode::Halt => {
                if sp == 0 { return Err(fail(VmTrap::EmptyReturn)); }
                return Ok(VmExecOutcome { result_bits: stack[sp - 1], gas_used, final_pc: fault_pc });
            }
            VmOpcode::Nop => {}
            VmOpcode::Jmp => {
                pc = u16::from_be_bytes([code[pc], code[pc + 1]]) as usize;
            }
            VmOpcode::JmpIfFalse | VmOpcode::JmpIfTrue => {
                if sp < 1 { return Err(fail(VmTrap::StackUnderflow)); }
                let target = u16::from_be_bytes([code[pc], code[pc + 1]]) as usize;
                pc += 2;
                sp -= 1;
                let take = if op == VmOpcode::JmpIfTrue { stack[sp] != 0 } else { stack[sp] == 0 };
                if take { pc = target; }
            }
            VmOpcode::PushU64 | VmOpcode::PushF64 => {
                if sp >= JRPD_VM_MAX_STACK_DEPTH { return Err(fail(VmTrap::StackOverflow)); }
                let imm = u64::from_be_bytes([
                    code[pc], code[pc + 1], code[pc + 2], code[pc + 3],
                    code[pc + 4], code[pc + 5], code[pc + 6], code[pc + 7],
                ]);
                pc += 8;
                stack[sp] = imm;
                sp += 1;
            }
            VmOpcode::Pop => {
                if sp < 1 { return Err(fail(VmTrap::StackUnderflow)); }
                sp -= 1;
            }
            VmOpcode::Dup => {
                if sp < 1 { return Err(fail(VmTrap::StackUnderflow)); }
                if sp >= JRPD_VM_MAX_STACK_DEPTH { return Err(fail(VmTrap::StackOverflow)); }
                stack[sp] = stack[sp - 1];
                sp += 1;
            }
            VmOpcode::Swap => {
                if sp < 2 { return Err(fail(VmTrap::StackUnderflow)); }
                stack.swap(sp - 1, sp - 2);
            }
            VmOpcode::LoadLocal => {
                if sp >= JRPD_VM_MAX_STACK_DEPTH { return Err(fail(VmTrap::StackOverflow)); }
                let idx = code[pc] as usize;
                pc += 1;
                stack[sp] = locals[idx];
                sp += 1;
            }
            VmOpcode::StoreLocal => {
                if sp < 1 { return Err(fail(VmTrap::StackUnderflow)); }
                let idx = code[pc] as usize;
                pc += 1;
                sp -= 1;
                locals[idx] = stack[sp];
            }
            VmOpcode::AddF64 | VmOpcode::SubF64 | VmOpcode::MulF64 => {
                if sp < 2 { return Err(fail(VmTrap::StackUnderflow)); }
                let b = f64::from_bits(stack[sp - 1]);
                let a = f64::from_bits(stack[sp - 2]);
                if !a.is_finite() || !b.is_finite() { return Err(fail(VmTrap::NonFiniteFloat)); }
                let out = match op { VmOpcode::AddF64 => a + b, VmOpcode::SubF64 => a - b, _ => a * b };
                if !out.is_finite() { return Err(fail(VmTrap::NonFiniteFloat)); }
                sp -= 1;
                stack[sp - 1] = out.to_bits();
            }
            VmOpcode::DivSafe => {
                if sp < 2 { return Err(fail(VmTrap::StackUnderflow)); }
                let b = f64::from_bits(stack[sp - 1]);
                let a = f64::from_bits(stack[sp - 2]);
                let out = div_safe_f64(a, b).map_err(fail)?;
                sp -= 1;
                stack[sp - 1] = out.to_bits();
            }
        }
    }
    Err(VmFault { trap: VmTrap::PcOutOfBounds, fault_pc: pc as u16, gas_used })
}
