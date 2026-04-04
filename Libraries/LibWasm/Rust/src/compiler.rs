/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

use crate::{CraneliftInsn, RuntimeHelpers};

use cranelift_codegen::ir::condcodes::{FloatCC, IntCC};
use cranelift_codegen::ir::types;
use cranelift_codegen::ir::{
    AbiParam, Function, InstBuilder, MemFlags, Signature, StackSlotData, StackSlotKind, UserFuncName,
};
use cranelift_codegen::isa::CallConv;
use cranelift_codegen::settings::{self, Configurable};
use cranelift_codegen::{self, Context};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Variable};
use cranelift_native;

// Wasm opcode constants (must match Opcode.h).
mod op {
    pub const UNREACHABLE: u64 = 0x00;
    pub const NOP: u64 = 0x01;
    pub const BLOCK: u64 = 0x02;
    pub const LOOP: u64 = 0x03;
    pub const IF: u64 = 0x04;
    pub const ELSE: u64 = 0x05;
    pub const END: u64 = 0x0b;
    pub const BR: u64 = 0x0c;
    pub const BR_IF: u64 = 0x0d;
    pub const BR_TABLE: u64 = 0x0e;
    pub const RETURN: u64 = 0x0f;
    pub const CALL: u64 = 0x10;
    pub const CALL_INDIRECT: u64 = 0x11;
    pub const DROP: u64 = 0x1a;
    pub const SELECT: u64 = 0x1b;
    pub const SELECT_TYPED: u64 = 0x1c;
    pub const LOCAL_GET: u64 = 0x20;
    pub const LOCAL_SET: u64 = 0x21;
    pub const LOCAL_TEE: u64 = 0x22;
    pub const GLOBAL_GET: u64 = 0x23;
    pub const GLOBAL_SET: u64 = 0x24;

    pub const I32_LOAD: u64 = 0x28;
    pub const I64_LOAD: u64 = 0x29;
    pub const F32_LOAD: u64 = 0x2a;
    pub const F64_LOAD: u64 = 0x2b;
    pub const I32_LOAD8_S: u64 = 0x2c;
    pub const I32_LOAD8_U: u64 = 0x2d;
    pub const I32_LOAD16_S: u64 = 0x2e;
    pub const I32_LOAD16_U: u64 = 0x2f;
    pub const I64_LOAD8_S: u64 = 0x30;
    pub const I64_LOAD8_U: u64 = 0x31;
    pub const I64_LOAD16_S: u64 = 0x32;
    pub const I64_LOAD16_U: u64 = 0x33;
    pub const I64_LOAD32_S: u64 = 0x34;
    pub const I64_LOAD32_U: u64 = 0x35;
    pub const I32_STORE: u64 = 0x36;
    pub const I64_STORE: u64 = 0x37;
    pub const F32_STORE: u64 = 0x38;
    pub const F64_STORE: u64 = 0x39;
    pub const I32_STORE8: u64 = 0x3a;
    pub const I32_STORE16: u64 = 0x3b;
    pub const I64_STORE8: u64 = 0x3c;
    pub const I64_STORE16: u64 = 0x3d;
    pub const I64_STORE32: u64 = 0x3e;
    pub const MEMORY_SIZE: u64 = 0x3f;
    pub const MEMORY_GROW: u64 = 0x40;

    // Multi-byte opcodes (0xfc prefix).
    pub const I32_TRUNC_SAT_F32_S: u64 = 0xfc00000000000000;
    pub const I32_TRUNC_SAT_F32_U: u64 = 0xfc00000000000001;
    pub const I32_TRUNC_SAT_F64_S: u64 = 0xfc00000000000002;
    pub const I32_TRUNC_SAT_F64_U: u64 = 0xfc00000000000003;
    pub const I64_TRUNC_SAT_F32_S: u64 = 0xfc00000000000004;
    pub const I64_TRUNC_SAT_F32_U: u64 = 0xfc00000000000005;
    pub const I64_TRUNC_SAT_F64_S: u64 = 0xfc00000000000006;
    pub const I64_TRUNC_SAT_F64_U: u64 = 0xfc00000000000007;
    pub const MEMORY_COPY: u64 = 0xfc0000000000000a;
    pub const MEMORY_FILL: u64 = 0xfc0000000000000b;

    pub const I32_CONST: u64 = 0x41;
    pub const I64_CONST: u64 = 0x42;
    pub const F32_CONST: u64 = 0x43;
    pub const F64_CONST: u64 = 0x44;

    pub const I32_EQZ: u64 = 0x45;
    pub const I32_EQ: u64 = 0x46;
    pub const I32_NE: u64 = 0x47;
    pub const I32_LTS: u64 = 0x48;
    pub const I32_LTU: u64 = 0x49;
    pub const I32_GTS: u64 = 0x4a;
    pub const I32_GTU: u64 = 0x4b;
    pub const I32_LES: u64 = 0x4c;
    pub const I32_LEU: u64 = 0x4d;
    pub const I32_GES: u64 = 0x4e;
    pub const I32_GEU: u64 = 0x4f;
    pub const I64_EQZ: u64 = 0x50;
    pub const I64_EQ: u64 = 0x51;
    pub const I64_NE: u64 = 0x52;
    pub const I64_LTS: u64 = 0x53;
    pub const I64_LTU: u64 = 0x54;
    pub const I64_GTS: u64 = 0x55;
    pub const I64_GTU: u64 = 0x56;
    pub const I64_LES: u64 = 0x57;
    pub const I64_LEU: u64 = 0x58;
    pub const I64_GES: u64 = 0x59;
    pub const I64_GEU: u64 = 0x5a;

    pub const F32_EQ: u64 = 0x5b;
    pub const F32_NE: u64 = 0x5c;
    pub const F32_LT: u64 = 0x5d;
    pub const F32_GT: u64 = 0x5e;
    pub const F32_LE: u64 = 0x5f;
    pub const F32_GE: u64 = 0x60;
    pub const F64_EQ: u64 = 0x61;
    pub const F64_NE: u64 = 0x62;
    pub const F64_LT: u64 = 0x63;
    pub const F64_GT: u64 = 0x64;
    pub const F64_LE: u64 = 0x65;
    pub const F64_GE: u64 = 0x66;

    pub const I32_CLZ: u64 = 0x67;
    pub const I32_CTZ: u64 = 0x68;
    pub const I32_POPCNT: u64 = 0x69;
    pub const I32_ADD: u64 = 0x6a;
    pub const I32_SUB: u64 = 0x6b;
    pub const I32_MUL: u64 = 0x6c;
    pub const I32_DIVS: u64 = 0x6d;
    pub const I32_DIVU: u64 = 0x6e;
    pub const I32_REMS: u64 = 0x6f;
    pub const I32_REMU: u64 = 0x70;
    pub const I32_AND: u64 = 0x71;
    pub const I32_OR: u64 = 0x72;
    pub const I32_XOR: u64 = 0x73;
    pub const I32_SHL: u64 = 0x74;
    pub const I32_SHRS: u64 = 0x75;
    pub const I32_SHRU: u64 = 0x76;
    pub const I32_ROTL: u64 = 0x77;
    pub const I32_ROTR: u64 = 0x78;

    pub const I64_CLZ: u64 = 0x79;
    pub const I64_CTZ: u64 = 0x7a;
    pub const I64_POPCNT: u64 = 0x7b;
    pub const I64_ADD: u64 = 0x7c;
    pub const I64_SUB: u64 = 0x7d;
    pub const I64_MUL: u64 = 0x7e;
    pub const I64_DIVS: u64 = 0x7f;
    pub const I64_DIVU: u64 = 0x80;
    pub const I64_REMS: u64 = 0x81;
    pub const I64_REMU: u64 = 0x82;
    pub const I64_AND: u64 = 0x83;
    pub const I64_OR: u64 = 0x84;
    pub const I64_XOR: u64 = 0x85;
    pub const I64_SHL: u64 = 0x86;
    pub const I64_SHRS: u64 = 0x87;
    pub const I64_SHRU: u64 = 0x88;
    pub const I64_ROTL: u64 = 0x89;
    pub const I64_ROTR: u64 = 0x8a;

    pub const F32_ABS: u64 = 0x8b;
    pub const F32_NEG: u64 = 0x8c;
    pub const F32_CEIL: u64 = 0x8d;
    pub const F32_FLOOR: u64 = 0x8e;
    pub const F32_TRUNC: u64 = 0x8f;
    pub const F32_NEAREST: u64 = 0x90;
    pub const F32_SQRT: u64 = 0x91;
    pub const F32_ADD: u64 = 0x92;
    pub const F32_SUB: u64 = 0x93;
    pub const F32_MUL: u64 = 0x94;
    pub const F32_DIV: u64 = 0x95;
    pub const F32_MIN: u64 = 0x96;
    pub const F32_MAX: u64 = 0x97;
    pub const F32_COPYSIGN: u64 = 0x98;

    pub const F64_ABS: u64 = 0x99;
    pub const F64_NEG: u64 = 0x9a;
    pub const F64_CEIL: u64 = 0x9b;
    pub const F64_FLOOR: u64 = 0x9c;
    pub const F64_TRUNC: u64 = 0x9d;
    pub const F64_NEAREST: u64 = 0x9e;
    pub const F64_SQRT: u64 = 0x9f;
    pub const F64_ADD: u64 = 0xa0;
    pub const F64_SUB: u64 = 0xa1;
    pub const F64_MUL: u64 = 0xa2;
    pub const F64_DIV: u64 = 0xa3;
    pub const F64_MIN: u64 = 0xa4;
    pub const F64_MAX: u64 = 0xa5;
    pub const F64_COPYSIGN: u64 = 0xa6;

    pub const I32_WRAP_I64: u64 = 0xa7;
    pub const I32_TRUNC_SF32: u64 = 0xa8;
    pub const I32_TRUNC_UF32: u64 = 0xa9;
    pub const I32_TRUNC_SF64: u64 = 0xaa;
    pub const I32_TRUNC_UF64: u64 = 0xab;
    pub const I64_EXTEND_SI32: u64 = 0xac;
    pub const I64_EXTEND_UI32: u64 = 0xad;
    pub const I64_TRUNC_SF32: u64 = 0xae;
    pub const I64_TRUNC_UF32: u64 = 0xaf;
    pub const I64_TRUNC_SF64: u64 = 0xb0;
    pub const I64_TRUNC_UF64: u64 = 0xb1;
    pub const F32_CONVERT_SI32: u64 = 0xb2;
    pub const F32_CONVERT_UI32: u64 = 0xb3;
    pub const F32_CONVERT_SI64: u64 = 0xb4;
    pub const F32_CONVERT_UI64: u64 = 0xb5;
    pub const F32_DEMOTE_F64: u64 = 0xb6;
    pub const F64_CONVERT_SI32: u64 = 0xb7;
    pub const F64_CONVERT_UI32: u64 = 0xb8;
    pub const F64_CONVERT_SI64: u64 = 0xb9;
    pub const F64_CONVERT_UI64: u64 = 0xba;
    pub const F64_PROMOTE_F32: u64 = 0xbb;
    pub const I32_REINTERPRET_F32: u64 = 0xbc;
    pub const I64_REINTERPRET_F64: u64 = 0xbd;
    pub const F32_REINTERPRET_I32: u64 = 0xbe;
    pub const F64_REINTERPRET_I64: u64 = 0xbf;

    pub const I32_EXTEND8_S: u64 = 0xc0;
    pub const I32_EXTEND16_S: u64 = 0xc1;
    pub const I64_EXTEND8_S: u64 = 0xc2;
    pub const I64_EXTEND16_S: u64 = 0xc3;
    pub const I64_EXTEND32_S: u64 = 0xc4;

    // Synthetic opcodes from the compiler.
    pub const SYNTHETIC_BASE: u64 = 0xfe00000000000000;
    pub const SYNTHETIC_END_EXPRESSION: u64 = SYNTHETIC_BASE + 0x0e;

    // Synthetic local_get_N / local_set_N
    pub const SYNTHETIC_LOCAL_GET_0: u64 = SYNTHETIC_BASE + 0x14;
    pub const SYNTHETIC_LOCAL_GET_7: u64 = SYNTHETIC_BASE + 0x1b;
    pub const SYNTHETIC_LOCAL_SET_0: u64 = SYNTHETIC_BASE + 0x1e;
    pub const SYNTHETIC_LOCAL_SET_7: u64 = SYNTHETIC_BASE + 0x25;
    pub const SYNTHETIC_LOCAL_COPY: u64 = SYNTHETIC_BASE + 0x26;
    pub const SYNTHETIC_BR_NOSTACK: u64 = SYNTHETIC_BASE + 0x1c;
    pub const SYNTHETIC_BR_IF_NOSTACK: u64 = SYNTHETIC_BASE + 0x1d;

    // Synthetic fused ops
    pub const SYNTHETIC_I32_ADD2LOCAL: u64 = SYNTHETIC_BASE + 0x00;
    pub const SYNTHETIC_I32_ADDCONSTLOCAL: u64 = SYNTHETIC_BASE + 0x01;
    pub const SYNTHETIC_I32_ANDCONSTLOCAL: u64 = SYNTHETIC_BASE + 0x02;
    pub const SYNTHETIC_I32_STORELOCAL: u64 = SYNTHETIC_BASE + 0x03;
    pub const SYNTHETIC_LOCAL_SETI32_CONST: u64 = SYNTHETIC_BASE + 0x05;

    // Synthetic call variants
    pub const SYNTHETIC_CALL_00: u64 = SYNTHETIC_BASE + 0x06;
    pub const SYNTHETIC_CALL_31: u64 = SYNTHETIC_BASE + 0x0d;

    pub const SYNTHETIC_ARGUMENT_GET: u64 = SYNTHETIC_BASE + 0x0f;
    pub const SYNTHETIC_ARGUMENT_SET: u64 = SYNTHETIC_BASE + 0x10;
    pub const SYNTHETIC_ARGUMENT_TEE: u64 = SYNTHETIC_BASE + 0x11;
    pub const SYNTHETIC_CALL_WITH_RECORD_0: u64 = SYNTHETIC_BASE + 0x12;
    pub const SYNTHETIC_CALL_WITH_RECORD_1: u64 = SYNTHETIC_BASE + 0x13;

    // Fused i32 binary-from-two-locals
    pub const SYNTHETIC_I32_SUB2LOCAL: u64 = SYNTHETIC_BASE + 0x27;
    pub const SYNTHETIC_I32_MUL2LOCAL: u64 = SYNTHETIC_BASE + 0x28;
    pub const SYNTHETIC_I32_AND2LOCAL: u64 = SYNTHETIC_BASE + 0x29;
    pub const SYNTHETIC_I32_OR2LOCAL: u64 = SYNTHETIC_BASE + 0x2a;
    pub const SYNTHETIC_I32_XOR2LOCAL: u64 = SYNTHETIC_BASE + 0x2b;
    pub const SYNTHETIC_I32_SHL2LOCAL: u64 = SYNTHETIC_BASE + 0x2c;
    pub const SYNTHETIC_I32_SHRU2LOCAL: u64 = SYNTHETIC_BASE + 0x2d;
    pub const SYNTHETIC_I32_SHRS2LOCAL: u64 = SYNTHETIC_BASE + 0x2e;

    // Fused i64 ops
    pub const SYNTHETIC_I64_ADD2LOCAL: u64 = SYNTHETIC_BASE + 0x2f;
    pub const SYNTHETIC_I64_ADDCONSTLOCAL: u64 = SYNTHETIC_BASE + 0x30;
    pub const SYNTHETIC_I64_ANDCONSTLOCAL: u64 = SYNTHETIC_BASE + 0x31;
    pub const SYNTHETIC_I64_STORELOCAL: u64 = SYNTHETIC_BASE + 0x32;
    pub const SYNTHETIC_I64_SUB2LOCAL: u64 = SYNTHETIC_BASE + 0x33;
    pub const SYNTHETIC_I64_MUL2LOCAL: u64 = SYNTHETIC_BASE + 0x34;
    pub const SYNTHETIC_I64_AND2LOCAL: u64 = SYNTHETIC_BASE + 0x35;
    pub const SYNTHETIC_I64_OR2LOCAL: u64 = SYNTHETIC_BASE + 0x36;
    pub const SYNTHETIC_I64_XOR2LOCAL: u64 = SYNTHETIC_BASE + 0x37;
    pub const SYNTHETIC_I64_SHL2LOCAL: u64 = SYNTHETIC_BASE + 0x38;
    pub const SYNTHETIC_I64_SHRU2LOCAL: u64 = SYNTHETIC_BASE + 0x39;
    pub const SYNTHETIC_I64_SHRS2LOCAL: u64 = SYNTHETIC_BASE + 0x3a;
    pub const SYNTHETIC_LOCAL_SETI64_CONST: u64 = SYNTHETIC_BASE + 0x3b;
    pub const SYNTHETIC_BR_TABLE_CONT: u64 = SYNTHETIC_BASE + 0x3c;
}

const REG_COUNT: usize = 8;
const STACK_MARKER: u8 = 8;

/// Control flow frame tracking for structured control flow → cranelift blocks.
struct ControlFrame {
    kind: ControlKind,
    /// The cranelift block to branch to (for `br` targeting this frame).
    /// For blocks: the merge/after block.
    /// For loops: the loop header block.
    branch_target: cranelift_codegen::ir::Block,
    /// Where execution continues after this construct ends.
    after_block: cranelift_codegen::ir::Block,
    /// Number of result values (arity).
    arity: u32,
    /// Number of parameters consumed from outer stack.
    param_count: usize,
    /// Stack depth at block entry (for cleaning up on br).
    stack_depth_at_entry: i32,
    /// Real value-stack size at block entry, minus this block's param count.
    /// Only meaningful (and only set) when vstack is disabled (max_stack_depth == 0).
    /// Used to compute the cleanup target on br/br_if.
    entry_real_depth_var: Option<Variable>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlKind {
    Block,
    Loop,
    If,
}

pub struct CompiledCode {
    ptr: *mut u8,
    len: usize,
    capacity: usize, // mmap'd size
}

impl CompiledCode {
    fn as_ptr(&self) -> *const u8 {
        self.ptr
    }
}

impl Drop for CompiledCode {
    fn drop(&mut self) {
        #[cfg(unix)]
        if !self.ptr.is_null() {
            unsafe {
                libc::munmap(self.ptr.cast(), self.capacity);
            }
        }
    }
}

pub struct CraneliftCompiler;

impl CraneliftCompiler {
    pub fn compile_to_bytes(
        insns: &[CraneliftInsn],
        helpers: &RuntimeHelpers,
        outcome_return_value: u64,
        result_arity: u32,
    ) -> Result<Vec<u8>, &'static str> {
        // Pre-scan: bail if any instruction is unsupported or uses multi-value blocks.
        for (_i, insn) in insns.iter().enumerate() {
            if !Self::is_supported(insn) {
                return Err("unsupported instruction");
            }
            // Bail on multi-value blocks (arity > 1) — not supported yet.
            if matches!(insn.opcode, op::BLOCK | op::LOOP | op::IF) {
                let arity = insn.imm3 & 0xffff;
                if arity > 1 {
                    return Err("multi-value blocks not supported");
                }
            }
            // Note: op::CALL is used for multi-value returns but also for some
            // single-return calls. We handle it via flush_vstack_to_real before the call.
        }

        let mut flag_builder = settings::builder();
        flag_builder.set("opt_level", "speed").unwrap();
        flag_builder.set("is_pic", "false").unwrap();
        let flags = settings::Flags::new(flag_builder);
        let isa = cranelift_native::builder()
            .map_err(|_| "unsupported host architecture")?
            .finish(flags)
            .map_err(|_| "failed to build ISA")?;

        // Function signature matches handler_ptr:
        //   u64 fn(void* interpreter, void* configuration, void* insn, u32 short_ip, void* cc, void* addrs)
        let ptr_type = isa.pointer_type();
        let mut sig = Signature::new(CallConv::SystemV);
        sig.params.push(AbiParam::new(ptr_type)); // interpreter
        sig.params.push(AbiParam::new(ptr_type)); // configuration
        sig.params.push(AbiParam::new(ptr_type)); // instruction (unused)
        sig.params.push(AbiParam::new(types::I32)); // short_ip (unused)
        sig.params.push(AbiParam::new(ptr_type)); // cc (unused)
        sig.params.push(AbiParam::new(ptr_type)); // addresses_ptr (unused)
        sig.returns.push(AbiParam::new(types::I64)); // Outcome

        let mut func = Function::with_name_signature(UserFuncName::user(0, 0), sig);
        let mut builder_ctx = FunctionBuilderContext::new();
        let mut builder = FunctionBuilder::new(&mut func, &mut builder_ctx);

        // Declare variables for virtual registers R0-R7.
        // We store everything as i64 and bitcast for floats.
        let reg_vars: [Variable; REG_COUNT] = std::array::from_fn(|i| Variable::from_u32(i as u32));
        for i in 0..REG_COUNT {
            builder.declare_var(reg_vars[i], types::I64);
        }

        let entry_block = builder.create_block();
        builder.append_block_params_for_function_params(entry_block);
        builder.switch_to_block(entry_block);
        builder.seal_block(entry_block);

        let interpreter_val = builder.block_params(entry_block)[0];
        let configuration_val = builder.block_params(entry_block)[1];

        // Load regs[0..7] from configuration. regs is at offset `regs_offset` from Configuration*.
        // Each Value is `value_size` bytes; the low 8 bytes are the i64 payload.
        let regs_offset = helpers.regs_offset as i32;
        let value_size = helpers.value_size as i32;
        for i in 0..REG_COUNT {
            let offset = regs_offset + (i as i32) * value_size;
            let val =
                builder
                    .ins()
                    .load(types::I64, MemFlags::trusted(), configuration_val, offset);
            builder.def_var(reg_vars[i], val);
        }

        // Create the return/epilogue block.
        let epilogue_block = builder.create_block();
        // Create a trap block.
        let trap_block = builder.create_block();

        // Build helper call signatures. We import them as indirect calls via function pointers.
        // read_local: i64 fn(config: ptr, index: i32)
        let mut read_local_sig = Signature::new(CallConv::SystemV);
        read_local_sig.params.push(AbiParam::new(ptr_type));
        read_local_sig.params.push(AbiParam::new(types::I32));
        read_local_sig.returns.push(AbiParam::new(types::I64));
        let read_local_sig = builder.import_signature(read_local_sig);

        // write_local: void fn(config: ptr, index: i32, value: i64)
        let mut write_local_sig = Signature::new(CallConv::SystemV);
        write_local_sig.params.push(AbiParam::new(ptr_type));
        write_local_sig.params.push(AbiParam::new(types::I32));
        write_local_sig.params.push(AbiParam::new(types::I64));
        let write_local_sig = builder.import_signature(write_local_sig);

        // call_function: bool fn(interp: ptr, config: ptr, func_idx: i32) -> i32 (0=ok, 1=trap)
        let mut call_fn_sig = Signature::new(CallConv::SystemV);
        call_fn_sig.params.push(AbiParam::new(ptr_type));
        call_fn_sig.params.push(AbiParam::new(ptr_type));
        call_fn_sig.params.push(AbiParam::new(types::I32));
        call_fn_sig.returns.push(AbiParam::new(types::I32));
        let call_fn_sig = builder.import_signature(call_fn_sig);

        let mut call_fn1_sig = Signature::new(CallConv::SystemV);
        call_fn1_sig.params.push(AbiParam::new(ptr_type));
        call_fn1_sig.params.push(AbiParam::new(ptr_type));
        call_fn1_sig.params.push(AbiParam::new(types::I32));
        call_fn1_sig.params.push(AbiParam::new(types::I64));
        call_fn1_sig.returns.push(AbiParam::new(types::I32));
        let call_fn1_sig = builder.import_signature(call_fn1_sig);

        let mut call_fn2_sig = Signature::new(CallConv::SystemV);
        call_fn2_sig.params.push(AbiParam::new(ptr_type));
        call_fn2_sig.params.push(AbiParam::new(ptr_type));
        call_fn2_sig.params.push(AbiParam::new(types::I32));
        call_fn2_sig.params.push(AbiParam::new(types::I64));
        call_fn2_sig.params.push(AbiParam::new(types::I64));
        call_fn2_sig.returns.push(AbiParam::new(types::I32));
        let call_fn2_sig = builder.import_signature(call_fn2_sig);

        let mut call_fn3_sig = Signature::new(CallConv::SystemV);
        call_fn3_sig.params.push(AbiParam::new(ptr_type));
        call_fn3_sig.params.push(AbiParam::new(ptr_type));
        call_fn3_sig.params.push(AbiParam::new(types::I32));
        call_fn3_sig.params.push(AbiParam::new(types::I64));
        call_fn3_sig.params.push(AbiParam::new(types::I64));
        call_fn3_sig.params.push(AbiParam::new(types::I64));
        call_fn3_sig.returns.push(AbiParam::new(types::I32));
        let call_fn3_sig = builder.import_signature(call_fn3_sig);

        // call_indirect: i32 fn(interp: ptr, config: ptr, table_idx: i32, type_idx: i32, element_index: i32)
        let mut call_indirect_sig = Signature::new(CallConv::SystemV);
        call_indirect_sig.params.push(AbiParam::new(ptr_type));
        call_indirect_sig.params.push(AbiParam::new(ptr_type));
        call_indirect_sig.params.push(AbiParam::new(types::I32));
        call_indirect_sig.params.push(AbiParam::new(types::I32));
        call_indirect_sig.params.push(AbiParam::new(types::I32));
        call_indirect_sig.returns.push(AbiParam::new(types::I32));
        let call_indirect_sig = builder.import_signature(call_indirect_sig);

        // memory_copy: i32 fn(interp: ptr, config: ptr, dst_mem: i32, src_mem: i32, dst: i32, src: i32, count: i32)
        let mut memory_copy_sig = Signature::new(CallConv::SystemV);
        memory_copy_sig.params.push(AbiParam::new(ptr_type));
        memory_copy_sig.params.push(AbiParam::new(ptr_type));
        memory_copy_sig.params.push(AbiParam::new(types::I32));
        memory_copy_sig.params.push(AbiParam::new(types::I32));
        memory_copy_sig.params.push(AbiParam::new(types::I32));
        memory_copy_sig.params.push(AbiParam::new(types::I32));
        memory_copy_sig.params.push(AbiParam::new(types::I32));
        memory_copy_sig.returns.push(AbiParam::new(types::I32));
        let memory_copy_sig = builder.import_signature(memory_copy_sig);

        // memory_fill: i32 fn(interp: ptr, config: ptr, mem_idx: i32, offset: i32, value: i32, count: i32)
        let mut memory_fill_sig = Signature::new(CallConv::SystemV);
        memory_fill_sig.params.push(AbiParam::new(ptr_type));
        memory_fill_sig.params.push(AbiParam::new(ptr_type));
        memory_fill_sig.params.push(AbiParam::new(types::I32));
        memory_fill_sig.params.push(AbiParam::new(types::I32));
        memory_fill_sig.params.push(AbiParam::new(types::I32));
        memory_fill_sig.params.push(AbiParam::new(types::I32));
        memory_fill_sig.returns.push(AbiParam::new(types::I32));
        let memory_fill_sig = builder.import_signature(memory_fill_sig);

        // set_trap: void fn(interp: ptr, msg: ptr, len: i32)
        let mut set_trap_sig = Signature::new(CallConv::SystemV);
        set_trap_sig.params.push(AbiParam::new(ptr_type));
        set_trap_sig.params.push(AbiParam::new(ptr_type));
        set_trap_sig.params.push(AbiParam::new(types::I32));
        let set_trap_sig = builder.import_signature(set_trap_sig);

        // memory_load*: i64 fn(config: ptr, mem_idx: i32, addr: i64)
        let mut mem_load_sig = Signature::new(CallConv::SystemV);
        mem_load_sig.params.push(AbiParam::new(ptr_type));
        mem_load_sig.params.push(AbiParam::new(types::I32));
        mem_load_sig.params.push(AbiParam::new(types::I64));
        mem_load_sig.returns.push(AbiParam::new(types::I64));
        let mem_load_sig = builder.import_signature(mem_load_sig);

        // memory_store*: i32 fn(config: ptr, mem_idx: i32, addr: i64, value: i64)
        let mut mem_store_sig = Signature::new(CallConv::SystemV);
        mem_store_sig.params.push(AbiParam::new(ptr_type));
        mem_store_sig.params.push(AbiParam::new(types::I32));
        mem_store_sig.params.push(AbiParam::new(types::I64));
        mem_store_sig.params.push(AbiParam::new(types::I64));
        mem_store_sig.returns.push(AbiParam::new(types::I32));
        let mem_store_sig = builder.import_signature(mem_store_sig);

        // memory_size: i64 fn(config: ptr, mem_idx: i32)
        let mut mem_size_sig = Signature::new(CallConv::SystemV);
        mem_size_sig.params.push(AbiParam::new(ptr_type));
        mem_size_sig.params.push(AbiParam::new(types::I32));
        mem_size_sig.returns.push(AbiParam::new(types::I64));
        let mem_size_sig = builder.import_signature(mem_size_sig);

        // memory_grow: i32 fn(config: ptr, mem_idx: i32, pages: i32)
        let mut mem_grow_sig = Signature::new(CallConv::SystemV);
        mem_grow_sig.params.push(AbiParam::new(ptr_type));
        mem_grow_sig.params.push(AbiParam::new(types::I32));
        mem_grow_sig.params.push(AbiParam::new(types::I32));
        mem_grow_sig.returns.push(AbiParam::new(types::I32));
        let mem_grow_sig = builder.import_signature(mem_grow_sig);

        // read_global: i64 fn(config: ptr, index: i32)
        let mut read_global_sig = Signature::new(CallConv::SystemV);
        read_global_sig.params.push(AbiParam::new(ptr_type));
        read_global_sig.params.push(AbiParam::new(types::I32));
        read_global_sig.returns.push(AbiParam::new(types::I64));
        let read_global_sig = builder.import_signature(read_global_sig);

        // write_global: void fn(config: ptr, index: i32, value: i64)
        let mut write_global_sig = Signature::new(CallConv::SystemV);
        write_global_sig.params.push(AbiParam::new(ptr_type));
        write_global_sig.params.push(AbiParam::new(types::I32));
        write_global_sig.params.push(AbiParam::new(types::I64));
        let write_global_sig = builder.import_signature(write_global_sig);

        // stack_push: void fn(config: ptr, value: i64)
        let mut stack_push_sig = Signature::new(CallConv::SystemV);
        stack_push_sig.params.push(AbiParam::new(ptr_type));
        stack_push_sig.params.push(AbiParam::new(types::I64));
        let stack_push_sig = builder.import_signature(stack_push_sig);

        // stack_pop: i64 fn(config: ptr)
        let mut stack_pop_sig = Signature::new(CallConv::SystemV);
        stack_pop_sig.params.push(AbiParam::new(ptr_type));
        stack_pop_sig.returns.push(AbiParam::new(types::I64));
        let stack_pop_sig = builder.import_signature(stack_pop_sig);

        // stack_size: i64 fn(config: ptr)
        let mut stack_size_sig = Signature::new(CallConv::SystemV);
        stack_size_sig.params.push(AbiParam::new(ptr_type));
        stack_size_sig.returns.push(AbiParam::new(types::I64));
        let stack_size_sig = builder.import_signature(stack_size_sig);

        // stack_cleanup: void fn(config: ptr, initial_size: i64, result_arity: i32)
        let mut stack_cleanup_sig = Signature::new(CallConv::SystemV);
        stack_cleanup_sig.params.push(AbiParam::new(ptr_type));
        stack_cleanup_sig.params.push(AbiParam::new(types::I64));
        stack_cleanup_sig.params.push(AbiParam::new(types::I32));
        let stack_cleanup_sig = builder.import_signature(stack_cleanup_sig);

        // callrec_read: i64 fn(config: ptr, index: i32)
        let mut callrec_read_sig = Signature::new(CallConv::SystemV);
        callrec_read_sig.params.push(AbiParam::new(ptr_type));
        callrec_read_sig.params.push(AbiParam::new(types::I32));
        callrec_read_sig.returns.push(AbiParam::new(types::I64));
        let callrec_read_sig = builder.import_signature(callrec_read_sig);

        // callrec_write: void fn(config: ptr, index: i32, value: i64)
        let mut callrec_write_sig = Signature::new(CallConv::SystemV);
        callrec_write_sig.params.push(AbiParam::new(ptr_type));
        callrec_write_sig.params.push(AbiParam::new(types::I32));
        callrec_write_sig.params.push(AbiParam::new(types::I64));
        let callrec_write_sig = builder.import_signature(callrec_write_sig);

        // call_with_record: i32 fn(interp: ptr, config: ptr, func_idx: i32)
        let mut call_wr_sig = Signature::new(CallConv::SystemV);
        call_wr_sig.params.push(AbiParam::new(ptr_type));
        call_wr_sig.params.push(AbiParam::new(ptr_type));
        call_wr_sig.params.push(AbiParam::new(types::I32));
        call_wr_sig.returns.push(AbiParam::new(types::I32));
        let call_wr_sig = builder.import_signature(call_wr_sig);

        // Helper pointer raw values — rematerialized as iconst in each use site.
        let h_read_local = helpers.read_local as i64;
        let h_write_local = helpers.write_local as i64;
        let h_call_fn = helpers.call_function as i64;
        let h_call_fn0 = helpers.call_function_0 as i64;
        let h_call_fn1 = helpers.call_function_1 as i64;
        let h_call_fn2 = helpers.call_function_2 as i64;
        let h_call_fn3 = helpers.call_function_3 as i64;
        let h_direct_call_0 = helpers.direct_call_0 as i64;
        let h_direct_call_1 = helpers.direct_call_1 as i64;
        let h_direct_call_2 = helpers.direct_call_2 as i64;
        let h_direct_call_3 = helpers.direct_call_3 as i64;
        let h_set_trap = helpers.set_trap as i64;
        let h_mem_load8_s = helpers.memory_load8_s as i64;
        let h_mem_load8_u = helpers.memory_load8_u as i64;
        let h_mem_load16_s = helpers.memory_load16_s as i64;
        let h_mem_load16_u = helpers.memory_load16_u as i64;
        let h_mem_load32_s = helpers.memory_load32_s as i64;
        let h_mem_load32_u = helpers.memory_load32_u as i64;
        let h_mem_load64 = helpers.memory_load64 as i64;
        let h_mem_store8 = helpers.memory_store8 as i64;
        let h_mem_store16 = helpers.memory_store16 as i64;
        let h_mem_store32 = helpers.memory_store32 as i64;
        let h_mem_store64 = helpers.memory_store64 as i64;
        let h_mem_size = helpers.memory_size as i64;
        let h_mem_grow = helpers.memory_grow as i64;
        let h_read_global = helpers.read_global as i64;
        let h_write_global = helpers.write_global as i64;
        let h_stack_push = helpers.stack_push as i64;
        let h_stack_pop = helpers.stack_pop as i64;
        let h_stack_size = helpers.stack_size as i64;
        let h_stack_cleanup = helpers.stack_cleanup as i64;
        let h_callrec_read = helpers.callrec_read as i64;
        let h_callrec_write = helpers.callrec_write as i64;
        let h_call_wr = helpers.call_with_record as i64;
        let h_call_indirect = helpers.call_indirect as i64;
        let h_memory_copy = helpers.memory_copy as i64;
        let h_memory_fill = helpers.memory_fill as i64;
        let locals_base_offset = helpers.locals_base_offset as i32;
        let default_memory_base_offset = helpers.default_memory_base_offset as i32;
        let compiled_call_result_scratch_offset = helpers.compiled_call_result_scratch_offset as i32;
        // Store interpreter and configuration in Variables so they survive across blocks.
        let interp_var = Variable::from_u32(8);
        builder.declare_var(interp_var, ptr_type);
        builder.def_var(interp_var, interpreter_val);
        let config_var = Variable::from_u32(9);
        builder.declare_var(config_var, ptr_type);
        builder.def_var(config_var, configuration_val);
        // Cache the locals_base pointer in a Variable for fast local access.
        let locals_base_var = Variable::from_u32(10);
        builder.declare_var(locals_base_var, ptr_type);
        let initial_locals_base = builder.ins().load(ptr_type, MemFlags::trusted(), configuration_val, locals_base_offset);
        builder.def_var(locals_base_var, initial_locals_base);
        let default_memory_base_var = Variable::from_u32(11);
        builder.declare_var(default_memory_base_var, ptr_type);
        let initial_default_memory_base = builder.ins().load(ptr_type, MemFlags::trusted(), configuration_val, default_memory_base_offset);
        builder.def_var(default_memory_base_var, initial_default_memory_base);

        // Control flow stack.
        let mut control_stack: Vec<ControlFrame> = Vec::new();

        // Virtual stack using Cranelift Variables — eliminates all stack_push/pop calls.
        // Disabled for functions with raw CALL (multi-value returns break sp tracking).
        let has_raw_call = insns.iter().any(|i| i.opcode == op::CALL || i.opcode == op::CALL_INDIRECT);
        // Pre-scan to find max stack depth (count Stack pushes/pops).
        let max_stack_depth = if has_raw_call { 0 } else {
            // Count total stack pushes as an upper bound. The simple linear
            // depth tracking cannot account for control flow merges, so use
            // the total number of stack-destination instructions instead.
            let total_pushes = insns.iter()
                .filter(|i| i.destination == STACK_MARKER)
                .count();
            total_pushes.max(16)
        }; // 0 if has_raw_call
        let mut is_unreachable = false;
        let mut dirty_regs = [false; REG_COUNT];
        const VSTACK_VAR_BASE: u32 = 12;
        let mut stack_vars: Vec<Variable> = Vec::with_capacity(max_stack_depth);
        for i in 0..max_stack_depth {
            let var = Variable::from_u32(VSTACK_VAR_BASE + i as u32);
            builder.declare_var(var, types::I64);
            // Initialize to 0 (needed for Cranelift SSA — all vars must be defined before use).
            let zero = builder.ins().iconst(types::I64, 0);
            builder.def_var(var, zero);
            stack_vars.push(var);
        }
        let mut sp: usize = 0; // compile-time stack pointer

        // Save initial value stack size for cleanup at function exit.
        // When vstack is enabled (no raw CALL), the real stack is never touched during
        // execution — only push_top_n_to_real at exit adds exactly result_arity values,
        // so stack_cleanup would be a no-op. Skip both stack_size and stack_cleanup.
        let initial_stack_size_var = Variable::from_u32(VSTACK_VAR_BASE + max_stack_depth as u32);
        builder.declare_var(initial_stack_size_var, types::I64);
        // Counter for allocating fresh Variables for per-control-frame entry depths
        // (only used when vstack is disabled).
        let mut next_var_id: u32 = VSTACK_VAR_BASE + max_stack_depth as u32 + 1;
        if has_raw_call {
            let stack_size_fp = builder.ins().iconst(ptr_type, h_stack_size);
            let cfg_for_size = builder.use_var(config_var);
            let stack_size_call = builder.ins().call_indirect(stack_size_sig, stack_size_fp, &[cfg_for_size]);
            let initial_stack_size = builder.inst_results(stack_size_call)[0];
            builder.def_var(initial_stack_size_var, initial_stack_size);
        } else {
            let zero = builder.ins().iconst(types::I64, 0);
            builder.def_var(initial_stack_size_var, zero);
        }

        // Callrecord marker constant (matches Dispatch::RegisterOrStack::CallRecord = 9)
        const CALLREC_BASE: u8 = 9;

        // Helper: read a value from a source location (register, virtual stack, or call record).
        macro_rules! read_src {
            ($builder:expr, $src:expr) => {{
                let src = $src;
                if src < STACK_MARKER {
                    $builder.use_var(reg_vars[src as usize])
                } else if src == STACK_MARKER {
                    if max_stack_depth > 0 && sp > 0 {
                        sp -= 1;
                        $builder.use_var(stack_vars[sp])
                    } else {
                        // vstack disabled — use real stack.
                        let fp = $builder.ins().iconst(ptr_type, h_stack_pop);
                        let cfg = $builder.use_var(config_var);
                        let call = $builder.ins().call_indirect(stack_pop_sig, fp, &[cfg]);
                        $builder.inst_results(call)[0]
                    }
                } else {
                    let fp = $builder.ins().iconst(ptr_type, h_callrec_read);
                    let cfg = $builder.use_var(config_var);
                    let idx = $builder.ins().iconst(types::I32, i64::from(src - CALLREC_BASE));
                    let call = $builder.ins().call_indirect(callrec_read_sig, fp, &[cfg, idx]);
                    $builder.inst_results(call)[0]
                }
            }};
        }

        // Helper: flush virtual stack slots [0..sp) to the real value stack (for calls).
        macro_rules! flush_vstack_to_real {
            ($builder:expr) => {{
                if max_stack_depth > 0 {
                    for i in 0..sp {
                        let val = $builder.use_var(stack_vars[i]);
                        let fp = $builder.ins().iconst(ptr_type, h_stack_push);
                        let cfg = $builder.use_var(config_var);
                        $builder.ins().call_indirect(stack_push_sig, fp, &[cfg, val]);
                    }
                }
                sp = 0;
            }};
        }
        // Helper: push only the top `n` values from vstack to real stack (for function return).
        macro_rules! push_top_n_to_real {
            ($builder:expr, $n:expr) => {{
                let n = $n as usize;
                if max_stack_depth > 0 && sp >= n {
                    // vstack enabled: push only top n values to real stack.
                    for i in 0..n {
                        let idx = sp - n + i;
                        let val = $builder.use_var(stack_vars[idx]);
                        let fp = $builder.ins().iconst(ptr_type, h_stack_push);
                        let cfg = $builder.use_var(config_var);
                        $builder.ins().call_indirect(stack_push_sig, fp, &[cfg, val]);
                    }
                }
                // When vstack disabled (max_stack_depth==0), values are already
                // on the real stack. The interpreter's label unwinding handles cleanup.
            }};
        }

        macro_rules! write_dst {
            ($builder:expr, $dst:expr, $val:expr) => {{
                let dst = $dst;
                let val = $val;
                if dst < STACK_MARKER {
                    $builder.def_var(reg_vars[dst as usize], val);
                    dirty_regs[dst as usize] = true;
                } else if dst == STACK_MARKER {
                    if max_stack_depth > 0 {
                        $builder.def_var(stack_vars[sp], val);
                        sp += 1;
                    } else {
                        // vstack disabled — use real stack, don't track sp.
                        let fp = $builder.ins().iconst(ptr_type, h_stack_push);
                        let cfg = $builder.use_var(config_var);
                        $builder.ins().call_indirect(stack_push_sig, fp, &[cfg, val]);
                    }
                } else {
                    let fp = $builder.ins().iconst(ptr_type, h_callrec_write);
                    let cfg = $builder.use_var(config_var);
                    let idx = $builder.ins().iconst(types::I32, i64::from(dst - CALLREC_BASE));
                    $builder.ins().call_indirect(callrec_write_sig, fp, &[cfg, idx, val]);
                }
            }};
        }

        // Macros for common instruction patterns. These read sources, compute, and write destination.
        // NOTE: In the interpreter, sources[0] = rhs (popped first), sources[1] = lhs.
        // We must read in the same order (sources[0] first for stack pops) but assign correctly.
        macro_rules! i32_binop {
            ($builder:expr, $insn:expr, $op:ident) => {{
                let rhs_raw = read_src!($builder, $insn.sources[0]);
                let lhs_raw = read_src!($builder, $insn.sources[1]);
                let lhs = $builder.ins().ireduce(types::I32, lhs_raw);
                let rhs = $builder.ins().ireduce(types::I32, rhs_raw);
                let result = $builder.ins().$op(lhs, rhs);
                let result = $builder.ins().sextend(types::I64, result);
                write_dst!($builder, $insn.destination, result);
            }};
        }
        macro_rules! i64_binop {
            ($builder:expr, $insn:expr, $op:ident) => {{
                let rhs = read_src!($builder, $insn.sources[0]);
                let lhs = read_src!($builder, $insn.sources[1]);
                let result = $builder.ins().$op(lhs, rhs);
                write_dst!($builder, $insn.destination, result);
            }};
        }
        macro_rules! i32_unop {
            ($builder:expr, $insn:expr, $op:ident) => {{
                let src_raw = read_src!($builder, $insn.sources[0]);
                let src = $builder.ins().ireduce(types::I32, src_raw);
                let result = $builder.ins().$op(src);
                let result = $builder.ins().sextend(types::I64, result);
                write_dst!($builder, $insn.destination, result);
            }};
        }
        macro_rules! i64_unop {
            ($builder:expr, $insn:expr, $op:ident) => {{
                let src = read_src!($builder, $insn.sources[0]);
                let result = $builder.ins().$op(src);
                write_dst!($builder, $insn.destination, result);
            }};
        }
        macro_rules! i32_cmp {
            ($builder:expr, $insn:expr, $cc:expr) => {{
                let rhs_raw = read_src!($builder, $insn.sources[0]);
                let lhs_raw = read_src!($builder, $insn.sources[1]);
                let lhs = $builder.ins().ireduce(types::I32, lhs_raw);
                let rhs = $builder.ins().ireduce(types::I32, rhs_raw);
                let cmp = $builder.ins().icmp($cc, lhs, rhs);
                let result = $builder.ins().uextend(types::I64, cmp);
                write_dst!($builder, $insn.destination, result);
            }};
        }
        macro_rules! i64_cmp {
            ($builder:expr, $insn:expr, $cc:expr) => {{
                let rhs = read_src!($builder, $insn.sources[0]);
                let lhs = read_src!($builder, $insn.sources[1]);
                let cmp = $builder.ins().icmp($cc, lhs, rhs);
                let result = $builder.ins().uextend(types::I64, cmp);
                write_dst!($builder, $insn.destination, result);
            }};
        }
        macro_rules! f32_binop {
            ($builder:expr, $insn:expr, $op:ident) => {{
                let rhs_raw = read_src!($builder, $insn.sources[0]);
                let lhs_raw = read_src!($builder, $insn.sources[1]);
                let lhs_i32 = $builder.ins().ireduce(types::I32, lhs_raw);
                let rhs_i32 = $builder.ins().ireduce(types::I32, rhs_raw);
                let lhs = $builder.ins().bitcast(types::F32, MemFlags::new(), lhs_i32);
                let rhs = $builder.ins().bitcast(types::F32, MemFlags::new(), rhs_i32);
                let result = $builder.ins().$op(lhs, rhs);
                let result = $builder.ins().bitcast(types::I32, MemFlags::new(), result);
                let result = $builder.ins().sextend(types::I64, result);
                write_dst!($builder, $insn.destination, result);
            }};
        }
        macro_rules! f64_binop {
            ($builder:expr, $insn:expr, $op:ident) => {{
                let rhs_raw = read_src!($builder, $insn.sources[0]);
                let lhs_raw = read_src!($builder, $insn.sources[1]);
                let lhs = $builder.ins().bitcast(types::F64, MemFlags::new(), lhs_raw);
                let rhs = $builder.ins().bitcast(types::F64, MemFlags::new(), rhs_raw);
                let result = $builder.ins().$op(lhs, rhs);
                let result = $builder.ins().bitcast(types::I64, MemFlags::new(), result);
                write_dst!($builder, $insn.destination, result);
            }};
        }
        macro_rules! f32_unop {
            ($builder:expr, $insn:expr, $op:ident) => {{
                let src_raw = read_src!($builder, $insn.sources[0]);
                let src_i32 = $builder.ins().ireduce(types::I32, src_raw);
                let src = $builder.ins().bitcast(types::F32, MemFlags::new(), src_i32);
                let result = $builder.ins().$op(src);
                let result = $builder.ins().bitcast(types::I32, MemFlags::new(), result);
                let result = $builder.ins().sextend(types::I64, result);
                write_dst!($builder, $insn.destination, result);
            }};
        }
        macro_rules! f64_unop {
            ($builder:expr, $insn:expr, $op:ident) => {{
                let src_raw = read_src!($builder, $insn.sources[0]);
                let src = $builder.ins().bitcast(types::F64, MemFlags::new(), src_raw);
                let result = $builder.ins().$op(src);
                let result = $builder.ins().bitcast(types::I64, MemFlags::new(), result);
                write_dst!($builder, $insn.destination, result);
            }};
        }
        macro_rules! f32_cmp {
            ($builder:expr, $insn:expr, $cc:expr) => {{
                let rhs_raw = read_src!($builder, $insn.sources[0]);
                let lhs_raw = read_src!($builder, $insn.sources[1]);
                let lhs_i32 = $builder.ins().ireduce(types::I32, lhs_raw);
                let rhs_i32 = $builder.ins().ireduce(types::I32, rhs_raw);
                let lhs = $builder.ins().bitcast(types::F32, MemFlags::new(), lhs_i32);
                let rhs = $builder.ins().bitcast(types::F32, MemFlags::new(), rhs_i32);
                let cmp = $builder.ins().fcmp($cc, lhs, rhs);
                let result = $builder.ins().uextend(types::I64, cmp);
                write_dst!($builder, $insn.destination, result);
            }};
        }
        macro_rules! f64_cmp {
            ($builder:expr, $insn:expr, $cc:expr) => {{
                let rhs_raw = read_src!($builder, $insn.sources[0]);
                let lhs_raw = read_src!($builder, $insn.sources[1]);
                let lhs = $builder.ins().bitcast(types::F64, MemFlags::new(), lhs_raw);
                let rhs = $builder.ins().bitcast(types::F64, MemFlags::new(), rhs_raw);
                let cmp = $builder.ins().fcmp($cc, lhs, rhs);
                let result = $builder.ins().uextend(types::I64, cmp);
                write_dst!($builder, $insn.destination, result);
            }};
        }

        // Inline local access: load/store directly from locals_base pointer.
        // locals_base is a Value* cached in locals_base_var (loaded from config at entry).
        // read_local_inline: *(locals_base + index * 16) as i64 (first 8 bytes of Value)
        macro_rules! read_local_inline {
            ($builder:expr, $idx_imm:expr) => {{
                let lb = $builder.use_var(locals_base_var);
                let offset = ($idx_imm as i32) * value_size;
                $builder.ins().load(types::I64, MemFlags::trusted(), lb, offset)
            }};
        }
        // write_local_inline: store i64 to first 8 bytes, zero to next 8 bytes
        macro_rules! write_local_inline {
            ($builder:expr, $idx_imm:expr, $val:expr) => {{
                let lb = $builder.use_var(locals_base_var);
                let offset = ($idx_imm as i32) * value_size;
                $builder.ins().store(MemFlags::trusted(), $val, lb, offset);
                let zero = $builder.ins().iconst(types::I64, 0);
                $builder.ins().store(MemFlags::trusted(), zero, lb, offset + 8);
            }};
        }

        // Call + trap-check macro for helper calls that do not consume caller register state.
        // The callee gets arguments explicitly (register immediates, stack, or call record),
        // and the caller's virtual registers stay live in SSA across the call. Writing the
        // whole register file back to Configuration before every nested Wasm call is pure
        // overhead on call-heavy workloads like Coremark, so keep the sync at function exit.
        macro_rules! do_call_and_check {
            ($builder:expr, $sig:expr, $ptr:expr, $args:expr) => {{
                let call = $builder.ins().call_indirect($sig, $ptr, $args);
                let trapped = $builder.inst_results(call)[0];
                let is_trap = $builder.ins().icmp_imm(IntCC::NotEqual, trapped, 0);
                let cont = $builder.create_block();
                $builder.ins().brif(is_trap, trap_block, &[], cont, &[]);
                $builder.switch_to_block(cont);
                $builder.seal_block(cont);
                // Restore locals_base to config — a nested slow-path call's unwind_impl may have
                // overwritten it. Our SSA variable holds the correct value.
                let _cfg_for_lb = $builder.use_var(config_var);
                let our_lb = $builder.use_var(locals_base_var);
                $builder.ins().store(MemFlags::trusted(), our_lb, _cfg_for_lb, locals_base_offset);
                // Reload default_memory_base — the callee may have grown memory.
                let new_default_memory_base = $builder.ins().load(ptr_type, MemFlags::trusted(), _cfg_for_lb, default_memory_base_offset);
                $builder.def_var(default_memory_base_var, new_default_memory_base);
            }};
        }

        // Process each instruction.
        let mut ip = 0usize;
        while ip < insns.len() {
            let insn = &insns[ip];
            let opc = insn.opcode;

            match opc {
                op::NOP => {}

                op::UNREACHABLE => {
                    // Sync regs and trap.
                    Self::sync_regs_to_config(&mut builder, &reg_vars, config_var, regs_offset, value_size, &dirty_regs);
                    let msg = b"unreachable executed";
                    // Allocate a stack slot for the message.
                    let ss = builder.create_sized_stack_slot(StackSlotData::new(
                        StackSlotKind::ExplicitSlot,
                        msg.len() as u32,
                        0,
                    ));
                    for (i, &byte) in msg.iter().enumerate() {
                        let b = builder.ins().iconst(types::I8, i64::from(byte));
                        builder.ins().stack_store(b, ss, i as i32);
                    }
                    let msg_ptr = builder.ins().stack_addr(ptr_type, ss, 0);
                    let msg_len = builder.ins().iconst(types::I32, msg.len() as i64);
                    let st_ptr = builder.ins().iconst(ptr_type, h_set_trap);
                    let interp = builder.use_var(interp_var);
                    builder.ins().call_indirect(set_trap_sig, st_ptr, &[interp, msg_ptr, msg_len]);
                    builder.ins().jump(trap_block, &[]);
                    is_unreachable = true;
                    let dead = builder.create_block();
                    builder.switch_to_block(dead);
                    builder.seal_block(dead);
                }

                op::BLOCK => {
                    let arity = (insn.imm3 & 0xffff) as u32;
                    let param_count = (insn.imm3 >> 16) as usize;
                    let after = builder.create_block();
                    let entry_real_depth_var = if max_stack_depth == 0 {
                        let var = Variable::from_u32(next_var_id);
                        next_var_id += 1;
                        builder.declare_var(var, types::I64);
                        let stack_size_fp = builder.ins().iconst(ptr_type, h_stack_size);
                        let cfg = builder.use_var(config_var);
                        let call = builder.ins().call_indirect(stack_size_sig, stack_size_fp, &[cfg]);
                        let cur = builder.inst_results(call)[0];
                        let entry = builder.ins().iadd_imm(cur, -(param_count as i64));
                        builder.def_var(var, entry);
                        Some(var)
                    } else {
                        None
                    };
                    control_stack.push(ControlFrame {
                        kind: ControlKind::Block,
                        branch_target: after,
                        after_block: after,
                        arity,
                        param_count,
                        stack_depth_at_entry: (sp - param_count) as i32,
                        entry_real_depth_var,
                    });
                }

                op::LOOP => {
                    let arity = (insn.imm3 & 0xffff) as u32;
                    let param_count = (insn.imm3 >> 16) as usize;
                    let header = builder.create_block();
                    let after = builder.create_block();
                    let entry_real_depth_var = if max_stack_depth == 0 {
                        let var = Variable::from_u32(next_var_id);
                        next_var_id += 1;
                        builder.declare_var(var, types::I64);
                        let stack_size_fp = builder.ins().iconst(ptr_type, h_stack_size);
                        let cfg = builder.use_var(config_var);
                        let call = builder.ins().call_indirect(stack_size_sig, stack_size_fp, &[cfg]);
                        let cur = builder.inst_results(call)[0];
                        let entry = builder.ins().iadd_imm(cur, -(param_count as i64));
                        builder.def_var(var, entry);
                        Some(var)
                    } else {
                        None
                    };
                    builder.ins().jump(header, &[]);
                    builder.switch_to_block(header);
                    control_stack.push(ControlFrame {
                        kind: ControlKind::Loop,
                        branch_target: header,
                        after_block: after,
                        arity,
                        param_count,
                        stack_depth_at_entry: (sp - param_count) as i32,
                        entry_real_depth_var,
                    });
                }

                op::IF => {
                    let arity = (insn.imm3 & 0xffff) as u32;
                    let _param_count = (insn.imm3 >> 16) as usize;
                    let has_else = insn.imm2 >= 0;
                    let then_block = builder.create_block();
                    let else_block = builder.create_block();
                    let after = builder.create_block();

                    let cond_raw = read_src!(builder, insn.sources[0]);
                    let cond = builder.ins().icmp_imm(IntCC::NotEqual, cond_raw, 0);
                    let entry_real_depth_var = if max_stack_depth == 0 {
                        let var = Variable::from_u32(next_var_id);
                        next_var_id += 1;
                        builder.declare_var(var, types::I64);
                        let stack_size_fp = builder.ins().iconst(ptr_type, h_stack_size);
                        let cfg = builder.use_var(config_var);
                        let call = builder.ins().call_indirect(stack_size_sig, stack_size_fp, &[cfg]);
                        let cur = builder.inst_results(call)[0];
                        let entry = builder.ins().iadd_imm(cur, -(_param_count as i64));
                        builder.def_var(var, entry);
                        Some(var)
                    } else {
                        None
                    };
                    if has_else {
                        builder.ins().brif(cond, then_block, &[], else_block, &[]);
                    } else {
                        builder.ins().brif(cond, then_block, &[], after, &[]);
                    }

                    builder.switch_to_block(then_block);
                    builder.seal_block(then_block);

                    control_stack.push(ControlFrame {
                        kind: ControlKind::If,
                        branch_target: after,
                        after_block: if has_else { else_block } else { after },
                        arity,
                        param_count: _param_count,
                        stack_depth_at_entry: (sp - _param_count) as i32,
                        entry_real_depth_var,
                    });
                }

                op::ELSE => {
                    if let Some(frame) = control_stack.last() {
                        let else_block = frame.after_block;
                        let after = frame.branch_target;
                        let entry_depth = frame.stack_depth_at_entry;
                        let pc = frame.param_count;
                        builder.ins().jump(after, &[]);
                        builder.switch_to_block(else_block);
                        builder.seal_block(else_block);
                        // Reset sp to entry depth + param_count (else branch inherits params).
                        sp = (entry_depth as usize) + pc;
                        // Update the frame so END knows the real after block.
                        if let Some(frame) = control_stack.last_mut() {
                            frame.after_block = after;
                        }
                    }
                }

                op::END | op::SYNTHETIC_END_EXPRESSION => {
                    if let Some(frame) = control_stack.pop() {
                        let after = if frame.kind == ControlKind::If && frame.after_block != frame.branch_target {
                            // If without else: the after_block IS the branch_target.
                            frame.branch_target
                        } else {
                            frame.after_block
                        };

                        builder.ins().jump(after, &[]);
                        builder.switch_to_block(after);
                        is_unreachable = false;

                        // After end of block, sp = entry depth + arity.
                        sp = (frame.stack_depth_at_entry + frame.arity as i32) as usize;

                        // Seal the target blocks.
                        if frame.kind == ControlKind::Loop {
                            builder.seal_block(frame.branch_target); // loop header
                        }
                        builder.seal_block(after);
                    } else if !is_unreachable {
                        // End of function — push exactly result_arity values to real stack.
                        push_top_n_to_real!(builder, result_arity);
                        builder.ins().jump(epilogue_block, &[]);
                        let dead = builder.create_block();
                        builder.switch_to_block(dead);
                        builder.seal_block(dead);
                    }
                }

                op::BR | op::SYNTHETIC_BR_NOSTACK => {
                    let label_idx = insn.imm1 as usize;
                    if label_idx < control_stack.len() {
                        let target_idx = control_stack.len() - 1 - label_idx;
                        let frame = &control_stack[target_idx];
                        let target = frame.branch_target;
                        let arity = if frame.kind == ControlKind::Loop { 0 } else { frame.arity };
                        let entry = frame.stack_depth_at_entry as usize;
                        if max_stack_depth > 0 {
                            // vstack enabled: move top arity values to entry position.
                            if arity > 0 {
                                let result = if sp > 0 {
                                    builder.use_var(stack_vars[sp - 1])
                                } else {
                                    let fp = builder.ins().iconst(ptr_type, h_stack_pop);
                                    let cfg = builder.use_var(config_var);
                                    let call = builder.ins().call_indirect(stack_pop_sig, fp, &[cfg]);
                                    builder.inst_results(call)[0]
                                };
                                builder.def_var(stack_vars[entry], result);
                            }
                            sp = entry + arity as usize;
                        } else {
                            // vstack disabled: trim the real value stack down to the target
                            // label's entry depth + arity, preserving the top arity values.
                            let entry_depth_var = frame.entry_real_depth_var
                                .expect("entry_real_depth_var must be set when vstack is disabled");
                            let target_size = builder.use_var(entry_depth_var);
                            let arity_val = builder.ins().iconst(types::I32, arity as i64);
                            let cfg = builder.use_var(config_var);
                            let cleanup_fp = builder.ins().iconst(ptr_type, h_stack_cleanup);
                            builder.ins().call_indirect(stack_cleanup_sig, cleanup_fp, &[cfg, target_size, arity_val]);
                        }
                        builder.ins().jump(target, &[]);
                    } else {
                        // br to function-level = return.
                        push_top_n_to_real!(builder, result_arity);
                        builder.ins().jump(epilogue_block, &[]);
                    }
                    sp = 0;
                    is_unreachable = true;
                    let dead = builder.create_block();
                    builder.switch_to_block(dead);
                    builder.seal_block(dead);
                }

                op::BR_IF | op::SYNTHETIC_BR_IF_NOSTACK => {
                    let label_idx = insn.imm1 as usize;
                    let cond_raw = read_src!(builder, insn.sources[0]);
                    let cond = builder.ins().icmp_imm(IntCC::NotEqual, cond_raw, 0);

                    if label_idx < control_stack.len() {
                        let target_idx = control_stack.len() - 1 - label_idx;
                        let frame = &control_stack[target_idx];
                        let target = frame.branch_target;
                        let arity = if frame.kind == ControlKind::Loop { 0 } else { frame.arity };
                        let entry = frame.stack_depth_at_entry as usize;
                        let extras = (sp as i32 - entry as i32 - arity as i32).max(0);
                        if max_stack_depth == 0 {
                            // vstack disabled: real value stack may have extras between the
                            // target label's entry depth and the result on top. On the taken
                            // path, call stack_cleanup using the saved entry-depth variable.
                            let entry_depth_var = frame.entry_real_depth_var
                                .expect("entry_real_depth_var must be set when vstack is disabled");
                            let taken_block = builder.create_block();
                            let fallthrough = builder.create_block();
                            builder.ins().brif(cond, taken_block, &[], fallthrough, &[]);
                            builder.switch_to_block(taken_block);
                            builder.seal_block(taken_block);
                            let target_size = builder.use_var(entry_depth_var);
                            let arity_val = builder.ins().iconst(types::I32, arity as i64);
                            let cfg = builder.use_var(config_var);
                            let cleanup_fp = builder.ins().iconst(ptr_type, h_stack_cleanup);
                            builder.ins().call_indirect(stack_cleanup_sig, cleanup_fp, &[cfg, target_size, arity_val]);
                            builder.ins().jump(target, &[]);
                            builder.switch_to_block(fallthrough);
                            builder.seal_block(fallthrough);
                        } else if extras > 0 {
                            // On the taken path, move result to entry slot.
                            let taken_block = builder.create_block();
                            let fallthrough = builder.create_block();
                            builder.ins().brif(cond, taken_block, &[], fallthrough, &[]);
                            builder.switch_to_block(taken_block);
                            builder.seal_block(taken_block);
                            if arity > 0 {
                                let result = builder.use_var(stack_vars[sp - 1]);
                                builder.def_var(stack_vars[entry], result);
                            }
                            // Note: we don't change sp here since fallthrough needs the original sp.
                            builder.ins().jump(target, &[]);
                            builder.switch_to_block(fallthrough);
                            builder.seal_block(fallthrough);
                        } else {
                            let fallthrough = builder.create_block();
                            builder.ins().brif(cond, target, &[], fallthrough, &[]);
                            builder.switch_to_block(fallthrough);
                            builder.seal_block(fallthrough);
                        }
                    } else {
                        if sp > 0 {
                            let taken_block = builder.create_block();
                            let fallthrough = builder.create_block();
                            builder.ins().brif(cond, taken_block, &[], fallthrough, &[]);
                            builder.switch_to_block(taken_block);
                            builder.seal_block(taken_block);
                            push_top_n_to_real!(builder, result_arity);
                            builder.ins().jump(epilogue_block, &[]);
                            builder.switch_to_block(fallthrough);
                            builder.seal_block(fallthrough);
                        } else {
                            let fallthrough = builder.create_block();
                            builder.ins().brif(cond, epilogue_block, &[], fallthrough, &[]);
                            builder.switch_to_block(fallthrough);
                            builder.seal_block(fallthrough);
                        }
                    }
                }

                op::RETURN => {
                    push_top_n_to_real!(builder, result_arity);
                    builder.ins().jump(epilogue_block, &[]);
                    sp = 0;
                    is_unreachable = true;
                    let dead = builder.create_block();
                    builder.switch_to_block(dead);
                    builder.seal_block(dead);
                }

                op::I32_CONST | op::I64_CONST | op::F32_CONST | op::F64_CONST => {
                    let val = builder.ins().iconst(types::I64, insn.imm1);
                    write_dst!(builder, insn.destination, val);
                }

                op::LOCAL_GET | op::SYNTHETIC_ARGUMENT_GET => {
                    let result = read_local_inline!(builder, insn.imm1);
                    write_dst!(builder, insn.destination, result);
                }
                op::LOCAL_SET | op::SYNTHETIC_ARGUMENT_SET => {
                    let val = read_src!(builder, insn.sources[0]);
                    write_local_inline!(builder, insn.imm1, val);
                }
                op::LOCAL_TEE | op::SYNTHETIC_ARGUMENT_TEE => {
                    let val = read_src!(builder, insn.sources[0]);
                    write_local_inline!(builder, insn.imm1, val);
                    write_dst!(builder, insn.destination, val);
                }

                opc if (op::SYNTHETIC_LOCAL_GET_0..=op::SYNTHETIC_LOCAL_GET_7).contains(&opc) => {
                    let local_idx = (opc - op::SYNTHETIC_LOCAL_GET_0) as i64;
                    let result = read_local_inline!(builder, local_idx);
                    write_dst!(builder, insn.destination, result);
                }
                opc if (op::SYNTHETIC_LOCAL_SET_0..=op::SYNTHETIC_LOCAL_SET_7).contains(&opc) => {
                    let local_idx = (opc - op::SYNTHETIC_LOCAL_SET_0) as i64;
                    let val = read_src!(builder, insn.sources[0]);
                    write_local_inline!(builder, local_idx, val);
                }
                op::SYNTHETIC_LOCAL_COPY => {
                    // Fused local.get(imm1) + local.set(imm2): copy between locals directly.
                    let val = read_local_inline!(builder, insn.imm1);
                    write_local_inline!(builder, insn.imm2, val);
                }

                op::GLOBAL_GET => {
                    let idx = builder.ins().iconst(types::I32, insn.imm1);
                    let _uv_config_var = builder.use_var(config_var);
                    let _ic_0 = builder.ins().iconst(ptr_type, h_read_global);
                    let call = builder.ins().call_indirect(read_global_sig, _ic_0, &[_uv_config_var, idx]);
                    let result = builder.inst_results(call)[0];
                    write_dst!(builder, insn.destination, result);
                }
                op::GLOBAL_SET => {
                    let val = read_src!(builder, insn.sources[0]);
                    let idx = builder.ins().iconst(types::I32, insn.imm1);
                    let _uv_config_var = builder.use_var(config_var);
                    let _ic_0 = builder.ins().iconst(ptr_type, h_write_global);
                    builder.ins().call_indirect(write_global_sig, _ic_0, &[_uv_config_var, idx, val]);
                }

                op::DROP => {
                    // If source is stack, we still need to pop it.
                    if insn.sources[0] == STACK_MARKER {
                        read_src!(builder, insn.sources[0]);
                    }
                }

                op::SELECT | op::SELECT_TYPED => {
                    // sources[0] = condition, sources[1] = rhs, sources[2] = lhs
                    // destination == sources[2] (the lhs slot)
                    let cond_raw = read_src!(builder, insn.sources[0]);
                    let rhs = read_src!(builder, insn.sources[1]);
                    let lhs = read_src!(builder, insn.sources[2]);
                    let cond = builder.ins().icmp_imm(IntCC::NotEqual, cond_raw, 0);
                    let result = builder.ins().select(cond, lhs, rhs);
                    write_dst!(builder, insn.destination, result);
                }

                op::BR_TABLE => {
                    let inline_count = (insn.imm3 & 0xff) as usize;
                    if inline_count == 0xff {
                        return Err("br_table too large for inline encoding");
                    }

                    let default_label = ((insn.imm3 >> 8) & 0xffff) as usize;

                    // Collect all labels: first 8 from this instruction, rest from continuations.
                    let mut all_labels: Vec<usize> = Vec::with_capacity(inline_count);
                    for i in 0..inline_count {
                        let packed = if i < 4 { insn.imm1 as u64 } else { insn.imm2 as u64 };
                        all_labels.push(((packed >> ((i % 4) * 16)) & 0xffff) as usize);
                    }
                    // Consume continuation instructions.
                    while ip + 1 < insns.len() && insns[ip + 1].opcode == op::SYNTHETIC_BR_TABLE_CONT {
                        ip += 1;
                        let cont = &insns[ip];
                        let chunk = (cont.imm3 & 0xff) as usize;
                        for j in 0..chunk {
                            let packed = if j < 4 { cont.imm1 as u64 } else { cont.imm2 as u64 };
                            all_labels.push(((packed >> ((j % 4) * 16)) & 0xffff) as usize);
                        }
                    }

                    let cond_raw = read_src!(builder, insn.sources[0]);
                    let cond = builder.ins().ireduce(types::I32, cond_raw);

                    let mut branch_to_label = |builder: &mut FunctionBuilder, label_idx: usize| {
                        if label_idx < control_stack.len() {
                            let target_idx = control_stack.len() - 1 - label_idx;
                            let frame = &control_stack[target_idx];
                            let target = frame.branch_target;
                            let arity = if frame.kind == ControlKind::Loop { 0 } else { frame.arity };
                            let entry = frame.stack_depth_at_entry as usize;
                            if max_stack_depth > 0 && arity > 0 {
                                let result = if sp > 0 {
                                    builder.use_var(stack_vars[sp - 1])
                                } else {
                                    let fp = builder.ins().iconst(ptr_type, h_stack_pop);
                                    let cfg = builder.use_var(config_var);
                                    let call = builder.ins().call_indirect(stack_pop_sig, fp, &[cfg]);
                                    builder.inst_results(call)[0]
                                };
                                builder.def_var(stack_vars[entry], result);
                            } else if max_stack_depth == 0 {
                                let entry_depth_var = frame.entry_real_depth_var
                                    .expect("entry_real_depth_var must be set when vstack is disabled");
                                let target_size = builder.use_var(entry_depth_var);
                                let arity_val = builder.ins().iconst(types::I32, arity as i64);
                                let cfg = builder.use_var(config_var);
                                let cleanup_fp = builder.ins().iconst(ptr_type, h_stack_cleanup);
                                builder.ins().call_indirect(stack_cleanup_sig, cleanup_fp, &[cfg, target_size, arity_val]);
                            }
                            builder.ins().jump(target, &[]);
                        } else {
                            push_top_n_to_real!(builder, result_arity);
                            builder.ins().jump(epilogue_block, &[]);
                        }
                    };

                    let mut fallthrough = builder.create_block();
                    for (i, &label) in all_labels.iter().enumerate() {
                        let case_block = builder.create_block();
                        let next_fallthrough = builder.create_block();
                        let compare = builder.ins().icmp_imm(IntCC::Equal, cond, i as i64);
                        builder.ins().brif(compare, case_block, &[], next_fallthrough, &[]);

                        builder.switch_to_block(case_block);
                        builder.seal_block(case_block);
                        branch_to_label(&mut builder, label);

                        builder.switch_to_block(next_fallthrough);
                        builder.seal_block(next_fallthrough);
                        fallthrough = next_fallthrough;
                    }

                    branch_to_label(&mut builder, default_label);
                    sp = 0;
                    is_unreachable = true;
                    let dead = builder.create_block();
                    builder.switch_to_block(dead);
                    builder.seal_block(dead);
                }

                // ---- i32 arithmetic ----
                op::I32_ADD => i32_binop!(builder, insn, iadd),
                op::I32_SUB => i32_binop!(builder, insn, isub),
                op::I32_MUL => i32_binop!(builder, insn, imul),
                op::I32_AND => i32_binop!(builder, insn, band),
                op::I32_OR => i32_binop!(builder, insn, bor),
                op::I32_XOR => i32_binop!(builder, insn, bxor),
                op::I32_SHL => i32_binop!(builder, insn, ishl),
                op::I32_SHRS => i32_binop!(builder, insn, sshr),
                op::I32_SHRU => i32_binop!(builder, insn, ushr),
                op::I32_ROTL => i32_binop!(builder, insn, rotl),
                op::I32_ROTR => i32_binop!(builder, insn, rotr),
                op::I32_DIVS => i32_binop!(builder, insn, sdiv),
                op::I32_DIVU => i32_binop!(builder, insn, udiv),
                op::I32_REMS => i32_binop!(builder, insn, srem),
                op::I32_REMU => i32_binop!(builder, insn, urem),
                op::I32_CLZ => i32_unop!(builder, insn, clz),
                op::I32_CTZ => i32_unop!(builder, insn, ctz),
                op::I32_POPCNT => i32_unop!(builder, insn, popcnt),

                // ---- i64 arithmetic ----
                op::I64_ADD => i64_binop!(builder, insn, iadd),
                op::I64_SUB => i64_binop!(builder, insn, isub),
                op::I64_MUL => i64_binop!(builder, insn, imul),
                op::I64_AND => i64_binop!(builder, insn, band),
                op::I64_OR => i64_binop!(builder, insn, bor),
                op::I64_XOR => i64_binop!(builder, insn, bxor),
                op::I64_SHL => i64_binop!(builder, insn, ishl),
                op::I64_SHRS => i64_binop!(builder, insn, sshr),
                op::I64_SHRU => i64_binop!(builder, insn, ushr),
                op::I64_ROTL => i64_binop!(builder, insn, rotl),
                op::I64_ROTR => i64_binop!(builder, insn, rotr),
                op::I64_DIVS => i64_binop!(builder, insn, sdiv),
                op::I64_DIVU => i64_binop!(builder, insn, udiv),
                op::I64_REMS => i64_binop!(builder, insn, srem),
                op::I64_REMU => i64_binop!(builder, insn, urem),
                op::I64_CLZ => i64_unop!(builder, insn, clz),
                op::I64_CTZ => i64_unop!(builder, insn, ctz),
                op::I64_POPCNT => i64_unop!(builder, insn, popcnt),

                // ---- i32 comparisons ----
                op::I32_EQZ => {
                    let src_raw = read_src!(builder, insn.sources[0]);
                    let src = builder.ins().ireduce(types::I32, src_raw);
                    let r = builder.ins().icmp_imm(IntCC::Equal, src, 0);
                    let result = builder.ins().uextend(types::I64, r);
                    write_dst!(builder, insn.destination, result);
                }
                op::I32_EQ => i32_cmp!(builder, insn, IntCC::Equal),
                op::I32_NE => i32_cmp!(builder, insn, IntCC::NotEqual),
                op::I32_LTS => i32_cmp!(builder, insn, IntCC::SignedLessThan),
                op::I32_LTU => i32_cmp!(builder, insn, IntCC::UnsignedLessThan),
                op::I32_GTS => i32_cmp!(builder, insn, IntCC::SignedGreaterThan),
                op::I32_GTU => i32_cmp!(builder, insn, IntCC::UnsignedGreaterThan),
                op::I32_LES => i32_cmp!(builder, insn, IntCC::SignedLessThanOrEqual),
                op::I32_LEU => i32_cmp!(builder, insn, IntCC::UnsignedLessThanOrEqual),
                op::I32_GES => i32_cmp!(builder, insn, IntCC::SignedGreaterThanOrEqual),
                op::I32_GEU => i32_cmp!(builder, insn, IntCC::UnsignedGreaterThanOrEqual),

                // ---- i64 comparisons ----
                op::I64_EQZ => {
                    let src = read_src!(builder, insn.sources[0]);
                    let r = builder.ins().icmp_imm(IntCC::Equal, src, 0);
                    let result = builder.ins().uextend(types::I64, r);
                    write_dst!(builder, insn.destination, result);
                }
                op::I64_EQ => i64_cmp!(builder, insn, IntCC::Equal),
                op::I64_NE => i64_cmp!(builder, insn, IntCC::NotEqual),
                op::I64_LTS => i64_cmp!(builder, insn, IntCC::SignedLessThan),
                op::I64_LTU => i64_cmp!(builder, insn, IntCC::UnsignedLessThan),
                op::I64_GTS => i64_cmp!(builder, insn, IntCC::SignedGreaterThan),
                op::I64_GTU => i64_cmp!(builder, insn, IntCC::UnsignedGreaterThan),
                op::I64_LES => i64_cmp!(builder, insn, IntCC::SignedLessThanOrEqual),
                op::I64_LEU => i64_cmp!(builder, insn, IntCC::UnsignedLessThanOrEqual),
                op::I64_GES => i64_cmp!(builder, insn, IntCC::SignedGreaterThanOrEqual),
                op::I64_GEU => i64_cmp!(builder, insn, IntCC::UnsignedGreaterThanOrEqual),

                // ---- f32 arithmetic ----
                op::F32_ADD => f32_binop!(builder, insn, fadd),
                op::F32_SUB => f32_binop!(builder, insn, fsub),
                op::F32_MUL => f32_binop!(builder, insn, fmul),
                op::F32_DIV => f32_binop!(builder, insn, fdiv),
                op::F32_MIN => f32_binop!(builder, insn, fmin),
                op::F32_MAX => f32_binop!(builder, insn, fmax),
                op::F32_COPYSIGN => f32_binop!(builder, insn, fcopysign),
                op::F32_ABS => f32_unop!(builder, insn, fabs),
                op::F32_NEG => f32_unop!(builder, insn, fneg),
                op::F32_CEIL => f32_unop!(builder, insn, ceil),
                op::F32_FLOOR => f32_unop!(builder, insn, floor),
                op::F32_TRUNC => f32_unop!(builder, insn, trunc),
                op::F32_NEAREST => f32_unop!(builder, insn, nearest),
                op::F32_SQRT => f32_unop!(builder, insn, sqrt),

                // ---- f64 arithmetic ----
                op::F64_ADD => f64_binop!(builder, insn, fadd),
                op::F64_SUB => f64_binop!(builder, insn, fsub),
                op::F64_MUL => f64_binop!(builder, insn, fmul),
                op::F64_DIV => f64_binop!(builder, insn, fdiv),
                op::F64_MIN => f64_binop!(builder, insn, fmin),
                op::F64_MAX => f64_binop!(builder, insn, fmax),
                op::F64_COPYSIGN => f64_binop!(builder, insn, fcopysign),
                op::F64_ABS => f64_unop!(builder, insn, fabs),
                op::F64_NEG => f64_unop!(builder, insn, fneg),
                op::F64_CEIL => f64_unop!(builder, insn, ceil),
                op::F64_FLOOR => f64_unop!(builder, insn, floor),
                op::F64_TRUNC => f64_unop!(builder, insn, trunc),
                op::F64_NEAREST => f64_unop!(builder, insn, nearest),
                op::F64_SQRT => f64_unop!(builder, insn, sqrt),

                // ---- f32 comparisons ----
                op::F32_EQ => f32_cmp!(builder, insn, FloatCC::Equal),
                op::F32_NE => f32_cmp!(builder, insn, FloatCC::NotEqual),
                op::F32_LT => f32_cmp!(builder, insn, FloatCC::LessThan),
                op::F32_GT => f32_cmp!(builder, insn, FloatCC::GreaterThan),
                op::F32_LE => f32_cmp!(builder, insn, FloatCC::LessThanOrEqual),
                op::F32_GE => f32_cmp!(builder, insn, FloatCC::GreaterThanOrEqual),

                // ---- f64 comparisons ----
                op::F64_EQ => f64_cmp!(builder, insn, FloatCC::Equal),
                op::F64_NE => f64_cmp!(builder, insn, FloatCC::NotEqual),
                op::F64_LT => f64_cmp!(builder, insn, FloatCC::LessThan),
                op::F64_GT => f64_cmp!(builder, insn, FloatCC::GreaterThan),
                op::F64_LE => f64_cmp!(builder, insn, FloatCC::LessThanOrEqual),
                op::F64_GE => f64_cmp!(builder, insn, FloatCC::GreaterThanOrEqual),

                // ---- conversions ----
                op::I32_WRAP_I64 => {
                    let src = read_src!(builder, insn.sources[0]);
                    let narrowed = builder.ins().ireduce(types::I32, src);
                    let result = builder.ins().sextend(types::I64, narrowed);
                    write_dst!(builder, insn.destination, result);
                }
                op::I64_EXTEND_SI32 => {
                    let src = read_src!(builder, insn.sources[0]);
                    let narrowed = builder.ins().ireduce(types::I32, src);
                    let result = builder.ins().sextend(types::I64, narrowed);
                    write_dst!(builder, insn.destination, result);
                }
                op::I64_EXTEND_UI32 => {
                    let src = read_src!(builder, insn.sources[0]);
                    let narrowed = builder.ins().ireduce(types::I32, src);
                    let result = builder.ins().uextend(types::I64, narrowed);
                    write_dst!(builder, insn.destination, result);
                }
                op::I32_EXTEND8_S => {
                    let src = read_src!(builder, insn.sources[0]);
                    let narrowed = builder.ins().ireduce(types::I8, src);
                    let extended = builder.ins().sextend(types::I32, narrowed);
                    let result = builder.ins().sextend(types::I64, extended);
                    write_dst!(builder, insn.destination, result);
                }
                op::I32_EXTEND16_S => {
                    let src = read_src!(builder, insn.sources[0]);
                    let narrowed = builder.ins().ireduce(types::I16, src);
                    let extended = builder.ins().sextend(types::I32, narrowed);
                    let result = builder.ins().sextend(types::I64, extended);
                    write_dst!(builder, insn.destination, result);
                }
                op::I64_EXTEND8_S => {
                    let src = read_src!(builder, insn.sources[0]);
                    let narrowed = builder.ins().ireduce(types::I8, src);
                    let result = builder.ins().sextend(types::I64, narrowed);
                    write_dst!(builder, insn.destination, result);
                }
                op::I64_EXTEND16_S => {
                    let src = read_src!(builder, insn.sources[0]);
                    let narrowed = builder.ins().ireduce(types::I16, src);
                    let result = builder.ins().sextend(types::I64, narrowed);
                    write_dst!(builder, insn.destination, result);
                }
                op::I64_EXTEND32_S => {
                    let src = read_src!(builder, insn.sources[0]);
                    let narrowed = builder.ins().ireduce(types::I32, src);
                    let result = builder.ins().sextend(types::I64, narrowed);
                    write_dst!(builder, insn.destination, result);
                }
                // Float-int conversions
                op::F32_CONVERT_SI32 => {
                    let src = read_src!(builder, insn.sources[0]);
                    let i32_val = builder.ins().ireduce(types::I32, src);
                    let f32_val = builder.ins().fcvt_from_sint(types::F32, i32_val);
                    let result = builder.ins().bitcast(types::I32, MemFlags::new(), f32_val);
                    let result = builder.ins().sextend(types::I64, result);
                    write_dst!(builder, insn.destination, result);
                }
                op::F32_CONVERT_UI32 => {
                    let src = read_src!(builder, insn.sources[0]);
                    let i32_val = builder.ins().ireduce(types::I32, src);
                    let f32_val = builder.ins().fcvt_from_uint(types::F32, i32_val);
                    let result = builder.ins().bitcast(types::I32, MemFlags::new(), f32_val);
                    let result = builder.ins().sextend(types::I64, result);
                    write_dst!(builder, insn.destination, result);
                }
                op::F32_CONVERT_SI64 => {
                    let src = read_src!(builder, insn.sources[0]);
                    let f32_val = builder.ins().fcvt_from_sint(types::F32, src);
                    let result = builder.ins().bitcast(types::I32, MemFlags::new(), f32_val);
                    let result = builder.ins().sextend(types::I64, result);
                    write_dst!(builder, insn.destination, result);
                }
                op::F32_CONVERT_UI64 => {
                    let src = read_src!(builder, insn.sources[0]);
                    let f32_val = builder.ins().fcvt_from_uint(types::F32, src);
                    let result = builder.ins().bitcast(types::I32, MemFlags::new(), f32_val);
                    let result = builder.ins().sextend(types::I64, result);
                    write_dst!(builder, insn.destination, result);
                }
                op::F64_CONVERT_SI32 => {
                    let src = read_src!(builder, insn.sources[0]);
                    let i32_val = builder.ins().ireduce(types::I32, src);
                    let f64_val = builder.ins().fcvt_from_sint(types::F64, i32_val);
                    let result = builder.ins().bitcast(types::I64, MemFlags::new(), f64_val);
                    write_dst!(builder, insn.destination, result);
                }
                op::F64_CONVERT_UI32 => {
                    let src = read_src!(builder, insn.sources[0]);
                    let i32_val = builder.ins().ireduce(types::I32, src);
                    let f64_val = builder.ins().fcvt_from_uint(types::F64, i32_val);
                    let result = builder.ins().bitcast(types::I64, MemFlags::new(), f64_val);
                    write_dst!(builder, insn.destination, result);
                }
                op::F64_CONVERT_SI64 => {
                    let src = read_src!(builder, insn.sources[0]);
                    let f64_val = builder.ins().fcvt_from_sint(types::F64, src);
                    let result = builder.ins().bitcast(types::I64, MemFlags::new(), f64_val);
                    write_dst!(builder, insn.destination, result);
                }
                op::F64_CONVERT_UI64 => {
                    let src = read_src!(builder, insn.sources[0]);
                    let f64_val = builder.ins().fcvt_from_uint(types::F64, src);
                    let result = builder.ins().bitcast(types::I64, MemFlags::new(), f64_val);
                    write_dst!(builder, insn.destination, result);
                }
                op::I32_REINTERPRET_F32 | op::F32_REINTERPRET_I32 | op::I64_REINTERPRET_F64
                | op::F64_REINTERPRET_I64 => {
                    let src = read_src!(builder, insn.sources[0]);
                    write_dst!(builder, insn.destination, src);
                }
                op::F32_DEMOTE_F64 => {
                    let src = read_src!(builder, insn.sources[0]);
                    let f64_val = builder.ins().bitcast(types::F64, MemFlags::new(), src);
                    let f32_val = builder.ins().fdemote(types::F32, f64_val);
                    let result = builder.ins().bitcast(types::I32, MemFlags::new(), f32_val);
                    let result = builder.ins().sextend(types::I64, result);
                    write_dst!(builder, insn.destination, result);
                }
                op::F64_PROMOTE_F32 => {
                    let src = read_src!(builder, insn.sources[0]);
                    let i32_val = builder.ins().ireduce(types::I32, src);
                    let f32_val = builder.ins().bitcast(types::F32, MemFlags::new(), i32_val);
                    let f64_val = builder.ins().fpromote(types::F64, f32_val);
                    let result = builder.ins().bitcast(types::I64, MemFlags::new(), f64_val);
                    write_dst!(builder, insn.destination, result);
                }
                // Truncation conversions (these can trap in wasm)
                op::I32_TRUNC_SF32 | op::I32_TRUNC_UF32 | op::I32_TRUNC_SF64
                | op::I32_TRUNC_UF64 | op::I64_TRUNC_SF32 | op::I64_TRUNC_UF32
                | op::I64_TRUNC_SF64 | op::I64_TRUNC_UF64 => {
                    // Use cranelift's fcvt_to_sint/fcvt_to_uint which traps on overflow/NaN.
                    let src = read_src!(builder, insn.sources[0]);
                    let is_f32_src = matches!(
                        opc,
                        op::I32_TRUNC_SF32
                            | op::I32_TRUNC_UF32
                            | op::I64_TRUNC_SF32
                            | op::I64_TRUNC_UF32
                    );
                    let is_i32_dst = matches!(
                        opc,
                        op::I32_TRUNC_SF32
                            | op::I32_TRUNC_UF32
                            | op::I32_TRUNC_SF64
                            | op::I32_TRUNC_UF64
                    );
                    let is_signed = matches!(
                        opc,
                        op::I32_TRUNC_SF32
                            | op::I32_TRUNC_SF64
                            | op::I64_TRUNC_SF32
                            | op::I64_TRUNC_SF64
                    );

                    let float_val = if is_f32_src {
                        let i32_val = builder.ins().ireduce(types::I32, src);
                        builder.ins().bitcast(types::F32, MemFlags::new(), i32_val)
                    } else {
                        builder.ins().bitcast(types::F64, MemFlags::new(), src)
                    };

                    let int_type = if is_i32_dst {
                        types::I32
                    } else {
                        types::I64
                    };
                    let int_val = if is_signed {
                        builder.ins().fcvt_to_sint(int_type, float_val)
                    } else {
                        builder.ins().fcvt_to_uint(int_type, float_val)
                    };

                    let result = if is_i32_dst {
                        builder.ins().sextend(types::I64, int_val)
                    } else {
                        int_val
                    };
                    write_dst!(builder, insn.destination, result);
                }

                op::I32_TRUNC_SAT_F32_S | op::I32_TRUNC_SAT_F32_U | op::I32_TRUNC_SAT_F64_S
                | op::I32_TRUNC_SAT_F64_U | op::I64_TRUNC_SAT_F32_S | op::I64_TRUNC_SAT_F32_U
                | op::I64_TRUNC_SAT_F64_S | op::I64_TRUNC_SAT_F64_U => {
                    let src = read_src!(builder, insn.sources[0]);
                    let is_f32_src = matches!(
                        opc,
                        op::I32_TRUNC_SAT_F32_S
                            | op::I32_TRUNC_SAT_F32_U
                            | op::I64_TRUNC_SAT_F32_S
                            | op::I64_TRUNC_SAT_F32_U
                    );
                    let is_i32_dst = matches!(
                        opc,
                        op::I32_TRUNC_SAT_F32_S
                            | op::I32_TRUNC_SAT_F32_U
                            | op::I32_TRUNC_SAT_F64_S
                            | op::I32_TRUNC_SAT_F64_U
                    );
                    let is_signed = matches!(
                        opc,
                        op::I32_TRUNC_SAT_F32_S
                            | op::I32_TRUNC_SAT_F64_S
                            | op::I64_TRUNC_SAT_F32_S
                            | op::I64_TRUNC_SAT_F64_S
                    );

                    let float_val = if is_f32_src {
                        let i32_val = builder.ins().ireduce(types::I32, src);
                        builder.ins().bitcast(types::F32, MemFlags::new(), i32_val)
                    } else {
                        builder.ins().bitcast(types::F64, MemFlags::new(), src)
                    };

                    let int_type = if is_i32_dst { types::I32 } else { types::I64 };
                    let int_val = if is_signed {
                        builder.ins().fcvt_to_sint_sat(int_type, float_val)
                    } else {
                        builder.ins().fcvt_to_uint_sat(int_type, float_val)
                    };

                    let result = if is_i32_dst {
                        builder.ins().sextend(types::I64, int_val)
                    } else {
                        int_val
                    };
                    write_dst!(builder, insn.destination, result);
                }

                // ---- memory operations ----
                op::I32_LOAD | op::I64_LOAD | op::F32_LOAD | op::F64_LOAD | op::I32_LOAD8_S
                | op::I32_LOAD8_U | op::I32_LOAD16_S | op::I32_LOAD16_U | op::I64_LOAD8_S
                | op::I64_LOAD8_U | op::I64_LOAD16_S | op::I64_LOAD16_U | op::I64_LOAD32_S
                | op::I64_LOAD32_U => {
                    let use_direct_memory = (insn.imm3 & (1u32 << 31)) != 0;
                    let memory_load_helper = match opc {
                        op::I32_LOAD | op::F32_LOAD => h_mem_load32_u,
                        op::I64_LOAD | op::F64_LOAD => h_mem_load64,
                        op::I32_LOAD8_S | op::I64_LOAD8_S => h_mem_load8_s,
                        op::I32_LOAD8_U | op::I64_LOAD8_U => h_mem_load8_u,
                        op::I32_LOAD16_S | op::I64_LOAD16_S => h_mem_load16_s,
                        op::I32_LOAD16_U | op::I64_LOAD16_U => h_mem_load16_u,
                        op::I64_LOAD32_S => h_mem_load32_s,
                        op::I64_LOAD32_U => h_mem_load32_u,
                        _ => unreachable!(),
                    };

                    // Compute effective address: base (from source reg as u32) + offset.
                    let base_raw = read_src!(builder, insn.sources[0]);
                    let base_u32 = builder.ins().ireduce(types::I32, base_raw);
                    let base_u64 = builder.ins().uextend(types::I64, base_u32);
                    let offset = builder.ins().iconst(types::I64, insn.imm1);
                    let addr = builder.ins().iadd(base_u64, offset);

                    let result = if use_direct_memory {
                        let memory_base = builder.use_var(default_memory_base_var);
                        let addr_offset = if ptr_type == types::I64 { addr } else { builder.ins().ireduce(ptr_type, addr) };
                        let native_addr = builder.ins().iadd(memory_base, addr_offset);
                        match opc {
                            op::I32_LOAD | op::F32_LOAD | op::I64_LOAD32_U => {
                                let loaded = builder.ins().load(types::I32, MemFlags::new(), native_addr, 0);
                                builder.ins().uextend(types::I64, loaded)
                            }
                            op::I64_LOAD | op::F64_LOAD => builder.ins().load(types::I64, MemFlags::new(), native_addr, 0),
                            op::I32_LOAD8_S | op::I64_LOAD8_S => {
                                let loaded = builder.ins().load(types::I8, MemFlags::new(), native_addr, 0);
                                builder.ins().sextend(types::I64, loaded)
                            }
                            op::I32_LOAD8_U | op::I64_LOAD8_U => {
                                let loaded = builder.ins().load(types::I8, MemFlags::new(), native_addr, 0);
                                builder.ins().uextend(types::I64, loaded)
                            }
                            op::I32_LOAD16_S | op::I64_LOAD16_S => {
                                let loaded = builder.ins().load(types::I16, MemFlags::new(), native_addr, 0);
                                builder.ins().sextend(types::I64, loaded)
                            }
                            op::I32_LOAD16_U | op::I64_LOAD16_U => {
                                let loaded = builder.ins().load(types::I16, MemFlags::new(), native_addr, 0);
                                builder.ins().uextend(types::I64, loaded)
                            }
                            op::I64_LOAD32_S => {
                                let loaded = builder.ins().load(types::I32, MemFlags::new(), native_addr, 0);
                                builder.ins().sextend(types::I64, loaded)
                            }
                            _ => unreachable!(),
                        }
                    } else {
                        let mem_idx = builder.ins().iconst(types::I32, i64::from(insn.imm3 & 0x7fff_ffff));
                        let _xv_config_var = builder.use_var(config_var);
                        let _xc_0 = builder.ins().iconst(ptr_type, memory_load_helper);
                        let call = builder.ins().call_indirect(
                            mem_load_sig,
                            _xc_0,
                            &[_xv_config_var, mem_idx, addr],
                        );
                        builder.inst_results(call)[0]
                    };
                    write_dst!(builder, insn.destination, result);
                }

                op::I32_STORE | op::I64_STORE | op::F32_STORE | op::F64_STORE | op::I32_STORE8
                | op::I32_STORE16 | op::I64_STORE8 | op::I64_STORE16 | op::I64_STORE32 => {
                    let use_direct_memory = (insn.imm3 & (1u32 << 31)) != 0;
                    let memory_store_helper = match opc {
                        op::I32_STORE | op::F32_STORE | op::I64_STORE32 => h_mem_store32,
                        op::I64_STORE | op::F64_STORE => h_mem_store64,
                        op::I32_STORE8 | op::I64_STORE8 => h_mem_store8,
                        op::I32_STORE16 | op::I64_STORE16 => h_mem_store16,
                        _ => unreachable!(),
                    };

                    let val = read_src!(builder, insn.sources[0]);
                    let base_raw = read_src!(builder, insn.sources[1]);
                    let base_u32 = builder.ins().ireduce(types::I32, base_raw);
                    let base_u64 = builder.ins().uextend(types::I64, base_u32);
                    let offset = builder.ins().iconst(types::I64, insn.imm1);
                    let addr = builder.ins().iadd(base_u64, offset);

                    if use_direct_memory {
                        let memory_base = builder.use_var(default_memory_base_var);
                        let addr_offset = if ptr_type == types::I64 { addr } else { builder.ins().ireduce(ptr_type, addr) };
                        let native_addr = builder.ins().iadd(memory_base, addr_offset);
                        match opc {
                            op::I32_STORE | op::F32_STORE | op::I64_STORE32 => {
                                let narrowed = builder.ins().ireduce(types::I32, val);
                                builder.ins().store(MemFlags::new(), narrowed, native_addr, 0);
                            }
                            op::I64_STORE | op::F64_STORE => {
                                builder.ins().store(MemFlags::new(), val, native_addr, 0);
                            }
                            op::I32_STORE8 | op::I64_STORE8 => {
                                let narrowed = builder.ins().ireduce(types::I8, val);
                                builder.ins().store(MemFlags::new(), narrowed, native_addr, 0);
                            }
                            op::I32_STORE16 | op::I64_STORE16 => {
                                let narrowed = builder.ins().ireduce(types::I16, val);
                                builder.ins().store(MemFlags::new(), narrowed, native_addr, 0);
                            }
                            _ => unreachable!(),
                        }
                    } else {
                        let mem_idx = builder.ins().iconst(types::I32, i64::from(insn.imm3 & 0x7fff_ffff));
                        let _xv_config_var = builder.use_var(config_var);
                        let _xc_0 = builder.ins().iconst(ptr_type, memory_store_helper);
                        let call = builder.ins().call_indirect(
                            mem_store_sig,
                            _xc_0,
                            &[_xv_config_var, mem_idx, addr, val],
                        );
                        let trapped = builder.inst_results(call)[0];
                        let is_trap = builder.ins().icmp_imm(IntCC::NotEqual, trapped, 0);
                        let cont = builder.create_block();
                        builder.ins().brif(is_trap, trap_block, &[], cont, &[]);
                        builder.switch_to_block(cont);
                        builder.seal_block(cont);
                    }
                }

                op::MEMORY_SIZE => {
                    let mem_idx = builder.ins().iconst(types::I32, insn.imm1);
                    let _xv_config_var = builder.use_var(config_var);
                    let _xc_0 = builder.ins().iconst(ptr_type, h_mem_size);
                    let call = builder.ins().call_indirect(
                        mem_size_sig,
                        _xc_0,
                        &[_xv_config_var, mem_idx],
                    );
                    let result = builder.inst_results(call)[0];
                    write_dst!(builder, insn.destination, result);
                }

                op::MEMORY_GROW => {
                    let pages = read_src!(builder, insn.sources[0]);
                    let pages_i32 = builder.ins().ireduce(types::I32, pages);
                    let mem_idx = builder.ins().iconst(types::I32, insn.imm1);
                    let _xv_config_var = builder.use_var(config_var);
                    let _xc_0 = builder.ins().iconst(ptr_type, h_mem_grow);
                    let call = builder.ins().call_indirect(
                        mem_grow_sig,
                        _xc_0,
                        &[_xv_config_var, mem_idx, pages_i32],
                    );
                    let result = builder.inst_results(call)[0];
                    let refreshed_memory_base = builder.ins().load(ptr_type, MemFlags::trusted(), _xv_config_var, default_memory_base_offset);
                    builder.def_var(default_memory_base_var, refreshed_memory_base);
                    let result = builder.ins().sextend(types::I64, result);
                    write_dst!(builder, insn.destination, result);
                }

                op::MEMORY_COPY => {
                    // imm1 = dst_mem, imm2 = src_mem
                    // sources: [0]=count, [1]=src_offset, [2]=dst_offset
                    let count = read_src!(builder, insn.sources[0]);
                    let src_offset = read_src!(builder, insn.sources[1]);
                    let dst_offset = read_src!(builder, insn.sources[2]);
                    let count_i32 = builder.ins().ireduce(types::I32, count);
                    let src_i32 = builder.ins().ireduce(types::I32, src_offset);
                    let dst_i32 = builder.ins().ireduce(types::I32, dst_offset);
                    let dst_mem = builder.ins().iconst(types::I32, insn.imm1);
                    let src_mem = builder.ins().iconst(types::I32, insn.imm2);
                    let cfp = builder.ins().iconst(ptr_type, h_memory_copy);
                    let iv = builder.use_var(interp_var);
                    let cv = builder.use_var(config_var);
                    do_call_and_check!(builder, memory_copy_sig, cfp, &[iv, cv, dst_mem, src_mem, dst_i32, src_i32, count_i32]);
                }

                op::MEMORY_FILL => {
                    // imm1 = mem_idx
                    // sources: [0]=count, [1]=value, [2]=offset
                    let count = read_src!(builder, insn.sources[0]);
                    let value = read_src!(builder, insn.sources[1]);
                    let offset = read_src!(builder, insn.sources[2]);
                    let count_i32 = builder.ins().ireduce(types::I32, count);
                    let value_i32 = builder.ins().ireduce(types::I32, value);
                    let offset_i32 = builder.ins().ireduce(types::I32, offset);
                    let mem_idx = builder.ins().iconst(types::I32, insn.imm1);
                    let cfp = builder.ins().iconst(ptr_type, h_memory_fill);
                    let iv = builder.use_var(interp_var);
                    let cv = builder.use_var(config_var);
                    do_call_and_check!(builder, memory_fill_sig, cfp, &[iv, cv, mem_idx, offset_i32, value_i32, count_i32]);
                }

                // ---- calls ----
                // For all call variants, push arguments from their source locations onto
                // the value stack, then call the helper (which uses UsingStack), then pop
                // any result from the stack to the destination.
                op::CALL => {
                    // Flush virtual stack — args are already on it from previous instructions.
                    flush_vstack_to_real!(builder);
                    let func_idx = builder.ins().iconst(types::I32, insn.imm1);
                    let cfp = builder.ins().iconst(ptr_type, h_call_fn);
                    let iv = builder.use_var(interp_var);
                    let cv = builder.use_var(config_var);
                    do_call_and_check!(builder, call_fn_sig, cfp, &[iv, cv, func_idx]);
                    // The helper always pushes the result to the real value_stack. If
                    // the regalloc assigned a non-stack destination for the result, pop
                    // it back off and route it to the right slot.
                    if insn.destination != STACK_MARKER {
                        let pop_fp = builder.ins().iconst(ptr_type, h_stack_pop);
                        let cfg = builder.use_var(config_var);
                        let call = builder.ins().call_indirect(stack_pop_sig, pop_fp, &[cfg]);
                        let result = builder.inst_results(call)[0];
                        write_dst!(builder, insn.destination, result);
                    }
                }

                op::CALL_INDIRECT => {
                    // Flush virtual stack — args are on it, plus the table index operand.
                    flush_vstack_to_real!(builder);
                    let element_index = read_src!(builder, insn.sources[0]);
                    let element_index = builder.ins().ireduce(types::I32, element_index);
                    let type_idx = builder.ins().iconst(types::I32, insn.imm1);
                    let table_idx = builder.ins().iconst(types::I32, insn.imm2);
                    let cfp = builder.ins().iconst(ptr_type, h_call_indirect);
                    let iv = builder.use_var(interp_var);
                    let cv = builder.use_var(config_var);
                    do_call_and_check!(builder, call_indirect_sig, cfp, &[iv, cv, table_idx, type_idx, element_index]);
                    // Same destination-routing fixup as op::CALL.
                    if insn.destination != STACK_MARKER {
                        let pop_fp = builder.ins().iconst(ptr_type, h_stack_pop);
                        let cfg = builder.use_var(config_var);
                        let call = builder.ins().call_indirect(stack_pop_sig, pop_fp, &[cfg]);
                        let result = builder.inst_results(call)[0];
                        write_dst!(builder, insn.destination, result);
                    }
                }

                opc if (op::SYNTHETIC_CALL_00..=op::SYNTHETIC_CALL_31).contains(&opc) => {
                    // synthetic_call_XY: X params, Y results (0 or 1).
                    let variant = (opc - op::SYNTHETIC_CALL_00) as usize;
                    let param_count = variant / 2;
                    let result_count = variant % 2;
                    let func_idx = builder.ins().iconst(types::I32, insn.imm1);
                    let iv = builder.use_var(interp_var);
                    let cv = builder.use_var(config_var);
                    // Use direct_call helpers which bypass Store::get and use the pre-built function table.
                    match param_count {
                        0 => {
                            let cfp = builder.ins().iconst(ptr_type, h_direct_call_0);
                            do_call_and_check!(builder, call_fn_sig, cfp, &[iv, cv, func_idx]);
                        }
                        1 => {
                            let arg0 = read_src!(builder, insn.sources[0]);
                            let cfp = builder.ins().iconst(ptr_type, h_direct_call_1);
                            do_call_and_check!(builder, call_fn1_sig, cfp, &[iv, cv, func_idx, arg0]);
                        }
                        2 => {
                            let s0 = read_src!(builder, insn.sources[0]); // last param (top)
                            let s1 = read_src!(builder, insn.sources[1]); // first param
                            let cfp = builder.ins().iconst(ptr_type, h_direct_call_2);
                            do_call_and_check!(builder, call_fn2_sig, cfp, &[iv, cv, func_idx, s1, s0]);
                        }
                        3 => {
                            let s0 = read_src!(builder, insn.sources[0]); // last param (top)
                            let s1 = read_src!(builder, insn.sources[1]); // middle param
                            let s2 = read_src!(builder, insn.sources[2]); // first param
                            let cfp = builder.ins().iconst(ptr_type, h_direct_call_3);
                            do_call_and_check!(builder, call_fn3_sig, cfp, &[iv, cv, func_idx, s2, s1, s0]);
                        }
                        _ => unreachable!(),
                    }

                    if result_count > 0 {
                        let cv = builder.use_var(config_var);
                        let result = builder.ins().load(
                            types::I64,
                            MemFlags::trusted(),
                            cv,
                            compiled_call_result_scratch_offset,
                        );
                        write_dst!(builder, insn.destination, result);
                    }
                }

                op::SYNTHETIC_CALL_WITH_RECORD_0 | op::SYNTHETIC_CALL_WITH_RECORD_1 => {
                    let func_idx = builder.ins().iconst(types::I32, insn.imm1);
                    let cwp = builder.ins().iconst(ptr_type, h_call_wr);
                    let iv = builder.use_var(interp_var);
                    let cv = builder.use_var(config_var);
                    do_call_and_check!(builder, call_wr_sig, cwp, &[iv, cv, func_idx]);
                    if opc == op::SYNTHETIC_CALL_WITH_RECORD_1 {
                        let cv2 = builder.use_var(config_var);
                        let result = builder.ins().load(
                            types::I64,
                            MemFlags::trusted(),
                            cv2,
                            compiled_call_result_scratch_offset,
                        );
                        write_dst!(builder, insn.destination, result);
                    }
                }

                // Fused synthetic: local_set + i32_const → write constant to local
                op::SYNTHETIC_LOCAL_SETI32_CONST | op::SYNTHETIC_LOCAL_SETI64_CONST => {
                    let val = builder.ins().iconst(types::I64, insn.imm1);
                    write_local_inline!(builder, insn.imm2, val);
                }

                // Fused: i32 op on two locals → result to destination
                // imm1 = local_index() (first local), imm2 = second local index
                op::SYNTHETIC_I32_ADD2LOCAL => {
                    let r1 = read_local_inline!(builder, insn.imm1);
                    let v1 = builder.ins().ireduce(types::I32, r1);
                    let r2 = read_local_inline!(builder, insn.imm2);
                    let v2 = builder.ins().ireduce(types::I32, r2);
                    let result = builder.ins().iadd(v1, v2);
                    let result = builder.ins().sextend(types::I64, result);
                    write_dst!(builder, insn.destination, result);
                }

                // Fused: i32_addconstlocal — local + i32 constant
                // imm1 = i32 constant, imm2 = local index
                op::SYNTHETIC_I32_ADDCONSTLOCAL => {
                    let r = read_local_inline!(builder, insn.imm2);
                    let v = builder.ins().ireduce(types::I32, r);
                    let k = builder.ins().iconst(types::I32, insn.imm1);
                    let result = builder.ins().iadd(v, k);
                    let result = builder.ins().sextend(types::I64, result);
                    write_dst!(builder, insn.destination, result);
                }

                op::SYNTHETIC_I32_ANDCONSTLOCAL => {
                    let r = read_local_inline!(builder, insn.imm2);
                    let v = builder.ins().ireduce(types::I32, r);
                    let k = builder.ins().iconst(types::I32, insn.imm1);
                    let result = builder.ins().band(v, k);
                    let result = builder.ins().sextend(types::I64, result);
                    write_dst!(builder, insn.destination, result);
                }

                // Generic handler for all i32 two-local fused ops
                opc if (op::SYNTHETIC_I32_SUB2LOCAL..=op::SYNTHETIC_I32_SHRS2LOCAL).contains(&opc) => {
                    let r1 = read_local_inline!(builder, insn.imm1);
                    let v1 = builder.ins().ireduce(types::I32, r1);
                    let r2 = read_local_inline!(builder, insn.imm2);
                    let v2 = builder.ins().ireduce(types::I32, r2);
                    let result = match opc {
                        op::SYNTHETIC_I32_SUB2LOCAL => builder.ins().isub(v1, v2),
                        op::SYNTHETIC_I32_MUL2LOCAL => builder.ins().imul(v1, v2),
                        op::SYNTHETIC_I32_AND2LOCAL => builder.ins().band(v1, v2),
                        op::SYNTHETIC_I32_OR2LOCAL => builder.ins().bor(v1, v2),
                        op::SYNTHETIC_I32_XOR2LOCAL => builder.ins().bxor(v1, v2),
                        op::SYNTHETIC_I32_SHL2LOCAL => builder.ins().ishl(v1, v2),
                        op::SYNTHETIC_I32_SHRU2LOCAL => builder.ins().ushr(v1, v2),
                        op::SYNTHETIC_I32_SHRS2LOCAL => builder.ins().sshr(v1, v2),
                        _ => unreachable!(),
                    };
                    let result = builder.ins().sextend(types::I64, result);
                    write_dst!(builder, insn.destination, result);
                }

                // i64 two-local and constlocal fused ops
                op::SYNTHETIC_I64_ADD2LOCAL => {
                    let v1 = read_local_inline!(builder, insn.imm1);
                    let v2 = read_local_inline!(builder, insn.imm2);
                    let result = builder.ins().iadd(v1, v2);
                    write_dst!(builder, insn.destination, result);
                }
                op::SYNTHETIC_I64_ADDCONSTLOCAL => {
                    let v = read_local_inline!(builder, insn.imm2);
                    let k = builder.ins().iconst(types::I64, insn.imm1);
                    let result = builder.ins().iadd(v, k);
                    write_dst!(builder, insn.destination, result);
                }
                op::SYNTHETIC_I64_ANDCONSTLOCAL => {
                    let v = read_local_inline!(builder, insn.imm2);
                    let k = builder.ins().iconst(types::I64, insn.imm1);
                    let result = builder.ins().band(v, k);
                    write_dst!(builder, insn.destination, result);
                }
                opc if (op::SYNTHETIC_I64_SUB2LOCAL..=op::SYNTHETIC_I64_SHRS2LOCAL).contains(&opc) => {
                    let v1 = read_local_inline!(builder, insn.imm1);
                    let v2 = read_local_inline!(builder, insn.imm2);
                    let result = match opc {
                        op::SYNTHETIC_I64_SUB2LOCAL => builder.ins().isub(v1, v2),
                        op::SYNTHETIC_I64_MUL2LOCAL => builder.ins().imul(v1, v2),
                        op::SYNTHETIC_I64_AND2LOCAL => builder.ins().band(v1, v2),
                        op::SYNTHETIC_I64_OR2LOCAL => builder.ins().bor(v1, v2),
                        op::SYNTHETIC_I64_XOR2LOCAL => builder.ins().bxor(v1, v2),
                        op::SYNTHETIC_I64_SHL2LOCAL => builder.ins().ishl(v1, v2),
                        op::SYNTHETIC_I64_SHRU2LOCAL => builder.ins().ushr(v1, v2),
                        op::SYNTHETIC_I64_SHRS2LOCAL => builder.ins().sshr(v1, v2),
                        _ => unreachable!(),
                    };
                    write_dst!(builder, insn.destination, result);
                }

                // Fused storelocal: reads local value, stores to memory
                // imm1 = memory offset (from MemoryArgument), imm2 = local index, imm3 = memory index
                op::SYNTHETIC_I32_STORELOCAL | op::SYNTHETIC_I64_STORELOCAL => {
                    let use_direct_memory = (insn.imm3 & (1u32 << 31)) != 0;
                    let base_raw = read_src!(builder, insn.sources[0]);
                    let val = read_local_inline!(builder, insn.imm2);
                    let base_u32 = builder.ins().ireduce(types::I32, base_raw);
                    let base_u64 = builder.ins().uextend(types::I64, base_u32);
                    let offset = builder.ins().iconst(types::I64, insn.imm1);
                    let addr = builder.ins().iadd(base_u64, offset);
                    if use_direct_memory {
                        let memory_base = builder.use_var(default_memory_base_var);
                        let addr_offset = if ptr_type == types::I64 { addr } else { builder.ins().ireduce(ptr_type, addr) };
                        let native_addr = builder.ins().iadd(memory_base, addr_offset);
                        if opc == op::SYNTHETIC_I32_STORELOCAL {
                            let narrowed = builder.ins().ireduce(types::I32, val);
                            builder.ins().store(MemFlags::new(), narrowed, native_addr, 0);
                        } else {
                            builder.ins().store(MemFlags::new(), val, native_addr, 0);
                        }
                    } else {
                        let mem_idx = builder.ins().iconst(types::I32, i64::from(insn.imm3 & 0x7fff_ffff));
                        let memory_store_helper = if opc == op::SYNTHETIC_I32_STORELOCAL { h_mem_store32 } else { h_mem_store64 };
                        let _uv_config_var = builder.use_var(config_var);
                        let _ic_0 = builder.ins().iconst(ptr_type, memory_store_helper);
                        let call = builder.ins().call_indirect(mem_store_sig, _ic_0, &[_uv_config_var, mem_idx, addr, val]);
                        let trapped = builder.inst_results(call)[0];
                        let is_trap = builder.ins().icmp_imm(IntCC::NotEqual, trapped, 0);
                        let cont = builder.create_block();
                        builder.ins().brif(is_trap, trap_block, &[], cont, &[]);
                        builder.switch_to_block(cont);
                        builder.seal_block(cont);
                    }
                }

                _ => {
                    // Unsupported opcode — should have been caught by is_supported().
                    return Err("unsupported instruction during codegen");
                }
            }

            ip += 1;
        }

        // If we fell through without hitting end, push results and jump to epilogue.
        if !is_unreachable {
            push_top_n_to_real!(builder, result_arity);
            builder.ins().jump(epilogue_block, &[]);
        }

        // ---- Trap block ----
        builder.switch_to_block(trap_block);
        builder.seal_block(trap_block);
        // Trap was already set by the helper; just return Outcome::Return.
        let trap_ret = builder.ins().iconst(types::I64, outcome_return_value as i64);
        builder.ins().return_(&[trap_ret]);

        // ---- Epilogue block ----
        builder.switch_to_block(epilogue_block);
        builder.seal_block(epilogue_block);
        // Clean up excess values on the real stack (e.g. from BR out of nested blocks).
        // When vstack is enabled, the real stack is untouched during execution, so cleanup is unnecessary.
        if has_raw_call {
            let cleanup_fp = builder.ins().iconst(ptr_type, h_stack_cleanup);
            let cfg = builder.use_var(config_var);
            let init_size = builder.use_var(initial_stack_size_var);
            let arity = builder.ins().iconst(types::I32, result_arity as i64);
            builder.ins().call_indirect(stack_cleanup_sig, cleanup_fp, &[cfg, init_size, arity]);
        }
        // Store regs back to configuration.
        Self::sync_regs_to_config(&mut builder, &reg_vars, config_var, regs_offset, value_size, &dirty_regs);
        let ret_val = builder.ins().iconst(types::I64, outcome_return_value as i64);
        builder.ins().return_(&[ret_val]);

        builder.finalize();

        // Compile the function.
        let mut ctx = Context::for_function(func);
        let code = ctx
            .compile(&*isa, &mut Default::default())
            .map_err(|_| "cranelift compilation failed")?;

        Ok(code.code_buffer().to_vec())
    }

    fn is_supported(insn: &CraneliftInsn) -> bool {
        let opc = insn.opcode;
        // Stack and CallRecord addressing are now supported via helper calls.
        matches!(
            opc,
            op::NOP
                | op::UNREACHABLE
                | op::BLOCK
                | op::LOOP
                | op::IF
                | op::ELSE
                | op::END
                | op::BR
                | op::BR_IF
                | op::BR_TABLE
                | op::RETURN
                | op::CALL
                | op::DROP
                | op::SELECT
                | op::SELECT_TYPED
                | op::LOCAL_GET
                | op::LOCAL_SET
                | op::LOCAL_TEE
                | op::GLOBAL_GET
                | op::GLOBAL_SET
                | op::I32_CONST
                | op::I64_CONST
                | op::F32_CONST
                | op::F64_CONST
                | op::I32_EQZ..=op::I32_GEU
                | op::I64_EQZ..=op::I64_GEU
                | op::F32_EQ..=op::F64_GE
                | op::I32_CLZ..=op::I32_ROTR
                | op::I64_CLZ..=op::I64_ROTR
                | op::F32_ABS..=op::F32_COPYSIGN
                | op::F64_ABS..=op::F64_COPYSIGN
                | op::I32_WRAP_I64..=op::F64_REINTERPRET_I64
                | op::I32_EXTEND8_S..=op::I64_EXTEND32_S
                | op::I32_LOAD..=op::I64_STORE32
                | op::MEMORY_SIZE
                | op::MEMORY_GROW
                | op::CALL_INDIRECT
                | op::I32_TRUNC_SAT_F32_S..=op::I64_TRUNC_SAT_F64_U
                | op::MEMORY_COPY
                | op::MEMORY_FILL
                | op::SYNTHETIC_END_EXPRESSION
                | op::SYNTHETIC_LOCAL_GET_0..=op::SYNTHETIC_LOCAL_GET_7
                | op::SYNTHETIC_LOCAL_SET_0..=op::SYNTHETIC_LOCAL_SET_7
                | op::SYNTHETIC_LOCAL_COPY
                | op::SYNTHETIC_BR_NOSTACK
                | op::SYNTHETIC_BR_IF_NOSTACK
                | op::SYNTHETIC_CALL_00..=op::SYNTHETIC_CALL_31
                | op::SYNTHETIC_I32_ADD2LOCAL..=op::SYNTHETIC_I32_ANDCONSTLOCAL
                | op::SYNTHETIC_I32_STORELOCAL
                | op::SYNTHETIC_LOCAL_SETI32_CONST
                | op::SYNTHETIC_CALL_WITH_RECORD_0
                | op::SYNTHETIC_CALL_WITH_RECORD_1
                | op::SYNTHETIC_ARGUMENT_GET
                | op::SYNTHETIC_ARGUMENT_SET
                | op::SYNTHETIC_ARGUMENT_TEE
                | op::SYNTHETIC_I32_SUB2LOCAL..=op::SYNTHETIC_I32_SHRS2LOCAL
                | op::SYNTHETIC_I64_ADD2LOCAL..=op::SYNTHETIC_LOCAL_SETI64_CONST
                | op::SYNTHETIC_BR_TABLE_CONT
        )
    }

    fn sync_regs_to_config(
        builder: &mut FunctionBuilder,
        reg_vars: &[Variable; REG_COUNT],
        config_var: Variable,
        regs_offset: i32,
        value_size: i32,
        dirty: &[bool; REG_COUNT],
    ) {
        let config = builder.use_var(config_var);
        for i in 0..REG_COUNT {
            if !dirty[i] {
                continue;
            }
            let val = builder.use_var(reg_vars[i]);
            let offset = regs_offset + (i as i32) * value_size;
            builder.ins().store(MemFlags::trusted(), val, config, offset);
            let zero = builder.ins().iconst(types::I64, 0);
            builder.ins().store(MemFlags::trusted(), zero, config, offset + 8);
        }
    }
}
