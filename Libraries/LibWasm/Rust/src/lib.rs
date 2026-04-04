/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

pub mod compiler;

use compiler::CraneliftCompiler;

/// Flat representation of a compiled wasm instruction, passed from C++.
/// Immediates are opcode-dependent:
///   constants:    imm1 = value (i32 sign-extended, i64, or f32/f64 bits)
///   local ops:    imm1 = local index
///   branch:       imm1 = label index (from control stack)
///   block/loop:   imm1 = end_ip, imm2 = else_ip (-1 if none), imm3 = arity | (param_count << 16)
///   call:         imm1 = function index
///   memory ops:   imm1 = offset, imm3 = memory index
///   drop/nop/etc: no immediates used
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CraneliftInsn {
    pub opcode: u64,
    pub sources: [u8; 3],
    pub destination: u8,
    pub imm1: i64,
    pub imm2: i64,
    pub imm3: u32,
    pub _pad: u32,
}

/// Helpers that the compiled code calls back into for operations requiring interpreter state.
/// These are implemented in C++ and passed in at compile time so cranelift can embed direct calls.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RuntimeHelpers {
    /// `i64 (*read_local)(void* config, u32 index)` — reads low 64 bits of local.
    pub read_local: usize,
    /// `void (*write_local)(void* config, u32 index, i64 lo)` — writes local (hi = 0).
    pub write_local: usize,
    /// `bool (*call_function)(void* interpreter, void* config, u32 func_index)` — returns true on trap.
    pub call_function: usize,
    /// `bool (*call_function_0)(void* interpreter, void* config, u32 func_index)` — fast call with 0 args.
    pub call_function_0: usize,
    /// `bool (*call_function_1)(void* interpreter, void* config, u32 func_index, i64 arg0)` — fast call with 1 arg.
    pub call_function_1: usize,
    /// `bool (*call_function_2)(void* interpreter, void* config, u32 func_index, i64 arg0, i64 arg1)` — fast call with 2 args.
    pub call_function_2: usize,
    /// `bool (*call_function_3)(void* interpreter, void* config, u32 func_index, i64 arg0, i64 arg1, i64 arg2)` — fast call with 3 args.
    pub call_function_3: usize,
    /// `void (*set_trap)(void* interpreter, *const u8 msg, u32 len)` — set trap message.
    pub set_trap: usize,
    /// `i64 (*memory_load8_s)(void* config, u32 mem_idx, u64 addr)` — load from memory.
    pub memory_load8_s: usize,
    /// `i64 (*memory_load8_u)(void* config, u32 mem_idx, u64 addr)` — load from memory.
    pub memory_load8_u: usize,
    /// `i64 (*memory_load16_s)(void* config, u32 mem_idx, u64 addr)` — load from memory.
    pub memory_load16_s: usize,
    /// `i64 (*memory_load16_u)(void* config, u32 mem_idx, u64 addr)` — load from memory.
    pub memory_load16_u: usize,
    /// `i64 (*memory_load32_s)(void* config, u32 mem_idx, u64 addr)` — load from memory.
    pub memory_load32_s: usize,
    /// `i64 (*memory_load32_u)(void* config, u32 mem_idx, u64 addr)` — load from memory.
    pub memory_load32_u: usize,
    /// `i64 (*memory_load64)(void* config, u32 mem_idx, u64 addr)` — load from memory.
    pub memory_load64: usize,
    /// `bool (*memory_store8)(void* config, u32 mem_idx, u64 addr, i64 value)` — store, returns true on OOB.
    pub memory_store8: usize,
    /// `bool (*memory_store16)(void* config, u32 mem_idx, u64 addr, i64 value)` — store, returns true on OOB.
    pub memory_store16: usize,
    /// `bool (*memory_store32)(void* config, u32 mem_idx, u64 addr, i64 value)` — store, returns true on OOB.
    pub memory_store32: usize,
    /// `bool (*memory_store64)(void* config, u32 mem_idx, u64 addr, i64 value)` — store, returns true on OOB.
    pub memory_store64: usize,
    /// `u64 (*memory_size)(void* config, u32 mem_idx)` — memory size in pages.
    pub memory_size: usize,
    /// `i32 (*memory_grow)(void* config, u32 mem_idx, u32 pages)` — grow memory, returns old size or -1.
    pub memory_grow: usize,
    /// `i64 (*read_global)(void* config, u32 index)`.
    pub read_global: usize,
    /// `void (*write_global)(void* config, u32 index, i64 value)`.
    pub write_global: usize,
    /// `void (*stack_push)(void* config, i64 value)` — push value to value stack.
    pub stack_push: usize,
    /// `i64 (*stack_pop)(void* config)` — pop value from value stack.
    pub stack_pop: usize,
    /// `i64 (*stack_size)(void* config)` — current value stack size.
    pub stack_size: usize,
    /// `void (*stack_cleanup)(void* config, i64 initial_size, i32 result_arity)` — trim excess stack values.
    pub stack_cleanup: usize,
    /// `i64 (*callrec_read)(void* config, u32 index)` — read call record slot.
    pub callrec_read: usize,
    /// `void (*callrec_write)(void* config, u32 index, i64 value)` — write call record slot.
    pub callrec_write: usize,
    /// `i32 (*call_with_record)(void* interp, void* config, u32 func_index)` — call using call record args.
    pub call_with_record: usize,
    /// Direct call helpers using pre-built function table.
    pub direct_call_0: usize,
    pub direct_call_1: usize,
    pub direct_call_2: usize,
    pub direct_call_3: usize,
    /// `i32 (*call_indirect)(void* interp, void* config, i32 table_idx, i32 type_idx, i32 element_index)`.
    pub call_indirect: usize,
    /// `i32 (*memory_copy)(void* interp, void* config, i32 dst_mem, i32 src_mem, i32 dst, i32 src, i32 count)`.
    pub memory_copy: usize,
    /// `i32 (*memory_fill)(void* interp, void* config, i32 mem_idx, i32 offset, i32 value, i32 count)`.
    pub memory_fill: usize,
    /// Offset from Configuration* to regs array (first data member, typically 0).
    pub regs_offset: u32,
    /// Size of each Value in bytes (16 for u128).
    pub value_size: u32,
    /// Offset from Configuration* to m_locals_base pointer.
    pub locals_base_offset: u32,
    /// Offset from Configuration* to cached memory 0 data pointer.
    pub default_memory_base_offset: u32,
    /// Offset from Configuration* to the cached compiled-call result scratch Value.
    pub compiled_call_result_scratch_offset: u32,
}

pub fn compile_to_bytes(
    insns: &[CraneliftInsn],
    helpers: &RuntimeHelpers,
    outcome_return_value: u64,
    result_arity: u32,
) -> Result<Vec<u8>, &'static str> {
    CraneliftCompiler::compile_to_bytes(insns, helpers, outcome_return_value, result_arity)
}
