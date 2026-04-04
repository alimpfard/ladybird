/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

use libwasm_cranelift::{compile_to_bytes, CraneliftInsn, RuntimeHelpers};
use std::env;
use std::fs::File;
use std::mem::{size_of, size_of_val};
use std::os::fd::FromRawFd;
use std::os::unix::fs::FileExt;

#[repr(C)]
#[derive(Clone, Copy)]
struct InputHeader {
    function_count: u32,
    helpers_offset: u32,
    outcome_return: u64,
    code_region_start: u64,
    total_size: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InputFunctionEntry {
    insn_offset: u32,
    insn_count: u32,
    result_arity: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct OutputFunctionEntry {
    code_offset: u64,
    code_size: u32,
    compiled: u32,
}

fn as_bytes<T>(value: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()) }
}

fn as_bytes_slice<T>(value: &[T]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(value.as_ptr().cast::<u8>(), size_of_val(value)) }
}

fn read_pod<T: Copy>(base: &[u8], offset: usize) -> Result<T, &'static str> {
    let end = offset.checked_add(size_of::<T>()).ok_or("overflow")?;
    let bytes = base.get(offset..end).ok_or("out of bounds read")?;
    Ok(unsafe { (bytes.as_ptr().cast::<T>()).read_unaligned() })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let shmfd = env::args()
        .nth(1)
        .ok_or("Usage: cranelift-compiler <shm-fd>")?
        .parse::<i32>()?;
    if shmfd < 0 {
        return Err("invalid fd".into());
    }

    let mut header_buf = [0u8; size_of::<InputHeader>()];
    let file = unsafe { File::from_raw_fd(shmfd) };
    file.read_exact_at(&mut header_buf, 0)?;
    let header = unsafe { (header_buf.as_ptr().cast::<InputHeader>()).read_unaligned() };

    let total_size = usize::try_from(header.total_size).map_err(|_| "total_size overflow")?;
    let mut mapped = vec![0u8; total_size];
    file.read_exact_at(&mut mapped, 0)?;

    let func_count = usize::try_from(header.function_count).map_err(|_| "function_count overflow")?;
    let entries_offset = size_of::<InputHeader>();
    let helpers_offset = usize::try_from(header.helpers_offset).map_err(|_| "helpers_offset overflow")?;
    let code_region_start = usize::try_from(header.code_region_start).map_err(|_| "code_region_start overflow")?;
    let helpers: RuntimeHelpers = read_pod(&mapped, helpers_offset)?;

    let out_entries_offset = code_region_start;
    let code_base_offset = out_entries_offset + func_count * size_of::<OutputFunctionEntry>();
    let code_capacity = mapped
        .len()
        .checked_sub(code_base_offset)
        .ok_or("bad code region")?;

    // Read all per-function input entries up front so worker threads can borrow
    // immutable slices into `mapped` without coordination.
    let mut entries: Vec<InputFunctionEntry> = Vec::with_capacity(func_count);
    for i in 0..func_count {
        let entry_offset = entries_offset + i * size_of::<InputFunctionEntry>();
        entries.push(read_pod(&mapped, entry_offset)?);
    }

    // Compile every function in parallel into thread-local Vec<u8> buffers, then
    // assemble them into the shared output region sequentially below.
    let thread_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1);
    let chunk_size = func_count.div_ceil(thread_count.max(1));
    let mapped_ref: &[u8] = &mapped;
    let helpers_ref = &helpers;
    let outcome_return = header.outcome_return;

    let compiled_chunks: Vec<Vec<(usize, Vec<u8>)>> = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(thread_count);
        for chunk_idx in 0..thread_count {
            let start = chunk_idx * chunk_size;
            if start >= func_count {
                break;
            }
            let end = (start + chunk_size).min(func_count);
            let chunk_entries = &entries[start..end];
            handles.push(scope.spawn(move || {
                let mut out: Vec<(usize, Vec<u8>)> = Vec::with_capacity(end - start);
                for (offset_in_chunk, entry) in chunk_entries.iter().enumerate() {
                    let i = start + offset_in_chunk;
                    if entry.insn_count == 0 {
                        continue;
                    }
                    let insn_offset = match usize::try_from(entry.insn_offset) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let insn_count = entry.insn_count as usize;
                    let insn_bytes_len = match insn_count.checked_mul(size_of::<CraneliftInsn>()) {
                        Some(v) => v,
                        None => continue,
                    };
                    let insn_bytes = match mapped_ref.get(insn_offset..insn_offset + insn_bytes_len) {
                        Some(b) => b,
                        None => continue,
                    };
                    let insns = unsafe {
                        std::slice::from_raw_parts(insn_bytes.as_ptr().cast::<CraneliftInsn>(), insn_count)
                    };
                    if let Ok(code) = compile_to_bytes(insns, helpers_ref, outcome_return, entry.result_arity) {
                        out.push((i, code));
                    }
                }
                out
            }));
        }
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    // Assemble compiled code into the output region sequentially.
    let mut out_entries = vec![OutputFunctionEntry::default(); func_count];
    let mut code_cursor = 0usize;
    for chunk in compiled_chunks {
        for (i, code) in chunk {
            let aligned = (code.len() + 15) & !15;
            if code_cursor + aligned > code_capacity {
                continue;
            }
            let code_offset = code_cursor;
            mapped[code_base_offset + code_offset..code_base_offset + code_offset + code.len()]
                .copy_from_slice(&code);
            out_entries[i] = OutputFunctionEntry {
                code_offset: u64::try_from(code_offset).map_err(|_| "code offset overflow")?,
                code_size: u32::try_from(code.len()).map_err(|_| "code size overflow")?,
                compiled: 1,
            };
            code_cursor += aligned;
        }
    }

    file.write_all_at(as_bytes_slice(&out_entries), u64::try_from(out_entries_offset)?)?;
    file.write_all_at(&mapped[code_base_offset..code_base_offset + code_cursor], u64::try_from(code_base_offset)?)?;
    file.sync_all()?;
    Ok(())
}
