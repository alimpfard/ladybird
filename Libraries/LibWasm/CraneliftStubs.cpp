/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

// Stubs for when Cranelift JIT is not compiled in.

#include <LibWasm/Types.h>

namespace Wasm {

bool try_cranelift_compile(CompiledInstructions&, u32) { return false; }
void flush_cranelift_batch() { }
void free_cranelift_code(void*) { }

}
