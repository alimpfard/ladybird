// `*.const; local.get; local.get; op` fusion must pick the right indices

test("i64.const; local.get; local.get; i64.add uses correct locals", () => {
    const bin = readBinaryWasmFile("Fixtures/Modules/const-local-local-fusion.wasm");
    const module = parseWebAssemblyModule(bin);
    const fn = module.getExport("i64_const_2local_add");

    // 1000 + (10 + 20) = 1030
    expect(module.invoke(fn, 10n, 20n)).toBe(1030n);
    // 1000 + (100 + 200) = 1300
    expect(module.invoke(fn, 100n, 200n)).toBe(1300n);
});

test("i64.const; local.get; local.get; i64.sub uses correct locals and order", () => {
    const bin = readBinaryWasmFile("Fixtures/Modules/const-local-local-fusion.wasm");
    const module = parseWebAssemblyModule(bin);
    const fn = module.getExport("i64_const_2local_sub");

    // 1000 + (50 - 20) = 1030
    expect(module.invoke(fn, 50n, 20n)).toBe(1030n);
    // 1000 + (200 - 50) = 1150
    expect(module.invoke(fn, 200n, 50n)).toBe(1150n);
});

test("i32.const; local.get; local.get; i32.add uses correct locals", () => {
    const bin = readBinaryWasmFile("Fixtures/Modules/const-local-local-fusion.wasm");
    const module = parseWebAssemblyModule(bin);
    const fn = module.getExport("i32_const_2local_add");

    // 1000 + (10 + 20) = 1030
    expect(module.invoke(fn, 10, 20)).toBe(1030);
    // 1000 + (100 + 200) = 1300
    expect(module.invoke(fn, 100, 200)).toBe(1300);
});

test("i32.const; local.get; local.get; i32.and uses correct locals", () => {
    const bin = readBinaryWasmFile("Fixtures/Modules/const-local-local-fusion.wasm");
    const module = parseWebAssemblyModule(bin);
    const fn = module.getExport("i32_const_2local_and");

    // 0xFF00 | (0xFF & 0x0F) = 0xFF00 | 0x0F = 0xFF0F
    expect(module.invoke(fn, 0xff, 0x0f)).toBe(0xff0f);
    // 0xFF00 | (0xAB & 0xF0) = 0xFF00 | 0xA0 = 0xFFA0
    expect(module.invoke(fn, 0xab, 0xf0)).toBe(0xffa0);
});
