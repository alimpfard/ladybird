set(ladybird_helper_processes
    Compositor
    ImageDecoder
    RequestServer
    WebContent
    WebWorker
)

if (ENABLE_CRANELIFT_JIT)
    list(APPEND ladybird_helper_processes WasmCompiler)
endif()
# Rust-built helpers go through `build_rust_binary`, so they don't appear as
# regular cmake targets; track them separately so InstallRules can handle them.
set(ladybird_rust_helper_processes WebRTCClient)
