# `compile_ipc` for the .ipc files lives in Libraries/LibWebRTCClient — that's
# where the C++ side of the endpoint is wired. We only need the binary here.
build_rust_binary(
    MANIFEST_PATH Cargo.toml
    CRATE_NAME webrtcclient_service
    BINARY_NAME WebRTCClient
    OUTPUT_PATH_VAR WEBRTC_CLIENT_BINARY
)
# The Rust IPC crates are emitted as a side effect of `compile_ipc` (run by
# LibWebRTCClient). Make sure that target is fully wired before cargo builds.
add_dependencies(WebRTCClient-build LibWebRTCClient)
