#
# Functions for generating sources using host tools
#

function(embed_as_string name source_file output source_variable_name)
    cmake_parse_arguments(PARSE_ARGV 4 EMBED_STRING_VIEW "" "NAMESPACE" "")
    set(namespace_arg "")
    if (EMBED_STRING_VIEW_NAMESPACE)
        set(namespace_arg "-s ${EMBED_STRING_VIEW_NAMESPACE}")
    endif()
    add_custom_command(
        OUTPUT "${output}"
        COMMAND "${Python3_EXECUTABLE}" "${LADYBIRD_SOURCE_DIR}/Meta/Generators/embed_as_string.py" "${source_file}" -o "${output}.tmp" -n "${source_variable_name}" ${namespace_arg}
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${output}.tmp" "${output}"
        COMMAND "${CMAKE_COMMAND}" -E remove "${output}.tmp"
        VERBATIM
        DEPENDS "${LADYBIRD_SOURCE_DIR}/Meta/Generators/embed_as_string.py"
        MAIN_DEPENDENCY "${source_file}"
    )

    add_custom_target("generate_${name}" DEPENDS "${output}")
    add_dependencies(ladybird_codegen_accumulator "generate_${name}")
endfunction()

function(compile_ipc source output)
    if (NOT IS_ABSOLUTE ${source})
        set(source ${CMAKE_CURRENT_SOURCE_DIR}/${source})
    endif()
    find_package(Python3 REQUIRED COMPONENTS Interpreter)

    # Materialize a per-endpoint Rust crate alongside the C++ header so the
    # generated definitions are picked up by the workspace glob in Cargo.toml.
    get_filename_component(ipc_stem "${source}" NAME_WE)
    string(TOLOWER "${ipc_stem}" ipc_stem_lower)
    set(rust_crate_name "ipc_${ipc_stem_lower}")
    set(rust_crate_dir "${CMAKE_BINARY_DIR}/cargo/generated/ipc/${rust_crate_name}")
    set(rust_output "${rust_crate_dir}/src/lib.rs")
    set(rust_cargo_toml "${rust_crate_dir}/Cargo.toml")

    file(MAKE_DIRECTORY "${rust_crate_dir}/src")
    file(CONFIGURE OUTPUT "${rust_cargo_toml}" CONTENT [=[
[package]
name = "@rust_crate_name@"
version = "0.1.0"
edition = "2024"
publish = false

[lib]
path = "src/lib.rs"

[dependencies]
libipc = { workspace = true }

[lints]
workspace = true
]=] @ONLY)

    # Seed lib.rs so the workspace glob has at least one match before the
    # build step runs the generator. Empty stub is fine — `cargo metadata`
    # only needs the file to exist.
    if (NOT EXISTS "${rust_output}")
        file(WRITE "${rust_output}" "// Generated at build time from ${source}\n")
    endif()

    add_custom_command(
        OUTPUT ${output} ${rust_output}
        COMMAND "${Python3_EXECUTABLE}" "${LADYBIRD_SOURCE_DIR}/Meta/Generators/generate_ipc_definitions.py"
            --input ${source}
            --output ${output}.tmp
            --rust-output ${rust_output}.tmp
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different ${output}.tmp ${output}
        COMMAND "${CMAKE_COMMAND}" -E remove ${output}.tmp
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different ${rust_output}.tmp ${rust_output}
        COMMAND "${CMAKE_COMMAND}" -E remove ${rust_output}.tmp
        VERBATIM
        DEPENDS "${LADYBIRD_SOURCE_DIR}/Meta/Generators/generate_ipc_definitions.py"
        MAIN_DEPENDENCY ${source}
    )
    get_filename_component(output_name ${output} NAME)
    add_custom_target(generate_${output_name} DEPENDS ${output} ${rust_output})
    add_dependencies(ladybird_codegen_accumulator generate_${output_name})

    cmake_path(RELATIVE_PATH CMAKE_CURRENT_SOURCE_DIR BASE_DIRECTORY ${LADYBIRD_SOURCE_DIR} OUTPUT_VARIABLE current_source_dir_relative)
    if (ENABLE_INSTALL_HEADERS)
        install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${output} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${current_source_dir_relative}" OPTIONAL)
    endif()
endfunction()
