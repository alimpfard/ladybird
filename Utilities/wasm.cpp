/*
 * Copyright (c) 2021, Ali Mohammad Pur <mpfard@serenityos.org>
 * Copyright (c) 2022, the SerenityOS developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/GenericLexer.h>
#include <AK/Hex.h>
#include <AK/MemoryStream.h>
#include <AK/StackInfo.h>
#include <AK/Utf16String.h>
#include <AK/Utf16StringBuilder.h>
#include <LibCore/ArgsParser.h>
#include <LibCore/EventLoop.h>
#include <LibCore/File.h>
#include <LibCore/MappedFile.h>
#include <LibCrypto/BigInt/SignedBigInteger.h>
#include <LibFileSystem/FileSystem.h>
#include <LibJS/Runtime/AbstractOperations.h>
#include <LibJS/Runtime/BigInt.h>
#include <LibJS/Runtime/NativeFunction.h>
#include <LibJS/Runtime/Object.h>
#include <LibJS/Runtime/VM.h>
#include <LibJS/Script.h>
#if defined(AK_OS_WINDOWS)
#    include <AK/Windows.h>
#endif
#include <LibMain/Main.h>
#include <LibWasm/AbstractMachine/AbstractMachine.h>
#include <LibWasm/AbstractMachine/BytecodeInterpreter.h>
#include <LibWasm/Printer/Printer.h>
#include <LibWasm/Types.h>
#if !defined(AK_OS_WINDOWS)
#    include <LibWasm/Wasi.h>
#endif
#include <LibCore/Process.h>
#include <math.h>
#if !defined(AK_OS_WINDOWS)
#    include <unistd.h>
#endif
#if !defined(AK_OS_WINDOWS) && !defined(AK_OS_ANDROID)
#    include <sys/ioctl.h>
#    include <termios.h>
#endif

static OwnPtr<Stream> g_stdout {};
static OwnPtr<Wasm::Printer> g_printer {};
static StackInfo g_stack_info;
static Wasm::BytecodeInterpreter g_interpreter(g_stack_info);

struct ParsedValue {
    Wasm::Value value;
    Wasm::ValueType type;
};

static Optional<u128> convert_to_uint(StringView string)
{
    if (string.is_empty())
        return {};

    u128 value = 0;
    auto const characters = string.characters_without_null_termination();

    for (size_t i = 0; i < string.length(); i++) {
        if (characters[i] < '0' || characters[i] > '9')
            return {};

        value *= 10;
        value += u128 { static_cast<u64>(characters[i] - '0'), 0 };
    }
    return value;
}

static Optional<u128> convert_to_uint_from_hex(StringView string)
{
    if (string.is_empty())
        return {};

    u128 value = 0;
    auto const count = string.length();
    auto const upper_bound = NumericLimits<u128>::max();

    for (size_t i = 0; i < count; i++) {
        char digit = string[i];
        if (value > (upper_bound >> 4))
            return {};

        auto digit_val = decode_hex_digit(digit);
        if (digit_val == 255)
            return {};

        value = (value << 4) + digit_val;
    }
    return value;
}

static ErrorOr<ParsedValue> parse_value(StringView spec)
{
    constexpr auto is_sep = [](char c) { return is_ascii_space(c) || c == ':'; };
    // Scalar: 'T.const[:\s]v' (i32.const 42)
    auto parse_scalar = []<typename T>(StringView text) -> ErrorOr<Wasm::Value> {
        if constexpr (IsFloatingPoint<T>) {
            if (text.trim_whitespace().equals_ignoring_ascii_case("nan"sv)) {
                if constexpr (IsSame<T, float>)
                    return Wasm::Value { nanf("") };
                else
                    return Wasm::Value { nan("") };
            }
            if (text.trim_whitespace().equals_ignoring_ascii_case("inf"sv)) {
                if constexpr (IsSame<T, float>)
                    return Wasm::Value { HUGE_VALF };
                else
                    return Wasm::Value { HUGE_VAL };
            }
        }
        if (auto v = text.to_number<T>(); v.has_value())
            return Wasm::Value { *v };
        return Error::from_string_literal("Invalid scalar value");
    };
    // Vector: 'v128.const[:\s]v' (v128.const 0x01000000020000000300000004000000) or 'v(T.const[:\s]v, ...)' (v(i32.const 1, i32.const 2, i32.const 3, i32.const 4))
    auto parse_u128 = [](StringView text) -> ErrorOr<Wasm::Value> {
        u128 value;
        if (text.starts_with("0x"sv)) {
            if (auto v = convert_to_uint_from_hex(text); v.has_value())
                value = *v;
            else
                return Error::from_string_literal("Invalid hex v128 value");
        } else {
            if (auto v = convert_to_uint(text); v.has_value())
                value = *v;
            else
                return Error::from_string_literal("Invalid v128 value");
        }

        return Wasm::Value { value };
    };

    GenericLexer lexer(spec);
    if (lexer.consume_specific("v128.const"sv)) {
        lexer.ignore_while(is_sep);
        // The rest of the string is the value
        auto text = lexer.consume_all();
        return ParsedValue {
            .value = TRY(parse_u128(text)),
            .type = Wasm::ValueType(Wasm::ValueType::Kind::V128)
        };
    }

    if (lexer.consume_specific("i8.const"sv)) {
        lexer.ignore_while(is_sep);
        auto text = lexer.consume_all();
        return ParsedValue {
            .value = TRY(parse_scalar.operator()<i8>(text)),
            .type = Wasm::ValueType(Wasm::ValueType::Kind::I32)
        };
    }
    if (lexer.consume_specific("i16.const"sv)) {
        lexer.ignore_while(is_sep);
        auto text = lexer.consume_all();
        return ParsedValue {
            .value = TRY(parse_scalar.operator()<i16>(text)),
            .type = Wasm::ValueType(Wasm::ValueType::Kind::I32)
        };
    }
    if (lexer.consume_specific("i32.const"sv)) {
        lexer.ignore_while(is_sep);
        auto text = lexer.consume_all();
        return ParsedValue {
            .value = TRY(parse_scalar.operator()<i32>(text)),
            .type = Wasm::ValueType(Wasm::ValueType::Kind::I32)
        };
    }
    if (lexer.consume_specific("i64.const"sv)) {
        lexer.ignore_while(is_sep);
        auto text = lexer.consume_all();
        return ParsedValue {
            .value = TRY(parse_scalar.operator()<i64>(text)),
            .type = Wasm::ValueType(Wasm::ValueType::Kind::I64)
        };
    }
    if (lexer.consume_specific("f32.const"sv)) {
        lexer.ignore_while(is_sep);
        auto text = lexer.consume_all();
        return ParsedValue {
            .value = TRY(parse_scalar.operator()<float>(text)),
            .type = Wasm::ValueType(Wasm::ValueType::Kind::F32)
        };
    }
    if (lexer.consume_specific("f64.const"sv)) {
        lexer.ignore_while(is_sep);
        auto text = lexer.consume_all();
        return ParsedValue {
            .value = TRY(parse_scalar.operator()<double>(text)),
            .type = Wasm::ValueType(Wasm::ValueType::Kind::F64)
        };
    }

    if (lexer.consume_specific("v("sv)) {
        Vector<ParsedValue> values;
        for (;;) {
            lexer.ignore_while(is_sep);
            if (lexer.consume_specific(")"sv))
                break;
            if (lexer.is_eof()) {
                warnln("Expected ')' to close vector");
                break;
            }
            auto value = parse_value(lexer.consume_until(is_any_of(",)"sv)));
            if (value.is_error())
                return value.release_error();
            lexer.consume_specific(',');
            values.append(value.release_value());
        }

        if (values.is_empty())
            return Error::from_string_literal("Empty vector");

        auto element_type = values.first().type;
        for (auto& value : values) {
            if (value.type != element_type)
                return Error::from_string_literal("Mixed types in vector");
        }

        unsigned total_size = 0;
        unsigned width = 0;
        u128 result = 0;
        u128 last_value = 0;
        for (auto& parsed : values) {
            if (total_size >= 128)
                return Error::from_string_literal("Vector too large");

            switch (parsed.type.kind()) {
            case Wasm::ValueType::F32:
            case Wasm::ValueType::I32:
                width = sizeof(u32);
                break;
            case Wasm::ValueType::F64:
            case Wasm::ValueType::I64:
                width = sizeof(u64);
                break;
            case Wasm::ValueType::V128:
            case Wasm::ValueType::I8:
            case Wasm::ValueType::I16:
            case Wasm::ValueType::FunctionReference:
            case Wasm::ValueType::NoFunctionReference:
            case Wasm::ValueType::ExternReference:
            case Wasm::ValueType::NoExternReference:
            case Wasm::ValueType::ExceptionReference:
            case Wasm::ValueType::NoExceptionReference:
            case Wasm::ValueType::AnyReference:
            case Wasm::ValueType::EqReference:
            case Wasm::ValueType::I31Reference:
            case Wasm::ValueType::StructReference:
            case Wasm::ValueType::ArrayReference:
            case Wasm::ValueType::NoneReference:
            case Wasm::ValueType::TypeUseReference:
                VERIFY_NOT_REACHED();
            }
            last_value = parsed.value.value();

            result |= last_value << total_size;
            total_size += width * 8;
        }

        if (total_size < 128)
            warnln("Vector value '{}' is only {} bytes wide, repeating last element", spec, total_size);
        while (total_size < 128) {
            // Repeat the last value until we fill the 128 bits
            result |= last_value << total_size;
            total_size += width * 8;
        }

        return ParsedValue {
            .value = Wasm::Value { result },
            .type = Wasm::ValueType(Wasm::ValueType::Kind::V128)
        };
    }

    return Error::from_string_literal("Invalid value");
}

static RefPtr<Wasm::Module> parse(StringView filename)
{
    auto result = Core::MappedFile::map(filename);
    if (result.is_error()) {
        warnln("Failed to open {}: {}", filename, result.error());
        return {};
    }

    auto parse_result = Wasm::Module::parse(*result.value());
    if (parse_result.is_error()) {
        warnln("Something went wrong, either the file is invalid, or there's a bug with LibWasm!");
        warnln("The parse error was {}", Wasm::parse_error_to_byte_string(parse_result.error()));
        return {};
    }
    return parse_result.release_value();
}

static void print_link_error(Wasm::LinkError const& error)
{
    for (auto const& missing : error.missing_imports)
        warnln("Missing import '{}'", missing);
}

template<typename T>
static ErrorOr<T, Wasm::Result> trap_for_js_exception(JS::VM& vm, JS::ThrowCompletionOr<T> const& result)
{
    if (!result.is_error())
        return result.value();

    auto const& completion = result.error();
    auto& exception = completion.value();
    warnln("JS exception: {}", MUST(exception.to_utf16_string(vm)));
    return Wasm::Trap { ByteString("JS exception") };
}

#if !defined(AK_OS_WINDOWS) && !defined(AK_OS_ANDROID)
static ByteString format_function_type(Wasm::FunctionType const& type)
{
    StringBuilder sb;
    sb.append('(');
    for (size_t i = 0; i < type.parameters().size(); ++i) {
        if (i > 0)
            sb.append(", "sv);
        sb.append(type.parameters()[i].kind_name());
    }
    sb.append(") -> ("sv);
    for (size_t i = 0; i < type.results().size(); ++i) {
        if (i > 0)
            sb.append(", "sv);
        sb.append(type.results()[i].kind_name());
    }
    sb.append(')');
    return sb.to_byte_string();
}

static Vector<ByteString> disassemble_native(Wasm::WasmFunction const& func)
{
    auto& ci = func.code().func().body().compiled_instructions;
    if (!ci.cranelift_compiled || ci.cranelift_code_size == 0)
        return {};

    auto entry = Wasm::cranelift_entry_acquire(ci);
    if (!entry)
        return {};
    auto const* code_ptr = bit_cast<u8 const*>(entry);
    auto code_size = ci.cranelift_code_size;

    char tmp_path[] = "/tmp/wasm-native-XXXXXX";
    int fd = mkstemp(tmp_path);
    if (fd < 0)
        return {};

    {
        auto tmp_file = MUST(Core::File::adopt_fd(fd, Core::File::OpenMode::Write));
#if ARCH(AARCH64) && defined(AK_OS_MACOS)
        struct [[gnu::packed]] {
            u32 magic = 0xFEEDFACF;
            u32 cputype = 0x0100000C;
            u32 cpusubtype = 0;
            u32 filetype = 1;
            u32 ncmds = 1;
            u32 sizeofcmds = 72 + 80;
            u32 flags = 0;
            u32 reserved = 0;
        } mach_header;
        struct [[gnu::packed]] {
            u32 cmd = 0x19;
            u32 cmdsize = 72 + 80;
            char segname[16] = {};
            u64 vmaddr = 0;
            u64 vmsize;
            u64 fileoff;
            u64 filesize;
            u32 maxprot = 7;
            u32 initprot = 7;
            u32 nsects = 1;
            u32 flags = 0;
        } segment;
        segment.vmsize = code_size;
        segment.fileoff = sizeof(mach_header) + sizeof(segment) + 80;
        segment.filesize = code_size;
        struct [[gnu::packed]] {
            char sectname[16] = "__text";
            char segname[16] = "__TEXT";
            u64 addr = 0;
            u64 size;
            u32 offset;
            u32 align = 2;
            u32 reloff = 0;
            u32 nreloc = 0;
            u32 flags = 0x80000400;
            u32 reserved1 = 0;
            u32 reserved2 = 0;
            u32 reserved3 = 0;
        } section;
        section.size = code_size;
        section.offset = static_cast<u32>(segment.fileoff);
        (void)tmp_file->write_until_depleted({ &mach_header, sizeof(mach_header) });
        (void)tmp_file->write_until_depleted({ &segment, sizeof(segment) });
        (void)tmp_file->write_until_depleted({ &section, sizeof(section) });
#endif
        (void)tmp_file->write_until_depleted({ code_ptr, code_size });
    }

#if defined(AK_OS_MACOS)
    auto cmd = ByteString::formatted("/usr/bin/objdump -d {} 2>/dev/null | tail -n +7", tmp_path);
#elif ARCH(X86_64)
    auto cmd = ByteString::formatted("/usr/bin/objdump -D -b binary -m i386:x86-64 {} 2>/dev/null | tail -n +8", tmp_path);
#elif ARCH(AARCH64)
    auto cmd = ByteString::formatted("/usr/bin/objdump -D -b binary -m aarch64 {} 2>/dev/null | tail -n +8", tmp_path);
#else
    auto cmd = ByteString::formatted("/usr/bin/objdump -D -b binary {} 2>/dev/null | tail -n +8", tmp_path);
#endif

    Vector<ByteString> lines;
    FILE* pipe = popen(cmd.characters(), "r");
    if (pipe) {
        char buf[1024];
        while (fgets(buf, sizeof(buf), pipe))
            lines.append(StringView(buf, strlen(buf)).trim("\n\r"sv));
        pclose(pipe);
    }
    unlink(tmp_path);
    return lines;
}

static void tui_run(Wasm::AbstractMachine& machine, Wasm::Module const& module, Wasm::ModuleInstance& instance, StringView filename)
{
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
        warnln("--tui requires an interactive terminal");
        return;
    }

    auto write_raw = [](StringView s) {
        (void)!write(STDOUT_FILENO, s.characters_without_null_termination(), s.length());
    };

    module.wait_for_cranelift_compilation();

    // -- Section item data --
    struct Item {
        ByteString text;
        enum class Detail { None, Function, Memory } detail = Detail::None;
        size_t detail_idx = 0;
    };

    static constexpr size_t SEC_COUNT = 8;
    char const* sec_names[] = { "Exports", "Imports", "Types", "Functions", "Globals", "Tables", "Memories", "Custom Sections" };
    Vector<Item> sec_items[SEC_COUNT];
    bool sec_expanded[SEC_COUNT] = {};

    auto fn_is_native = [&](Wasm::FunctionAddress addr) -> bool {
        auto* fn = machine.store().get(addr);
        if (!fn || !fn->has<Wasm::WasmFunction>())
            return false;
        auto& ci = fn->get<Wasm::WasmFunction>().code().func().body().compiled_instructions;
        return ci.cranelift_compiled && ci.cranelift_code_size > 0;
    };

    auto fn_type_str = [&](Wasm::FunctionInstance* fn) -> ByteString {
        return fn->visit(
            [](Wasm::WasmFunction const& f) { return format_function_type(f.type()); },
            [](Wasm::HostFunction const& f) { return format_function_type(f.type()); });
    };

    // Exports
    for (auto& entry : instance.exports()) {
        Item item;
        entry.value().visit(
            [&](Wasm::FunctionAddress const& addr) {
                auto* fn = machine.store().get(addr);
                auto sig = fn ? fn_type_str(fn) : ByteString("(?)");
                auto native = fn_is_native(addr) ? " [native]" : "";
                item.text = ByteString::formatted("{:30s}  func {}{}", entry.name(), sig, native);
                item.detail = Item::Detail::Function;
                item.detail_idx = addr.value();
            },
            [&](Wasm::TableAddress const&) { item.text = ByteString::formatted("{:30s}  table", entry.name()); },
            [&](Wasm::MemoryAddress const&) { item.text = ByteString::formatted("{:30s}  memory", entry.name()); },
            [&](Wasm::GlobalAddress const& addr) {
                auto* g = machine.store().get(addr);
                item.text = g ? ByteString::formatted("{:30s}  global {} {}", entry.name(), g->type().type().kind_name(), g->is_mutable() ? "mut" : "const")
                              : ByteString::formatted("{:30s}  global", entry.name());
            },
            [&](Wasm::TagAddress const&) { item.text = ByteString::formatted("{:30s}  tag", entry.name()); });
        sec_items[0].append(move(item));
    }

    // Imports
    for (auto& imp : module.import_section().imports()) {
        ByteString kind;
        imp.description().visit(
            [&](Wasm::TypeIndex const& idx) {
                if (idx.value() < module.type_section().types().size() && module.type_section().types()[idx.value()].is_function())
                    kind = ByteString::formatted("func {}", format_function_type(module.type_section().types()[idx.value()].function()));
                else
                    kind = ByteString::formatted("type #{}", idx.value());
            },
            [&](Wasm::FunctionType const& ft) { kind = ByteString::formatted("func {}", format_function_type(ft)); },
            [&](Wasm::TableType const& t) { kind = ByteString::formatted("table {}", t.element_type().kind_name()); },
            [&](Wasm::MemoryType const&) { kind = "memory"; },
            [&](Wasm::GlobalType const& g) { kind = ByteString::formatted("global {} {}", g.type().kind_name(), g.is_mutable() ? "mut" : "const"); },
            [&](Wasm::TagType const&) { kind = "tag"; });
        sec_items[1].append({ ByteString::formatted("{}.{}  {}", imp.module(), imp.name(), kind) });
    }

    // Types
    for (size_t i = 0; i < module.type_section().types().size(); ++i) {
        ByteString desc;
        module.type_section().types()[i].description().visit(
            [&](Wasm::FunctionType const& ft) { desc = ByteString::formatted("func {}", format_function_type(ft)); },
            [&](Wasm::StructType const& st) {
                StringBuilder sb;
                sb.append("struct {"sv);
                for (size_t j = 0; j < st.fields().size(); ++j) {
                    if (j)
                        sb.append(", "sv);
                    sb.append(st.fields()[j].type().kind_name());
                }
                sb.append('}');
                desc = sb.to_byte_string();
            },
            [&](Wasm::ArrayType const& at) { desc = ByteString::formatted("array {}", at.type().type().kind_name()); });
        sec_items[2].append({ ByteString::formatted("[{}] {}", i, desc) });
    }

    // Functions
    for (size_t i = 0; i < instance.functions().size(); ++i) {
        auto addr = instance.functions()[i];
        auto* fn = machine.store().get(addr);
        if (!fn)
            continue;
        ByteString export_name;
        for (auto& entry : instance.exports())
            if (auto* a = entry.value().get_pointer<Wasm::FunctionAddress>(); a && *a == addr) {
                export_name = ByteString::formatted("  '{}'", entry.name());
                break;
            }
        auto native_tag = fn_is_native(addr) ? " [native]" : "";
        ByteString text;
        fn->visit(
            [&](Wasm::WasmFunction const& f) { text = ByteString::formatted("[{}] {}{}{}", i, format_function_type(f.type()), export_name, native_tag); },
            [&](Wasm::HostFunction const& f) { text = ByteString::formatted("[{}] {} (host){}", i, format_function_type(f.type()), export_name); });
        sec_items[3].append({ text, Item::Detail::Function, addr.value() });
    }

    // Globals
    for (size_t i = 0; i < instance.globals().size(); ++i) {
        auto* g = machine.store().get(instance.globals()[i]);
        if (!g)
            continue;
        ByteString export_name;
        for (auto& entry : instance.exports())
            if (auto* a = entry.value().get_pointer<Wasm::GlobalAddress>(); a && *a == instance.globals()[i]) {
                export_name = ByteString::formatted("  '{}'", entry.name());
                break;
            }
        AllocatingMemoryStream vs;
        Wasm::Printer pr { vs };
        pr.print(g->value(), g->type().type());
        auto vb = MUST(ByteBuffer::create_uninitialized(vs.used_buffer_size()));
        MUST(vs.read_until_filled(vb));
        sec_items[4].append({ ByteString::formatted("[{}] {} {} = {}{}", i, g->type().type().kind_name(),
            g->is_mutable() ? "mut" : "const", StringView(vb).trim_whitespace(), export_name) });
    }

    // Tables
    for (size_t i = 0; i < instance.tables().size(); ++i) {
        auto* t = machine.store().get(instance.tables()[i]);
        if (!t)
            continue;
        sec_items[5].append({ ByteString::formatted("[{}] {} elements={} min={} max={}", i,
            t->type().element_type().kind_name(), t->elements().size(), t->type().limits().min(),
            t->type().limits().max().has_value() ? ByteString::number(*t->type().limits().max()) : ByteString("inf")) });
    }

    // Memories
    for (size_t i = 0; i < instance.memories().size(); ++i) {
        auto* m = machine.store().get(instance.memories()[i]);
        if (!m)
            continue;
        sec_items[6].append({ ByteString::formatted("[{}] {} bytes ({} pages, max {})", i, m->size(), m->type().limits().min(),
            m->type().limits().max().has_value() ? ByteString::number(*m->type().limits().max()) : ByteString("inf")),
            Item::Detail::Memory, i });
    }

    // Custom Sections
    for (auto& s : module.custom_sections())
        sec_items[7].append({ ByteString::formatted("'{}' ({} bytes)", s.name(), s.contents().size()) });

    // -- Terminal raw mode --
    struct termios orig_termios;
    tcgetattr(STDIN_FILENO, &orig_termios);
    {
        struct termios raw = orig_termios;
        raw.c_lflag &= ~(unsigned)(ECHO | ICANON | ISIG | IEXTEN);
        raw.c_iflag &= ~(unsigned)(IXON | ICRNL | BRKINT);
        raw.c_cc[VMIN] = 1;
        raw.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    }
    write_raw("\033[?1049h\033[?25l\033[?7l"sv);

    auto restore_term = [&] {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
        write_raw("\033[?7h\033[?25h\033[?1049l\033[0m"sv);
    };

    // -- Key input --
    enum class Key { None, Up, Down, Left, Right, Enter, Escape, PageUp, PageDown, Home, End, Quit, Tab };
    auto read_key = []() -> Key {
        char c;
        if (read(STDIN_FILENO, &c, 1) != 1)
            return Key::None;
        switch (c) {
        case 'q':
        case 3:
            return Key::Quit;
        case '\r':
            return Key::Enter;
        case 'k':
            return Key::Up;
        case 'j':
            return Key::Down;
        case 'h':
            return Key::Left;
        case 'l':
            return Key::Right;
        case 'g':
            return Key::Home;
        case 'G':
            return Key::End;
        case ' ':
            return Key::PageDown;
        case 'b':
            return Key::PageUp;
        case '\t':
        case 'd':
            return Key::Tab;
        case 27: {
            char s[2];
            if (read(STDIN_FILENO, &s[0], 1) != 1)
                return Key::Escape;
            if (s[0] != '[')
                return Key::Escape;
            if (read(STDIN_FILENO, &s[1], 1) != 1)
                return Key::Escape;
            switch (s[1]) {
            case 'A':
                return Key::Up;
            case 'B':
                return Key::Down;
            case 'C':
                return Key::Right;
            case 'D':
                return Key::Left;
            case 'H':
                return Key::Home;
            case 'F':
                return Key::End;
            case '5': {
                char t;
                (void)read(STDIN_FILENO, &t, 1);
                return Key::PageUp;
            }
            case '6': {
                char t;
                (void)read(STDIN_FILENO, &t, 1);
                return Key::PageDown;
            }
            }
            return Key::None;
        }
        }
        return Key::None;
    };

    // -- Render helpers --
    struct TermSize {
        int rows, cols;
    };
    auto get_size = []() -> TermSize {
        struct winsize ws;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0)
            return { ws.ws_row, ws.ws_col };
        return { 24, 80 };
    };

    auto render_separator = [](StringBuilder& scr, int cols) {
        scr.append("\033[2m  "sv);
        for (int i = 0; i < cols - 4; ++i)
            scr.append("\xe2\x94\x80"sv);
        scr.append("\033[0m\033[K"sv);
    };

    // -- Scrollable detail view (reused for bytecode, native disasm, hex dump) --
    auto show_detail = [&](ByteString const& title, auto const& get_line, size_t line_count, ByteString const& extra_status) {
        size_t dscroll = 0;
        for (;;) {
            auto [rows, cols] = get_size();
            int vp = max(1, rows - 3);
            if (line_count <= (size_t)vp)
                dscroll = 0;
            else if (dscroll + vp > line_count)
                dscroll = line_count - vp;

            StringBuilder scr;
            scr.appendff("\033[1;1H\033[1m  {}\033[0m\033[K", title);
            scr.append("\033[2;1H"sv);
            render_separator(scr, cols);
            for (int r = 0; r < vp; ++r) {
                scr.appendff("\033[{};1H", r + 3);
                size_t idx = dscroll + r;
                if (idx < line_count)
                    scr.appendff("  {}\033[K", get_line(idx));
                else
                    scr.append("\033[K"sv);
            }
            scr.appendff("\033[{};1H\033[7m  j/k scroll  q back  {}{}\033[0m\033[K",
                rows, extra_status,
                line_count > 0 ? ByteString::formatted("  {}/{}", min(dscroll + 1, line_count), line_count) : ByteString(""));
            write_raw(scr.string_view());

            auto key = read_key();
            switch (key) {
            case Key::Quit:
            case Key::Escape:
            case Key::Left:
                return key;
            case Key::Up:
                if (dscroll > 0)
                    --dscroll;
                break;
            case Key::Down:
                if (dscroll + vp < line_count)
                    ++dscroll;
                break;
            case Key::PageUp:
                dscroll = dscroll > (size_t)vp ? dscroll - vp : 0;
                break;
            case Key::PageDown:
                if (line_count > (size_t)vp)
                    dscroll = min(dscroll + vp, line_count - vp);
                break;
            case Key::Home:
                dscroll = 0;
                break;
            case Key::End:
                if (line_count > (size_t)vp)
                    dscroll = line_count - vp;
                break;
            case Key::Tab:
                return Key::Tab;
            default:
                break;
            }
        }
    };

    // -- Visible row for main tree view --
    struct VisRow {
        StringView text;
        bool is_section;
        size_t section_idx;
        Item::Detail detail;
        size_t detail_idx;
    };

    ByteString sec_hdrs[SEC_COUNT];
    auto build_visible = [&]() -> Vector<VisRow> {
        for (size_t s = 0; s < SEC_COUNT; ++s)
            sec_hdrs[s] = ByteString::formatted("{} {} ({})",
                sec_expanded[s] ? "\xe2\x96\xbc" : "\xe2\x96\xb6", sec_names[s], sec_items[s].size());
        Vector<VisRow> v;
        for (size_t s = 0; s < SEC_COUNT; ++s) {
            v.append({ sec_hdrs[s], true, s, Item::Detail::None, 0 });
            if (sec_expanded[s])
                for (auto& item : sec_items[s])
                    v.append({ item.text, false, s, item.detail, item.detail_idx });
        }
        return v;
    };

    // -- Main loop --
    size_t cursor = 0, scroll = 0;
    for (;;) {
        auto [rows, cols] = get_size();
        int vp = max(1, rows - 3);

        auto vis = build_visible();
        size_t total = vis.size();
        if (cursor >= total)
            cursor = total ? total - 1 : 0;
        if (cursor < scroll)
            scroll = cursor;
        if (cursor >= scroll + (size_t)vp)
            scroll = cursor - vp + 1;

        StringBuilder scr;
        scr.appendff("\033[1;1H\033[1m  Module: {}\033[0m\033[K", filename);
        scr.append("\033[2;1H"sv);
        render_separator(scr, cols);

        for (int r = 0; r < vp; ++r) {
            scr.appendff("\033[{};1H", r + 3);
            size_t idx = scroll + r;
            if (idx < total) {
                auto& row = vis[idx];
                if (idx == cursor)
                    scr.append("\033[7m"sv);
                if (row.is_section)
                    scr.append("\033[1m"sv);
                scr.appendff("  {}\033[0m\033[K", row.text);
            } else {
                scr.append("\033[K"sv);
            }
        }

        scr.appendff("\033[{};1H\033[7m  j/k navigate  enter open  q quit  {}/{}\033[0m\033[K",
            rows, cursor + 1, total);
        write_raw(scr.string_view());

        auto key = read_key();
        switch (key) {
        case Key::Quit:
            restore_term();
            return;
        case Key::Up:
            if (cursor > 0)
                --cursor;
            break;
        case Key::Down:
            if (cursor + 1 < total)
                ++cursor;
            break;
        case Key::PageUp:
            cursor = cursor > (size_t)vp ? cursor - vp : 0;
            break;
        case Key::PageDown:
            cursor = min(cursor + (size_t)vp, total - 1);
            break;
        case Key::Home:
            cursor = 0;
            break;
        case Key::End:
            cursor = total ? total - 1 : 0;
            break;
        case Key::Left:
            if (cursor < total) {
                auto& row = vis[cursor];
                if (row.is_section && sec_expanded[row.section_idx]) {
                    sec_expanded[row.section_idx] = false;
                } else if (!row.is_section) {
                    sec_expanded[row.section_idx] = false;
                    for (size_t i = cursor;; --i) {
                        if (vis[i].is_section && vis[i].section_idx == row.section_idx) {
                            cursor = i;
                            break;
                        }
                        if (i == 0)
                            break;
                    }
                }
            }
            break;
        case Key::Enter:
        case Key::Right:
            if (cursor < total) {
                auto& row = vis[cursor];
                if (row.is_section) {
                    sec_expanded[row.section_idx] = !sec_expanded[row.section_idx];
                } else if (row.detail == Item::Detail::Function) {
                    Wasm::FunctionAddress addr(row.detail_idx);
                    auto* fn = machine.store().get(addr);
                    if (!fn)
                        break;

                    ByteString export_name;
                    for (auto& entry : instance.exports())
                        if (auto* a = entry.value().get_pointer<Wasm::FunctionAddress>(); a && *a == addr) {
                            export_name = ByteString::formatted(" '{}'", entry.name());
                            break;
                        }

                    fn->visit(
                        [&](Wasm::WasmFunction const& f) {
                            bool has_native = fn_is_native(addr);

                            AllocatingMemoryStream stream;
                            Wasm::Printer printer { stream, 0 };
                            printer.print(f.code());
                            auto buf = MUST(ByteBuffer::create_uninitialized(stream.used_buffer_size()));
                            MUST(stream.read_until_filled(buf));
                            Vector<ByteString> bytecode_lines;
                            StringView(buf).for_each_split_view('\n', SplitBehavior::KeepEmpty, [&](auto line) {
                                bytecode_lines.append(ByteString(line));
                            });
                            while (!bytecode_lines.is_empty() && bytecode_lines.last().is_empty())
                                bytecode_lines.take_last();

                            Vector<ByteString> native_lines;
                            bool showing_native = false;
                            bool native_loaded = false;

                            auto bc_title = ByteString::formatted("Function #{}: {}{}", addr.value(), format_function_type(f.type()), export_name);
                            auto nat_title = ByteString::formatted("Function #{}: {}{} (native disassembly)", addr.value(), format_function_type(f.type()), export_name);

                            for (;;) {
                                auto& title = showing_native ? nat_title : bc_title;
                                ByteString extra;
                                if (has_native)
                                    extra = showing_native ? "d: bytecode  " : "d: disassembly  ";

                                Key result;
                                if (showing_native) {
                                    if (!native_loaded) {
                                        native_lines = disassemble_native(f);
                                        if (native_lines.is_empty())
                                            native_lines.append("(disassembly unavailable - is objdump installed?)");
                                        native_loaded = true;
                                    }
                                    result = show_detail(title, [&](size_t i) -> StringView { return native_lines[i]; }, native_lines.size(), extra);
                                } else {
                                    result = show_detail(title, [&](size_t i) -> StringView { return bytecode_lines[i]; }, bytecode_lines.size(), extra);
                                }

                                if (result == Key::Tab && has_native) {
                                    showing_native = !showing_native;
                                    continue;
                                }
                                break;
                            }
                        },
                        [&](Wasm::HostFunction const& f) {
                            Vector<ByteString> lines;
                            lines.append(ByteString::formatted("Host function: {}", f.name()));
                            lines.append("(no bytecode available)");
                            show_detail(
                                ByteString::formatted("Function #{}: {}{}", addr.value(), format_function_type(f.type()), export_name),
                                [&](size_t i) -> StringView { return lines[i]; }, lines.size(), ByteString());
                        });
                } else if (row.detail == Item::Detail::Memory) {
                    auto mem_idx = row.detail_idx;
                    auto* mem = machine.store().get(instance.memories()[mem_idx]);
                    if (!mem)
                        break;
                    auto mem_sz = mem->size();
                    auto line_count = (mem_sz + 15) / 16;
                    auto title = ByteString::formatted("Memory [{}]: {} bytes ({} pages)", mem_idx, mem_sz, mem_sz / 65536);

                    auto format_hex = [&](size_t line_idx) -> ByteString {
                        auto offset = line_idx * 16;
                        auto end = min(offset + 16, mem_sz);
                        StringBuilder sb;
                        sb.appendff("{:08x}  ", offset);
                        StringBuilder ascii;
                        for (size_t i = 0; i < 16; ++i) {
                            if (offset + i < end) {
                                u8 byte = mem->data()[offset + i];
                                sb.appendff("{:02x} ", byte);
                                ascii.append(byte >= 0x20 && byte < 0x7f ? static_cast<char>(byte) : '.');
                            } else {
                                sb.append("   "sv);
                                ascii.append(' ');
                            }
                            if (i == 7)
                                sb.append(' ');
                        }
                        sb.appendff(" |{}|", ascii.string_view());
                        return sb.to_byte_string();
                    };
                    show_detail(title, format_hex, line_count, ByteString());
                }
            }
            break;
        default:
            break;
        }
    }
}
#endif

ErrorOr<int> ladybird_main(Main::Arguments arguments)
{
    StringView filename;
    bool print = false;
    bool print_compiled = false;
    bool dump_native = false;
    bool attempt_instantiate = false;
    bool export_all_imports = false;
    [[maybe_unused]] bool wasi = false;
    [[maybe_unused]] bool tui = false;
    Optional<u64> specific_function_address;
    ByteString exported_function_to_execute;
    Vector<ParsedValue> values_to_push;
    Vector<ByteString> modules_to_link_in;
    Vector<StringView> args_if_wasi;
    Vector<StringView> wasi_preopened_mappings;
    HashMap<Wasm::Linker::Name, Wasm::ExternValue> js_exports;

    IGNORE_USE_IN_ESCAPING_LAMBDA Wasm::AbstractMachine machine;
    auto vm = JS::VM::create();
    auto root_execution_context = JS::create_simple_execution_context<JS::GlobalObject>(*vm);
    auto& realm = *root_execution_context->realm;
    IGNORE_USE_IN_ESCAPING_LAMBDA Wasm::ModuleInstance* reentry_instance = nullptr;

    Core::ArgsParser parser;
    parser.add_positional_argument(filename, "File name to parse", "file");
    parser.add_option(print, "Print the parsed module", "print", 'p');
    parser.add_option(print_compiled, "Print the compiled module", "print-compiled");
    parser.add_option(dump_native, "Disassemble Cranelift-compiled native code for each function", "dump-native");
    parser.add_option(specific_function_address, "Optional compiled function address to print", "print-function", 'f', "address");
    parser.add_option(attempt_instantiate, "Attempt to instantiate the module", "instantiate", 'i');
    parser.add_option(exported_function_to_execute, "Attempt to execute the named exported function from the module (implies -i)", "execute", 'e', "name");
    parser.add_option(export_all_imports, "Export noop functions corresponding to imports", "export-noop");
#if !defined(AK_OS_WINDOWS)
    parser.add_option(wasi, "Enable WASI", "wasi", 'w');
#endif
#if !defined(AK_OS_WINDOWS) && !defined(AK_OS_ANDROID)
    parser.add_option(tui, "Interactive TUI inspector (implies -i --export-noop)", "tui", 't');
#endif
    parser.add_option(Core::ArgsParser::Option {
        .argument_mode = Core::ArgsParser::OptionArgumentMode::Required,
        .help_string = "Export js `function(arg...) { source }` returning T as [module].[function]",
        .long_name = "export-js",
        .short_name = 0,
        .value_name = "module.function(arg:T...):T=source",
        .accept_value = [&](StringView str) {
            GenericLexer lexer(str);
            // [module] <.> [function] <(> {[name] <:> [type]} <)> (<:> [type])? <=> [text]
            auto module = lexer.consume_until('.');
            if (!lexer.consume_specific('.')) {
                warnln("Invalid JS export module in '{}'", str);
                return false;
            }
            auto fn_name = lexer.consume_until(is_any_of("(=:"sv));
            struct Arg {
                Wasm::ValueType type;
                StringView name;
            };
            Vector<Arg> formal_params;
            if (lexer.consume_specific('(')) {
                while (!lexer.consume_specific(')')) {
                    auto name = lexer.consume_until(is_any_of(",:)"sv));
                    if (name.is_empty()) {
                        warnln("Invalid JS export argument name in '{}'", str);
                        return false;
                    }
                    auto type_kind = Wasm::ValueType::I32;
                    if (lexer.consume_specific(':')) {
                        if (lexer.consume_specific("i32"sv)) {
                            type_kind = Wasm::ValueType::I32;
                        } else if (lexer.consume_specific("i64"sv)) {
                            type_kind = Wasm::ValueType::I64;
                        } else if (lexer.consume_specific("f32"sv)) {
                            type_kind = Wasm::ValueType::F32;
                        } else if (lexer.consume_specific("f64"sv)) {
                            type_kind = Wasm::ValueType::F64;
                        } else if (lexer.consume_specific("v128"sv)) {
                            type_kind = Wasm::ValueType::V128;
                        } else {
                            warnln("Invalid JS export argument type in '{}'", str);
                            return false;
                        }
                    }
                    formal_params.append(Arg { Wasm::ValueType(type_kind), name });
                    lexer.consume_specific(',');
                }
            }
            Vector<Wasm::ValueType::Kind> returns;
            if (lexer.consume_specific(':')) {
                if (lexer.consume_specific("i32"sv)) {
                    returns.append(Wasm::ValueType::I32);
                } else if (lexer.consume_specific("i64"sv)) {
                    returns.append(Wasm::ValueType::I64);
                } else if (lexer.consume_specific("f32"sv)) {
                    returns.append(Wasm::ValueType::F32);
                } else if (lexer.consume_specific("f64"sv)) {
                    returns.append(Wasm::ValueType::F64);
                } else if (lexer.consume_specific("v128"sv)) {
                    returns.append(Wasm::ValueType::V128);
                } else {
                    warnln("Invalid JS export return type in '{}'", str);
                    return false;
                }
            }

            if (!lexer.consume_specific('=') || lexer.is_eof()) {
                warnln("Invalid JS export source in '{}'", str);
                return false;
            }

            auto source_text = lexer.consume_all().trim_whitespace();
            Utf16StringBuilder builder;
            builder.append_ascii("(function ("sv);
            auto first = true;
            for (auto& arg : formal_params) {
                if (!first)
                    builder.append_ascii(", "sv);
                first = false;
                auto argument_name = Utf16String::from_utf8(arg.name);
                builder.append(argument_name.utf16_view());
            }
            builder.append_ascii(") { return ("sv);
            auto source_text_utf16 = Utf16String::from_utf8(source_text);
            builder.append(source_text_utf16.utf16_view());
            builder.append_ascii("); })"sv);
            auto js_function = builder.to_string();
            auto name = ByteString::formatted("{}.{}", module, fn_name);
            auto script = JS::Script::parse(js_function, realm, name);
            if (script.is_error()) {
                warnln("Failed to parse JS export source '{}':", js_function);
                return false;
            }

            auto js_script = script.release_value();
            auto maybe_function = vm->run(*js_script);
            if (maybe_function.is_error()) {
                warnln("Failed to run JS export source '{}'", js_function);
                return false;
            }
            auto function_val = maybe_function.release_value();
            if (!function_val.is_function()) {
                warnln("JS export source '{}' did not parse as a function", js_function);
                return false;
            }

            auto& function = function_val.as_function();

            Vector<Wasm::ValueType> results;
            Vector<Wasm::ValueType> params;
            for (auto& type : returns)
                results.append(Wasm::ValueType(type));
            for (auto& arg : formal_params)
                params.append(Wasm::ValueType(arg.type));

            Wasm::FunctionType function_type = { move(params), move(results) };
            auto host_function = Wasm::HostFunction {
                [&vm, &function, &machine, &realm, &reentry_instance, formal_params, returns, name](Wasm::Configuration&, Span<Wasm::Value> args) mutable -> Wasm::Result {
                    Vector<JS::Value> js_args;
                    js_args.ensure_capacity(args.size());
                    for (size_t i = 0; i < formal_params.size(); ++i) {
                        auto type = formal_params[i].type;
                        if (i >= args.size()) {
                            warnln("Not enough arguments provided to JS export function '{}'", name);
                            return Wasm::Trap { ByteString("Not enough arguments") };
                        }
                        auto& arg = args[i];
                        switch (type.kind()) {
                        case Wasm::ValueType::I32:
                            js_args.append(JS::Value(arg.to<u32>()));
                            break;
                        case Wasm::ValueType::I64:
                            js_args.append(JS::Value(arg.to<u64>()));
                            break;
                        case Wasm::ValueType::F32:
                            js_args.append(JS::Value(arg.to<f32>()));
                            break;
                        case Wasm::ValueType::F64:
                            js_args.append(JS::Value(arg.to<f64>()));
                            break;
                        case Wasm::ValueType::V128: {
                            auto value = arg.to<u128>();
                            ReadonlyBytes data { bit_cast<u8 const*>(&value), sizeof(u128) };
                            js_args.append(vm->heap().allocate<JS::BigInt>(Crypto::SignedBigInteger { Crypto::UnsignedBigInteger { data } }));
                            break;
                        }
                        default:
                            warnln("Unsupported argument type '{}' for JS export function '{}'", type.kind_name(), name);
                            return Wasm::Trap { ByteString("Unsupported argument type") };
                        }
                    }
                    auto reentry_this = JS::Object::create(realm, realm.intrinsics().object_prototype());
                    auto invoke = JS::NativeFunction::create(
                        realm, [&machine, &reentry_instance](JS::VM& vm) -> JS::ThrowCompletionOr<JS::Value> {
                            if (!reentry_instance)
                                return vm.throw_completion<JS::TypeError>("wasm reentry: instance not ready yet"_utf16);
                            auto export_name = TRY(vm.argument(0).to_utf16_string(vm)).to_byte_string();
                            Optional<Wasm::FunctionAddress> address;
                            for (auto& entry : reentry_instance->exports()) {
                                if (entry.name() == export_name) {
                                    if (auto* addr = entry.value().get_pointer<Wasm::FunctionAddress>())
                                        address = *addr;
                                }
                            }
                            if (!address.has_value())
                                return vm.throw_completion<JS::TypeError>(Utf16String::formatted("wasm reentry: no exported function '{}'"sv, export_name));
                            auto* callee = machine.store().get(*address);
                            if (!callee || !callee->has<Wasm::WasmFunction>())
                                return vm.throw_completion<JS::TypeError>("wasm reentry: target is not a wasm function"_utf16);
                            auto const& type = callee->get<Wasm::WasmFunction>().type();
                            Vector<Wasm::Value> wasm_args;
                            for (size_t i = 0; i < type.parameters().size(); ++i) {
                                auto value = vm.argument(i + 1);
                                switch (type.parameters()[i].kind()) {
                                case Wasm::ValueType::I32:
                                    wasm_args.append(Wasm::Value(TRY(value.to_u32(vm))));
                                    break;
                                case Wasm::ValueType::I64:
                                    wasm_args.append(Wasm::Value(TRY(value.to_bigint_uint64(vm))));
                                    break;
                                case Wasm::ValueType::F32:
                                    wasm_args.append(Wasm::Value(static_cast<f32>(TRY(value.to_double(vm)))));
                                    break;
                                case Wasm::ValueType::F64:
                                    wasm_args.append(Wasm::Value(TRY(value.to_double(vm))));
                                    break;
                                default:
                                    return vm.throw_completion<JS::TypeError>("wasm reentry: unsupported parameter type"_utf16);
                                }
                            }
                            auto result = machine.invoke(g_interpreter, *address, move(wasm_args));
                            if (result.is_trap())
                                return vm.throw_completion<JS::TypeError>(Utf16String::formatted("wasm reentry trapped: {}"sv, result.trap().format()));
                            if (result.values().is_empty() || type.results().is_empty())
                                return JS::js_undefined();
                            if (type.results().size() > 1)
                                return vm.throw_completion<JS::TypeError>("wasm reentry: multi-value results are not yet supported"_utf16);
                            auto const& returned = result.values().first();
                            switch (type.results()[0].kind()) {
                            case Wasm::ValueType::I32:
                                return JS::Value(returned.to<i32>());
                            case Wasm::ValueType::I64:
                                return JS::Value(static_cast<double>(returned.to<i64>()));
                            case Wasm::ValueType::F32:
                                return JS::Value(static_cast<double>(returned.to<f32>()));
                            case Wasm::ValueType::F64:
                                return JS::Value(returned.to<f64>());
                            default:
                                return JS::js_undefined();
                            }
                        },
                        1, "invoke"_utf16);
                    reentry_this->define_direct_property("invoke"_utf16, invoke, JS::default_attributes);

                    auto result = TRY(trap_for_js_exception(vm, JS::call(vm, function, reentry_this, js_args.span())));
                    if (returns.is_empty())
                        return Wasm::Result { Vector<Wasm::Value> {} };

                    if (returns.size() != 1)
                        return Wasm::Trap { ByteString("NYI") };

                    switch (returns[0]) {
                    case Wasm::ValueType::I32:
                        return Wasm::Result { Vector<Wasm::Value> { Wasm::Value { TRY(trap_for_js_exception(*vm, result.to_u32(vm))) } } };
                    case Wasm::ValueType::I64:
                        return Wasm::Result { Vector<Wasm::Value> { Wasm::Value { TRY(trap_for_js_exception(*vm, result.to_bigint_uint64(vm))) } } };
                    case Wasm::ValueType::F32:
                        return Wasm::Result { Vector<Wasm::Value> { Wasm::Value { static_cast<f32>(TRY(trap_for_js_exception(*vm, result.to_double(vm)))) } } };
                    case Wasm::ValueType::F64:
                        return Wasm::Result { Vector<Wasm::Value> { Wasm::Value { TRY(trap_for_js_exception(*vm, result.to_double(vm))) } } };
                    case Wasm::ValueType::V128: {
                        auto value = TRY(trap_for_js_exception(*vm, result.to_bigint(vm)));
                        u128 out {};
                        Bytes data { bit_cast<u8*>(&out), sizeof(u128) };
                        if (value->big_integer().unsigned_value().export_data(data).size() != data.size()) {
                            dbgln("JS export function '{}' returned a v128 value that is not 128 bits wide", name);
                            return Wasm::Trap { ByteString("Invalid v128 value") };
                        }
                        return Wasm::Result { Vector<Wasm::Value> { Wasm::Value { out } } };
                    }
                    default:
                        warnln("Unsupported return type for JS export function '{}'", name);
                        return Wasm::Trap { ByteString("Unsupported return type") };
                    }
                },
                function_type,
                name,
            };
            auto host_function_instance = machine.store().allocate(move(host_function));
            if (!host_function_instance.has_value()) {
                warnln("Failed to allocate host function instance for '{}'", name);
                return false;
            }
            js_exports.set({ .module = module, .name = fn_name, .type = function_type }, *host_function_instance);
            return true;
        },
    });
    parser.add_option(Core::ArgsParser::Option {
        .argument_mode = Core::ArgsParser::OptionArgumentMode::Required,
        .help_string = "Directory mappings to expose via WASI",
        .long_name = "wasi-map-dir",
        .short_name = 0,
        .value_name = "path[:path]",
        .accept_value = [&](StringView str) {
            if (!str.is_empty()) {
                wasi_preopened_mappings.append(str);
                return true;
            }
            return false;
        },
    });
    parser.add_option(Core::ArgsParser::Option {
        .argument_mode = Core::ArgsParser::OptionArgumentMode::Required,
        .help_string = "Extra modules to link with, use to resolve imports",
        .long_name = "link",
        .short_name = 'l',
        .value_name = "file",
        .accept_value = [&](StringView str) {
            if (!str.is_empty()) {
                modules_to_link_in.append(str);
                return true;
            }
            return false;
        },
    });
    parser.add_option(Core::ArgsParser::Option {
        .argument_mode = Core::ArgsParser::OptionArgumentMode::Required,
        .help_string = "Supply arguments to the function (default=0) (T.const:v or v(T.const:v, ...))",
        .long_name = "arg",
        .short_name = 0,
        .value_name = "value",
        .accept_value = [&](StringView str) -> bool {
            auto result = parse_value(str);
            if (result.is_error()) {
                warnln("Failed to parse value: {}", result.error());
                return false;
            }
            values_to_push.append(result.release_value());
            return true;
        },
    });
    parser.add_positional_argument(args_if_wasi, "Arguments to pass to the WASI module", "args", Core::ArgsParser::Required::No);
    parser.parse(arguments);

    if (!exported_function_to_execute.is_empty())
        attempt_instantiate = true;

#if !defined(AK_OS_WINDOWS) && !defined(AK_OS_ANDROID)
    if (tui) {
        attempt_instantiate = true;
        export_all_imports = true;
    }
#endif

    auto parse_result = parse(filename);
    if (parse_result.is_null())
        return 1;

    g_stdout = TRY(Core::File::standard_output());
    g_printer = TRY(try_make<Wasm::Printer>(*g_stdout));

    if (print && !attempt_instantiate) {
        Wasm::Printer printer(*g_stdout);
        printer.print(*parse_result);
    }

    if (attempt_instantiate || print_compiled || dump_native) {
#if !defined(AK_OS_WINDOWS)
        Optional<Wasm::Wasi::Implementation> wasi_impl;

        if (wasi) {
            wasi_impl.emplace(Wasm::Wasi::Implementation::Details {
                .provide_arguments = [&] {
                    Vector<String> strings;
                    for (auto& string : args_if_wasi)
                        strings.append(String::from_utf8(string).release_value_but_fixme_should_propagate_errors());
                    return strings; },
                .provide_environment = {},
                .provide_preopened_directories = [&] {
                    Vector<Wasm::Wasi::Implementation::MappedPath> paths;
                    for (auto& string : wasi_preopened_mappings) {
                        auto split_index = string.find(':');
                        if (split_index.has_value()) {
                            LexicalPath host_path { FileSystem::real_path(string.substring_view(0, *split_index)).release_value_but_fixme_should_propagate_errors() };
                            LexicalPath mapped_path { string.substring_view(*split_index + 1) };
                            paths.append({move(host_path), move(mapped_path)});
                        } else {
                            LexicalPath host_path { FileSystem::real_path(string).release_value_but_fixme_should_propagate_errors() };
                            LexicalPath mapped_path { string };
                            paths.append({move(host_path), move(mapped_path)});
                        }
                    }
                    return paths; },
            });
        }
#endif

        Core::EventLoop::initialize_for_current_thread();
        // First, resolve the linked modules
        Vector<NonnullRefPtr<Wasm::ModuleInstance>> linked_instances;
        Vector<NonnullRefPtr<Wasm::Module>> linked_modules;
        for (auto& name : modules_to_link_in) {
            auto parse_result = parse(name);
            if (parse_result.is_null()) {
                warnln("Failed to parse linked module '{}'", name);
                return 1;
            }
            linked_modules.append(parse_result.release_nonnull());
            Wasm::Linker linker { linked_modules.last() };
            for (auto& instance : linked_instances)
                linker.link(*instance);
            auto link_result = linker.finish();
            if (link_result.is_error()) {
                warnln("Linking imported module '{}' failed", name);
                print_link_error(link_result.error());
                return 1;
            }
            auto instantiation_result = machine.instantiate(linked_modules.last(), link_result.release_value());
            if (instantiation_result.is_error()) {
                warnln("Instantiation of imported module '{}' failed: {}", name, instantiation_result.error().error);
                return 1;
            }
            linked_instances.append(instantiation_result.release_value());
        }

        Wasm::Linker linker { *parse_result };
        for (auto& instance : linked_instances)
            linker.link(*instance);

#if !defined(AK_OS_WINDOWS)
        if (wasi) {
            HashMap<Wasm::Linker::Name, Wasm::ExternValue> wasi_exports;
            for (auto& entry : linker.unresolved_imports()) {
                if (entry.module != "wasi_snapshot_preview1"sv)
                    continue;
                auto function = wasi_impl->function_by_name(entry.name);
                if (function.is_error()) {
                    dbgln("wasi function {} not implemented :(", entry.name);
                    continue;
                }
                auto address = machine.store().allocate(function.release_value());
                wasi_exports.set(entry, *address);
            }

            linker.link(wasi_exports);
        }
#endif

        linker.link(js_exports);

        if (export_all_imports) {
            HashMap<Wasm::Linker::Name, Wasm::ExternValue> exports;

            auto allocate_function_stub = [&](Wasm::FunctionType const& func, ByteString const& name) {
                return *machine.store().allocate(Wasm::HostFunction(
                    [name, func](auto&, auto arguments) -> Wasm::Result {
                        StringBuilder argument_builder;
                        bool first = true;
                        size_t index = 0;
                        for (auto& argument : arguments) {
                            AllocatingMemoryStream stream;
                            auto value_type = func.parameters()[index];
                            Wasm::Printer { stream }.print(argument, value_type);
                            if (first)
                                first = false;
                            else
                                argument_builder.append(", "sv);
                            auto buffer = ByteBuffer::create_uninitialized(stream.used_buffer_size()).release_value_but_fixme_should_propagate_errors();
                            stream.read_until_filled(buffer).release_value_but_fixme_should_propagate_errors();
                            argument_builder.append(StringView(buffer).trim_whitespace());
                            ++index;
                        }
                        dbgln("[wasm runtime] Stub function {} was called with the following arguments: {}", name, argument_builder.to_byte_string());
                        Vector<Wasm::Value> result;
                        result.ensure_capacity(func.results().size());
                        for (auto expect_result : func.results())
                            result.append(Wasm::Value(expect_result));
                        return Wasm::Result { move(result) };
                    },
                    func,
                    name));
            };

            for (auto& entry : linker.unresolved_imports()) {
                Optional<Wasm::ExternValue> address;
                entry.type.visit(
                    [&](Wasm::TypeIndex const& type_index) {
                        auto& type = parse_result->type_section().types()[type_index.value()];
                        if (!type.is_function()) {
                            dbgln("[wasm runtime] Cannot stub import {}::{} of non-function {}", entry.module, entry.name, type.name());
                            return;
                        }
                        address = allocate_function_stub(type.function(), entry.name);
                    },
                    [&](Wasm::FunctionType const& func) {
                        address = allocate_function_stub(func, entry.name);
                    },
                    [&](Wasm::TableType const& table_type) {
                        address = *machine.store().allocate(table_type);
                    },
                    [&](Wasm::MemoryType const& memory_type) {
                        address = *machine.store().allocate(memory_type);
                    },
                    [&](Wasm::GlobalType const& global_type) {
                        address = *machine.store().allocate(global_type, Wasm::Value(global_type.type()));
                    },
                    [&](Wasm::TagType const& tag_type) {
                        auto& type = parse_result->type_section().types()[tag_type.type().value()];
                        if (!type.is_function()) {
                            dbgln("[wasm runtime] Cannot stub tag import {}::{}: type is not a function", entry.module, entry.name);
                            return;
                        }
                        // The module is not yet validated here, so its canonical types may not be known.
                        address = *machine.store().allocate(type.function(), nullptr, tag_type.flags());
                    });

                if (address.has_value())
                    exports.set(entry, address.release_value());
            }

            linker.link(exports);
        }

        auto link_result = linker.finish();
        if (link_result.is_error()) {
            warnln("Linking main module failed");
            print_link_error(link_result.error());
            return 1;
        }

        auto result = machine.instantiate(*parse_result, link_result.release_value());
        if (result.is_error()) {
            warnln("Module instantiation failed: {}", result.error().error);
            return 1;
        }
        auto module_instance = result.release_value();
        reentry_instance = module_instance.ptr();

        if (print_compiled) {
            Span<Wasm::FunctionAddress const> functions = module_instance->functions();
            Wasm::FunctionAddress spec = specific_function_address.value_or(0);

            if (specific_function_address.has_value())
                functions = { &spec, 1 };
            for (auto address : functions) {
                auto function = machine.store().get(address)->get_pointer<Wasm::WasmFunction>();
                if (!function)
                    continue;
                auto& expression = function->code().func().body();
                if (expression.compiled_instructions.dispatches.is_empty())
                    continue;

                ByteString export_name;
                for (auto& entry : function->module().exports()) {
                    if (entry.value() == address) {
                        export_name = ByteString::formatted(" '{}'", entry.name());
                        break;
                    }
                }

                TRY(g_stdout->write_until_depleted(ByteString::formatted("Function #{}{} (stack usage = {}):\n", address.value(), export_name, expression.stack_usage_hint())));

                Wasm::Printer printer { *g_stdout, 1 };
                for (size_t ip = 0; ip < expression.compiled_instructions.dispatches.size(); ++ip) {
                    auto& dispatch = expression.compiled_instructions.dispatches[ip];
                    auto& addresses = expression.compiled_instructions.src_dst_mappings[ip];
                    ByteString regs;
                    auto first = true;
                    ssize_t in_count = 0;
                    ssize_t out_count = 0;
#define M(name, _, ins, outs)              \
    case Wasm::Instructions::name.value(): \
        in_count = ins;                    \
        out_count = outs;                  \
        break;
                    switch (dispatch.instruction->opcode().value()) {
                        ENUMERATE_WASM_OPCODES(M)
                    }
#undef M
                    constexpr auto reg_name = [](Wasm::Dispatch::RegisterOrStack reg) -> ByteString {
                        if (reg == Wasm::Dispatch::RegisterOrStack::Stack)
                            return "stack"sv;
                        if (reg >= Wasm::Dispatch::RegisterOrStack::CallRecord)
                            return ByteString::formatted("cr{}", to_underlying(reg) - to_underlying(Wasm::Dispatch::RegisterOrStack::CallRecord));
                        return ByteString::formatted("reg{}", to_underlying(reg));
                    };
                    if (in_count > -1) {
                        for (ssize_t index = 0; index < in_count; ++index) {
                            if (first)
                                regs = ByteString::formatted("{} ({}", regs, reg_name(addresses.sources[index]));
                            else
                                regs = ByteString::formatted("{}, {}", regs, reg_name(addresses.sources[index]));
                            first = false;
                        }
                        if (out_count > 0) {
                            if (first)
                                regs = ByteString::formatted(" () -> {}", reg_name(addresses.destination));
                            else
                                regs = ByteString::formatted("{}) -> {}", regs, reg_name(addresses.destination));
                        } else if (out_count == 0) {
                            if (first)
                                regs = ByteString::formatted(" () -x");
                            else
                                regs = ByteString::formatted("{}) -x", regs);
                        } else {
                            if (first)
                                regs = ByteString::formatted(" () -?");
                            else
                                regs = ByteString::formatted("{}) -?", regs);
                        }
                    } else if (dispatch.instruction->opcode() == Wasm::Instructions::call || dispatch.instruction->opcode() == Wasm::Instructions::call_indirect) {
                        if (addresses.destination != Wasm::Dispatch::RegisterOrStack::Stack)
                            regs = ByteString::formatted("(?) -> {}", reg_name(addresses.destination));
                    }

                    if (regs.is_empty())
                        regs = ByteString::formatted(" {{{:-<34}}}", regs);
                    else
                        regs = ByteString::formatted(" {{{: <33} }}", regs);

                    TRY(g_stdout->write_until_depleted(ByteString::formatted("  [{:>03}]", ip)));
                    TRY(g_stdout->write_until_depleted(regs.bytes()));
                    printer.print(*dispatch.instruction);
                }

                TRY(g_stdout->write_until_depleted("\n"sv.bytes()));
            }
        }

        if (getenv("WASM_CRANELIFT_STATS")) {
            size_t total = 0, eligible = 0, compiled_count = 0;
            size_t total_insns = 0, compiled_insns = 0, elig_rej_insns = 0, cl_rej_insns = 0;
            for (auto address : module_instance->functions()) {
                auto* function = machine.store().get(address)->get_pointer<Wasm::WasmFunction>();
                if (!function)
                    continue;
                auto& ci = function->code().func().body().compiled_instructions;
                ++total;
                auto insns = function->code().func().body().instructions().size();
                total_insns += insns;
                if (ci.cranelift_eligible)
                    ++eligible;
                if (ci.cranelift_compiled) {
                    ++compiled_count;
                    compiled_insns += insns;
                } else if (!ci.cranelift_eligible) {
                    elig_rej_insns += insns;
                } else {
                    cl_rej_insns += insns;
                }
            }
            warnln("cranelift-stats: fns total={} eligible={} compiled={} | insns total={} compiled={} inelig={} rejected={}",
                total, eligible, compiled_count, total_insns, compiled_insns, elig_rej_insns, cl_rej_insns);
        }

        if (dump_native) {
            Span<Wasm::FunctionAddress const> functions = module_instance->functions();
            Wasm::FunctionAddress spec = specific_function_address.value_or(0);

            if (specific_function_address.has_value())
                functions = { &spec, 1 };
            for (auto address : functions) {
                auto* function = machine.store().get(address)->get_pointer<Wasm::WasmFunction>();
                if (!function)
                    continue;
                auto& ci = function->code().func().body().compiled_instructions;
                if (!ci.cranelift_compiled || ci.cranelift_code_size == 0)
                    continue;

                ByteString export_name;
                for (auto& entry : function->module().exports()) {
                    if (entry.value() == address) {
                        export_name = ByteString::formatted(" '{}'", entry.name());
                        break;
                    }
                }

                auto const* code_ptr = bit_cast<u8 const*>(Wasm::cranelift_entry_acquire(ci));
                auto code_size = ci.cranelift_code_size;

#if defined(AK_OS_WINDOWS)
                char tmp_path[MAX_PATH];
                {
                    char tmp_dir[MAX_PATH];
                    GetTempPathA(MAX_PATH, tmp_dir);
                    GetTempFileNameA(tmp_dir, "wn", 0, tmp_path);
                }
                {
                    auto tmp_file = Core::File::open(StringView { tmp_path, strlen(tmp_path) }, Core::File::OpenMode::Write);
                    if (tmp_file.is_error()) {
                        warnln("Failed to create temp file for function #{}", address.value());
                        continue;
                    }
                    (void)tmp_file.value()->write_until_depleted({ code_ptr, code_size });
                }
#else
                char tmp_path[] = "/tmp/wasm-native-XXXXXX";
                int fd = mkstemp(tmp_path);
                if (fd < 0) {
                    warnln("Failed to create temp file for function #{}", address.value());
                    continue;
                }

                {
                    auto tmp_file = MUST(Core::File::adopt_fd(fd, Core::File::OpenMode::Write));

#    if ARCH(AARCH64) && defined(AK_OS_MACOS)
                    // Write a minimal Mach-O object file so objdump can disassemble it.
                    struct [[gnu::packed]] {
                        u32 magic = 0xFEEDFACF;
                        u32 cputype = 0x0100000C; // CPU_TYPE_ARM64
                        u32 cpusubtype = 0;
                        u32 filetype = 1; // MH_OBJECT
                        u32 ncmds = 1;
                        u32 sizeofcmds = 72 + 80; // segment + section
                        u32 flags = 0;
                        u32 reserved = 0;
                    } mach_header;

                    struct [[gnu::packed]] {
                        u32 cmd = 0x19; // LC_SEGMENT_64
                        u32 cmdsize = 72 + 80;
                        char segname[16] = {};
                        u64 vmaddr = 0;
                        u64 vmsize;
                        u64 fileoff;
                        u64 filesize;
                        u32 maxprot = 7;
                        u32 initprot = 7;
                        u32 nsects = 1;
                        u32 flags = 0;
                    } segment;
                    segment.vmsize = code_size;
                    segment.fileoff = sizeof(mach_header) + sizeof(segment) + 80;
                    segment.filesize = code_size;

                    struct [[gnu::packed]] {
                        char sectname[16] = "__text";
                        char segname[16] = "__TEXT";
                        u64 addr = 0;
                        u64 size;
                        u32 offset;
                        u32 align = 2;
                        u32 reloff = 0;
                        u32 nreloc = 0;
                        u32 flags = 0x80000400; // S_REGULAR | S_ATTR_PURE_INSTRUCTIONS
                        u32 reserved1 = 0;
                        u32 reserved2 = 0;
                        u32 reserved3 = 0;
                    } section;
                    static_assert(sizeof(section) == 80);
                    section.size = code_size;
                    section.offset = static_cast<u32>(segment.fileoff);

                    (void)tmp_file->write_until_depleted({ &mach_header, sizeof(mach_header) });
                    (void)tmp_file->write_until_depleted({ &segment, sizeof(segment) });
                    (void)tmp_file->write_until_depleted({ &section, sizeof(section) });
#    endif
                    (void)tmp_file->write_until_depleted({ code_ptr, code_size });
                }
#endif

                outln("Function #{}{} ({} bytes):", address.value(), export_name, code_size);
                fflush(stdout);

#if defined(AK_OS_WINDOWS)
                auto result = Core::Process::spawn({
                    .name = "ndisasm"sv,
                    .executable = "ndisasm"sv,
                    .search_for_executable_in_path = true,
                    .arguments = { "-b"sv, (sizeof(void*) == sizeof(u64) ? "64"sv : "32"sv), tmp_path },
                });
#elif defined(AK_OS_MACOS)
                auto cmd = ByteString::formatted("/usr/bin/objdump -d {} | tail -n +7", tmp_path);
                auto result = Core::Process::spawn({
                    .name = "sh"sv,
                    .executable = "/bin/sh"sv,
                    .arguments = { "-c"sv, cmd },
                });
#else
#    if ARCH(X86_64)
                auto cmd = ByteString::formatted("/usr/bin/objdump -D -b binary -m i386:x86-64 {} | tail -n +8", tmp_path);
#    elif ARCH(AARCH64)
                auto cmd = ByteString::formatted("/usr/bin/objdump -D -b binary -m aarch64 {} | tail -n +8", tmp_path);
#    else
                auto cmd = ByteString::formatted("/usr/bin/objdump -D -b binary {} | tail -n +8", tmp_path);
#    endif
                auto result = Core::Process::spawn({
                    .name = "sh"sv,
                    .executable = "/bin/sh"sv,
                    .arguments = { "-c"sv, cmd },
                });
#endif
                if (!result.is_error())
                    (void)result.release_value().wait_for_termination();
                else
                    warnln("Failed to run disassembler: {}", result.error());

#if defined(AK_OS_WINDOWS)
                DeleteFileA(tmp_path);
#else
                unlink(tmp_path);
#endif
                outln();
            }
        }

        auto print_func = [&](auto const& address) {
            Wasm::FunctionInstance* fn = machine.store().get(address);
            g_stdout->write_until_depleted(ByteString::formatted("- Function with address {}, ptr = {}\n", address.value(), fn)).release_value_but_fixme_should_propagate_errors();
            if (fn) {
                g_stdout->write_until_depleted(ByteString::formatted("    wasm function? {}\n", fn->has<Wasm::WasmFunction>())).release_value_but_fixme_should_propagate_errors();
                fn->visit(
                    [&](Wasm::WasmFunction const& func) {
                        Wasm::Printer printer { *g_stdout, 3 };
                        g_stdout->write_until_depleted("    type:\n"sv).release_value_but_fixme_should_propagate_errors();
                        printer.print(func.type());
                        g_stdout->write_until_depleted("    code:\n"sv).release_value_but_fixme_should_propagate_errors();
                        printer.print(func.code());
                    },
                    [](Wasm::HostFunction const&) {});
            }
        };
        if (print) {
            // Now, let's dump the functions!
            for (auto& address : module_instance->functions()) {
                print_func(address);
            }
        }

        if (!exported_function_to_execute.is_empty()) {
            Optional<Wasm::FunctionAddress> run_address;
            Vector<Wasm::Value> values;
            for (auto& entry : module_instance->exports()) {
                if (entry.name() == exported_function_to_execute) {
                    if (auto addr = entry.value().get_pointer<Wasm::FunctionAddress>())
                        run_address = *addr;
                }
            }
            if (!run_address.has_value()) {
                warnln("No such exported function, sorry :(");
                return 1;
            }

            auto instance = machine.store().get(*run_address);
            VERIFY(instance);

            if (instance->has<Wasm::HostFunction>()) {
                warnln("Exported function is a host function, cannot run that yet");
                return 1;
            }

            for (auto& param : instance->get<Wasm::WasmFunction>().type().parameters()) {
                if (values_to_push.is_empty()) {
                    values.append(Wasm::Value(param));
                } else if (param == values_to_push.last().type) {
                    values.append(values_to_push.take_last().value);
                } else {
                    warnln("Type mismatch in argument: expected {}, but got {}", param.kind_name(), values_to_push.last().type.kind_name());
                    return 1;
                }
            }

            if (print) {
                outln("Executing ");
                print_func(*run_address);
                outln();
            }

            auto result = machine.invoke(g_interpreter, run_address.value(), move(values));
            if (result.is_trap()) {
                auto trap_reason = result.trap().format();
                if (trap_reason.starts_with("exit:"sv))
                    return -trap_reason.substring_view(5).to_number<i32>().value_or(-1);
                warnln("Execution trapped: {}", trap_reason);
            } else {
                if (!result.values().is_empty())
                    warnln("Returned:");
                auto result_type = instance->get<Wasm::WasmFunction>().type().results();
                size_t index = 0;
                for (auto& value : result.values()) {
                    g_stdout->write_until_depleted("  -> "sv.bytes()).release_value_but_fixme_should_propagate_errors();
                    g_printer->print(value, result_type[index]);
                    ++index;
                }
            }
        }

#if !defined(AK_OS_WINDOWS) && !defined(AK_OS_ANDROID)
        if (tui)
            tui_run(machine, *parse_result, *module_instance, filename);
#endif
    }

    return 0;
}
