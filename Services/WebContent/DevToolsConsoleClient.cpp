/*
 * Copyright (c) 2025, Tim Flynn <trflynn89@ladybird.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/GenericShorthands.h>
#include <AK/JsonObject.h>
#include <AK/JsonValue.h>
#include <AK/MemoryStream.h>
#include <LibGC/Heap.h>
#include <LibJS/Print.h>
#include <LibJS/Runtime/BigInt.h>
#include <LibJS/Runtime/ErrorData.h>
#include <LibJS/Runtime/Realm.h>
#include <LibWeb/HTML/Scripting/Environments.h>
#include <LibWeb/HTML/Scripting/TemporaryExecutionContext.h>
#include <LibWeb/HTML/Window.h>
#include <LibWeb/WebDriver/BiDi/RemoteValue.h>
#include <WebContent/ConsoleGlobalEnvironmentExtensions.h>
#include <WebContent/DevToolsConsoleClient.h>
#include <WebContent/PageClient.h>

namespace WebContent {

GC_DEFINE_ALLOCATOR(DevToolsConsoleClient);

GC::Ref<DevToolsConsoleClient> DevToolsConsoleClient::create(JS::Realm& realm, JS::Console& console, PageClient& client)
{
    auto& window = Web::HTML::relevant_window(realm.global_object());
    auto console_global_environment_extensions = realm.create<ConsoleGlobalEnvironmentExtensions>(realm, window);

    return GC::Heap::the().allocate<DevToolsConsoleClient>(console, client, console_global_environment_extensions);
}

DevToolsConsoleClient::DevToolsConsoleClient(JS::Console& console, PageClient& client, ConsoleGlobalEnvironmentExtensions& console_global_environment_extensions)
    : WebContentConsoleClient(console, client, console_global_environment_extensions)
{
}

DevToolsConsoleClient::~DevToolsConsoleClient() = default;

// https://firefox-source-docs.mozilla.org/devtools/backend/protocol.html#grips
JsonValue DevToolsConsoleClient::serialize_value(JS::Realm& realm, JS::Value value)
{
    auto& vm = realm.vm();

    auto serialize_type = [](StringView type) {
        JsonObject serialized;
        serialized.set("type"sv, type);
        return serialized;
    };

    if (value.is_undefined())
        return serialize_type("undefined"sv);

    if (value.is_null())
        return serialize_type("null"sv);

    if (value.is_boolean())
        return value.as_bool();

    if (value.is_string())
        return value.as_string().utf16_string_view().to_utf8_but_should_be_ported_to_utf16();

    if (value.is_number()) {
        if (value.is_nan())
            return serialize_type("NaN"sv);
        if (value.is_positive_infinity())
            return serialize_type("Infinity"sv);
        if (value.is_negative_infinity())
            return serialize_type("-Infinity"sv);
        if (value.is_negative_zero())
            return serialize_type("-0"sv);
        return value.as_double();
    }

    if (value.is_bigint()) {
        auto serialized = serialize_type("BigInt"sv);
        serialized.set("text"sv, MUST(value.as_bigint().big_integer().to_base(10)));
        return serialized;
    }

    if (value.is_symbol())
        return value.as_symbol().descriptive_string().to_utf8();

    // FIXME: Handle serialization of object grips. For now, we stringify the object.
    if (value.is_object()) {
        Web::HTML::TemporaryExecutionContext execution_context { realm };
        AllocatingMemoryStream stream;

        JS::PrintContext context { .vm = vm, .stream = &stream, .strip_ansi = true };
        MUST(JS::print(value, context));

        return MUST(String::from_stream(stream, stream.used_buffer_size()));
    }

    return {};
}

void DevToolsConsoleClient::handle_result(JS::Value result)
{
    auto& settings = Web::HTML::relevant_settings_object(*m_console_global_environment_extensions);
    m_client->did_execute_js_console_input(serialize_value(settings.realm(), result));
}

void DevToolsConsoleClient::report_exception(Utf16View name, Utf16View message, JS::ErrorData const& error_data, bool in_promise)
{
    if (m_client->webdriver_bidi_session_active())
        emit_webdriver_javascript_log_entry(name, message, error_data);

    Vector<WebView::StackFrame> trace;
    trace.ensure_capacity(error_data.traceback().size());

    for (auto const& frame : error_data.traceback()) {
        auto const& source_range = frame.source_range();
        WebView::StackFrame stack_frame;

        if (!frame.function_name.is_empty())
            stack_frame.function = frame.function_name.to_utf8();

        if (!source_range.filename().is_empty() || source_range.start.line != 0 || source_range.start.column != 0) {
            stack_frame.file = source_range.filename().to_utf8();
            stack_frame.line = source_range.start.line;
            stack_frame.column = source_range.start.column;
        }

        if (stack_frame.function.has_value() || stack_frame.file.has_value())
            trace.unchecked_append(move(stack_frame));
    }

    send_console_output({
        .timestamp = UnixDateTime::now(),
        .output = WebView::ConsoleError {
            .name = MUST(name.to_utf8()),
            .message = MUST(message.to_utf8()),
            .trace = move(trace),
            .inside_promise = in_promise,
        },
    });
}

void DevToolsConsoleClient::send_console_output(WebView::ConsoleOutput console_output)
{
    m_client->did_output_js_console_message(move(console_output));
}

// 2.3. Printer(logLevel, args[, options]), https://console.spec.whatwg.org/#printer
JS::ThrowCompletionOr<JS::Value> DevToolsConsoleClient::printer(JS::Console::LogLevel log_level, PrinterArguments arguments)
{
    if (log_level == JS::Console::LogLevel::Trace) {
        auto const& trace = arguments.get<JS::Console::Trace>();

        m_console->output_debug_message(log_level, trace.label);

        if (m_client->webdriver_bidi_session_active())
            emit_webdriver_console_log_entry(log_level, trace.arguments, trace.label.to_utf8());

        Vector<WebView::StackFrame> stack_frames;
        stack_frames.ensure_capacity(trace.stack.size());

        for (auto const& frame : trace.stack) {
            Optional<String> source_file;
            if (frame.source_file.has_value())
                source_file = frame.source_file->to_utf8();

            stack_frames.unchecked_append(WebView::StackFrame {
                .function = frame.function_name.to_utf8(),
                .file = move(source_file),
                .line = frame.line,
                .column = frame.column,
            });
        }

        send_console_output({
            .timestamp = UnixDateTime::now(),
            .output = WebView::ConsoleTrace {
                .label = trace.label.to_utf8(),
                .stack = move(stack_frames),
            },
        });

        return JS::js_undefined();
    }

    if (first_is_one_of(log_level, JS::Console::LogLevel::Group, JS::Console::LogLevel::GroupCollapsed)) {
        auto const& group = arguments.get<JS::Console::Group>();
        if (m_client->webdriver_bidi_session_active())
            emit_webdriver_console_log_entry(log_level, group.arguments, group.label.to_utf8());

        // FIXME: Report groups to DevTools.
        return JS::js_undefined();
    }

    // FIXME: Implement this.
    if (log_level == JS::Console::LogLevel::Table)
        return JS::js_undefined();

    auto const& argument_values = arguments.has<JS::Console::Log>() ? arguments.get<JS::Console::Log>().formatted_arguments : arguments.get<GC::RootVector<JS::Value>>();

    auto output = TRY(generically_format_values(argument_values));
    m_console->output_debug_message(log_level, output);

    // The log entry reports the data the function was called with, described by the formatted data.
    if (m_client->webdriver_bidi_session_active()) {
        auto const& original_arguments = arguments.has<JS::Console::Log>() ? arguments.get<JS::Console::Log>().arguments : argument_values;
        emit_webdriver_console_log_entry(log_level, original_arguments, webdriver_console_log_text(argument_values));
    }

    Vector<JsonValue> serialized_arguments;
    serialized_arguments.ensure_capacity(argument_values.size());

    for (auto value : argument_values)
        serialized_arguments.unchecked_append(serialize_value(m_console->realm(), value));

    send_console_output({
        .timestamp = UnixDateTime::now(),
        .output = WebView::ConsoleLog {
            .level = log_level,
            .arguments = move(serialized_arguments),
            .type = WebView::ConsoleLogType::ConsoleAPI,
            .location = {},
            .stacktrace = {},
        },
    });

    return JS::js_undefined();
}

// https://console.spec.whatwg.org/#printer
static StringView console_method_name(JS::Console::LogLevel log_level)
{
    switch (log_level) {
    case JS::Console::LogLevel::Assert:
        return "assert"sv;
    case JS::Console::LogLevel::Count:
        return "count"sv;
    case JS::Console::LogLevel::CountReset:
        return "countReset"sv;
    case JS::Console::LogLevel::Debug:
        return "debug"sv;
    case JS::Console::LogLevel::Dir:
        return "dir"sv;
    case JS::Console::LogLevel::DirXML:
        return "dirxml"sv;
    case JS::Console::LogLevel::Error:
        return "error"sv;
    case JS::Console::LogLevel::Group:
        return "group"sv;
    case JS::Console::LogLevel::GroupCollapsed:
        return "groupCollapsed"sv;
    case JS::Console::LogLevel::Info:
        return "info"sv;
    case JS::Console::LogLevel::Log:
        return "log"sv;
    case JS::Console::LogLevel::Table:
        return "table"sv;
    case JS::Console::LogLevel::Trace:
        return "trace"sv;
    case JS::Console::LogLevel::Warn:
        return "warn"sv;
    default:
        return "log"sv;
    }
}

// https://w3c.github.io/webdriver-bidi/#event-log-entryAdded
// 5. For each arg in formatted args:
//    1. If arg is not the first entry in args, append a U+0020 SPACE to text.
//    2. If arg is a primitive ECMAScript value, append ToString(arg) to text. Otherwise append an
//       implementation-defined string to text.
String DevToolsConsoleClient::webdriver_console_log_text(GC::RootVector<JS::Value> const& formatted_arguments)
{
    StringBuilder text;
    for (auto argument : formatted_arguments) {
        if (!text.is_empty())
            text.append(' ');
        // NB: Objects are described without running script, which is the implementation-defined string here.
        text.append(argument.to_utf16_string_without_side_effects());
    }
    return text.to_string_without_validation();
}

// https://w3c.github.io/webdriver-bidi/#event-log-entryAdded
// Define the following console steps with method, args, and options:
void DevToolsConsoleClient::emit_webdriver_console_log_entry(JS::Console::LogLevel log_level, GC::RootVector<JS::Value> const& arguments, Optional<String> text)
{
    auto& realm = m_console->realm();
    auto method = console_method_name(log_level);

    // 1. If method is "error" or "assert", let level be "error". If method is "debug" or "trace" let level be "debug".
    //    If method is "warn", let level be "warn". Otherwise let level be "info".
    auto level = "info"sv;
    if (method.is_one_of("error"sv, "assert"sv))
        level = "error"sv;
    else if (method.is_one_of("debug"sv, "trace"sv))
        level = "debug"sv;
    else if (method == "warn"sv)
        level = "warn"sv;

    // 2. Let timestamp be a time value representing the current date and time in UTC.
    auto timestamp = UnixDateTime::now().milliseconds_since_epoch();

    // 3. Let text be an empty string.
    // 4. If Type(args[0]) is String, and args[0] contains a formatting specifier, let formatted args be
    //    Formatter(args). Otherwise let formatted args be args.
    // 5. For each arg in formatted args:
    //    1. If arg is not the first entry in args, append a U+0020 SPACE to text.
    //    2. If arg is a primitive ECMAScript value, append ToString(arg) to text. Otherwise append an
    //       implementation-defined string to text.
    // NB: A trace or group already carries its formatted label.
    if (!text.has_value())
        text = webdriver_console_log_text(arguments);

    // 6. Let realm be the realm id of the current Realm Record.
    // 7. Let serialized args be a new list.
    JsonArray serialized_args;

    // 8. Let serialization options be a map matching the script.SerializationOptions production with the fields set
    //    to their default values.
    Web::WebDriver::BiDi::SerializationOptions serialization_options;

    // 9. For each arg of args:
    for (auto argument : arguments) {
        // 1. Let serialized arg be the result of serialize as a remote value with arg as value, serialization
        //    options, none as ownership type, a new map as serialization internal map, realm and session.
        Web::WebDriver::BiDi::SerializationInternalMap serialization_internal_map;
        auto serialized_arg = Web::WebDriver::BiDi::serialize_as_a_remote_value(realm, argument, serialization_options, Web::WebDriver::BiDi::ResultOwnership::None, serialization_internal_map);

        // 2. Add serialized arg to serialized args.
        serialized_args.must_append(move(serialized_arg));
    }

    // 10. Let source be the result of get the source given current Realm Record.
    auto source = Web::WebDriver::BiDi::get_the_source(realm);

    // 11. Let stack be the current stack trace.
    auto stack = Web::WebDriver::BiDi::current_stack_trace(realm.vm());

    // 12. Let entry be a map matching the log.ConsoleLogEntry production, with the the level field set to level, the
    //     text field set to text, the timestamp field set to timestamp, the stackTrace field set to stack, the method
    //     field set to method, the source field set to source, and the args field set to serialized args.
    JsonObject entry;
    entry.set("type"sv, "console"sv);
    entry.set("level"sv, level);
    entry.set("text"sv, text.release_value());
    entry.set("timestamp"sv, timestamp);
    entry.set("stackTrace"sv, move(stack));
    entry.set("method"sv, method);
    entry.set("source"sv, move(source));
    entry.set("args"sv, move(serialized_args));

    // 13. Let body be a map matching the log.EntryAdded production, with the params field set to entry.
    // 14. Let settings be the current settings object
    // 15. Let related navigables be the result of get related navigables given settings.
    // 16. If event is enabled with session, "log.entryAdded" and related navigables, emit an event with session and
    //     body. Otherwise, buffer a log event with session, related browsing contexts, and body.
    m_client->webdriver_bidi_event("log.entryAdded"_string, move(entry));
}

// https://w3c.github.io/webdriver-bidi/#event-log-entryAdded
// Define the following error reporting steps with arguments script, line number, column number, message and handled:
void DevToolsConsoleClient::emit_webdriver_javascript_log_entry(Utf16View name, Utf16View message, JS::ErrorData const& error_data)
{
    // 1. If handled is true return.
    // NB: Only unhandled exceptions are reported to the console.

    auto& realm = m_console->realm();

    // 2. Let settings be script's settings object.
    // 3. Let timestamp be a time value representing the current date and time in UTC.
    auto timestamp = UnixDateTime::now().milliseconds_since_epoch();

    // 4. Let stack be the stack trace for an exception with the exception corresponding to the error being reported.
    auto stack = Web::WebDriver::BiDi::stack_trace_for_an_exception(error_data);

    // 5. Let source be the result of get the source given current Realm Record.
    auto source = Web::WebDriver::BiDi::get_the_source(realm);

    // 6. Let entry be a map matching the log.JavascriptLogEntry production, with level set to "error", text set to
    //    message, source set to source, timestamp set to timestamp, and the stackTrace field set to stack.
    JsonObject entry;
    entry.set("type"sv, "javascript"sv);
    entry.set("level"sv, "error"sv);
    entry.set("text"sv, MUST(String::formatted("{}: {}", name, message)));
    entry.set("source"sv, move(source));
    entry.set("timestamp"sv, timestamp);
    entry.set("stackTrace"sv, move(stack));

    // 7. Let body be a map matching the log.EntryAdded production, with the params field set to entry.
    // 8. Let related navigables be the result of get related navigables given settings.
    // 9. For each session in active BiDi sessions:
    //    1. If event is enabled with session, "log.entryAdded" and related navigables, emit an event with session and
    //       body. Otherwise, buffer a log event with session, related browsing contexts, and body.
    m_client->webdriver_bidi_event("log.entryAdded"_string, move(entry));
}

}
