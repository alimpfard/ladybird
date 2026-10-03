/*
 * Copyright (c) 2026, Ali Mohammad Pur <mpfard@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Array.h>
#include <AK/JsonArray.h>
#include <WebDriver/BiDi/Commands.h>
#include <WebDriver/BiDi/Modules.h>

namespace WebDriver::BiDi {

static constexpr auto s_commands = Array {
    Command { "session.status"sv, session_status, true },
    Command { "session.new"sv, session_new, true },
    Command { "session.end"sv, session_end },
    Command { "session.subscribe"sv, session_subscribe },
    Command { "session.unsubscribe"sv, session_unsubscribe },
    Command { "browsingContext.close"sv, browsing_context_close },
    Command { "browsingContext.create"sv, browsing_context_create },
    Command { "browsingContext.getTree"sv, browsing_context_get_tree },
    Command { "browsingContext.handleUserPrompt"sv, browsing_context_handle_user_prompt },
    Command { "browsingContext.navigate"sv, browsing_context_navigate },
    Command { "permissions.setPermission"sv, permissions_set_permission },
    Command { "script.callFunction"sv, script_call_function },
    Command { "script.evaluate"sv, script_evaluate },
};

struct EventModule {
    StringView module_name;
    ReadonlySpan<StringView> event_names;
};

// https://w3c.github.io/webdriver-bidi/#module-browsingContext-definition
static constexpr auto s_browsing_context_events = Array {
    "browsingContext.contextCreated"sv,
    "browsingContext.contextDestroyed"sv,
    "browsingContext.domContentLoaded"sv,
    "browsingContext.downloadEnd"sv,
    "browsingContext.downloadWillBegin"sv,
    "browsingContext.fragmentNavigated"sv,
    "browsingContext.historyUpdated"sv,
    "browsingContext.load"sv,
    "browsingContext.navigationAborted"sv,
    "browsingContext.navigationCommitted"sv,
    "browsingContext.navigationFailed"sv,
    "browsingContext.navigationStarted"sv,
    "browsingContext.userPromptClosed"sv,
    "browsingContext.userPromptOpened"sv,
};

// https://w3c.github.io/webdriver-bidi/#module-log-definition
static constexpr auto s_log_events = Array {
    "log.entryAdded"sv,
};

static constexpr auto s_event_modules = Array {
    EventModule { "browsingContext"sv, s_browsing_context_events },
    EventModule { "log"sv, s_log_events },
};

static Optional<Command const&> find_command(StringView name)
{
    for (auto const& command : s_commands) {
        if (command.name == name)
            return command;
    }
    return {};
}

bool is_command_name(StringView name)
{
    return find_command(name).has_value();
}

Optional<MatchedCommand> match_command(JsonValue const& parsed)
{
    // Command = {
    //   id: js-uint,
    //   CommandData,
    //   Extensible,
    // }
    if (!parsed.is_object())
        return {};
    auto const& object = parsed.as_object();

    auto id = object.get("id"sv);
    if (!id.has_value() || !id->is_integer<u64>())
        return {};
    if (id->get_integer<u64>().value() > 9007199254740991ull)
        return {};

    // Each CommandData group has a `method` string literal and a `params` map.
    auto method = object.get_string("method"sv);
    if (!method.has_value())
        return {};

    auto command = find_command(*method);
    if (!command.has_value())
        return {};

    auto parameters = object.get_object("params"sv);
    if (!parameters.has_value())
        return {};

    return MatchedCommand { *id, *command, *parameters };
}

// https://w3c.github.io/webdriver-bidi/#obtain-a-set-of-event-names
ErrorOr<Vector<String>, Web::WebDriver::Error> obtain_a_set_of_event_names(StringView name)
{
    // 1. Let events be an empty set.
    Vector<String> events;

    // 2. If name contains a U+002E (period):
    if (name.contains('.')) {
        // 1. If name is the event name for an event, append name to events and return success with data events.
        for (auto const& module : s_event_modules) {
            for (auto event_name : module.event_names) {
                if (event_name == name) {
                    events.append(MUST(String::from_utf8(name)));
                    return events;
                }
            }
        }

        // 2. Return an error with error code invalid argument
        return Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, MUST(String::formatted("Unknown event: {}", name)));
    }

    // 3. Otherwise name is interpreted as representing all the events in a module. If name is not a module name return
    //    an error with error code invalid argument.
    for (auto const& module : s_event_modules) {
        if (module.module_name != name)
            continue;

        // 4. Append the event name for each event in the module with name name to events.
        for (auto event_name : module.event_names)
            events.append(MUST(String::from_utf8(event_name)));

        // 5. Return success with data events.
        return events;
    }

    return Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, MUST(String::formatted("Unknown module: {}", name)));
}

static Web::WebDriver::Error invalid_parameter(StringView key, StringView expected)
{
    return Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, MUST(String::formatted("Parameter '{}' must be {}", key, expected)));
}

ErrorOr<String, Web::WebDriver::Error> get_required_string(JsonObject const& parameters, StringView key)
{
    auto value = parameters.get_string(key);
    if (!value.has_value())
        return invalid_parameter(key, "a string"sv);
    return *value;
}

ErrorOr<Optional<String>, Web::WebDriver::Error> get_optional_string(JsonObject const& parameters, StringView key)
{
    auto value = parameters.get(key);
    if (!value.has_value())
        return Optional<String> {};
    if (!value->is_string())
        return invalid_parameter(key, "a string"sv);
    return value->as_string();
}

ErrorOr<bool, Web::WebDriver::Error> get_required_bool(JsonObject const& parameters, StringView key)
{
    auto value = parameters.get_bool(key);
    if (!value.has_value())
        return invalid_parameter(key, "a boolean"sv);
    return *value;
}

ErrorOr<Optional<bool>, Web::WebDriver::Error> get_optional_bool(JsonObject const& parameters, StringView key)
{
    auto value = parameters.get(key);
    if (!value.has_value())
        return Optional<bool> {};
    if (!value->is_bool())
        return invalid_parameter(key, "a boolean"sv);
    return value->as_bool();
}

ErrorOr<Optional<u64>, Web::WebDriver::Error> get_optional_unsigned(JsonObject const& parameters, StringView key)
{
    auto value = parameters.get(key);
    if (!value.has_value())
        return Optional<u64> {};
    if (!value->is_integer<u64>())
        return invalid_parameter(key, "a non-negative integer"sv);
    return value->get_integer<u64>().value();
}

ErrorOr<Optional<Vector<String>>, Web::WebDriver::Error> get_optional_string_list(JsonObject const& parameters, StringView key, size_t minimum_size)
{
    auto value = parameters.get(key);
    if (!value.has_value())
        return Optional<Vector<String>> {};
    if (!value->is_array() || value->as_array().size() < minimum_size)
        return invalid_parameter(key, "a list"sv);

    Vector<String> result;
    TRY(value->as_array().try_for_each([&](JsonValue const& item) -> ErrorOr<void, Web::WebDriver::Error> {
        if (!item.is_string())
            return invalid_parameter(key, "a list of strings"sv);
        result.append(item.as_string());
        return {};
    }));
    return result;
}

CommandPromise resolved(JsonValue value)
{
    return Session::WebDriverPromise::resolved(move(value));
}

CommandPromise rejected(Web::WebDriver::Error error)
{
    return Session::WebDriverPromise::rejected(move(error));
}

}
