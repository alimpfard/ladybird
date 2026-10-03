/*
 * Copyright (c) 2026, Ali Mohammad Pur <mpfard@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/JsonObject.h>
#include <AK/JsonValue.h>
#include <AK/NonnullRefPtr.h>
#include <AK/Optional.h>
#include <AK/RefPtr.h>
#include <AK/StringView.h>
#include <AK/Vector.h>
#include <LibWebCommon/WebDriver/Error.h>
#include <WebDriver/Forward.h>
#include <WebDriver/Session.h>

// Rejects the command promise being built with the error of a fallible expression. Only usable in functions returning
// a CommandPromise.
#define TRY_OR_REJECT(expression)                                                                    \
    ({                                                                                               \
        auto&& _temporary_result = (expression);                                                     \
        if (_temporary_result.is_error()) [[unlikely]]                                               \
            return ::WebDriver::BiDi::rejected(_temporary_result.release_error());                   \
        static_assert(!::AK::Detail::IsLvalueReference<decltype(_temporary_result.release_value())>, \
            "Do not return a reference from a fallible expression");                                 \
        _temporary_result.release_value();                                                           \
    })

namespace WebDriver::BiDi {

using CommandPromise = NonnullRefPtr<Session::WebDriverPromise>;

// https://w3c.github.io/webdriver-bidi/#commands
// The remote end steps of a command, given the connection the command arrived on, the session (null for a static
// command sent over a connection not associated with a session) and the command parameters.
using CommandHandler = CommandPromise (*)(BiDiConnection&, RefPtr<Session>, JsonObject const& parameters);

struct Command {
    StringView name;
    CommandHandler handler;
    bool is_static { false };
};

struct MatchedCommand {
    JsonValue command_id;
    Command const& command;
    JsonObject parameters;
};

// Matches a parsed message against the Command production of the remote end definition.
Optional<MatchedCommand> match_command(JsonValue const& parsed);

// https://w3c.github.io/webdriver-bidi/#set-of-all-command-names
bool is_command_name(StringView);

// https://w3c.github.io/webdriver-bidi/#obtain-a-set-of-event-names
ErrorOr<Vector<String>, Web::WebDriver::Error> obtain_a_set_of_event_names(StringView name);

// Helpers for the command parameter productions.
ErrorOr<String, Web::WebDriver::Error> get_required_string(JsonObject const&, StringView key);
ErrorOr<Optional<String>, Web::WebDriver::Error> get_optional_string(JsonObject const&, StringView key);
ErrorOr<bool, Web::WebDriver::Error> get_required_bool(JsonObject const&, StringView key);
ErrorOr<Optional<bool>, Web::WebDriver::Error> get_optional_bool(JsonObject const&, StringView key);
ErrorOr<Optional<u64>, Web::WebDriver::Error> get_optional_unsigned(JsonObject const&, StringView key);
ErrorOr<Optional<Vector<String>>, Web::WebDriver::Error> get_optional_string_list(JsonObject const&, StringView key, size_t minimum_size = 0);

CommandPromise resolved(JsonValue);
CommandPromise rejected(Web::WebDriver::Error);

}
