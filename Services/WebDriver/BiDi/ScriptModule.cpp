/*
 * Copyright (c) 2026, Ali Mohammad Pur <mpfard@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/JsonObject.h>
#include <WebDriver/BiDi/Modules.h>
#include <WebDriver/Session.h>

namespace WebDriver::BiDi {

// https://w3c.github.io/webdriver-bidi/#type-script-Target
// Both script commands take a script.Target; the navigable it names decides which process runs the command.
static ErrorOr<String, Web::WebDriver::Error> get_navigable_id_from_target(JsonObject const& parameters)
{
    auto target = parameters.get_object("target"sv);
    if (!target.has_value())
        return Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, "Parameter 'target' must be an object"sv);

    // script.ContextTarget = {
    //   context: browsingContext.BrowsingContext,
    //   ? sandbox: text
    // }
    if (target->has("context"sv)) {
        auto context = TRY(get_required_string(*target, "context"sv));
        if (auto sandbox = TRY(get_optional_string(*target, "sandbox"sv)); sandbox.has_value() && !sandbox->is_empty())
            return Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::UnsupportedOperation, "Sandboxed script execution is not supported"sv);
        return context;
    }

    // script.RealmTarget = {
    //   realm: script.Realm
    // }
    if (target->has("realm"sv)) {
        TRY(get_required_string(*target, "realm"sv));
        // FIXME: Realms are not tracked outside of their navigable's active document yet.
        return Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::UnsupportedOperation, "Realm targets are not supported"sv);
    }

    return Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, "Parameter 'target' must be a script.ContextTarget or script.RealmTarget"sv);
}

// https://w3c.github.io/webdriver-bidi/#command-script-callFunction
CommandPromise script_call_function(BiDiConnection&, RefPtr<Session> session, JsonObject const& parameters)
{
    // script.CallFunctionParameters = {
    //   functionDeclaration: text,
    //   awaitPromise: bool,
    //   target: script.Target,
    //   ? arguments: [*script.LocalValue],
    //   ? resultOwnership: script.ResultOwnership,
    //   ? serializationOptions: script.SerializationOptions,
    //   ? this: script.LocalValue,
    //   ? userActivation: bool .default false,
    // }
    TRY_OR_REJECT(get_required_string(parameters, "functionDeclaration"sv));
    TRY_OR_REJECT(get_required_bool(parameters, "awaitPromise"sv));
    auto navigable_id = TRY_OR_REJECT(get_navigable_id_from_target(parameters));

    // NB: The process hosting the realm runs the remote end steps.
    return session->run_bidi_content_command(move(navigable_id), "script.callFunction"_string, parameters);
}

// https://w3c.github.io/webdriver-bidi/#command-script-evaluate
CommandPromise script_evaluate(BiDiConnection&, RefPtr<Session> session, JsonObject const& parameters)
{
    // script.EvaluateParameters = {
    //   expression: text,
    //   target: script.Target,
    //   awaitPromise: bool,
    //   ? resultOwnership: script.ResultOwnership,
    //   ? serializationOptions: script.SerializationOptions,
    //   ? userActivation: bool .default false,
    // }
    TRY_OR_REJECT(get_required_string(parameters, "expression"sv));
    TRY_OR_REJECT(get_required_bool(parameters, "awaitPromise"sv));
    auto navigable_id = TRY_OR_REJECT(get_navigable_id_from_target(parameters));

    // NB: The process hosting the realm runs the remote end steps.
    return session->run_bidi_content_command(move(navigable_id), "script.evaluate"_string, parameters);
}

}
