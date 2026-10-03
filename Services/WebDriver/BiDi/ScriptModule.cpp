/*
 * Copyright (c) 2026, Ali Mohammad Pur <mpfard@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/JsonArray.h>
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

// https://w3c.github.io/webdriver-bidi/#command-script-addPreloadScript
CommandPromise script_add_preload_script(BiDiConnection&, RefPtr<Session> session, JsonObject const& parameters)
{
    // script.AddPreloadScriptParameters = {
    //   functionDeclaration: text,
    //   ? arguments: [*script.ChannelValue],
    //   ? contexts: [+browsingContext.BrowsingContext],
    //   ? userContexts: [+browser.UserContext],
    //   ? sandbox: text
    // }
    // 1. If command parameters contains "userContexts" and command parameters contains "contexts", return error with
    //    error code invalid argument.
    if (parameters.has("userContexts"sv) && parameters.has("contexts"sv))
        return rejected(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, "Parameters 'contexts' and 'userContexts' are mutually exclusive"sv));

    // 2. Let function declaration be the functionDeclaration field of command parameters.
    auto function_declaration = TRY_OR_REJECT(get_required_string(parameters, "functionDeclaration"sv));

    // 3. Let arguments be the arguments field of command parameters if present, or an empty list otherwise.
    if (auto arguments = parameters.get("arguments"sv); arguments.has_value()) {
        if (!arguments->is_array())
            return rejected(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, "Parameter 'arguments' must be a list"sv));
        // FIXME: Support channel arguments.
        if (!arguments->as_array().is_empty())
            return rejected(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::UnsupportedOperation, "Channels are not supported"sv));
    }

    JsonObject preload_script;
    preload_script.set("functionDeclaration"sv, move(function_declaration));

    // 6. If the contexts field of command parameters is present:
    if (auto contexts = TRY_OR_REJECT(get_optional_string_list(parameters, "contexts"sv, 1)); contexts.has_value()) {
        JsonArray navigables;
        // 2. For each navigable id of command parameters["contexts"]
        for (auto const& navigable_id : *contexts) {
            // 1. Let navigable be the result of trying to get a navigable with navigable id.
            // 2. If navigable is not a top-level traversable, return error with error code invalid argument.
            if (!session->has_window_handle(navigable_id))
                return rejected(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, "Parameter 'contexts' must name top-level browsing contexts"sv));
            navigables.must_append(navigable_id);
        }
        preload_script.set("contexts"sv, move(navigables));
    }
    // 7. Otherwise, if command parameters contains userContexts:
    else if (auto user_contexts = TRY_OR_REJECT(get_optional_string_list(parameters, "userContexts"sv, 1)); user_contexts.has_value()) {
        // 2. For each user context id of user contexts:
        //    1. Set user context to get user context with user context id.
        //    2. If user context is null, return error with error code no such user context.
        for (auto const& user_context_id : *user_contexts) {
            if (user_context_id != "default"sv)
                return rejected(Web::WebDriver::Error { 404, "no such user context"_string, MUST(String::formatted("Unknown user context: {}", user_context_id)), {} });
        }
    }

    // 8. Let sandbox be the value of the "sandbox" field in command parameters, if present, or null otherwise.
    if (auto sandbox = TRY_OR_REJECT(get_optional_string(parameters, "sandbox"sv)); sandbox.has_value() && !sandbox->is_empty())
        return rejected(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::UnsupportedOperation, "Sandboxed script execution is not supported"sv));

    // 9-12. Let script be a new UUID naming the preload script in session's preload script map.
    auto script = session->add_preload_script(move(preload_script));

    // 13. Return a new map matching the script.AddPreloadScriptResult with the script field set to script.
    JsonObject body;
    body.set("script"sv, move(script));
    return resolved(move(body));
}

// https://w3c.github.io/webdriver-bidi/#command-script-removePreloadScript
CommandPromise script_remove_preload_script(BiDiConnection&, RefPtr<Session> session, JsonObject const& parameters)
{
    // 1. Let script be the value of the "script" field in command parameters.
    auto script = TRY_OR_REJECT(get_required_string(parameters, "script"sv));

    // 2-4. Remove script from session's preload script map.
    TRY_OR_REJECT(session->remove_preload_script(script));

    // 5. Return null
    return resolved(JsonObject {});
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
