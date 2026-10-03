/*
 * Copyright (c) 2026, Ali Mohammad Pur <mpfard@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/JsonArray.h>
#include <LibGC/Heap.h>
#include <LibJS/Runtime/AbstractOperations.h>
#include <LibJS/Runtime/Promise.h>
#include <LibJS/Runtime/Realm.h>
#include <LibWeb/DOM/Document.h>
#include <LibWeb/HTML/BrowsingContext.h>
#include <LibWeb/HTML/Scripting/ClassicScript.h>
#include <LibWeb/HTML/Scripting/Environments.h>
#include <LibWeb/HTML/Scripting/TemporaryExecutionContext.h>
#include <LibWeb/HTML/Window.h>
#include <LibWeb/HighResolutionTime/TimeOrigin.h>
#include <LibWeb/WebDriver/BiDi/RemoteValue.h>
#include <LibWeb/WebDriver/BiDi/Script.h>
#include <LibWeb/WebIDL/Promise.h>

namespace Web::WebDriver::BiDi {

struct EvaluationParameters {
    bool await_promise { false };
    SerializationOptions serialization_options;
    ResultOwnership result_ownership { ResultOwnership::None };
    bool user_activation { false };
};

// The parameters both commands share.
static ErrorOr<EvaluationParameters, Error> parse_evaluation_parameters(JsonObject const& parameters)
{
    EvaluationParameters result;

    auto await_promise = parameters.get_bool("awaitPromise"sv);
    if (!await_promise.has_value())
        return Error::from_code(ErrorCode::InvalidArgument, "Parameter 'awaitPromise' must be a boolean"sv);
    result.await_promise = *await_promise;

    // Let serialization options be the value of the serializationOptions field of command parameters, if present, or
    // otherwise a map matching the script.SerializationOptions production with the fields set to their default values.
    if (auto serialization_options = parameters.get("serializationOptions"sv); serialization_options.has_value()) {
        if (!serialization_options->is_object())
            return Error::from_code(ErrorCode::InvalidArgument, "Parameter 'serializationOptions' must be an object"sv);
        result.serialization_options = TRY(SerializationOptions::deserialize(serialization_options->as_object()));
    }

    // Let result ownership be the value of the resultOwnership field of command parameters, if present, or none
    // otherwise.
    if (auto result_ownership = parameters.get("resultOwnership"sv); result_ownership.has_value()) {
        if (result_ownership->is_string() && result_ownership->as_string() == "none"sv)
            result.result_ownership = ResultOwnership::None;
        else if (result_ownership->is_string() && result_ownership->as_string() == "root"sv)
            result.result_ownership = ResultOwnership::Root;
        else
            return Error::from_code(ErrorCode::InvalidArgument, "Parameter 'resultOwnership' must be 'none' or 'root'"sv);
    }

    if (auto user_activation = parameters.get("userActivation"sv); user_activation.has_value()) {
        if (!user_activation->is_bool())
            return Error::from_code(ErrorCode::InvalidArgument, "Parameter 'userActivation' must be a boolean"sv);
        result.user_activation = user_activation->as_bool();
    }

    return result;
}

// https://w3c.github.io/webdriver-bidi/#type-script-EvaluateResult
static JsonObject evaluate_result_success(JS::Realm& realm, JsonValue result)
{
    // script.EvaluateResultSuccess = {
    //   type: "success",
    //   result: script.RemoteValue,
    //   realm: script.Realm
    // }
    JsonObject body;
    body.set("type"sv, "success"sv);
    body.set("result"sv, move(result));
    body.set("realm"sv, realm_id(realm));
    return body;
}

static JsonObject evaluate_result_exception(JS::Realm& realm, JS::Value exception, ResultOwnership result_ownership)
{
    // script.EvaluateResultException = {
    //   type: "exception",
    //   exceptionDetails: script.ExceptionDetails
    //   realm: script.Realm
    // }
    JsonObject body;
    body.set("type"sv, "exception"sv);
    body.set("exceptionDetails"sv, get_exception_details(realm, exception, result_ownership));
    body.set("realm"sv, realm_id(realm));
    return body;
}

// The tail of both commands: await the evaluation status if asked to, then serialize it.
static void complete_evaluation(JS::Realm& realm, JS::ThrowCompletionOr<JS::Value> evaluation_status, EvaluationParameters const& parameters, GC::Ref<OnEvaluateComplete> on_complete)
{
    auto serialize_status = [&realm, parameters, on_complete](JS::ThrowCompletionOr<JS::Value> evaluation_status) {
        // If evaluation status.[[Type]] is throw:
        if (evaluation_status.is_throw_completion()) {
            // 1. Let exception details be the result of get exception details given realm, evaluation status, result
            //    ownership and session.
            // 2. Return a new map matching the script.EvaluateResultException production, with the exceptionDetails
            //    field set to exception details.
            on_complete->function()(JsonValue { evaluate_result_exception(realm, evaluation_status.error_value(), parameters.result_ownership) });
            return;
        }

        // Assert: evaluation status.[[Type]] is normal.
        // Let result be the result of serialize as a remote value with evaluation status.[[Value]], serialization
        // options, result ownership, a new map as serialization internal map, realm and session.
        SerializationInternalMap serialization_internal_map;
        auto result = serialize_as_a_remote_value(realm, evaluation_status.value(), parameters.serialization_options, parameters.result_ownership, serialization_internal_map);

        // Return a new map matching the script.EvaluateResultSuccess production, with the realm field set to realm
        // id, and the result field set to result.
        on_complete->function()(JsonValue { evaluate_result_success(realm, move(result)) });
    };

    // If evaluation status.[[Type]] is normal, and await promise is true, and IsPromise(evaluation status.[[Value]]):
    if (!evaluation_status.is_throw_completion() && parameters.await_promise && evaluation_status.value().is_object() && is<JS::Promise>(evaluation_status.value().as_object())) {
        // 1. Set evaluation status to Await(evaluation status.[[Value]]).
        auto promise = WebIDL::create_resolved_promise(realm, evaluation_status.value());

        WebIDL::react_to_promise(promise,
            GC::create_function(realm.heap(), [&realm, serialize_status](JS::Value value) -> WebIDL::ExceptionOr<JS::Value> {
                HTML::TemporaryExecutionContext execution_context { realm, HTML::TemporaryExecutionContext::CallbacksEnabled::Yes };
                serialize_status(value);
                return JS::js_undefined();
            }),
            GC::create_function(realm.heap(), [&realm, serialize_status](JS::Value reason) -> WebIDL::ExceptionOr<JS::Value> {
                HTML::TemporaryExecutionContext execution_context { realm, HTML::TemporaryExecutionContext::CallbacksEnabled::Yes };
                serialize_status(JS::throw_completion(reason));
                return JS::js_undefined();
            }));
        return;
    }

    serialize_status(move(evaluation_status));
}

// https://html.spec.whatwg.org/multipage/interaction.html#activation-notification
static void run_activation_notification_steps(JS::Realm& realm)
{
    auto document = HTML::principal_realm_settings_object(realm).responsible_document();
    if (!document)
        return;
    auto window = document->window();
    if (!window)
        return;

    // 1. Assert: document is fully active.
    // 2. Let windows be « document's relevant global object ».
    // 3. Extend windows with the active window of each of document's ancestor navigables.
    // 4. Extend windows with the active window of each of document's descendant navigables, filtered to include only
    //    those navigables whose active document's origin is same origin with document's origin.
    // 5. For each window in windows, set window's last activation timestamp to the current high resolution time.
    // FIXME: Notify the windows of the ancestor and same-origin descendant navigables too.
    window->set_last_activation_timestamp(HighResolutionTime::current_high_resolution_time(realm.global_object()));
}

// https://w3c.github.io/webdriver-bidi/#get-a-realm-from-a-navigable
static JS::Realm& get_a_realm_from_a_navigable(HTML::BrowsingContext& browsing_context)
{
    // 2. If sandbox is null or is an empty string:
    //    1. Let document be navigable's active document.
    //    2. Let environment settings be the environment settings object whose relevant global object's associated
    //       Document is document.
    //    3. Let realm be environment settings' realm execution context's Realm component.
    return browsing_context.active_document()->relevant_settings_object().realm();
}

// https://w3c.github.io/webdriver-bidi/#evaluate-function-body
static JS::Completion evaluate_function_body(StringView function_declaration, HTML::EnvironmentSettingsObject& environment_settings, URL::URL const& base_url)
{
    // 1. Let bypassDisabledScripting be true.
    // 2. Let parenthesized function declaration be concatenate «"(", function declaration, ")"»
    auto parenthesized_function_declaration = Utf16String::formatted("({})", function_declaration);

    // 3. Let function script be the result of create a classic script with parenthesized function declaration,
    //    environment settings, base URL, options and bypassDisabledScripting.
    auto function_script = HTML::ClassicScript::create("<webdriver-bidi>", parenthesized_function_declaration, environment_settings, base_url);
    environment_settings.responsible_document()->add_webdriver_bidi_script(function_script);

    // 4. Prepare to run script with environment settings.
    // 5. Let function body evaluation status be ScriptEvaluation(function script's record).
    // 6. Clean up after running script with environment settings.
    // NB: Running the script prepares and cleans up around the evaluation.
    auto function_body_evaluation_status = function_script->run(HTML::ClassicScript::RethrowErrors::Yes);

    // 7. Return function body evaluation status.
    return function_body_evaluation_status;
}

// https://w3c.github.io/webdriver-bidi/#command-script-callFunction
void call_function(HTML::BrowsingContext& browsing_context, JsonObject const& parameters, GC::Ref<OnEvaluateComplete> on_complete)
{
    auto evaluation_parameters = parse_evaluation_parameters(parameters);
    if (evaluation_parameters.is_error()) {
        on_complete->function()(evaluation_parameters.release_error());
        return;
    }

    // 1. Let realm be the result of trying to get a realm from a target given the value of the target field of
    //    command parameters.
    auto& realm = get_a_realm_from_a_navigable(browsing_context);
    auto& vm = realm.vm();

    // 3. Let environment settings be the environment settings object whose realm execution context's Realm component
    //    is realm.
    auto& environment_settings = HTML::relevant_settings_object(realm.global_object());

    HTML::TemporaryExecutionContext execution_context { realm, HTML::TemporaryExecutionContext::CallbacksEnabled::Yes };

    // 4. Let command arguments be the value of the arguments field of command parameters.
    // 5. Let deserialized arguments be an empty list.
    GC::RootVector<JS::Value> deserialized_arguments;

    // 6. If command arguments is not null, set deserialized arguments to the result of trying to deserialize
    //    arguments given realm, command arguments and session.
    if (auto command_arguments = parameters.get("arguments"sv); command_arguments.has_value()) {
        if (!command_arguments->is_array()) {
            on_complete->function()(Error::from_code(ErrorCode::InvalidArgument, "Parameter 'arguments' must be a list"sv));
            return;
        }

        // https://w3c.github.io/webdriver-bidi/#deserialize-arguments
        for (auto const& serialized_argument : command_arguments->as_array().values()) {
            // 1. Let deserialized argument be the result of trying to deserialize local value given serialized
            //    argument, realm and session.
            auto deserialized_argument = deserialize_local_value(realm, serialized_argument);
            if (deserialized_argument.is_error()) {
                on_complete->function()(deserialized_argument.release_error());
                return;
            }

            // 2. Append deserialized argument to the deserialized arguments list.
            deserialized_arguments.append(deserialized_argument.release_value());
        }
    }

    // 7. Let this parameter be the value of the this field of command parameters.
    // 8. Let this object be null.
    JS::Value this_object = JS::js_undefined();

    // 9. If this parameter is not null, set this object to the result of trying to deserialize local value given this
    //    parameter, realm and session.
    if (auto this_parameter = parameters.get("this"sv); this_parameter.has_value()) {
        auto deserialized_this = deserialize_local_value(realm, *this_parameter);
        if (deserialized_this.is_error()) {
            on_complete->function()(deserialized_this.release_error());
            return;
        }
        this_object = deserialized_this.release_value();
    }

    // 10. Let function declaration be the value of the functionDeclaration field of command parameters.
    auto function_declaration = parameters.get_string("functionDeclaration"sv).value();

    // 14. Let base URL be the API base URL of environment settings.
    auto base_url = environment_settings.api_base_url();

    // 15. Let options be the default script fetch options.
    // 16. Let function body evaluation status be the result of evaluate function body with function declaration,
    //     environment settings, base URL, and options.
    auto function_body_evaluation_status = evaluate_function_body(function_declaration, environment_settings, base_url);

    // 17. If function body evaluation status.[[Type]] is throw:
    if (function_body_evaluation_status.is_error()) {
        // 1. Let exception details be the result of get exception details given realm, function body evaluation
        //    status, result ownership and session.
        // 2. Return a new map matching the script.EvaluateResultException production, with the exceptionDetails field
        //    set to exception details.
        on_complete->function()(JsonValue { evaluate_result_exception(realm, function_body_evaluation_status.value(), evaluation_parameters.value().result_ownership) });
        return;
    }

    // 18. Let function object be function body evaluation status.[[Value]].
    auto function_object = function_body_evaluation_status.value();

    // 19. If IsCallable(function object) is false:
    if (!function_object.is_function()) {
        // 1. Return an error with error code invalid argument
        on_complete->function()(Error::from_code(ErrorCode::InvalidArgument, "Parameter 'functionDeclaration' does not evaluate to a function"sv));
        return;
    }

    // 20. If command parameters["userActivation"] is true, run activation notification steps.
    if (evaluation_parameters.value().user_activation)
        run_activation_notification_steps(realm);

    // 21. Prepare to run script with environment settings.
    HTML::prepare_to_run_script(environment_settings);

    // 22. Set evaluation status to Call(function object, this object, deserialized arguments).
    auto evaluation_status = JS::call(vm, function_object.as_function(), this_object, deserialized_arguments.span());

    // 24. Clean up after running script with environment settings.
    HTML::clean_up_after_running_script(environment_settings);

    // 23. If evaluation status.[[Type]] is normal, and await promise is true, and IsPromise(evaluation
    //     status.[[Value]]):
    //     1. Set evaluation status to Await(evaluation status.[[Value]]).
    // 25-28. Serialize the completion.
    complete_evaluation(realm, move(evaluation_status), evaluation_parameters.value(), on_complete);
}

// https://w3c.github.io/webdriver-bidi/#command-script-evaluate
void evaluate(HTML::BrowsingContext& browsing_context, JsonObject const& parameters, GC::Ref<OnEvaluateComplete> on_complete)
{
    auto evaluation_parameters = parse_evaluation_parameters(parameters);
    if (evaluation_parameters.is_error()) {
        on_complete->function()(evaluation_parameters.release_error());
        return;
    }

    // 1. Let realm be the result of trying to get a realm from a target given the value of the target field of
    //    command parameters.
    auto& realm = get_a_realm_from_a_navigable(browsing_context);

    // 3. Let environment settings be the environment settings object whose realm execution context's Realm component
    //    is realm.
    auto& environment_settings = HTML::relevant_settings_object(realm.global_object());

    HTML::TemporaryExecutionContext execution_context { realm, HTML::TemporaryExecutionContext::CallbacksEnabled::Yes };

    // 4. Let source be the value of the expression field of command parameters.
    auto source = parameters.get_string("expression"sv).value();

    // 8. Let options be the default script fetch options.
    // 9. Let base URL be the API base URL of environment settings.
    auto base_url = environment_settings.api_base_url();

    // 10. Let bypassDisabledScripting be true.
    // 11. Let script be the result of create a classic script with source, environment settings, base URL, options
    //     and bypassDisabledScripting.
    auto script = HTML::ClassicScript::create("<webdriver-bidi>", Utf16String::from_utf8(source), environment_settings, base_url);
    environment_settings.responsible_document()->add_webdriver_bidi_script(script);

    // 12. If command parameters["userActivation"] is true, run activation notification steps.
    if (evaluation_parameters.value().user_activation)
        run_activation_notification_steps(realm);

    // 13. Prepare to run script with environment settings.
    // 14. Set evaluation status to ScriptEvaluation(script's record).
    // 16. Clean up after running script with environment settings.
    auto evaluation_status = script->run(HTML::ClassicScript::RethrowErrors::Yes);

    // 15. If evaluation status.[[Type]] is normal, await promise is true, and IsPromise(evaluation status.[[Value]]):
    //     1. Set evaluation status to Await(evaluation status.[[Value]]).
    // 17-20. Serialize the completion.
    if (evaluation_status.is_error())
        complete_evaluation(realm, JS::throw_completion(evaluation_status.value()), evaluation_parameters.value(), on_complete);
    else
        complete_evaluation(realm, evaluation_status.value(), evaluation_parameters.value(), on_complete);
}

}
