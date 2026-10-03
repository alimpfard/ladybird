/*
 * Copyright (c) 2026, Ali Mohammad Pur <mpfard@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/JsonArray.h>
#include <AK/JsonObject.h>
#include <AK/NeverDestroyed.h>
#include <AK/Time.h>
#include <LibJS/Runtime/AbstractOperations.h>
#include <LibWeb/DOM/Document.h>
#include <LibWeb/HTML/LocalNavigable.h>
#include <LibWeb/HTML/Navigable.h>
#include <LibWeb/HTML/Scripting/ClassicScript.h>
#include <LibWeb/HTML/Scripting/Environments.h>
#include <LibWeb/HTML/Scripting/ExceptionReporter.h>
#include <LibWeb/HTML/Scripting/TemporaryExecutionContext.h>
#include <LibWeb/HTML/Window.h>
#include <LibWeb/Page/Page.h>
#include <LibWeb/WebDriver/BiDi/Events.h>
#include <LibWeb/WebDriver/BiDi/RemoteValue.h>

namespace Web::WebDriver::BiDi {

// https://w3c.github.io/webdriver-bidi/#get-the-navigation-info
static JsonObject get_the_navigation_info(HTML::Navigable& navigable, Utf16String const& navigation_id, URL::URL const& url)
{
    // 1. Let navigable id be the navigable id for navigable.
    // 2. Let user context id be the user context id of navigable's associated user context.
    // 3. Let params be a map matching the browsingContext.NavigationInfo production with the context field set to
    //    navigable id, the navigation field set to navigation status's id, the url field set to the result of the URL
    //    serializer given navigation status's url, the timestamp field set to a time value representing the current
    //    date and time in UTC, and the userContext field set to user context id.
    JsonObject params;
    params.set("context"sv, BiDi::navigable_id(navigable));
    params.set("navigation"sv, navigation_id.to_utf8());
    params.set("url"sv, url.serialize());
    params.set("timestamp"sv, UnixDateTime::now().milliseconds_since_epoch());
    params.set("userContext"sv, "default"sv);
    return params;
}

void emit_navigation_event(HTML::Navigable& navigable, StringView method, Utf16String const& navigation_id, URL::URL const& url)
{
    // The page's client holds the session; it decides whether anyone listens.
    navigable.page().client().page_did_emit_webdriver_bidi_event(MUST(String::from_utf8(method)), get_the_navigation_info(navigable, navigation_id, url));
}

// https://w3c.github.io/webdriver-bidi/#preload-script-map
static JsonValue& preload_scripts()
{
    static NeverDestroyed<JsonValue> scripts;
    return *scripts;
}

void set_preload_scripts(JsonValue scripts)
{
    preload_scripts() = move(scripts);
}

// https://w3c.github.io/webdriver-bidi/#run-webdriver-bidi-preload-scripts
void run_preload_scripts(DOM::Document& document)
{
    if (!preload_scripts().is_array() || preload_scripts().as_array().is_empty())
        return;

    // 1. Let document be environment settings' relevant global object's associated Document.
    auto window = document.window();
    if (!window || &window->associated_document() != &document)
        return;
    auto& environment_settings = HTML::relevant_settings_object(*window);

    // 2. Let navigable be document's navigable.
    auto navigable = document.navigable();
    if (!navigable)
        return;

    // 3. Let user context be navigable's associated user context.
    // 4. Let user context id be user context's user context id.
    // 5. For each session in active BiDi sessions:
    //    1. For each preload script in session's preload script map's values:
    preload_scripts().as_array().for_each([&](JsonValue const& preload_script_value) {
        auto const& preload_script = preload_script_value.as_object();

        // 1. If preload script's user contexts's size is not zero:
        //    1. If preload script's user contexts does not contain user context id, continue.
        // NB: Every navigable belongs to the default user context.

        // 2. If preload script's contexts is not null:
        if (auto contexts = preload_script.get_array("contexts"sv); contexts.has_value()) {
            // 1. Let navigable id be navigable's top-level traversable's id.
            auto top_level_id = BiDi::navigable_id(*navigable->top_level_traversable());

            // 2. If preload script's contexts does not contain navigable id, continue.
            auto contains = false;
            contexts->for_each([&](JsonValue const& context) {
                if (context.is_string() && context.as_string() == top_level_id)
                    contains = true;
            });
            if (!contains)
                return;
        }

        // 3. If preload script's sandbox is not null, let realm be get or create a sandbox realm with preload
        //    script's sandbox and navigable. Otherwise let realm be environment settings' realm execution context's
        //    Realm component.
        auto& realm = environment_settings.realm();

        // 4. Let exception reporting global be environment settings' realm execution context's Realm component's
        //    global object.
        HTML::TemporaryExecutionContext execution_context { realm, HTML::TemporaryExecutionContext::CallbacksEnabled::Yes };

        // 5-7. Let deserialized arguments be the channels created for each argument.
        // FIXME: Create channels for the arguments.

        // 8. Let base URL be the API base URL of environment settings.
        auto base_url = environment_settings.api_base_url();

        // 9. Let options be the default script fetch options.
        // 10. Let function declaration be preload script's function declaration.
        auto function_declaration = preload_script.get_string("functionDeclaration"sv).value_or({});

        // 11. Let function body evaluation status be the result of evaluate function body with function declaration,
        //     environment settings, base URL, and options.
        // https://w3c.github.io/webdriver-bidi/#evaluate-function-body
        auto function_script = HTML::ClassicScript::create("<webdriver-bidi-preload>", Utf16String::formatted("({})", function_declaration), environment_settings, base_url);
        document.add_webdriver_bidi_script(function_script);
        auto function_body_evaluation_status = function_script->run(HTML::ClassicScript::RethrowErrors::Yes);

        // 12. If function body evaluation status is an abrupt completion, then report an exception given by function
        //     body evaluation status.[[Value]] for exception reporting global.
        if (function_body_evaluation_status.is_error()) {
            HTML::report_exception(function_body_evaluation_status, realm);
            return;
        }

        // 13. Let function object be function body evaluation status.[[Value]].
        auto function_object = function_body_evaluation_status.value();

        // 14. If IsCallable(function object) is false:
        if (!function_object.is_function()) {
            // 1. Let error be a new TypeError object in realm.
            // 2. Report an exception error for exception reporting global.
            HTML::report_exception(realm.vm().throw_completion<JS::TypeError>("Preload script is not a function"sv), realm);
            return;
        }

        // 15. Prepare to run script with environment settings.
        HTML::prepare_to_run_script(environment_settings);

        // 16. Set evaluation status to Call(function object, null, deserialized arguments).
        auto evaluation_status = JS::call(realm.vm(), function_object.as_function(), JS::js_null());

        // 17. Clean up after running script with environment settings.
        HTML::clean_up_after_running_script(environment_settings);

        // 18. If evaluation status is an abrupt completion, then report an exception given by evaluation
        //     status.[[Value]] for exception reporting global.
        if (evaluation_status.is_throw_completion())
            HTML::report_exception(evaluation_status.throw_completion(), realm);
    });
}

}
