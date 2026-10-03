/*
 * Copyright (c) 2026, Ali Mohammad Pur <mpfard@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/JsonObject.h>
#include <WebDriver/BiDi/Modules.h>
#include <WebDriver/Session.h>

namespace WebDriver::BiDi {

// https://w3c.github.io/webdriver-bidi/#command-browsingContext-close
CommandPromise browsing_context_close(BiDiConnection&, RefPtr<Session> session, JsonObject const& parameters)
{
    // browsingContext.CloseParameters = {
    //   context: browsingContext.BrowsingContext,
    //   ? promptUnload: bool .default false
    // }
    // 1. Let navigable id be the value of the context field of command parameters.
    auto navigable_id = TRY_OR_REJECT(get_required_string(parameters, "context"sv));

    // 2. Let prompt unload be the value of the promptUnload field of command parameters.
    // FIXME: Prompt to unload when asked to.
    TRY_OR_REJECT(get_optional_bool(parameters, "promptUnload"sv));

    // 3. Let navigable be the result of trying to get a navigable with navigable id.
    // 5. If navigable is not a top-level traversable, return error with error code invalid argument.
    // NB: Only top-level traversables have window handles; any other navigable id is looked up by the browser.
    if (!session->has_window_handle(navigable_id)) {
        auto promise = Session::WebDriverPromise::construct();
        auto lookup = session->get_browsing_context_tree(navigable_id, 0);
        promise->add_child(lookup);
        lookup->when_resolved([promise](JsonValue&) {
                  promise->reject(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, "Only a top-level browsing context can be closed"sv));
              })
            .when_rejected([promise](Web::WebDriver::Error& error) {
                promise->reject(Web::WebDriver::Error(error));
            });
        return promise;
    }

    // 6. If prompt unload is true:
    //    1. Close navigable.
    // 7. Otherwise:
    //    1. Close navigable without prompting to unload.
    // NB: The window is gone once the browser reports it closed, so the response waits for that.
    auto promise = Session::WebDriverPromise::construct();
    auto close = session->run_content_command_in_window(navigable_id, "close_window"sv);
    promise->add_child(close);
    close->when_resolved([promise, session, navigable_id](JsonValue&) {
             auto closed = session->wait_for_window_closed(navigable_id);
             promise->add_child(closed);
             closed->when_resolved([promise](JsonValue&) {
                       // 8. Return success with data null.
                       promise->resolve(JsonObject {});
                   })
                 .when_rejected([promise](Web::WebDriver::Error& error) {
                     promise->reject(Web::WebDriver::Error(error));
                 });
         })
        .when_rejected([promise](Web::WebDriver::Error& error) {
            promise->reject(Web::WebDriver::Error(error));
        });
    return promise;
}

// https://w3c.github.io/webdriver-bidi/#command-browsingContext-navigate
CommandPromise browsing_context_navigate(BiDiConnection&, RefPtr<Session> session, JsonObject const& parameters)
{
    // browsingContext.NavigateParameters = {
    //   context: browsingContext.BrowsingContext,
    //   url: text,
    //   ? wait: browsingContext.ReadinessState,
    // }
    // 1. Let navigable id be the value of the context field of command parameters.
    auto navigable_id = TRY_OR_REJECT(get_required_string(parameters, "context"sv));

    // 4. Let wait condition be "committed".
    // 5. If command parameters contains wait and command parameters[wait] is not "none", set wait condition to
    //    command parameters[wait].
    auto wait_condition = TRY_OR_REJECT(get_optional_string(parameters, "wait"sv)).value_or("none"_string);
    if (!wait_condition.is_one_of("none"sv, "interactive"sv, "complete"sv))
        return rejected(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, "Parameter 'wait' must be 'none', 'interactive' or 'complete'"sv));

    // 6. Let url be the value of the url field of command parameters.
    auto url = TRY_OR_REJECT(get_required_string(parameters, "url"sv));

    // 2. Let navigable be the result of trying to get a navigable with navigable id.
    // 7-11. The process hosting navigable's active document parses url against its base URL and navigates.
    // 12. Return the result of await a navigation with navigable, request and wait condition.
    return session->navigate_context(move(navigable_id), move(url), wait_condition);
}

// https://w3c.github.io/webdriver-bidi/#command-browsingContext-create
CommandPromise browsing_context_create(BiDiConnection&, RefPtr<Session> session, JsonObject const& parameters)
{
    // browsingContext.CreateParameters = {
    //   type: browsingContext.CreateType,
    //   ? referenceContext: browsingContext.BrowsingContext,
    //   ? background: bool .default false,
    //   ? userContext: browser.UserContext
    // }
    // 1. Let type be the value of the type field of command parameters.
    auto type = TRY_OR_REJECT(get_required_string(parameters, "type"sv));
    if (!type.is_one_of("tab"sv, "window"sv))
        return rejected(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, "Parameter 'type' must be 'tab' or 'window'"sv));

    // 2. Let reference navigable id be the value of the referenceContext field of command parameters, if present, or
    //    null otherwise.
    auto reference_navigable_id = TRY_OR_REJECT(get_optional_string(parameters, "referenceContext"sv));
    TRY_OR_REJECT(get_optional_bool(parameters, "background"sv));

    // 7. Let user context id be the value of the userContext field of command parameters if present, or null
    //    otherwise.
    // 8. If user context id is not null, set user context to the result of trying to get user context with user
    //    context id.
    // 9. If user context is null, return error with error code no such user context.
    if (auto user_context_id = TRY_OR_REJECT(get_optional_string(parameters, "userContext"sv)); user_context_id.has_value() && *user_context_id != "default"sv)
        return rejected(Web::WebDriver::Error { 404, "no such user context"_string, MUST(String::formatted("Unknown user context: {}", *user_context_id)), {} });

    // 3. If reference navigable id is not null, let reference navigable be the result of trying to get a navigable
    //    with reference navigable id. Otherwise let reference navigable be null.
    // 4. If reference navigable is not null and is not a top-level traversable, return error with error code invalid
    //    argument.
    // NB: A new top-level traversable is opened from an existing window; without a reference, any window will do.
    String opener_window_handle;
    if (reference_navigable_id.has_value()) {
        if (!session->has_window_handle(*reference_navigable_id))
            return rejected(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, "Parameter 'referenceContext' must name a top-level browsing context"sv));
        opener_window_handle = *reference_navigable_id;
    } else {
        auto window_handles = session->window_handles();
        if (window_handles.is_empty())
            return rejected(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::UnsupportedOperation, "No window is open to create a new browsing context from"sv));
        opener_window_handle = window_handles.first();
    }

    // 11. Let traversable be the result of trying to create a new top-level traversable steps with null, empty
    //     string, null, and false, and setting the associated user context for the newly created top-level
    //     traversable to user context.
    JsonObject new_window_parameters;
    new_window_parameters.set("type"sv, type);

    auto promise = Session::WebDriverPromise::construct();
    auto new_window = session->run_content_command_in_window(opener_window_handle, "new_window"sv, move(new_window_parameters));
    promise->add_child(new_window);
    new_window->when_resolved([promise, session](JsonValue& result) {
                  auto handle = result.is_object() ? result.as_object().get_string("handle"sv) : Optional<String> {};
                  if (!handle.has_value()) {
                      promise->reject(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::UnknownError, "New Window response does not contain a string 'handle' property"sv));
                      return;
                  }

                  // NB: The browser reports the new window once it exists; the response waits for that.
                  auto wait = session->wait_for_window_handle(*handle);
                  promise->add_child(wait);
                  wait->when_resolved([promise, handle = *handle](JsonValue&) {
                          // 12. If the value of the command parameters' background field is false:
                          //     1. Let activate result be the result of activate a navigable with the newly created
                          //        navigable.
                          // FIXME: Activate the new window.

                          // 13. Let body be a map matching the browsingContext.CreateResult production, with the
                          //     context field set to traversable's navigable id and the userContext property set to
                          //     the user context id of traversable's associated user context.
                          JsonObject body;
                          body.set("context"sv, handle);
                          body.set("userContext"sv, "default"sv);

                          // 14. Return success with data body.
                          promise->resolve(move(body));
                      })
                      .when_rejected([promise](Web::WebDriver::Error& error) {
                          promise->reject(Web::WebDriver::Error(error));
                      });
              })
        .when_rejected([promise](Web::WebDriver::Error& error) {
            promise->reject(Web::WebDriver::Error(error));
        });
    return promise;
}

// https://w3c.github.io/webdriver-bidi/#command-browsingContext-getTree
CommandPromise browsing_context_get_tree(BiDiConnection&, RefPtr<Session> session, JsonObject const& parameters)
{
    // browsingContext.GetTreeParameters = {
    //   ? maxDepth: js-uint,
    //   ? root: browsingContext.BrowsingContext,
    // }
    // 1. Let root id be the value of the root field of command parameters if present, or null otherwise.
    auto root_id = TRY_OR_REJECT(get_optional_string(parameters, "root"sv));

    // 2. Let max depth be the value of the maxDepth field of command parameters if present, or null otherwise.
    auto max_depth = TRY_OR_REJECT(get_optional_unsigned(parameters, "maxDepth"sv));

    // NB: The browser process holds the navigables and runs the remaining steps.
    return session->get_browsing_context_tree(move(root_id), max_depth);
}

// https://w3c.github.io/webdriver-bidi/#command-browsingContext-handleUserPrompt
CommandPromise browsing_context_handle_user_prompt(BiDiConnection&, RefPtr<Session> session, JsonObject const& parameters)
{
    // browsingContext.HandleUserPromptParameters = {
    //   context: browsingContext.BrowsingContext,
    //   ? accept: bool,
    //   ? userText: text,
    // }
    // 1. Let navigable id be the value of the context field of command parameters.
    auto navigable_id = TRY_OR_REJECT(get_required_string(parameters, "context"sv));

    // 3. Let accept be the value of the accept field of command parameters if present, or true otherwise.
    auto accept = TRY_OR_REJECT(get_optional_bool(parameters, "accept"sv)).value_or(true);

    // 4. Let userText be the value of the userText field of command parameters if present, or the empty string
    //    otherwise.
    auto user_text = TRY_OR_REJECT(get_optional_string(parameters, "userText"sv)).value_or(String {});

    JsonObject content_parameters;
    content_parameters.set("accept"sv, accept);
    content_parameters.set("userText"sv, move(user_text));

    // NB: The process hosting the navigable's document runs the remaining steps.
    return session->run_bidi_content_command(move(navigable_id), "browsingContext.handleUserPrompt"_string, move(content_parameters));
}

}
