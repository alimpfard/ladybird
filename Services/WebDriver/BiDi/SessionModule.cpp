/*
 * Copyright (c) 2026, Ali Mohammad Pur <mpfard@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/JsonObject.h>
#include <LibWebCommon/WebDriver/Capabilities.h>
#include <WebDriver/BiDi/Modules.h>
#include <WebDriver/BiDiConnection.h>
#include <WebDriver/Session.h>

namespace WebDriver::BiDi {

// https://w3c.github.io/webdriver-bidi/#command-session-status
CommandPromise session_status(BiDiConnection&, RefPtr<Session>, JsonObject const&)
{
    // https://w3c.github.io/webdriver/#dfn-readiness-state
    auto ready = Session::session_count(Web::WebDriver::SessionFlags::Http) == 0 && !Session::has_pending_http_session_creation();

    // 1. Let body be a new map with the following properties:
    JsonObject body;
    // "ready"
    //     The remote end’s readiness state.
    body.set("ready"sv, ready);
    // "message"
    //     An implementation-defined string explaining the remote end’s readiness state.
    body.set("message"sv, MUST(String::formatted("{} to accept a new session", ready ? "Ready"sv : "Not ready"sv)));

    // 2. Return success with data body
    return resolved(move(body));
}

// https://w3c.github.io/webdriver-bidi/#command-session-new
CommandPromise session_new(BiDiConnection&, RefPtr<Session> session, JsonObject const& parameters)
{
    // 1. If session is not null, return an error with error code session not created.
    if (session)
        return rejected(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::SessionNotCreated, "This connection already has a session"sv));

    // 2. If the implementation is unable to start a new session for any reason, return an error with error code
    //    session not created.
    // NB: Creating the session below fails with that error code.

    // 3. Let flags be a set containing "bidi".
    static constexpr auto flags = Web::WebDriver::SessionFlags::BiDi;

    // 4. Let capabilities json be the result of trying to process capabilities with command parameters and flags.
    auto capabilities = TRY_OR_REJECT(Web::WebDriver::process_capabilities(parameters, flags));

    // 5. Let capabilities be convert a JSON-derived JavaScript value to an Infra value with capabilities json.
    if (capabilities.is_null())
        return rejected(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::SessionNotCreated, "Could not match capabilities"sv));

    // 6. Let session be the result of trying to create a session with capabilities and flags.
    auto session_promise = Session::create(move(capabilities), flags);
    if (session_promise.is_error())
        return rejected(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::SessionNotCreated, MUST(String::formatted("Failed to start session: {}", session_promise.error()))));

    auto promise = Session::WebDriverPromise::construct();
    promise->add_child(*session_promise.value());
    session_promise.value()->when_resolved([promise](Session::NewSession& new_session) {
                               // 7. Set session's BiDi flag to true.
                               // NB: Creating the session with the "bidi" flag did this.

                               // 8. Let body be a new map matching the session.NewResult production, with the
                               //    sessionId field set to session's session ID, and the capabilities field set to
                               //    capabilities.
                               JsonObject body;
                               body.set("sessionId"sv, new_session.session->session_id());
                               body.set("capabilities"sv, move(new_session.capabilities));

                               // 9. Return success with data body.
                               promise->resolve(move(body));
                           })
        .when_rejected([promise](Web::WebDriver::Error& error) {
            promise->reject(Web::WebDriver::Error(error));
        });
    return promise;
}

// https://w3c.github.io/webdriver-bidi/#command-session-end
CommandPromise session_end(BiDiConnection&, RefPtr<Session> session, JsonObject const&)
{
    // 1. End the session with session.
    session->end();

    // 2. Return success with data null, and in parallel run the following steps:
    //    1. Wait until the Send a WebSocket message steps have been called with the response to this command.
    //    2. Cleanup the session with session.
    // NB: The connection runs the cleanup once it has sent this response.
    return resolved(JsonObject {});
}

// https://w3c.github.io/webdriver-bidi/#command-session-subscribe
CommandPromise session_subscribe(BiDiConnection&, RefPtr<Session> session, JsonObject const& parameters)
{
    // session.SubscribeParameters = {
    //   events: [+text],
    //   ? contexts: [+browsingContext.BrowsingContext],
    //   ? userContexts: [+browser.UserContext],
    // }
    auto events = TRY_OR_REJECT(get_optional_string_list(parameters, "events"sv, 1));
    if (!events.has_value())
        return rejected(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, "Parameter 'events' must be a list"sv));
    auto contexts = TRY_OR_REJECT(get_optional_string_list(parameters, "contexts"sv, 1));
    auto user_contexts = TRY_OR_REJECT(get_optional_string_list(parameters, "userContexts"sv, 1));

    return session->subscribe_to_events(events.release_value(), move(contexts), move(user_contexts));
}

// https://w3c.github.io/webdriver-bidi/#command-session-unsubscribe
CommandPromise session_unsubscribe(BiDiConnection&, RefPtr<Session> session, JsonObject const& parameters)
{
    // session.UnsubscribeParameters = session.UnsubscribeByAttributesRequest / session.UnsubscribeByIDRequest

    // 1. If command parameters does not contain "subscriptions":
    if (!parameters.has("subscriptions"sv)) {
        // session.UnsubscribeByAttributesRequest = {
        //   events: [+text],
        // }
        auto events = TRY_OR_REJECT(get_optional_string_list(parameters, "events"sv, 1));
        if (!events.has_value())
            return rejected(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, "Parameter 'events' must be a list"sv));

        TRY_OR_REJECT(session->unsubscribe_from_events(events.release_value()));
    }
    // 2. Otherwise:
    else {
        // session.UnsubscribeByIDRequest = {
        //   subscriptions: [+session.Subscription],
        // }
        auto subscriptions = TRY_OR_REJECT(get_optional_string_list(parameters, "subscriptions"sv, 1));
        TRY_OR_REJECT(session->unsubscribe_from_subscriptions(subscriptions.release_value()));
    }

    // 3. Return success with data null.
    return resolved(JsonObject {});
}

}
