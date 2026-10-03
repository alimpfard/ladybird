/*
 * Copyright (c) 2022, Florent Castelli <florent.castelli@gmail.com>
 * Copyright (c) 2022, Sam Atkins <atkinssj@serenityos.org>
 * Copyright (c) 2022, Tobias Christiansen <tobyase@serenityos.org>
 * Copyright (c) 2022, Linus Groh <linusg@serenityos.org>
 * Copyright (c) 2022-2025, Tim Flynn <trflynn89@ladybird.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/HashMap.h>
#include <AK/JsonObject.h>
#include <AK/NumericLimits.h>
#include <AK/Vector.h>
#include <AK/WeakPtr.h>
#if !defined(AK_OS_MACOS)
#    include <LibCore/LocalServer.h>
#    include <LibCore/Socket.h>
#    include <LibCore/StandardPaths.h>
#else
#    include <LibIPC/TransportBootstrapMach.h>
#    include <LibWebView/Utilities.h>
#endif
#include <AK/Random.h>
#include <LibCore/EventLoop.h>
#include <LibCore/Process.h>
#include <LibCore/System.h>
#include <LibCore/Timer.h>
#include <LibFileSystem/FileSystem.h>
#include <LibIPC/Transport.h>
#include <LibURL/Parser.h>
#include <LibWebCommon/WebDriver/Proxy.h>
#include <LibWebCommon/WebDriver/TimeoutsConfiguration.h>
#include <LibWebCommon/WebDriver/UserPrompt.h>
#include <WebDriver/BiDi/Commands.h>
#include <WebDriver/BiDiConnection.h>
#include <WebDriver/Session.h>

namespace WebDriver {

static HashMap<String, NonnullRefPtr<Session>> s_sessions;
static HashMap<String, NonnullRefPtr<Session>> s_http_sessions;

static LaunchBrowserCallback s_launch_browser_callback;

// https://w3c.github.io/webdriver-bidi/#websocket-listener
// The one listener of this endpoint node: the HTTP server, which upgrades connections for the WebSocket resources.
struct WebSocketListener {
    IPv4Address host;
    u16 port { 0 };
};
static Optional<WebSocketListener> s_websocket_listener;

struct SessionCreationState;
static WeakPtr<SessionCreationState> s_http_session_creation;

struct SessionCreationState
    : public RefCounted<SessionCreationState>
    , public Weakable<SessionCreationState> {
    SessionCreationState(JsonValue capabilities, Web::WebDriver::SessionFlags flags)
        : capabilities(move(capabilities))
        , promise(Session::NewSessionPromise::construct())
    {
        if (has_flag(flags, Web::WebDriver::SessionFlags::Http))
            s_http_session_creation = *this;
    }

    JsonValue capabilities;
    NonnullRefPtr<Session::NewSessionPromise> promise;
};

static Web::WebDriver::Error session_not_created_error(AK::Error const& error)
{
    return Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::SessionNotCreated, MUST(String::formatted("Browser startup failed: {}", error)));
}

void Session::set_launch_browser_callback(LaunchBrowserCallback callback)
{
    s_launch_browser_callback = move(callback);
}

void Session::set_websocket_listener(IPv4Address host, u16 port)
{
    s_websocket_listener = WebSocketListener { host, port };
}

// https://w3c.github.io/webdriver-bidi/#construct-a-websocket-url
static String construct_a_websocket_url(WebSocketListener const& listener, Session const& session)
{
    // 1. Let resource name be the result of construct a WebSocket resource name with session.
    // https://w3c.github.io/webdriver-bidi/#construct-a-websocket-resource-name
    // 2. Return the result of concatenating the string "/session/" with session's session ID.
    auto resource_name = MUST(String::formatted("/session/{}", session.session_id()));

    // 2. Return a WebSocket URI constructed with host set to listener's host, port set to listener's port, path set
    //    to resource name, following the wss-URI construct if listener's secure flag is set and the ws-URL construct
    //    otherwise.
    // NB: A listener on every interface is reached through the loopback address.
    auto host = listener.host == IPv4Address {} ? IPv4Address { 127, 0, 0, 1 } : listener.host;
    return MUST(String::formatted("ws://{}:{}{}", host, listener.port, resource_name));
}

// https://w3c.github.io/webdriver-bidi/#establishing
// The WebDriver new session algorithm defined by this specification, with parameters session, capabilities, and flags
void Session::run_bidi_new_session_algorithm(JsonObject& capabilities, Web::WebDriver::SessionFlags& flags)
{
    // 1. If flags contains "bidi", return.
    if (has_flag(flags, Web::WebDriver::SessionFlags::BiDi))
        return;

    // 2. Let webSocketUrl be the result of getting a property named "webSocketUrl" from capabilities.
    auto web_socket_url = capabilities.get("webSocketUrl"sv);

    // 3. If webSocketUrl is undefined, return.
    if (!web_socket_url.has_value())
        return;

    // 4. Assert: webSocketUrl is true.
    VERIFY(web_socket_url->is_bool() && web_socket_url->as_bool());

    // 5. Let listener be the result of start listening for a WebSocket connection given session.
    // https://w3c.github.io/webdriver-bidi/#start-listening-for-a-websocket-connection
    // 1. If there is an existing WebSocket listener in active listeners which the remote end would like to reuse, let
    //    listener be that listener.
    VERIFY(s_websocket_listener.has_value());
    auto const& listener = *s_websocket_listener;

    // 6. Set webSocketUrl to the result of construct a WebSocket URL with listener and session.
    // 7. Set a property on capabilities named "webSocketUrl" to webSocketUrl.
    capabilities.set("webSocketUrl"sv, construct_a_websocket_url(listener, *this));

    // 8. Set session's BiDi flag to true.
    // 9. Append "bidi" to flags.
    flags |= Web::WebDriver::SessionFlags::BiDi;
    m_session_flags = flags;
}

// https://w3c.github.io/webdriver/#dfn-create-a-session
ErrorOr<NonnullRefPtr<Session::NewSessionPromise>> Session::create(JsonValue capabilities, Web::WebDriver::SessionFlags flags)
{
    if (has_flag(flags, Web::WebDriver::SessionFlags::Http) && s_http_session_creation)
        return Error::from_string_literal("An HTTP session is already being created");

    auto state = adopt_ref(*new SessionCreationState(move(capabilities), flags));

    // 1. Let session id be the result of generating a UUID.
    auto session_id = generate_random_uuid();

    // 2. Let session be a new session with session ID session id, and HTTP flag flags contains "http".
    auto session = adopt_ref(*new Session(state->capabilities.as_object(), move(session_id), flags));
    auto start_result = session->start(s_launch_browser_callback);
    if (start_result.is_error()) {
        auto error = start_result.release_error();
        session->close();
        return error;
    }
    auto start_promise = start_result.release_value();
    state->promise->add_child(start_promise);

    start_promise->when_resolved([state, session, flags](Empty&) mutable {
                     auto& capabilities = state->capabilities.as_object();

                     // 3. Let proxy be the result of getting property "proxy" from capabilities and run the substeps of the first matching statement:
                     // -> proxy is a proxy configuration object
                     if (auto proxy = capabilities.get_object("proxy"sv); proxy.has_value()) {
                         // Take implementation-defined steps to set the user agent proxy using the extracted proxy configuration. If the
                         // defined proxy cannot be configured return error with error code session not created. Otherwise set the has
                         // proxy configuration flag to true.
                         session->close();
                         state->promise->reject(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::SessionNotCreated, "Proxy configuration is not yet supported"sv));
                         return;
                     }
                     // -> Otherwise
                     else {
                         // Set a property of capabilities with name "proxy" and a value that is a new JSON Object.
                         capabilities.set("proxy"sv, JsonObject {});
                     }

                     // FIXME: 4. If capabilites has a property named "acceptInsecureCerts", set the endpoint node's accept insecure TLS flag
                     //           to the result of getting a property named "acceptInsecureCerts" from capabilities.

                     // 5. Let user prompt handler capability be the result of getting property "unhandledPromptBehavior" from capabilities.
                     auto user_prompt_handler_capability = capabilities.get_object("unhandledPromptBehavior"sv);

                     // 6. If user prompt handler capability is not undefined, update the user prompt handler with user prompt handler capability.
                     if (user_prompt_handler_capability.has_value())
                         Web::WebDriver::update_the_user_prompt_handler(*user_prompt_handler_capability);

                     session->m_browser_connection->async_set_user_prompt_handler(Web::WebDriver::user_prompt_handler());

                     // 7. Let serialized user prompt handler be serialize the user prompt handler.
                     auto serialized_user_prompt_handler = Web::WebDriver::serialize_the_user_prompt_handler();

                     // 8. Set a property on capabilities with the name "unhandledPromptBehavior", and the value serialized user prompt handler.
                     capabilities.set("unhandledPromptBehavior"sv, move(serialized_user_prompt_handler));

                     // 9. If flags contains "http":
                     if (has_flag(flags, Web::WebDriver::SessionFlags::Http)) {
                         // 1. Let strategy be the result of getting property "pageLoadStrategy" from capabilities. If strategy is a
                         //    string, set the session's page loading strategy to strategy. Otherwise, set the page loading strategy to
                         //    normal and set a property of capabilities with name "pageLoadStrategy" and value "normal".
                         if (auto strategy = capabilities.get_string("pageLoadStrategy"sv); strategy.has_value()) {
                             session->m_page_load_strategy = Web::WebDriver::page_load_strategy_from_string(*strategy);
                             session->m_browser_connection->async_set_page_load_strategy(session->m_page_load_strategy);
                         } else {
                             capabilities.set("pageLoadStrategy"sv, "normal"sv);
                         }

                         // 3. Let strictFileInteractability be the result of getting property "strictFileInteractability" from .
                         //    capabilities. If strictFileInteractability is a boolean, set session's strict file interactability to
                         //    strictFileInteractability.
                         if (auto strict_file_interactiblity = capabilities.get_bool("strictFileInteractability"sv); strict_file_interactiblity.has_value()) {
                             session->m_strict_file_interactiblity = *strict_file_interactiblity;
                             session->m_browser_connection->async_set_strict_file_interactability(session->m_strict_file_interactiblity);
                         }

                         // 4. Let timeouts be the result of getting a property "timeouts" from capabilities. If timeouts is not
                         //    undefined, set session's session timeouts to timeouts.
                         if (auto timeouts = capabilities.get_object("timeouts"sv); timeouts.has_value()) {
                             auto result = session->set_timeouts(*timeouts);
                             if (result.is_error()) {
                                 session->close();
                                 state->promise->reject(result.release_error());
                                 return;
                             }
                         }

                         // 5. Set a property on capabilities with name "timeouts" and value serialize the timeouts configuration with
                         //    session's session timeouts.
                         capabilities.set("timeouts"sv, session->m_timeouts_configuration.value_or_lazy_evaluated([]() {
                             return Web::WebDriver::timeouts_object({});
                         }));
                     }

                     // FIXME: 10. Process any extension capabilities in capabilities in an implementation-defined manner.

                     // 11. Run any WebDriver new session algorithm defined in external specifications, with arguments session, capabilities, and flags.
                     session->run_bidi_new_session_algorithm(capabilities, flags);
                     if (session->is_bidi_session())
                         session->m_browser_connection->async_set_bidi_session(true);

                     // 12. Append session to active sessions.
                     s_sessions.set(session->session_id(), session);

                     // 13. If flags contains "http", append session to active HTTP sessions.
                     if (has_flag(flags, Web::WebDriver::SessionFlags::Http))
                         s_http_sessions.set(session->session_id(), session);

                     // 14. Set the webdriver-active flag to true.
                     // NB: WebContent sets the flag when a page's WebDriver session is created.

                     state->promise->resolve(NewSession { session, move(state->capabilities) });
                 })
        .when_rejected([state, session](Error& error) {
            auto web_driver_error = session_not_created_error(error);
            session->close();
            state->promise->reject(move(web_driver_error));
        });

    return state->promise;
}

Session::Session(JsonObject const& capabilities, String session_id, Web::WebDriver::SessionFlags flags)
    : m_options(capabilities)
    , m_session_id(move(session_id))
    , m_session_flags(flags)
    , m_event_loop(Core::EventLoop::current())
{
}

Session::~Session() = default;

ErrorOr<NonnullRefPtr<Session>, Web::WebDriver::Error> Session::find_session(StringView session_id, Web::WebDriver::SessionFlags session_flags, AllowInvalidWindowHandle allow_invalid_window_handle)
{
    auto& sessions = has_flag(session_flags, Web::WebDriver::SessionFlags::Http) ? s_http_sessions : s_sessions;

    if (auto session = sessions.get(session_id); session.has_value()) {
        if (allow_invalid_window_handle == AllowInvalidWindowHandle::No)
            TRY(session.value()->ensure_current_window_handle_is_valid());

        return *session.release_value();
    }

    return Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidSessionId, "Invalid session id"sv);
}

size_t Session::session_count(Web::WebDriver::SessionFlags session_flags)
{
    if (has_flag(session_flags, Web::WebDriver::SessionFlags::Http))
        return s_http_sessions.size();
    return s_sessions.size();
}

bool Session::has_pending_http_session_creation()
{
    return s_http_session_creation;
}

bool Session::is_active(Session const& session)
{
    auto active_session = s_sessions.get(session.m_session_id);
    return active_session.has_value() && active_session.value() == &session;
}

// https://w3c.github.io/webdriver-bidi/#end-the-session
void Session::end()
{
    // 1. Remove session from active sessions.
    if (has_flag(session_flags(), Web::WebDriver::SessionFlags::Http))
        s_http_sessions.remove(m_session_id);
    s_sessions.remove(m_session_id);

    // 2. If active sessions is empty, set the webdriver-active flag to false.
    // NOTE: This is handled by the WebContent process.
}

NonnullRefPtr<Session::WebDriverPromise> Session::enqueue_http_request(Function<NonnullRefPtr<WebDriverPromise>()> handler)
{
    auto promise = WebDriverPromise::construct();
    m_http_request_queue.enqueue({ move(handler), promise });
    if (m_http_request_queue.size() == 1)
        process_next_http_request();
    return promise;
}

void Session::process_next_http_request()
{
    m_event_loop.deferred_invoke([this_ref = NonnullRefPtr { *this }] {
        auto& request = this_ref->m_http_request_queue.head();
        auto promise = request.promise;

        // https://w3c.github.io/webdriver/#processing-model
        // 1. If session is no longer in the list of active sessions, then send an error with error code invalid session id and return.
        if (!s_sessions.contains(this_ref->m_session_id)) {
            promise->reject(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidSessionId, "Invalid session id"sv));
            this_ref->dequeue_current_http_request();
            return;
        }

        auto request_promise = request.handler();
        promise->add_child(request_promise);
        request_promise->when_resolved([this_ref, promise](JsonValue& value) {
                           promise->resolve(value);
                           this_ref->dequeue_current_http_request();
                       })
            .when_rejected([this_ref, promise](Web::WebDriver::Error& error) {
                promise->reject(Web::WebDriver::Error(error));
                this_ref->dequeue_current_http_request();
            });
    });
}

void Session::dequeue_current_http_request()
{
    (void)m_http_request_queue.dequeue();
    if (!m_http_request_queue.is_empty())
        process_next_http_request();
}

void Session::close_all()
{
    // close() unregisters each session as it runs, so snapshot first. s_sessions holds every
    // session (HTTP ones are also in s_http_sessions), so iterating it alone covers all of them.
    Vector<NonnullRefPtr<Session>> sessions;
    sessions.ensure_capacity(s_sessions.size());
    for (auto& session : s_sessions)
        sessions.unchecked_append(session.value);
    for (auto& session : sessions)
        session->close();
}

void Session::reject_pending_browser_commands()
{
    auto pending_browser_commands = move(m_pending_browser_commands);
    for (auto& command : pending_browser_commands) {
        command.value->reject(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::UnknownError, "Browser connection lost"sv));
    }
}

void Session::arm_browser_startup_timeout(NonnullRefPtr<ServerPromise> promise)
{
    m_start_promise = move(promise);
    static constexpr u32 BROWSER_STARTUP_TIMEOUT_MS = 30'000;
    m_start_timer = Core::Timer::create_single_shot(BROWSER_STARTUP_TIMEOUT_MS, [this] {
        [[maybe_unused]] auto timer_lifetime_guard = move(m_start_timer);
        reject_start_promise(Error::from_string_literal("Timed out waiting for browser startup"));
        close();
    });
    m_start_timer->start();
}

void Session::cancel_browser_startup_timeout()
{
    if (auto timer = move(m_start_timer))
        timer->stop();
}

void Session::reject_start_promise(AK::Error error)
{
    cancel_browser_startup_timeout();
    if (auto start_promise = move(m_start_promise))
        start_promise->reject(move(error));
}

// https://w3c.github.io/webdriver/#dfn-close-the-session
void Session::close()
{
    if (m_closing)
        return;
    m_closing = true;

    // NB: Step 2 removes this session from the active-sessions map — usually dropping the last reference to it. So hold
    //     a strong reference across close() — so removal can't destroy the session while the steps below still use it.
    auto protector = NonnullRefPtr { *this };

    // 1. If session's HTTP flag is set, remove session from active HTTP sessions.
    if (has_flag(session_flags(), Web::WebDriver::SessionFlags::Http))
        s_http_sessions.remove(m_session_id);

    // 2. Remove session from active sessions.
    s_sessions.remove(m_session_id);

    // 3. Perform the following substeps based on the remote end's type:
    // -> Remote end is an endpoint node
    //     1. If the list of active sessions is empty:
    if (s_sessions.is_empty()) {
        // 1. Set the webdriver-active flag to false
        // NOTE: This is handled by the WebContent process.

        // 2. Set the user prompt handler to null.
        Web::WebDriver::set_user_prompt_handler({});

        // FIXME: 3. Unset the accept insecure TLS flag.

        // 4. Reset the has proxy configuration flag to its default value.
        Web::WebDriver::reset_has_proxy_configuration();

        // 5. Optionally, close all top-level browsing contexts, without prompting to unload.
        // NB: The browser process closes its windows when the session tells it to shut down below.
    }
    // -> Remote end is an intermediary node
    //     1. Close the associated session. If this causes an error to occur, complete the remainder of this algorithm
    //        before returning the error.

    // https://w3c.github.io/webdriver-bidi/#cleanup-the-session
    // 1. Close the WebSocket connections with session.
    // https://w3c.github.io/webdriver-bidi/#close-the-websocket-connections
    // 1. For each connection in session's session WebSocket connections:
    //    1. Start the WebSocket closing handshake with connection.
    // NB: Closing a connection removes it from the session, so iterate a copy.
    for (auto* connection : Vector<BiDiConnection*> { m_websocket_connections })
        connection->close();

    // 4. Perform any implementation-specific cleanup steps.
    reject_start_promise(Error::from_string_literal("Session closed during browser startup"));
    reject_pending_browser_commands();
    auto window_handle_callbacks = move(m_window_handle_became_available_callbacks);
    for (auto& callbacks : window_handle_callbacks) {
        for (auto& callback : callbacks.value)
            callback.on_session_close();
    }
    if (m_browser_connection) {
        m_browser_connection->on_close = nullptr;
        m_browser_connection->on_did_create_window = nullptr;
        m_browser_connection->on_did_close_window = nullptr;
        m_browser_connection->on_command_complete = nullptr;
        m_browser_connection->on_bidi_event = nullptr;
        m_browser_connection->async_close_session();
        m_browser_connection = nullptr;
    }

    // The browser may have exited on its own already; its death is one of the triggers for
    // closing the session, so the process being gone is not an error here.
    if (m_browser_process.has_value()) {
        if (auto result = Core::Process::terminate_process(m_browser_process->pid(), Core::Process::TerminationMode::Graceful);
            result.is_error() && result.error().code() != ESRCH) {
            dbgln("Unable to terminate the browser process: {}", result.error());
        }
    }

#if defined(AK_OS_MACOS)
    m_browser_mach_port_server = nullptr;
#else
    if (!m_browser_endpoint.is_empty())
        MUST(FileSystem::remove(m_browser_endpoint, FileSystem::RecursionMode::Disallowed));
#endif
    m_browser_endpoint = {};

    // 5. If an error has occurred in any of the steps above, return the error, otherwise return success with data null.
}

ErrorOr<void> Session::accept_browser_transport(NonnullOwnPtr<IPC::Transport> transport)
{
    if (m_browser_connection)
        return {};

    auto browser_connection = TRY(adopt_nonnull_ref_or_enomem(new (nothrow) BrowserConnection(move(transport))));
    dbgln("WebDriver is connected to the browser process");

    browser_connection->on_close = [this]() {
        // Keep the connection alive through this callback, while preventing close() from sending to the dead connection.
        [[maybe_unused]] auto connection_lifetime_guard = move(m_browser_connection);
        reject_start_promise(Error::from_string_literal("Browser connection lost"));
        reject_pending_browser_commands();
        close();
    };
    browser_connection->on_did_create_window = [this](String window_handle) {
        cancel_browser_startup_timeout();
        if (!m_windows.contains(window_handle))
            m_windows.set(window_handle, Session::Window { window_handle });
        if (m_current_window_handle.is_empty())
            m_current_window_handle = window_handle;

        dispatch_window_handle_became_available_callbacks(window_handle);
        if (auto start_promise = move(m_start_promise))
            start_promise->resolve({});
    };
    browser_connection->on_did_close_window = [this](String window_handle) {
        remove_window(window_handle);
    };
    browser_connection->on_command_complete = [this](u64 command_id, Web::WebDriver::Response response) {
        auto promise = m_pending_browser_commands.take(command_id);
        if (!promise.has_value()) {
            m_browser_connection->did_misbehave("Received response for unknown WebDriver command ID");
            return;
        }

        if (response.is_error())
            promise.value()->reject(response.release_error());
        else
            promise.value()->resolve(response.release_value());
    };
    browser_connection->on_bidi_event = [this](String method, JsonValue params, Vector<String> related_top_level_traversable_ids) {
        did_receive_bidi_event(move(method), move(params), move(related_top_level_traversable_ids));
    };

    m_browser_connection = move(browser_connection);
#if defined(AK_OS_MACOS)
    m_browser_mach_port_server = nullptr;
#else
    m_event_loop.deferred_invoke([session = NonnullRefPtr { *this }] {
        session->m_browser_server = nullptr;
    });
#endif
    return {};
}

NonnullRefPtr<Session::WebDriverPromise> Session::perform_browser_command(Function<void(u64 command_id)> send_command)
{
    auto promise = WebDriverPromise::construct();
    if (!m_browser_connection) {
        promise->reject(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::UnknownError, "Browser connection lost"sv));
        return promise;
    }

    auto command_id = m_next_browser_command_id++;
    m_pending_browser_commands.set(command_id, promise);

    send_command(command_id);
    return promise;
}

NonnullRefPtr<Session::WebDriverPromise> continue_with_promise(NonnullRefPtr<Session::WebDriverPromise> source, Function<NonnullRefPtr<Session::WebDriverPromise>()> continuation)
{
    auto promise = Session::WebDriverPromise::construct();
    promise->add_child(source);
    source->when_resolved([promise, continuation = move(continuation)](JsonValue&) mutable {
              auto continuation_promise = continuation();
              promise->add_child(continuation_promise);
              continuation_promise->when_resolved([promise](JsonValue& value) {
                                      promise->resolve(value);
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

NonnullRefPtr<Session::WebDriverPromise> Session::navigate_to(URL::URL url)
{
    auto navigate_promise = perform_browser_command([this, url = move(url)](u64 command_id) {
        m_browser_connection->async_navigate_to(command_id, m_current_window_handle, url);
    });
    auto navigation_completion_promise = continue_with_promise(move(navigate_promise), [this_ref = NonnullRefPtr { *this }] {
        return this_ref->wait_for_navigation_completion();
    });

    // https://w3c.github.io/webdriver/#dfn-navigate-to
    // 8. Run these steps, but abort when timer's timeout fired flag is set:
    //    3. Set the current browsing context with session and current top-level browsing context.
    return continue_with_promise(move(navigation_completion_promise), [this_ref = NonnullRefPtr { *this }] {
        return this_ref->reset_current_browsing_context();
    });
}

NonnullRefPtr<Session::WebDriverPromise> Session::refresh()
{
    auto refresh_promise = perform_browser_command([this](u64 command_id) {
        m_browser_connection->async_refresh(command_id, m_current_window_handle);
    });
    auto navigation_completion_promise = continue_with_promise(move(refresh_promise), [this_ref = NonnullRefPtr { *this }] {
        return this_ref->wait_for_navigation_completion();
    });

    // https://w3c.github.io/webdriver/#dfn-refresh
    // 5. Set the current browsing context with session and session's current top-level browsing context.
    return continue_with_promise(move(navigation_completion_promise), [this_ref = NonnullRefPtr { *this }] {
        return this_ref->reset_current_browsing_context();
    });
}

NonnullRefPtr<Session::WebDriverPromise> Session::wait_for_navigation_completion()
{
    if (m_page_load_strategy == Web::WebDriver::PageLoadStrategy::None) {
        auto promise = WebDriverPromise::construct();
        promise->resolve(JsonValue {});
        return promise;
    }

    return perform_browser_command([this](u64 command_id) {
        m_browser_connection->async_wait_for_navigation_completion(command_id, m_current_window_handle, page_load_timeout());
    });
}

NonnullRefPtr<Session::WebDriverPromise> Session::traverse_history(i32 delta, HandleUserPrompts handle_user_prompts)
{
    return perform_browser_command([this, delta, handle_user_prompts](u64 command_id) {
        m_browser_connection->async_traverse_history(command_id, m_current_window_handle, delta, handle_user_prompts == HandleUserPrompts::Yes);
    });
}

NonnullRefPtr<Session::WebDriverPromise> Session::session_history()
{
    return perform_browser_command([this](u64 command_id) {
        m_browser_connection->async_get_session_history(command_id, m_current_window_handle);
    });
}

NonnullRefPtr<Session::WebDriverPromise> Session::load_url(URL::URL url)
{
    return perform_browser_command([this, url = move(url)](u64 command_id) {
        m_browser_connection->async_load_url(command_id, m_current_window_handle, url);
    });
}

NonnullRefPtr<Session::WebDriverPromise> Session::run_content_command(StringView name, JsonValue payload, Vector<String> arguments)
{
    return run_content_command(Web::WebDriver::SessionBrowsingContext::Current, name, move(payload), move(arguments));
}

NonnullRefPtr<Session::WebDriverPromise> Session::run_top_level_content_command(StringView name, JsonValue payload, Vector<String> arguments)
{
    return run_content_command(Web::WebDriver::SessionBrowsingContext::CurrentTopLevel, name, move(payload), move(arguments));
}

NonnullRefPtr<Session::WebDriverPromise> Session::run_content_command(Web::WebDriver::SessionBrowsingContext browsing_context, StringView name, JsonValue payload, Vector<String> arguments)
{
    return perform_browser_command([this, browsing_context, name = MUST(String::from_utf8(name)), payload = move(payload), arguments = move(arguments)](u64 command_id) mutable {
        m_browser_connection->async_run_content_command(command_id, m_current_window_handle, browsing_context, move(name), move(payload), move(arguments));
    });
}

NonnullRefPtr<Session::WebDriverPromise> Session::reset_current_browsing_context()
{
    return perform_browser_command([this](u64 command_id) {
        m_browser_connection->async_set_current_browsing_context_to_top_level(command_id, m_current_window_handle);
    });
}

NonnullRefPtr<Session::WebDriverPromise> Session::switch_to_parent_frame()
{
    return perform_browser_command([this](u64 command_id) {
        m_browser_connection->async_switch_to_parent_frame(command_id, m_current_window_handle);
    });
}

void Session::remove_window(StringView window_handle)
{
    if (!m_windows.remove(window_handle))
        return;

    if (auto promises = m_window_closed_promises.take(window_handle); promises.has_value()) {
        for (auto& promise : *promises)
            promise->resolve(JsonValue {});
    }

    if (m_current_window_handle == window_handle)
        m_current_window_handle = "NoSuchWindowPleaseSelectANewOne"_string;

    // https://w3c.github.io/webdriver-bidi/#event-browsingContext-contextDestroyed
    // 2. Let subscriptions to remove be a set.
    // 3. For each subscription in session's subscriptions:
    //    1. If subscription's top-level traversable ids contains navigable's navigable id;
    //       1. Remove navigable's navigable id from subscription's top-level traversable ids.
    //       2. If subscription's top-level traversable ids is empty:
    //          1. Append subscription to subscriptions to remove.
    // 4. Remove subscriptions to remove from session's subscriptions.
    m_subscriptions.remove_all_matching([&](Subscription& subscription) {
        if (!subscription.top_level_traversable_ids.remove(window_handle))
            return false;
        return subscription.top_level_traversable_ids.is_empty();
    });

    if (m_windows.is_empty())
        close();
}

ErrorOr<void> Session::create_server()
{
#if defined(AK_OS_WINDOWS)
    static_assert(IsSame<IPC::Transport, IPC::TransportSocketWindows>, "Need to handle other IPC transports here");
#elif defined(AK_OS_MACOS)
    static_assert(IsSame<IPC::Transport, IPC::TransportMachPort>, "Need to handle other IPC transports here");
#else
    static_assert(IsSame<IPC::Transport, IPC::TransportSocket>, "Need to handle other IPC transports here");
#endif

    dbgln("Listening for WebDriver connection on {}", m_browser_endpoint);

#if defined(AK_OS_MACOS)
    m_browser_mach_port_server = make<IPC::MachBootstrapListener>(m_browser_endpoint);
    if (!m_browser_mach_port_server->is_initialized())
        return Error::from_string_literal("Failed to initialize Mach port server for WebDriver");

    m_browser_mach_port_server->on_bootstrap_request = [this](auto request) {
        auto result = m_transport_bootstrap_server.handle_bootstrap_request(request.pid, move(request.reply_port));
        if (result.is_error()) {
            m_event_loop.deferred_invoke([this, error = result.release_error()]() mutable {
                reject_start_promise(move(error));
            });
            return;
        }

        result.release_value().visit(
            [](IPC::TransportBootstrapMachServer::ChildTransportHandled) {
                VERIFY_NOT_REACHED();
            },
            [this](IPC::TransportBootstrapMachServer::OnDemandTransport& transport) {
                m_event_loop.deferred_invoke([this, transport = move(transport.ports)]() mutable {
                    if (auto result = accept_browser_transport(make<IPC::Transport>(move(transport.receive_right), move(transport.send_right))); result.is_error())
                        reject_start_promise(result.release_error());
                });
            });
    };

    return {};
#else
    (void)FileSystem::remove(m_browser_endpoint, FileSystem::RecursionMode::Disallowed);

    auto server = Core::LocalServer::construct();
    server->listen(m_browser_endpoint);

    server->on_accept = [this](auto client_socket) {
        auto maybe_transport = IPC::Transport::from_socket(move(client_socket));
        if (maybe_transport.is_error()) {
            reject_start_promise(maybe_transport.release_error());
            return;
        }
        if (auto result = accept_browser_transport(maybe_transport.release_value()); result.is_error())
            reject_start_promise(result.release_error());
    };

    server->on_accept_error = [this](auto error) {
        if (m_browser_connection)
            return;
        reject_start_promise(move(error));
    };

    m_browser_server = server;
    return {};
#endif
}

ErrorOr<NonnullRefPtr<Session::ServerPromise>> Session::start(LaunchBrowserCallback const& launch_browser_callback)
{
    auto promise = ServerPromise::construct();

#if defined(AK_OS_MACOS)
    m_browser_endpoint = ByteString::formatted("{}.{}", WebView::mach_server_name_for_process("WebDriver"sv, Core::System::getpid()), m_session_id);
#else
    m_browser_endpoint = ByteString::formatted("{}/webdriver/session_{}_{}", TRY(Core::StandardPaths::runtime_directory()), Core::System::getpid(), m_session_id);
#endif
    TRY(create_server());

    m_browser_process = TRY(launch_browser_callback(m_browser_endpoint, m_options.headless));
    arm_browser_startup_timeout(promise);
    return promise;
}

// 9.1 Get Timeouts, https://w3c.github.io/webdriver/#dfn-get-timeouts
Web::WebDriver::Response Session::get_timeouts() const
{
    // 1. Let timeouts be the timeouts object for session’s timeouts configuration
    // 2. Return success with data timeouts.
    if (m_timeouts_configuration.has_value())
        return JsonValue { *m_timeouts_configuration };
    return JsonValue { Web::WebDriver::timeouts_object({}) };
}

// 9.2 Set Timeouts, https://w3c.github.io/webdriver/#dfn-set-timeouts
Web::WebDriver::Response Session::set_timeouts(JsonValue payload)
{
    // FIXME: Spec issue: As written, the spec replaces the timeouts configuration with the newly provided values. But
    //        all other implementations update the existing configuration with any new values instead. WPT relies on
    //        this behavior, and sends us one timeout value at time.
    //        https://github.com/w3c/webdriver/issues/1596

    // 1. Let timeouts be the result of trying to JSON deserialize as a timeouts configuration the request’s parameters.
    // 2. Make the session timeouts the new timeouts.
    TRY(Web::WebDriver::json_deserialize_as_a_timeouts_configuration_into(payload, m_timeouts));
    m_timeouts_configuration = Web::WebDriver::timeouts_object(m_timeouts);

    if (m_browser_connection)
        m_browser_connection->async_set_timeouts_configuration(*m_timeouts_configuration);

    // 3. Return success with data null.
    return JsonValue {};
}

Optional<u64> Session::page_load_timeout() const
{
    Optional<u64> page_load_timeout = Web::WebDriver::TimeoutsConfiguration {}.page_load_timeout;
    if (m_timeouts_configuration.has_value() && m_timeouts_configuration->is_object()) {
        if (auto value = m_timeouts_configuration->as_object().get("pageLoad"sv); value.has_value()) {
            if (value->is_null())
                page_load_timeout = {};
            else
                page_load_timeout = value->get_integer<u64>().value_or(*page_load_timeout);
        }
    }
    return page_load_timeout;
}

// 11.2 Close Window, https://w3c.github.io/webdriver/#dfn-close-window
NonnullRefPtr<Session::WebDriverPromise> Session::close_window()
{
    auto promise = WebDriverPromise::construct();

    // 3. Close the current top-level browsing context.
    auto close_window_promise = run_top_level_content_command("close_window"sv);
    promise->add_child(close_window_promise);
    close_window_promise->when_resolved([this_ref = NonnullRefPtr { *this }, promise](JsonValue&) {
                            // 4. If there are no more open top-level browsing contexts, then close the session.
                            auto closed_window_handle = this_ref->m_current_window_handle;
                            this_ref->remove_window(closed_window_handle);

                            // 5. Return the result of running the remote end steps for the Get Window Handles command.
                            auto result = this_ref->get_window_handles();
                            if (result.is_error())
                                promise->reject(result.release_error());
                            else
                                promise->resolve(result.release_value());
                        })
        .when_rejected([promise](Web::WebDriver::Error& error) {
            promise->reject(Web::WebDriver::Error(error));
        });
    return promise;
}

// 11.3 Switch to Window, https://w3c.github.io/webdriver/#dfn-switch-to-window
NonnullRefPtr<Session::WebDriverPromise> Session::switch_to_window(StringView handle)
{
    auto promise = WebDriverPromise::construct();

    // 4. If handle is equal to the associated window handle for some top-level browsing context, let context be the that
    //    browsing context, and set the current top-level browsing context with session and context.
    //    Otherwise, return error with error code no such window.
    if (auto it = m_windows.find(handle); it != m_windows.end()) {
        m_current_window_handle = it->key;
    } else {
        promise->reject(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::NoSuchWindow, "Window not found"sv));
        return promise;
    }

    // 5. Update any implementation-specific state that would result from the user selecting the current
    //    browsing context for interaction, without altering OS-level focus.
    return perform_browser_command([this](u64 command_id) {
        m_browser_connection->async_switch_to_window(command_id, m_current_window_handle);
    });
}

// 11.4 Get Window Handles, https://w3c.github.io/webdriver/#dfn-get-window-handles
Web::WebDriver::Response Session::get_window_handles() const
{
    // 1. Let handles be a JSON List.
    JsonArray handles {};

    // 2. For each top-level browsing context in the remote end, push the associated window handle onto handles.
    for (auto const& window_handle : m_windows.keys()) {
        handles.must_append(JsonValue(window_handle));
    }

    // 3. Return success with data handles.
    return JsonValue { move(handles) };
}

void Session::dispatch_window_handle_became_available_callbacks(String const& window_handle)
{
    // Registrations are one-shot: take() erases them before invoking their callbacks.
    auto callbacks = m_window_handle_became_available_callbacks.take(window_handle);
    if (!callbacks.has_value())
        return;

    for (auto& callback : callbacks.value())
        callback.callback();
}

Session::WindowHandleBecameAvailableCallbackID Session::add_window_handle_became_available_callback(String const& handle, Function<void()> callback, Function<void()> on_session_close)
{
    auto id = m_next_window_handle_became_available_callback_id++;
    m_window_handle_became_available_callbacks.ensure(handle).append({ id, move(callback), move(on_session_close) });
    return id;
}

void Session::remove_window_handle_became_available_callback(String const& handle, WindowHandleBecameAvailableCallbackID id)
{
    auto callbacks = m_window_handle_became_available_callbacks.find(handle);
    if (callbacks == m_window_handle_became_available_callbacks.end())
        return;

    callbacks->value.remove_all_matching([id](auto const& callback) {
        return callback.id == id;
    });

    if (callbacks->value.is_empty())
        m_window_handle_became_available_callbacks.remove(callbacks);
}

ErrorOr<void, Web::WebDriver::Error> Session::ensure_current_window_handle_is_valid() const
{
    if (!m_windows.contains(m_current_window_handle))
        return Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::NoSuchWindow, "Window not found"sv);

    return {};
}

NonnullRefPtr<Session::WebDriverPromise> Session::get_browsing_context_tree(Optional<String> root, Optional<u64> max_depth)
{
    return perform_browser_command([this, root = move(root), max_depth](u64 command_id) {
        m_browser_connection->async_get_browsing_context_tree(command_id, root, max_depth);
    });
}

NonnullRefPtr<Session::WebDriverPromise> Session::get_top_level_traversables_for_contexts(Vector<String> context_ids)
{
    return perform_browser_command([this, context_ids = move(context_ids)](u64 command_id) mutable {
        m_browser_connection->async_get_top_level_traversables_for_contexts(command_id, move(context_ids));
    });
}

NonnullRefPtr<Session::WebDriverPromise> Session::run_content_command_in_window(String const& window_handle, StringView name, JsonValue payload)
{
    return perform_browser_command([this, window_handle, name = MUST(String::from_utf8(name)), payload = move(payload)](u64 command_id) mutable {
        m_browser_connection->async_run_content_command(command_id, window_handle, Web::WebDriver::SessionBrowsingContext::CurrentTopLevel, move(name), move(payload), {});
    });
}

NonnullRefPtr<Session::WebDriverPromise> Session::wait_for_window_handle(String handle)
{
    auto promise = WebDriverPromise::construct();
    if (has_window_handle(handle)) {
        promise->resolve(JsonValue { handle });
        return promise;
    }

    static constexpr u32 CONNECTION_TIMEOUT_MS = 5000;
    struct WaitState : public RefCounted<WaitState> {
        WindowHandleBecameAvailableCallbackID callback_id { 0 };
        RefPtr<Core::Timer> timer;
        bool settled { false };
    };
    auto wait_state = adopt_ref(*new WaitState);
    auto this_ref = NonnullRefPtr { *this };
    wait_state->timer = Core::Timer::create_single_shot(CONNECTION_TIMEOUT_MS, [promise, this_ref, handle, wait_state] {
        if (wait_state->settled)
            return;
        wait_state->settled = true;
        Core::deferred_invoke([this_ref, handle, wait_state] {
            this_ref->remove_window_handle_became_available_callback(handle, wait_state->callback_id);
            wait_state->timer = nullptr;
        });
        promise->reject(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::Timeout, "Timed out waiting for window handle"sv));
    });

    wait_state->callback_id = add_window_handle_became_available_callback(
        handle,
        [promise, handle, wait_state] {
            if (wait_state->settled)
                return;
            auto timer = move(wait_state->timer);
            wait_state->settled = true;
            if (timer)
                timer->stop();
            promise->resolve(JsonValue { handle });
        },
        [promise, wait_state] {
            if (wait_state->settled)
                return;
            wait_state->settled = true;
            if (auto timer = move(wait_state->timer))
                timer->stop();
            promise->reject(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::UnknownError, "Browser connection lost"sv));
        });
    wait_state->timer->start();
    return promise;
}

NonnullRefPtr<Session::WebDriverPromise> Session::wait_for_window_closed(String handle)
{
    auto promise = WebDriverPromise::construct();
    if (!has_window_handle(handle)) {
        promise->resolve(JsonValue {});
        return promise;
    }
    m_window_closed_promises.ensure(handle).append(promise);
    return promise;
}

// https://w3c.github.io/webdriver-bidi/#command-browsingContext-navigate
NonnullRefPtr<Session::WebDriverPromise> Session::navigate_context(String context_id, String url, StringView wait_condition)
{
    // 12. Return the result of await a navigation with navigable, request and wait condition.
    // https://w3c.github.io/webdriver-bidi/#await-a-navigation
    // 2. Navigate navigable with resource request, and using navigable's active document as the source Document,
    //    with navigation id navigation id, and history handling behavior history handling.
    // NB: A top-level traversable is navigated by the browser process, any other navigable by the process hosting its
    //     document; both answer with the navigation's id.
    NonnullRefPtr<WebDriverPromise> navigate_promise = [&]() -> NonnullRefPtr<WebDriverPromise> {
        if (has_window_handle(context_id)) {
            return perform_browser_command([this, context_id, url](u64 command_id) {
                m_browser_connection->async_bidi_navigate_to(command_id, context_id, url);
            });
        }

        JsonObject parameters;
        parameters.set("url"sv, url);
        return run_bidi_content_command(context_id, "browsingContext.navigate"_string, move(parameters));
    }();

    auto promise = WebDriverPromise::construct();
    promise->add_child(navigate_promise);
    navigate_promise->when_resolved([this_ref = NonnullRefPtr { *this }, promise, url, wait_condition = MUST(String::from_utf8(wait_condition))](JsonValue& result) {
                        auto navigation_id = result.is_string() ? result.as_string() : result.as_object().get_string("navigation"sv).value_or({});
                        auto navigated_url = result.is_object() ? result.as_object().get_string("url"sv).value_or(url) : url;

                        auto awaited = this_ref->await_a_navigation(move(navigation_id), move(navigated_url), wait_condition);
                        promise->add_child(awaited);
                        awaited->when_resolved([promise](JsonValue& body) { promise->resolve(move(body)); })
                            .when_rejected([promise](Web::WebDriver::Error& error) { promise->reject(Web::WebDriver::Error(error)); });
                    })
        .when_rejected([promise](Web::WebDriver::Error& error) {
            promise->reject(Web::WebDriver::Error(error));
        });
    return promise;
}

// https://w3c.github.io/webdriver-bidi/#await-a-navigation
NonnullRefPtr<Session::WebDriverPromise> Session::await_a_navigation(String navigation_id, String url, StringView wait_condition)
{
    auto result = [](String const& navigation_id, String const& url) {
        // Let body be a map matching the browsingContext.NavigateResult production, with the navigation field set
        // to navigation id, and the url field set to the result of the URL serializer given navigation status's url.
        JsonObject body;
        body.set("navigation"sv, navigation_id);
        body.set("url"sv, url);
        return JsonValue { move(body) };
    };

    // 8. If wait condition is "committed", let event name be "committed".
    // AD-HOC: Answer once the navigation has started instead, as other browsers do: A client that asked not to wait
    //         gets to act, closing the window say, while the navigation's response is still on its way.
    if (wait_condition == "none"sv)
        return WebDriverPromise::resolved(result(navigation_id, url));

    // 9. Otherwise, if wait condition is "interactive", let event name be "domContentLoaded".
    // 10. Otherwise, let event name be "load".
    auto event_name = wait_condition == "interactive"sv ? "browsingContext.domContentLoaded"_string : "browsingContext.load"_string;

    // 11. Let (event received, status) be await given «event name, "download started", "navigation aborted",
    //     "navigation failed"» and navigation id.
    // NB: A navigation that only changed the fragment completed with its fragmentNavigated event.
    auto matches = [&](JsonObject const& event) {
        if (event.get_string("navigation"sv) != navigation_id)
            return false;
        auto method = event.get_string("method"sv).value();
        return method == event_name || method.is_one_of("browsingContext.fragmentNavigated"sv, "browsingContext.navigationFailed"sv, "browsingContext.navigationAborted"sv);
    };
    for (auto const& event : m_recent_navigation_events) {
        if (!matches(event))
            continue;
        auto method = event.get_string("method"sv).value();
        if (method.is_one_of("browsingContext.navigationFailed"sv, "browsingContext.navigationAborted"sv))
            return WebDriverPromise::rejected(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::UnknownError, "Navigation failed"sv));
        return WebDriverPromise::resolved(result(navigation_id, event.get_string("url"sv).value_or(url)));
    }

    auto promise = WebDriverPromise::construct();
    PendingNavigation pending { navigation_id, event_name, promise, nullptr };
    pending.timer = Core::Timer::create_single_shot(page_load_timeout().value_or(300'000), [this, promise, navigation_id] {
        m_pending_navigations.remove_all_matching([&](auto const& pending) { return pending.promise.ptr() == promise.ptr(); });
        promise->reject(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::Timeout, "Navigation timed out"sv));
    });
    pending.timer->start();
    m_pending_navigations.append(move(pending));
    return promise;
}

Session::NavigationEventDisposition Session::settle_pending_navigation(String const& method, JsonValue const& params)
{
    if (!method.starts_with_bytes("browsingContext."sv) || !params.is_object())
        return NavigationEventDisposition::Emit;
    auto navigation_id = params.as_object().get_string("navigation"sv);
    if (!navigation_id.has_value())
        return NavigationEventDisposition::Emit;

    // Both the browser process and the process hosting the document can notice that a navigation failed; one report
    // is enough.
    static constexpr u32 RECENT_NAVIGATION_EVENTS_LIMIT = 64;
    JsonObject event = params.as_object();
    event.set("method"sv, method);
    if (method.is_one_of("browsingContext.navigationFailed"sv, "browsingContext.navigationAborted"sv)) {
        auto already_reported = m_recent_navigation_events.find_if([&](auto const& recent) {
            return recent.get_string("navigation"sv) == navigation_id && recent.get_string("method"sv).has_value() && recent.get_string("method"sv)->is_one_of("browsingContext.navigationFailed"sv, "browsingContext.navigationAborted"sv, "browsingContext.load"sv);
        });
        if (!already_reported.is_end())
            return NavigationEventDisposition::Duplicate;
    }
    if (m_recent_navigation_events.size() >= RECENT_NAVIGATION_EVENTS_LIMIT)
        m_recent_navigation_events.remove(0);
    m_recent_navigation_events.append(event);

    m_pending_navigations.remove_all_matching([&](PendingNavigation& pending) {
        if (pending.navigation_id != *navigation_id)
            return false;
        bool failed = method.is_one_of("browsingContext.navigationFailed"sv, "browsingContext.navigationAborted"sv);
        if (method != pending.event_name && method != "browsingContext.fragmentNavigated"sv && !failed)
            return false;

        pending.timer->stop();
        if (failed) {
            pending.promise->reject(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::UnknownError, "Navigation failed"sv));
        } else {
            JsonObject body;
            body.set("navigation"sv, *navigation_id);
            body.set("url"sv, params.as_object().get_string("url"sv).value_or({}));
            pending.promise->resolve(JsonValue { move(body) });
        }
        return true;
    });
    return NavigationEventDisposition::Emit;
}

// https://w3c.github.io/webdriver-bidi/#command-script-addPreloadScript
String Session::add_preload_script(JsonObject preload_script)
{
    // 10. Let script be the string representation of a UUID.
    auto script = generate_random_uuid();
    preload_script.set("script"sv, script);

    // 11. Let preload script map be session's preload script map.
    // 12. Set preload script map[script] to a struct with function declaration function declaration, arguments
    //     arguments, contexts navigables, sandbox sandbox, and user contexts user contexts.
    m_preload_scripts.set(script, move(preload_script));
    push_preload_scripts();
    return script;
}

// https://w3c.github.io/webdriver-bidi/#command-script-removePreloadScript
ErrorOr<void, Web::WebDriver::Error> Session::remove_preload_script(StringView script)
{
    // 3. If preload script map does not contain script, return error with error code no such script.
    if (!m_preload_scripts.remove(script))
        return Web::WebDriver::Error { 404, "no such script"_string, "Unknown preload script"_string, {} };

    // 4. Remove script from preload script map.
    push_preload_scripts();
    return {};
}

void Session::push_preload_scripts()
{
    if (!m_browser_connection)
        return;
    JsonArray scripts;
    for (auto const& [script, preload_script] : m_preload_scripts)
        scripts.must_append(preload_script);
    m_browser_connection->async_set_preload_scripts(move(scripts));
}

NonnullRefPtr<Session::WebDriverPromise> Session::set_permission(JsonValue descriptor, String state, String origin, String embedded_origin)
{
    return perform_browser_command([this, descriptor = move(descriptor), state = move(state), origin = move(origin), embedded_origin = move(embedded_origin)](u64 command_id) mutable {
        m_browser_connection->async_set_permission(command_id, move(descriptor), move(state), move(origin), move(embedded_origin));
    });
}

NonnullRefPtr<Session::WebDriverPromise> Session::run_bidi_content_command(String context_id, String method, JsonValue parameters)
{
    return perform_browser_command([this, context_id = move(context_id), method = move(method), parameters = move(parameters)](u64 command_id) mutable {
        m_browser_connection->async_run_bidi_content_command(command_id, move(context_id), move(method), move(parameters));
    });
}

void Session::add_websocket_connection(Badge<BiDiConnection>, BiDiConnection& connection)
{
    m_websocket_connections.append(&connection);
}

void Session::remove_websocket_connection(Badge<BiDiConnection>, BiDiConnection& connection)
{
    m_websocket_connections.remove_all_matching([&](auto* other) { return other == &connection; });
}

// https://w3c.github.io/webdriver-bidi/#emit-an-event
void Session::emit_event(JsonValue const& body)
{
    // 1. Assert: body matches the Event production.
    VERIFY(body.is_object() && body.as_object().get_string("type"sv) == "event"sv);

    // 2. Let serialized be the result of serialize an infra value to JSON bytes given body.
    // 3. For each connection in session's session WebSocket connections:
    //    1. Send a WebSocket message comprised of serialized over connection.
    for (auto* connection : m_websocket_connections)
        connection->send_event(body);
}

// https://w3c.github.io/webdriver-bidi/#event-is-enabled
bool Session::event_is_enabled(StringView event_name, ReadonlySpan<String> top_level_traversable_ids) const
{
    // 1. Let top-level traversables be get top-level traversables with navigables.
    // NB: The browser reports events against the top-level traversables of their navigables.

    // 2. For each subscription in session's subscriptions:
    for (auto const& subscription : m_subscriptions) {
        // 1. If subscription's event names do not contain event name, continue.
        if (!subscription.event_names.contains(event_name))
            continue;

        // 2. If subscription is global return true.
        if (subscription.is_global())
            return true;

        // 3. If user context ids is not empty:
        if (!subscription.user_context_ids.is_empty()) {
            // 1. For each navigable in top-level traversables:
            //    1. If subscription's user context ids contains navigable's associated user context's user context
            //       id, return true.
            // NB: Every navigable belongs to the default user context.
            if (!top_level_traversable_ids.is_empty() && subscription.user_context_ids.contains("default"sv))
                return true;
        }
        // 4. Otherwise:
        else {
            // 1. Let subscription top-level traversables be get navigables by ids with subscription's top-level
            //    traversable ids.
            // 2. If the intersection of top-level traversables and subscription top-level traversables is not empty
            //    return true.
            for (auto const& id : top_level_traversable_ids) {
                if (subscription.top_level_traversable_ids.contains(id))
                    return true;
            }
        }
    }

    // 3. Return false.
    return false;
}

// https://w3c.github.io/webdriver-bidi/#set-of-top-level-traversables-for-which-an-event-is-enabled
Vector<String> Session::top_level_traversables_for_which_an_event_is_enabled(StringView event_name) const
{
    // 1. Let result be a new set.
    HashTable<String> result;

    // 2. For each subscription in session's subscriptions:
    for (auto const& subscription : m_subscriptions) {
        // 1. If subscription's event names does not contain event name, continue.
        if (!subscription.event_names.contains(event_name))
            continue;

        // 2. If subscription's is global:
        // 3. Otherwise, if user context ids is not empty:
        // NB: Every navigable belongs to the default user context, so both cover every top-level traversable.
        if (subscription.is_global() || !subscription.user_context_ids.is_empty()) {
            // 1. For each traversable in remote end's top-level traversables:
            //    1. Append traversable to result.
            for (auto const& window_handle : m_windows.keys())
                result.set(window_handle);

            // 2. Break.
            break;
        }

        // 4. Otherwise:
        // 1. Let top-level traversables be get navigables by ids with subscription's top-level traversable ids.
        // 2. Append each item of top-level traversables to result.
        for (auto const& id : subscription.top_level_traversable_ids) {
            if (m_windows.contains(id))
                result.set(id);
        }
    }

    // 3. Return result.
    return result.values();
}

String Session::add_subscription(Vector<String> event_names, Vector<String> top_level_traversable_ids, Vector<String> user_context_ids)
{
    Subscription subscription;

    // Let subscription be a subscription with subscription id set to the string representation of a UUID, event names
    // set to event names, top-level traversable ids set to top-level traversable context ids and user context ids set
    // to input user context ids.
    subscription.subscription_id = generate_random_uuid();
    for (auto& name : event_names)
        subscription.event_names.set(move(name));
    for (auto& id : top_level_traversable_ids)
        subscription.top_level_traversable_ids.set(move(id));
    for (auto& id : user_context_ids)
        subscription.user_context_ids.set(move(id));

    auto subscription_id = subscription.subscription_id;

    // Append subscription to session's subscriptions.
    m_subscriptions.append(move(subscription));

    // Append subscription's subscription id to session's known subscription ids.
    m_known_subscription_ids.set(subscription_id);

    return subscription_id;
}

// https://w3c.github.io/webdriver-bidi/#command-session-subscribe
NonnullRefPtr<Session::WebDriverPromise> Session::subscribe_to_events(Vector<String> events, Optional<Vector<String>> contexts, Optional<Vector<String>> user_contexts)
{
    // 1. Let event names be an empty set.
    HashTable<String> event_names;

    // 2. For each entry name in command parameters["events"], let event names be the union of event names and the
    //    result of trying to obtain a set of event names with name.
    for (auto const& name : events) {
        auto names = BiDi::obtain_a_set_of_event_names(name);
        if (names.is_error())
            return WebDriverPromise::rejected(names.release_error());
        for (auto& event_name : names.value())
            event_names.set(move(event_name));
    }

    // 3. Let input user context ids be create a set with command parameters[userContexts].
    auto input_user_context_ids = user_contexts.value_or({});

    // 4. Let input context ids be create a set with command parameters[contexts].
    auto input_context_ids = contexts.value_or({});

    // 5. If input user context ids is not empty and input context ids is not empty, return error with error code
    //    invalid argument.
    if (!input_user_context_ids.is_empty() && !input_context_ids.is_empty())
        return WebDriverPromise::rejected(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, "Parameters 'contexts' and 'userContexts' are mutually exclusive"sv));

    auto complete_subscription = [this_ref = NonnullRefPtr { *this }, event_names = move(event_names), input_user_context_ids](Vector<String> subscription_navigables, Vector<String> top_level_traversable_context_ids) -> NonnullRefPtr<WebDriverPromise> {
        // 11. Let subscription be a subscription with subscription id set to the string representation of a UUID,
        //     event names set to event names, top-level traversable ids set to top-level traversable context ids and
        //     user context ids set to input user context ids.
        // 12. Let subscribe step events be a new map.
        HashMap<String, Vector<String>> subscribe_step_events;

        // 13. For each event name in the event names:
        for (auto const& event_name : event_names) {
            // 1. If the event with event name event name does not define remote end subscribe steps, continue;
            if (!event_name.is_one_of("log.entryAdded"sv, "browsingContext.contextCreated"sv))
                continue;

            // 2. Let existing navigables be a set of top-level traversables for which an event is enabled with session
            //    and event name.
            auto existing_navigables = this_ref->top_level_traversables_for_which_an_event_is_enabled(event_name);

            // 3. Set subscribe step events[event name] to set difference of subscription navigables and existing
            //    navigables.
            Vector<String> navigables;
            for (auto const& navigable : subscription_navigables) {
                if (!existing_navigables.contains_slow(navigable))
                    navigables.append(navigable);
            }
            subscribe_step_events.set(event_name, move(navigables));
        }

        // 14. Append subscription to session's subscriptions.
        // 15. Append subscription's subscription id to session's known subscription ids.
        auto subscription_id = this_ref->add_subscription(event_names.values(), move(top_level_traversable_context_ids), input_user_context_ids);

        // 16. Sort in ascending order subscribe step events using the following less than algorithm given two
        //     entries with keys event name one and event name two:
        // NB: Only one event defines subscribe steps.

        // 17. If subscription is global, let include global be true, otherwise let include global be false.
        auto include_global = this_ref->m_subscriptions.last().is_global();

        // 18. For each event name → navigables in subscribe step events:
        for (auto const& [event_name, navigables] : subscribe_step_events) {
            // 1. Run the remote end subscribe steps for the event with event name event name given session,
            //    navigables and include global.
            if (event_name != "log.entryAdded"sv)
                continue;

            // https://w3c.github.io/webdriver-bidi/#event-log-entryAdded
            // The remote end subscribe steps, with subscribe priority 10, given session, navigables and include global
            // are:
            // 1. For each navigable id → events in session's log event buffer:
            this_ref->m_log_event_buffer.remove_all_matching([&](auto const& navigable_id, auto& events) {
                // 2. If maybe context is an error, remove navigable id from log event buffer and continue.
                if (!this_ref->m_windows.contains(navigable_id))
                    return true;

                // 5. If include global is true and top level navigable is not in navigables, or if include global is
                //    false and top level navigable is in navigables:
                auto in_navigables = navigables.contains_slow(navigable_id);
                if (include_global == in_navigables)
                    return false;

                // 1. For each (event, other navigables) in events:
                //    1. Emit an event with session and event.
                for (auto const& event : events)
                    this_ref->emit_event(event);
                return true;
            });
        }

        // 19. Let body be a new map matching the session.SubscribeResult production, with the subscription field set
        //     to subscription's subscription id.
        JsonObject body;
        body.set("subscription"sv, move(subscription_id));

        // 20. Return success with data body.
        // https://w3c.github.io/webdriver-bidi/#event-browsingContext-contextCreated
        // The remote end subscribe steps, with subscribe priority 1, given session, navigables and include global are:
        // 1. For each navigable in navigables:
        //    1. Recursively emit context created events given session and navigable.
        // NB: The browser process holds the navigables, so these steps complete before the response is sent.
        if (event_names.contains("browsingContext.contextCreated"sv)) {
            auto promise = WebDriverPromise::construct();
            auto events = this_ref->emit_context_created_events_for_subscription(move(subscription_navigables), include_global);
            promise->add_child(events);
            events->when_resolved([promise, body = move(body)](JsonValue&) mutable { promise->resolve(move(body)); })
                .when_rejected([promise](Web::WebDriver::Error& error) { promise->reject(Web::WebDriver::Error(error)); });
            return promise;
        }
        return WebDriverPromise::resolved(move(body));
    };

    // 6. Let subscription navigables be a set.
    // 7. Let top-level traversable context ids be a set.
    // 8. If input context ids is not empty:
    if (!input_context_ids.is_empty()) {
        // 1. Let navigables be the result of trying to get valid navigables by ids with input context ids.
        // 2. Set subscription navigables be get top-level traversables with navigables.
        // 3. For each navigable in subscription navigables:
        //    1. Append navigable's navigable id to top-level traversable context ids.
        // NB: The browser process holds the navigables; it answers with their top-level traversables' ids.
        auto promise = WebDriverPromise::construct();
        auto lookup = get_top_level_traversables_for_contexts(move(input_context_ids));
        promise->add_child(lookup);
        lookup->when_resolved([promise, complete_subscription = move(complete_subscription)](JsonValue& value) mutable {
                  Vector<String> top_level_traversable_context_ids;
                  value.as_array().for_each([&](JsonValue const& id) {
                      top_level_traversable_context_ids.append(id.as_string());
                  });

                  auto result = complete_subscription(top_level_traversable_context_ids, top_level_traversable_context_ids);
                  promise->add_child(result);
                  result->when_resolved([promise](JsonValue& body) { promise->resolve(move(body)); })
                      .when_rejected([promise](Web::WebDriver::Error& error) { promise->reject(Web::WebDriver::Error(error)); });
              })
            .when_rejected([promise](Web::WebDriver::Error& error) {
                promise->reject(Web::WebDriver::Error(error));
            });
        return promise;
    }

    // 9. Otherwise, if input user context ids is not empty:
    if (!input_user_context_ids.is_empty()) {
        // 1. For each user context id of input user context ids:
        for (auto const& user_context_id : input_user_context_ids) {
            // 1. Let user context be get user context with user context id.
            // 2. If user context is null, return error with error code no such user context.
            // NB: The default user context is the only one.
            if (user_context_id != "default"sv)
                return WebDriverPromise::rejected(Web::WebDriver::Error { 404, "no such user context"_string, MUST(String::formatted("Unknown user context: {}", user_context_id)), {} });

            // 3. For each top-level traversable in the list of all top-level traversables whose associated user
            //    context is user context:
            //    1. Append top-level traversable to subscription navigables.
        }
        return complete_subscription(m_windows.keys(), {});
    }

    // 10. Otherwise, set subscription navigables to a set of all top-level traversables in the remote end.
    return complete_subscription(m_windows.keys(), {});
}

// https://w3c.github.io/webdriver-bidi/#command-session-unsubscribe
ErrorOr<void, Web::WebDriver::Error> Session::unsubscribe_from_events(Vector<String> events)
{
    // 1. Let event names be an empty set.
    HashTable<String> event_names;

    // 2. For each entry name in command parameters["events"], let event names be the union of event names and the
    //    result of trying to obtain a set of event names with name.
    for (auto const& name : events) {
        for (auto& event_name : TRY(BiDi::obtain_a_set_of_event_names(name)))
            event_names.set(move(event_name));
    }

    // 3. Let new subscriptions to be a list.
    Vector<Subscription> new_subscriptions;

    // 4. Let matched events to be a set.
    HashTable<String> matched_events;

    // 5. For each subscription of session's subscriptions:
    for (auto& subscription : m_subscriptions) {
        // 1. If intersection of subscription's event names and event names is an empty set:
        auto has_intersection = any_of(subscription.event_names, [&](auto const& name) { return event_names.contains(name); });
        if (!has_intersection) {
            // 1. Append subscription to new subscriptions.
            new_subscriptions.append(move(subscription));
            // 2. Continue.
            continue;
        }

        // 2. If subscription is not global:
        if (!subscription.is_global()) {
            // 1. Append subscription to new subscriptions.
            new_subscriptions.append(move(subscription));
            // 2. Continue.
            continue;
        }

        // 3. Let subscription event names be clone of subscription's event names.
        auto subscription_event_names = subscription.event_names;

        // 4. For each event name of event names:
        for (auto const& event_name : event_names) {
            // 1. If subscription event names contains event name:
            if (subscription_event_names.contains(event_name)) {
                // 1. Append event name to matched events.
                matched_events.set(event_name);
                // 2. Remove event name from subscription event names.
                subscription_event_names.remove(event_name);
            }
        }

        // 5. If subscription event names is not empty:
        if (!subscription_event_names.is_empty()) {
            // 1. Let cloned subscription be a subscription with subscription id set to subscription's subscription
            //    id, event names set to a new set containing subscription event names.
            // 2. Append cloned subscription to new subscriptions.
            subscription.event_names = move(subscription_event_names);
            new_subscriptions.append(move(subscription));
        }
    }

    // 6. If matched events is not equal to event names, return error with error code invalid argument.
    if (matched_events.size() != event_names.size())
        return Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, "No global subscription matches the given events"sv);

    // 7. Set session's subscriptions to new subscriptions.
    m_subscriptions = move(new_subscriptions);
    return {};
}

ErrorOr<void, Web::WebDriver::Error> Session::unsubscribe_from_subscriptions(Vector<String> subscription_ids)
{
    // 1. Let subscriptions be create a set with command parameters[subscriptions].
    HashTable<String> subscriptions;
    for (auto& id : subscription_ids)
        subscriptions.set(move(id));

    // 2. Let unknown subscription ids to set difference between subscriptions and session's known subscription ids.
    // 3. If unknown subscription ids is not empty:
    //    1. Return error with error code invalid argument.
    for (auto const& id : subscriptions) {
        if (!m_known_subscription_ids.contains(id))
            return Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, "No subscription found"sv);
    }

    // 4. Let subscriptions to remove be an empty set.
    // 5. For each subscription in session's subscriptions:
    //    1. If subscriptions contains subscription's subscription id:
    //       1. Append subscription to subscriptions to remove.
    // 7. Remove each item in subscriptions to remove from session's subscriptions.
    m_subscriptions.remove_all_matching([&](auto const& subscription) {
        return subscriptions.contains(subscription.subscription_id);
    });

    // 6. Set session's known subscription ids to set difference between session's known subscription ids and
    //    subscriptions.
    for (auto const& id : subscriptions)
        m_known_subscription_ids.remove(id);

    return {};
}

// https://w3c.github.io/webdriver-bidi/#recursively-emit-context-created-events
NonnullRefPtr<Session::WebDriverPromise> Session::emit_context_created_events_for_subscription(Vector<String> top_level_traversable_ids, bool is_global)
{
    auto promise = WebDriverPromise::construct();
    auto tree = get_browsing_context_tree({}, {});
    promise->add_child(tree);
    tree->when_resolved([this_ref = NonnullRefPtr { *this }, promise, top_level_traversable_ids = move(top_level_traversable_ids), is_global](JsonValue& result) {
            auto emit_recursively = [&](auto& self, JsonObject const& info, JsonValue const& parent_id) -> void {
                // https://w3c.github.io/webdriver-bidi/#emit-a-context-created-event
                // 1. Let params be the result of get the navigable info given navigable, 0, and true.
                JsonObject params = info;
                params.set("children"sv, JsonValue {});
                params.set("parent"sv, parent_id);
                // 2. Set params["hasPlannedNavigation"] to has planned navigation.
                params.set("hasPlannedNavigation"sv, false);

                // 4. Let body be a map matching the browsingContext.ContextCreated production, with the params field
                //    set to params.
                JsonObject body;
                body.set("type"sv, "event"sv);
                body.set("method"sv, "browsingContext.contextCreated"sv);
                body.set("params"sv, move(params));

                // 5. Emit an event with session and body.
                this_ref->emit_event(body);

                // 2. For each child navigable, child, of navigable:
                //    1. Recursively emit context created events given session and child.
                if (auto children = info.get_array("children"sv); children.has_value()) {
                    children->for_each([&](JsonValue const& child) {
                        self(self, child.as_object(), info.get("context"sv).value());
                    });
                }
            };

            result.as_object().get_array("contexts"sv)->for_each([&](JsonValue const& context) {
                auto const& info = context.as_object();
                if (is_global || top_level_traversable_ids.contains_slow(info.get_string("context"sv).value()))
                    emit_recursively(emit_recursively, info, JsonValue {});
            });
            promise->resolve(JsonObject {});
        })
        .when_rejected([promise](Web::WebDriver::Error& error) { promise->reject(Web::WebDriver::Error(error)); });
    return promise;
}

void Session::did_receive_bidi_event(String method, JsonValue params, Vector<String> related_top_level_traversable_ids)
{
    // A navigation this session is waiting on completes with its events, whether or not they are subscribed to.
    if (settle_pending_navigation(method, params) == NavigationEventDisposition::Duplicate)
        return;

    JsonObject body;
    body.set("type"sv, "event"sv);
    body.set("method"sv, method);
    body.set("params"sv, move(params));

    // For each session in the set of sessions for which an event is enabled given event name and related navigables:
    //   1. Emit an event with session and body.
    if (!is_bidi_session())
        return;

    if (event_is_enabled(method, related_top_level_traversable_ids)) {
        emit_event(body);
        return;
    }

    // https://w3c.github.io/webdriver-bidi/#event-log-entryAdded
    // Otherwise, buffer a log event with session, related browsing contexts, and body.
    if (method != "log.entryAdded"sv)
        return;

    // https://w3c.github.io/webdriver-bidi/#buffer-a-log-event
    for (auto const& navigable_id : related_top_level_traversable_ids)
        m_log_event_buffer.ensure(navigable_id).append(body);
}

}
