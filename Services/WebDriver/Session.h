/*
 * Copyright (c) 2022, Florent Castelli <florent.castelli@gmail.com>
 * Copyright (c) 2022, Linus Groh <linusg@serenityos.org>
 * Copyright (c) 2022-2025, Tim Flynn <trflynn89@ladybird.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Badge.h>
#include <AK/Error.h>
#include <AK/HashTable.h>
#include <AK/IPv4Address.h>
#include <AK/JsonValue.h>
#include <AK/NonnullRefPtr.h>
#include <AK/Queue.h>
#include <AK/RefCounted.h>
#include <AK/RefPtr.h>
#include <AK/ScopeGuard.h>
#include <AK/String.h>
#include <AK/Vector.h>
#include <LibCore/EventLoop.h>
#if !defined(AK_OS_MACOS)
#    include <LibCore/LocalServer.h>
#else
#    include <LibIPC/MachBootstrapListener.h>
#    include <LibIPC/TransportBootstrapMach.h>
#endif
#include <LibCore/Process.h>
#include <LibCore/Promise.h>
#include <LibWebCommon/WebDriver/Capabilities.h>
#include <LibWebCommon/WebDriver/Error.h>
#include <LibWebCommon/WebDriver/Response.h>
#include <LibWebCommon/WebDriver/SessionBrowsingContext.h>
#include <LibWebCommon/WebDriver/TimeoutsConfiguration.h>
#include <WebDriver/BrowserConnection.h>
#include <WebDriver/Client.h>
#include <WebDriver/Forward.h>

namespace WebDriver {

class Session : public RefCounted<Session> {
public:
    using WebDriverPromise = Core::Promise<JsonValue, Web::WebDriver::Error>;

    struct NewSession {
        NonnullRefPtr<Session> session;
        JsonValue capabilities;
    };
    using NewSessionPromise = Core::Promise<NewSession, Web::WebDriver::Error>;

    static void set_launch_browser_callback(LaunchBrowserCallback);
    // https://w3c.github.io/webdriver-bidi/#websocket-listener
    static void set_websocket_listener(IPv4Address host, u16 port);

    static ErrorOr<NonnullRefPtr<NewSessionPromise>> create(JsonValue capabilities, Web::WebDriver::SessionFlags flags);
    ~Session();

    enum class AllowInvalidWindowHandle {
        No,
        Yes,
    };
    static ErrorOr<NonnullRefPtr<Session>, Web::WebDriver::Error> find_session(StringView session_id, Web::WebDriver::SessionFlags = Web::WebDriver::SessionFlags::Default, AllowInvalidWindowHandle = AllowInvalidWindowHandle::No);
    static size_t session_count(Web::WebDriver::SessionFlags);
    static bool has_pending_http_session_creation();
    static bool is_active(Session const&);
    static void close_all();

    NonnullRefPtr<WebDriverPromise> enqueue_http_request(Function<NonnullRefPtr<WebDriverPromise>()>);

    struct Window {
        String handle;
    };

    void close();
    // https://w3c.github.io/webdriver-bidi/#end-the-session
    void end();

    String session_id() const { return m_session_id; }
    Web::WebDriver::SessionFlags session_flags() const { return m_session_flags; }
    String const& current_window_handle() const { return m_current_window_handle; }
    bool test_hooks_enabled() const { return m_options.enable_test_hooks; }

    // https://w3c.github.io/webdriver-bidi/#bidi-session
    bool is_bidi_session() const { return has_flag(m_session_flags, Web::WebDriver::SessionFlags::BiDi); }
    void add_websocket_connection(Badge<BiDiConnection>, BiDiConnection&);
    void remove_websocket_connection(Badge<BiDiConnection>, BiDiConnection&);

    // https://w3c.github.io/webdriver-bidi/#events
    NonnullRefPtr<WebDriverPromise> subscribe_to_events(Vector<String> events, Optional<Vector<String>> contexts, Optional<Vector<String>> user_contexts);
    ErrorOr<void, Web::WebDriver::Error> unsubscribe_from_events(Vector<String> events);
    ErrorOr<void, Web::WebDriver::Error> unsubscribe_from_subscriptions(Vector<String> subscription_ids);
    bool event_is_enabled(StringView event_name, ReadonlySpan<String> top_level_traversable_ids) const;
    void emit_event(JsonValue const& body);
    void did_receive_bidi_event(String method, JsonValue params, Vector<String> related_top_level_traversable_ids);

    NonnullRefPtr<WebDriverPromise> get_browsing_context_tree(Optional<String> root, Optional<u64> max_depth);
    NonnullRefPtr<WebDriverPromise> run_bidi_content_command(String context_id, String method, JsonValue parameters);
    NonnullRefPtr<WebDriverPromise> run_content_command_in_window(String const& window_handle, StringView name, JsonValue payload = {});
    // Resolves once the browser has reported the window with the given handle, or rejects after a timeout.
    NonnullRefPtr<WebDriverPromise> wait_for_window_handle(String handle);
    // Resolves once the browser has reported that the window with the given handle closed.
    NonnullRefPtr<WebDriverPromise> wait_for_window_closed(String handle);
    // https://w3c.github.io/webdriver-bidi/#command-browsingContext-navigate
    NonnullRefPtr<WebDriverPromise> navigate_context(String context_id, String url, StringView wait_condition);

    // https://w3c.github.io/webdriver-bidi/#preload-script-map
    String add_preload_script(JsonObject preload_script);
    ErrorOr<void, Web::WebDriver::Error> remove_preload_script(StringView script);
    Vector<String> window_handles() const { return m_windows.keys(); }
    // https://w3c.github.io/permissions/#webdriver-bidi-command-permissions-setPermission
    NonnullRefPtr<WebDriverPromise> set_permission(JsonValue descriptor, String state, String origin, String embedded_origin);

    bool has_window_handle(StringView handle) const { return m_windows.contains(handle); }
    using WindowHandleBecameAvailableCallbackID = u64;
    // Registrations are dispatched at most once. Callers must remove them when handling a timeout.
    WindowHandleBecameAvailableCallbackID add_window_handle_became_available_callback(String const& handle, Function<void()> callback, Function<void()> on_session_close);
    void remove_window_handle_became_available_callback(String const& handle, WindowHandleBecameAvailableCallbackID);

    Web::WebDriver::Response get_timeouts() const;
    Web::WebDriver::Response set_timeouts(JsonValue);
    NonnullRefPtr<WebDriverPromise> close_window();
    NonnullRefPtr<WebDriverPromise> switch_to_window(StringView);
    Web::WebDriver::Response get_window_handles() const;

    enum class HandleUserPrompts {
        No,
        Yes,
    };
    NonnullRefPtr<WebDriverPromise> navigate_to(URL::URL);
    NonnullRefPtr<WebDriverPromise> refresh();
    NonnullRefPtr<WebDriverPromise> wait_for_navigation_completion();
    NonnullRefPtr<WebDriverPromise> traverse_history(i32 delta, HandleUserPrompts);
    NonnullRefPtr<WebDriverPromise> session_history();
    NonnullRefPtr<WebDriverPromise> load_url(URL::URL);
    NonnullRefPtr<WebDriverPromise> switch_to_parent_frame();
    NonnullRefPtr<WebDriverPromise> run_content_command(StringView name, JsonValue payload = {}, Vector<String> arguments = {});
    NonnullRefPtr<WebDriverPromise> run_top_level_content_command(StringView name, JsonValue payload = {}, Vector<String> arguments = {});
    ErrorOr<void, Web::WebDriver::Error> ensure_current_window_handle_is_valid() const;

private:
    Session(JsonObject const& capabilities, String session_id, Web::WebDriver::SessionFlags flags);

    using ServerPromise = Core::Promise<Empty>;

    ErrorOr<NonnullRefPtr<ServerPromise>> start(LaunchBrowserCallback const&);
    void run_bidi_new_session_algorithm(JsonObject& capabilities, Web::WebDriver::SessionFlags& flags);
    NonnullRefPtr<WebDriverPromise> emit_context_created_events_for_subscription(Vector<String> top_level_traversable_ids, bool is_global);
    ErrorOr<void> accept_browser_transport(NonnullOwnPtr<IPC::Transport>);
    NonnullRefPtr<WebDriverPromise> perform_browser_command(Function<void(u64 command_id)> send_command);
    Optional<u64> page_load_timeout() const;
    NonnullRefPtr<WebDriverPromise> reset_current_browsing_context();
    NonnullRefPtr<WebDriverPromise> run_content_command(Web::WebDriver::SessionBrowsingContext, StringView name, JsonValue payload, Vector<String> arguments);
    NonnullRefPtr<WebDriverPromise> get_top_level_traversables_for_contexts(Vector<String> context_ids);
    ErrorOr<void> create_server();
    void remove_window(StringView window_handle);
    void dispatch_window_handle_became_available_callbacks(String const& window_handle);
    void reject_pending_browser_commands();
    void arm_browser_startup_timeout(NonnullRefPtr<ServerPromise>);
    void cancel_browser_startup_timeout();
    void reject_start_promise(AK::Error);
    void process_next_http_request();
    void dequeue_current_http_request();

    Web::WebDriver::LadybirdOptions m_options;

    String m_session_id;
    Web::WebDriver::SessionFlags m_session_flags { Web::WebDriver::SessionFlags::Default };

    HashMap<String, Window> m_windows;
    String m_current_window_handle;

    RefPtr<BrowserConnection> m_browser_connection;
    bool m_closing { false };

    u64 m_next_browser_command_id { 1 };
    HashMap<u64, NonnullRefPtr<WebDriverPromise>> m_pending_browser_commands;
    RefPtr<ServerPromise> m_start_promise;
    RefPtr<Core::Timer> m_start_timer;

    struct PendingHttpRequest {
        Function<NonnullRefPtr<WebDriverPromise>()> handler;
        NonnullRefPtr<WebDriverPromise> promise;
    };

    // https://w3c.github.io/webdriver/#dfn-request-queue
    // An HTTP session has an associated request queue which is a queue of requests that are currently awaiting
    // processing.
    Queue<PendingHttpRequest> m_http_request_queue;

    ByteString m_browser_endpoint;
    Optional<Core::Process> m_browser_process;
    Core::EventLoop& m_event_loop;

#if defined(AK_OS_MACOS)
    OwnPtr<IPC::MachBootstrapListener> m_browser_mach_port_server;
    IPC::TransportBootstrapMachServer m_transport_bootstrap_server;
#else
    RefPtr<Core::LocalServer> m_browser_server;
#endif

    Web::WebDriver::PageLoadStrategy m_page_load_strategy { Web::WebDriver::PageLoadStrategy::Normal };
    Web::WebDriver::TimeoutsConfiguration m_timeouts;
    Optional<JsonValue> m_timeouts_configuration;
    bool m_strict_file_interactiblity { false };

    struct WindowHandleBecameAvailableCallback {
        WindowHandleBecameAvailableCallbackID id;
        Function<void()> callback;
        Function<void()> on_session_close;
    };
    HashMap<String, Vector<WindowHandleBecameAvailableCallback>> m_window_handle_became_available_callbacks;
    HashMap<String, Vector<NonnullRefPtr<WebDriverPromise>>> m_window_closed_promises;

    // https://w3c.github.io/webdriver-bidi/#await-a-navigation
    struct PendingNavigation {
        String navigation_id;
        String event_name;
        NonnullRefPtr<WebDriverPromise> promise;
        RefPtr<Core::Timer> timer;
    };
    NonnullRefPtr<WebDriverPromise> await_a_navigation(String navigation_id, String url, StringView wait_condition);
    enum class NavigationEventDisposition {
        Emit,
        Duplicate,
    };
    NavigationEventDisposition settle_pending_navigation(String const& method, JsonValue const& params);
    Vector<PendingNavigation> m_pending_navigations;
    // Navigation events the browser reported before their navigation command was answered.
    Vector<JsonObject> m_recent_navigation_events;

    void push_preload_scripts();
    HashMap<String, JsonObject> m_preload_scripts;
    WindowHandleBecameAvailableCallbackID m_next_window_handle_became_available_callback_id { 1 };

    // https://w3c.github.io/webdriver-bidi/#session-websocket-connections
    // The connections hold the session; they remove themselves when their WebSocket closes.
    Vector<BiDiConnection*> m_websocket_connections;

    // https://w3c.github.io/webdriver-bidi/#subscription
    struct Subscription {
        String subscription_id;
        HashTable<String> event_names;
        HashTable<String> top_level_traversable_ids;
        HashTable<String> user_context_ids;

        // https://w3c.github.io/webdriver-bidi/#subscription-global
        bool is_global() const { return top_level_traversable_ids.is_empty() && user_context_ids.is_empty(); }
    };
    Vector<String> top_level_traversables_for_which_an_event_is_enabled(StringView event_name) const;
    String add_subscription(Vector<String> event_names, Vector<String> top_level_traversable_ids, Vector<String> user_context_ids);

    // https://w3c.github.io/webdriver-bidi/#subscriptions
    Vector<Subscription> m_subscriptions;
    // https://w3c.github.io/webdriver-bidi/#known-subscription-ids
    HashTable<String> m_known_subscription_ids;

    // https://w3c.github.io/webdriver-bidi/#log-event-buffer
    // NB: Keyed by top-level traversable id rather than navigable id, as that is what the browser reports events
    //     against; the difference only shows for frames navigated before the local end subscribes.
    HashMap<String, Vector<JsonValue>> m_log_event_buffer;
};

NonnullRefPtr<Session::WebDriverPromise> continue_with_promise(NonnullRefPtr<Session::WebDriverPromise>, Function<NonnullRefPtr<Session::WebDriverPromise>()>);

}
