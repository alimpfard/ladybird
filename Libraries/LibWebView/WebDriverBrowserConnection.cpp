/*
 * Copyright (c) 2026, Shannon Booth <shannon@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/HashTable.h>
#include <AK/JsonArray.h>
#include <AK/JsonObject.h>
#include <AK/QuickSort.h>
#include <LibCore/EventLoop.h>
#include <LibURL/Parser.h>
#include <LibWebView/Application.h>
#include <LibWebView/CanonicalTraversable.h>
#include <LibWebView/ViewImplementation.h>
#include <LibWebView/WebContentClient.h>
#include <LibWebView/WebDriverBrowserConnection.h>
#if defined(AK_OS_MACOS)
#    include <LibIPC/TransportBootstrapMach.h>
#else
#    include <LibCore/Socket.h>
#endif

namespace WebView {

ErrorOr<NonnullRefPtr<WebDriverBrowserConnection>> WebDriverBrowserConnection::connect(ByteString const& webdriver_endpoint)
{
#if defined(AK_OS_MACOS)
    auto transport_ports = TRY(IPC::bootstrap_transport_from_mach_server(webdriver_endpoint));
    auto transport = make<IPC::Transport>(move(transport_ports.receive_right), move(transport_ports.send_right));
#else
    auto socket = TRY(Core::LocalSocket::connect(webdriver_endpoint));
    auto transport = TRY(IPC::Transport::from_socket(move(socket)));
#endif
    return adopt_nonnull_ref_or_enomem(new (nothrow) WebDriverBrowserConnection(move(transport)));
}

WebDriverBrowserConnection::WebDriverBrowserConnection(NonnullOwnPtr<IPC::Transport> transport)
    : IPC::ConnectionToServer<WebDriverBrowserClientEndpoint, WebDriverBrowserServerEndpoint>(*this, move(transport))
{
}

void WebDriverBrowserConnection::die()
{
    Application::the().webdriver_browser_connection_died({});
}

void WebDriverBrowserConnection::close_session()
{
    Core::EventLoop::current().quit(0);
}

// 10.1 Navigate To, https://w3c.github.io/webdriver/#navigate-to
void WebDriverBrowserConnection::navigate_to(u64 command_id, String window_handle, URL::URL url)
{
    navigate_window(command_id, move(window_handle), move(url), NavigateResult::NavigationId);
}

void WebDriverBrowserConnection::navigate_window(u64 command_id, String window_handle, URL::URL url, NavigateResult navigate_result)
{
    // 1. If the current top-level browsing context is no longer open, return error with error code no such window.
    auto view = ViewImplementation::find_view_by_handle(window_handle);
    if (!view.has_value()) {
        async_command_complete(command_id, Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::NoSuchWindow, "Window not found"sv));
        return;
    }

    // 4. Handle any user prompts and return its value if it is an error.
    auto strong_this = NonnullRefPtr { *this };
    view->run_webdriver_user_prompt_handling([strong_this, command_id, view_id = view->view_id(), url = move(url), navigate_result](Web::WebDriver::Response response) {
        if (response.is_error()) {
            strong_this->async_command_complete(command_id, move(response));
            return;
        }

        auto view = ViewImplementation::find_view_by_id(view_id);
        if (!view.has_value()) {
            strong_this->async_command_complete(command_id, Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::NoSuchWindow, "Window not found"sv));
            return;
        }

        // 5. Let current URL be the current top-level browsing context’s active document’s URL.
        // NB: The URL replica is ordered after every navigation report WebContent sent before it
        //     answered the user prompt job, so it reflects the document state this command observed.
        auto const& current_url = view->url();

        // FIXME: 6. If current URL and url do not have the same absolute URL:
        // FIXME:     a. If timer has not been started, start a timer. If this algorithm has not completed before timer reaches the session’s session page load timeout in milliseconds, return an error with error code timeout.

        // 7. Navigate the current top-level browsing context to url.
        // NB: "Navigate to a javascript: URL" can evaluate without producing a new Document,
        //     in which case "we will not perform a navigation".
        // https://html.spec.whatwg.org/multipage/browsing-the-web.html#navigate-to-a-javascript:-url
        auto is_same_document_fragment_navigation = url.fragment().has_value()
            && url.equals(current_url, URL::ExcludeFragment::Yes);
        if (url.scheme() != "javascript"sv && !is_same_document_fragment_navigation)
            view->did_start_webdriver_navigation();
        auto navigation_id = view->load_for_webdriver_navigation(url);

        // FIXME: 10. If the current top-level browsing context contains a refresh state pragma directive of time 1 second or less, wait until the refresh timeout has elapsed, a new navigate has begun, and return to the first step of this algorithm.

        // 11. Return success with data null.
        // NB: WebDriver BiDi names the navigation it started by its id, so that is the data; a navigation it asked for
        //     by a relative URL also learns the URL it resolved to.
        if (navigate_result == NavigateResult::NavigationId) {
            strong_this->async_command_complete(command_id, JsonValue { navigation_id.to_utf8() });
            return;
        }
        JsonObject result;
        result.set("navigation"sv, navigation_id.to_utf8());
        result.set("url"sv, url.serialize());
        strong_this->async_command_complete(command_id, JsonValue { move(result) });
    });
}

// https://w3c.github.io/webdriver-bidi/#command-browsingContext-navigate
void WebDriverBrowserConnection::bidi_navigate_to(u64 command_id, String window_handle, String url)
{
    auto view = ViewImplementation::find_view_by_handle(window_handle);
    if (!view.has_value()) {
        async_command_complete(command_id, Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::NoSuchWindow, "Window not found"sv));
        return;
    }

    // 7. Let document be navigable's active document.
    // 8. Let base URL be document's document base URL.
    // 9. Let url record be the result of running the URL parser with input url and base URL base URL.
    // 10. If url record is failure, return error with error code invalid argument.
    // NB: The document's URL stands in for its base URL, which the process hosting the document knows.
    auto url_record = URL::Parser::basic_parse(url, view->webdriver_bidi_navigable_url(view->traversable()));
    if (!url_record.has_value()) {
        async_command_complete(command_id, Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, "Parameter 'url' is not a valid URL"sv));
        return;
    }

    // 11. Navigate navigable to url record with ...
    navigate_window(command_id, move(window_handle), url_record.release_value(), NavigateResult::NavigationIdAndUrl);
}

// 10.5 Refresh, https://w3c.github.io/webdriver/#dfn-refresh
void WebDriverBrowserConnection::refresh(u64 command_id, String window_handle)
{
    // 1. If the current top-level browsing context is no longer open, return error with error code no such window.
    auto view = ViewImplementation::find_view_by_handle(window_handle);
    if (!view.has_value()) {
        async_command_complete(command_id, Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::NoSuchWindow, "Window not found"sv));
        return;
    }

    // 2. Handle any user prompts and return its value if it is an error.
    auto strong_this = NonnullRefPtr { *this };
    view->run_webdriver_user_prompt_handling([strong_this, command_id, view_id = view->view_id()](Web::WebDriver::Response response) {
        if (response.is_error()) {
            strong_this->async_command_complete(command_id, move(response));
            return;
        }

        auto view = ViewImplementation::find_view_by_id(view_id);
        if (!view.has_value()) {
            strong_this->async_command_complete(command_id, Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::NoSuchWindow, "Window not found"sv));
            return;
        }

        // 3. Initiate an overridden reload of the current top-level browsing context’s active document.
        view->did_start_webdriver_navigation();
        view->reload();

        // FIXME: 4. If url is special except for file:
        // FIXME:     1. Try to wait for navigation to complete.
        // FIXME:     2. Try to run the post-navigation checks.

        // 6. Return success with data null.
        strong_this->async_command_complete(command_id, JsonValue {});
    });
}

void WebDriverBrowserConnection::wait_for_navigation_completion(u64 command_id, String window_handle, Optional<u64> page_load_timeout)
{
    auto view = ViewImplementation::find_view_by_handle(window_handle);
    if (!view.has_value()) {
        async_command_complete(command_id, Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::NoSuchWindow, "Window not found"sv));
        return;
    }

    auto strong_this = NonnullRefPtr { *this };
    view->wait_for_webdriver_navigation_completion(page_load_timeout, [strong_this, command_id](Web::WebDriver::Response response) {
        strong_this->async_command_complete(command_id, move(response));
    });
}

void WebDriverBrowserConnection::load_url(u64 command_id, String window_handle, URL::URL url)
{
    auto view = ViewImplementation::find_view_by_handle(window_handle);
    if (!view.has_value()) {
        async_command_complete(command_id, Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::NoSuchWindow, "Window not found"sv));
        return;
    }

    view->did_start_webdriver_navigation();

    auto strong_this = NonnullRefPtr { *this };
    Core::deferred_invoke([strong_this, command_id, view_id = view->view_id(), url = move(url)]() {
        auto view = ViewImplementation::find_view_by_id(view_id);
        if (!view.has_value()) {
            strong_this->async_command_complete(command_id, Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::NoSuchWindow, "Window not found"sv));
            return;
        }

        view->load(url);
        strong_this->async_command_complete(command_id, JsonValue {});
    });
}

void WebDriverBrowserConnection::run_content_command(u64 command_id, String window_handle, Web::WebDriver::SessionBrowsingContext browsing_context, String name, JsonValue payload, Vector<String> arguments)
{
    auto view = ViewImplementation::find_view_by_handle(window_handle);
    if (!view.has_value()) {
        async_command_complete(command_id, Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::NoSuchWindow, "Window not found"sv));
        return;
    }

    view->run_webdriver_content_command(command_id, browsing_context, name, move(payload), move(arguments));
}

// 11.3 Switch to Window, https://w3c.github.io/webdriver/#dfn-switch-to-window
void WebDriverBrowserConnection::switch_to_window(u64 command_id, String window_handle)
{
    // 4. If handle is equal to the associated window handle for some top-level browsing context, let context be the that
    //    browsing context, and set the current top-level browsing context with session and context.
    //    Otherwise, return error with error code no such window.
    auto view = ViewImplementation::find_view_by_handle(window_handle);
    if (!view.has_value()) {
        async_command_complete(command_id, Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::NoSuchWindow, "Window not found"sv));
        return;
    }
    view->set_webdriver_current_browsing_context_to_top_level();

    // 5. Update any implementation-specific state that would result from the user selecting the current
    //    browsing context for interaction, without altering OS-level focus.
    if (view->on_activate_tab)
        view->on_activate_tab();

    async_command_complete(command_id, JsonValue {});
}

void WebDriverBrowserConnection::switch_to_parent_frame(u64 command_id, String window_handle)
{
    auto view = ViewImplementation::find_view_by_handle(window_handle);
    if (!view.has_value()) {
        async_command_complete(command_id, Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::NoSuchWindow, "Window not found"sv));
        return;
    }

    view->switch_webdriver_to_parent_frame([strong_this = NonnullRefPtr { *this }, command_id](Web::WebDriver::Response response) {
        strong_this->async_command_complete(command_id, move(response));
    });
}

void WebDriverBrowserConnection::set_current_browsing_context_to_top_level(u64 command_id, String window_handle)
{
    auto view = ViewImplementation::find_view_by_handle(window_handle);
    if (!view.has_value()) {
        async_command_complete(command_id, Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::NoSuchWindow, "Window not found"sv));
        return;
    }

    view->set_webdriver_current_browsing_context_to_top_level();
    async_command_complete(command_id, JsonValue {});
}

void WebDriverBrowserConnection::set_user_prompt_handler(Web::WebDriver::UserPromptHandler user_prompt_handler)
{
    Application::the().update_webdriver_session_config({}, [user_prompt_handler = move(user_prompt_handler)](auto& config) {
        config.user_prompt_handler = user_prompt_handler;
    });
}

void WebDriverBrowserConnection::set_page_load_strategy(Web::WebDriver::PageLoadStrategy page_load_strategy)
{
    Application::the().update_webdriver_session_config({}, [page_load_strategy](auto& config) {
        config.page_load_strategy = page_load_strategy;
    });
}

void WebDriverBrowserConnection::set_strict_file_interactability(bool strict_file_interactability)
{
    Application::the().update_webdriver_session_config({}, [strict_file_interactability](auto& config) {
        config.strict_file_interactability = strict_file_interactability;
    });
}

void WebDriverBrowserConnection::set_bidi_session(bool bidi_session)
{
    Application::the().update_webdriver_session_config({}, [bidi_session](auto& config) {
        config.bidi_session = bidi_session;
    });
}

void WebDriverBrowserConnection::set_preload_scripts(JsonValue scripts)
{
    Application::the().update_webdriver_session_config({}, [scripts = move(scripts)](auto& config) {
        config.preload_scripts = scripts;
    });
}

void WebDriverBrowserConnection::set_timeouts_configuration(JsonValue timeouts)
{
    Application::the().update_webdriver_session_config({}, [timeouts = move(timeouts)](auto& config) {
        config.timeouts = timeouts;
    });
}

// 10.3 Back, https://w3c.github.io/webdriver/#dfn-back
// 10.4 Forward, https://w3c.github.io/webdriver/#dfn-forward
void WebDriverBrowserConnection::traverse_history(u64 command_id, String window_handle, i32 delta, bool handle_user_prompts)
{
    // 1. If session's current top-level browsing context is no longer open, return error with error code no such window.
    auto view = ViewImplementation::find_view_by_handle(window_handle);
    if (!view.has_value()) {
        async_command_complete(command_id, Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::NoSuchWindow, "Window not found"sv));
        return;
    }

    auto strong_this = NonnullRefPtr { *this };
    auto run_traversal = [strong_this, command_id, view_id = view->view_id(), delta]() {
        // Defer the traversal, so its cancelation checks can safely call back into the WebContent
        // process whose message dispatch we may currently be inside.
        Core::deferred_invoke([strong_this, command_id, view_id, delta]() {
            auto view = ViewImplementation::find_view_by_id(view_id);
            if (!view.has_value()) {
                strong_this->async_command_complete(command_id, Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::NoSuchWindow, "Window not found"sv));
                return;
            }

            view->traverse_the_history_by_delta(delta, CheckForCancelation::Yes, [strong_this, command_id]() {
                strong_this->async_command_complete(command_id, JsonValue {});
            });
        });
    };

    if (!handle_user_prompts) {
        run_traversal();
        return;
    }

    // 2. Try to handle any user prompts with session.
    view->run_webdriver_user_prompt_handling([strong_this, command_id, run_traversal = move(run_traversal)](Web::WebDriver::Response response) mutable {
        if (response.is_error()) {
            strong_this->async_command_complete(command_id, move(response));
            return;
        }

        run_traversal();
    });
}

void WebDriverBrowserConnection::get_session_history(u64 command_id, String window_handle)
{
    auto view = ViewImplementation::find_view_by_handle(window_handle);
    if (!view.has_value()) {
        async_command_complete(command_id, Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::NoSuchWindow, "Window not found"sv));
        return;
    }

    JsonObject result;
    result.set("ui"sv, view->webdriver_session_history());
    async_command_complete(command_id, JsonValue { move(result) });
}

// https://w3c.github.io/webdriver-bidi/#command-browsingContext-getTree
void WebDriverBrowserConnection::get_browsing_context_tree(u64 command_id, Optional<String> root, Optional<u64> max_depth)
{
    // 5. Let navigables infos be an empty list.
    JsonArray navigables_infos;

    // 4. If root id is not null, append the result of trying to get a navigable given root id to navigables.
    //    Otherwise append all top-level traversables to navigables.
    // 6. For each navigable of navigables:
    //    1. Let info be the result of get the navigable info given navigable, max depth, and true.
    //    2. Append info to navigables infos
    if (root.has_value()) {
        auto context = ViewImplementation::find_webdriver_bidi_context(*root);
        if (!context.has_value()) {
            async_command_complete(command_id, Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::NoSuchFrame, "No such browsing context"sv));
            return;
        }
        navigables_infos.must_append(context->view.webdriver_bidi_navigable_info(context->navigable, max_depth, true));
    } else {
        // NB: Listed in the order the windows were opened, as clients expect the window they just opened last.
        Vector<ViewImplementation*> views;
        ViewImplementation::for_each_view([&](ViewImplementation& view) {
            views.append(&view);
            return IterationDecision::Continue;
        });
        quick_sort(views, [](auto* a, auto* b) { return a->view_id() < b->view_id(); });
        for (auto* view : views)
            navigables_infos.must_append(view->webdriver_bidi_navigable_info(view->traversable(), max_depth, true));
    }

    // 7. Let body be a map matching the browsingContext.GetTreeResult production, with the contexts field set to
    //    navigables infos.
    JsonObject body;
    body.set("contexts"sv, move(navigables_infos));

    // 8. Return success with data body.
    async_command_complete(command_id, JsonValue { move(body) });
}

// https://w3c.github.io/webdriver-bidi/#get-valid-navigables-by-ids
// https://w3c.github.io/webdriver-bidi/#get-top-level-traversables
void WebDriverBrowserConnection::get_top_level_traversables_for_contexts(u64 command_id, Vector<String> context_ids)
{
    HashTable<String> top_level_traversable_ids;

    for (auto const& context_id : context_ids) {
        auto context = ViewImplementation::find_webdriver_bidi_context(context_id);
        if (!context.has_value()) {
            async_command_complete(command_id, Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::NoSuchFrame, "No such browsing context"sv));
            return;
        }
        top_level_traversable_ids.set(context->view.handle());
    }

    JsonArray result;
    for (auto const& id : top_level_traversable_ids)
        result.must_append(id);
    async_command_complete(command_id, JsonValue { move(result) });
}

void WebDriverBrowserConnection::run_bidi_content_command(u64 command_id, String context_id, String method, JsonValue parameters)
{
    // https://w3c.github.io/webdriver-bidi/#get-a-navigable
    // 2. If there is no navigable with navigable id navigable id return error with error code no such frame
    auto context = ViewImplementation::find_webdriver_bidi_context(context_id);
    if (!context.has_value()) {
        async_command_complete(command_id, Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::NoSuchFrame, "No such browsing context"sv));
        return;
    }

    context->view.run_webdriver_bidi_command(command_id, context->navigable.id(), method, move(parameters));
}

// https://w3c.github.io/permissions/#webdriver-bidi-command-permissions-setPermission
void WebDriverBrowserConnection::set_permission(u64 command_id, JsonValue descriptor, String state, String origin, String embedded_origin)
{
    // 11. Set a permission with typedDescriptor, state, key, and user agent.
    // NB: Every process hosting web content keeps its own permission store, so each one sets the permission.
    WebContentClient::for_each_client([&](WebContentClient& client) {
        client.for_each_page([&](WebContentPage& page) {
            page.async_webdriver_set_permission(descriptor, state, origin, embedded_origin);
            return IterationDecision::Continue;
        });
        return IterationDecision::Continue;
    });

    async_command_complete(command_id, JsonValue {});
}

}
