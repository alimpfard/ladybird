/*
 * Copyright (c) 2025, Ali Mohammad Pur <mpfard@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "LibCore/Environment.h"

#include <AK/NonnullOwnPtr.h>
#include <AK/Vector.h>
#include <LibCore/ArgsParser.h>
#include <LibCore/ResourceImplementationFile.h>
#include <LibJS/Lexer.h>
#include <LibJS/Runtime/StringPrototype.h>
#include <LibLine/Editor.h>
#include <LibMain/Main.h>
#include <LibWeb/PixelUnits.h>
#include <LibWebView/Application.h>
#include <LibWebView/ConsoleOutput.h>
#include <LibWebView/Utilities.h>
#include <LibWebView/ViewImplementation.h>

class ReplWebView;

Vector<String> g_repl_statements;
static RefPtr<Line::Editor> s_editor;
static int s_repl_line_level = 0;
static bool s_keep_running_repl = true;
static int s_exit_code = 0;
static bool s_piece_done = false;
ReplWebView* g_main_web_view = nullptr;
StringView s_evaluate_script;
Vector<ByteString> s_script_paths;
bool g_use_modules = false;

static Web::DevicePixelRect s_pretend_screen_rect { 0, 0, 3840, 2160 }; // 4k@0x0
constexpr static StringView s_service_request_init = "\u{1F6E0}\u{FE0F}req:"sv;

class ReplWebView final : public WebView::ViewImplementation {
public:
    static NonnullOwnPtr<ReplWebView> create(Core::AnonymousBuffer theme, Web::DevicePixelSize window_size)
    {
        auto view = adopt_own(*new ReplWebView(move(theme), window_size));
        view->initialize_client(CreateNewClient::Yes);
        return view;
    }
    static NonnullOwnPtr<ReplWebView> create_child(ReplWebView& parent, u64 page_index)
    {
        auto view = adopt_own(*new ReplWebView(parent.m_theme, parent.m_viewport_size));
        view->m_client_state.client = parent.client();
        view->m_client_state.page_index = page_index;
        view->initialize_client(CreateNewClient::No);
        return view;
    }

private:
    ReplWebView(Core::AnonymousBuffer theme, Web::DevicePixelSize viewport_size);

    virtual void update_zoom() override { }
    virtual void initialize_client(CreateNewClient create_new_client) override
    {
        ViewImplementation::initialize_client(create_new_client);
        client().async_update_system_theme(m_client_state.page_index, m_theme);
        client().async_set_viewport_size(m_client_state.page_index, viewport_size());
        client().async_set_window_size(m_client_state.page_index, viewport_size());
        client().async_update_screen_rects(m_client_state.page_index, { { s_pretend_screen_rect } }, 0);
    }

    virtual Web::DevicePixelSize viewport_size() const override { return m_viewport_size; }
    virtual Gfx::IntPoint to_content_position(Gfx::IntPoint widget_position) const override { return widget_position; }
    virtual Gfx::IntPoint to_widget_position(Gfx::IntPoint content_position) const override { return content_position; }

    Core::AnonymousBuffer m_theme;
    Web::DevicePixelSize m_viewport_size;
    int m_max_console_message_id_seen { -1 };
};

class Application final : public WebView::Application {
    WEB_VIEW_APPLICATION(Application)
public:
    virtual ~Application() override = default;

    static Application& the() { return static_cast<Application&>(WebView::Application::the()); }

    virtual void create_platform_arguments(Core::ArgsParser& parser) override
    {
        parser.add_option(s_evaluate_script, "Evaluate argument as a script", "evaluate", 'c', "script");
        parser.add_option(g_use_modules, "Use modules for the REPL", "use-modules", 'm');
        parser.add_positional_argument(s_script_paths, "Path to script files", "scripts", Core::ArgsParser::Required::No);
    }
    virtual void create_platform_options(WebView::BrowserOptions& browser_options, WebView::WebContentOptions& web_content_options) override
    {
        web_content_options.is_headless = WebView::IsHeadless::Yes;
        browser_options.urls.clear();
        auto urls = move(browser_options.raw_urls);
        browser_options.raw_urls = {};
        urls.extend(move(s_script_paths));
        s_script_paths = move(urls);
    }

    ReplWebView& create_web_view(Core::AnonymousBuffer theme, Web::DevicePixelSize window_size)
    {
        auto web_view = ReplWebView::create(move(theme), window_size);
        m_web_views.append(move(web_view));
        return *m_web_views.last();
    }
    ReplWebView& create_child_web_view(ReplWebView& parent, u64 page_index)
    {
        auto web_view = ReplWebView::create_child(parent, page_index);
        m_web_views.append(move(web_view));
        return *m_web_views.last();
    }

    void destroy_web_views() { m_web_views.clear(); }

    template<typename Callback>
    void for_each_web_view(Callback&& callback)
    {
        for (auto& web_view : m_web_views)
            callback(*web_view);
    }

private:
    Vector<NonnullOwnPtr<ReplWebView>> m_web_views;
};

void handle_request(JsonValue const&);

ReplWebView::ReplWebView(Core::AnonymousBuffer theme, Web::DevicePixelSize viewport_size)
    : m_theme(move(theme))
    , m_viewport_size(viewport_size)
{
    on_new_web_view = [this](auto&&, auto&&, Optional<u64> page_index) {
        auto& view = page_index.has_value() ? Application::the().create_child_web_view(*this, *page_index) : Application::the().create_web_view(m_theme, m_viewport_size);
        return view.handle();
    };
    on_reposition_window = [this](auto position) {
        client().async_set_window_position(m_client_state.page_index, position.template to_type<Web::DevicePixels>());
        client().async_did_update_window_rect(m_client_state.page_index);
    };
    on_resize_window = [this](Gfx::IntSize size) {
        m_viewport_size = size.to_type<Web::DevicePixels>();
        client().async_set_window_size(m_client_state.page_index, m_viewport_size);
        client().async_set_viewport_size(m_client_state.page_index, m_viewport_size);
        client().async_did_update_window_rect(m_client_state.page_index);
    };
    on_restore_window = [this]() {
        set_system_visibility_state(Web::HTML::VisibilityState::Visible);
    };
    on_minimize_window = [this]() {
        set_system_visibility_state(Web::HTML::VisibilityState::Hidden);
    };
    on_maximize_window = [this]() {
        on_resize_window(s_pretend_screen_rect.size().to_type<int>());
        client().async_set_window_position(m_client_state.page_index, s_pretend_screen_rect.location());
    };
    on_request_clipboard_entries = [this](auto request_id) {
        client().async_retrieved_clipboard_entries(page_id(), request_id, {});
    };
    on_web_content_crashed = [this]() {
        handle_web_content_process_crash(LoadErrorPage::No);
    };
    on_console_message_available = [this](i32) {
        client().async_js_console_request_messages(page_id(), max(0, m_max_console_message_id_seen));
    };
    on_received_console_messages = [this](i32 id, Vector<WebView::ConsoleOutput> messages) {
        Optional<decltype(s_editor->hide_for_external_terminal_edits())> editor_handle;
        if (s_editor)
            editor_handle = s_editor->hide_for_external_terminal_edits();

        for (auto& message : messages) {
            auto message_id = id++;
            if (message_id <= m_max_console_message_id_seen)
                continue;
            m_max_console_message_id_seen = message_id;
            message.output.visit(
                [](WebView::ConsoleLog const& log) {
                    if (log.level == JS::Console::LogLevel::Info && !log.arguments.is_empty() && log.arguments.first().is_string() && log.arguments.first().as_string().starts_with_bytes(s_service_request_init)) {
                        ByteString request_json = log.arguments.first().as_string().bytes_as_string_view().substring_view(s_service_request_init.length());
                        auto request = JsonValue::from_string(request_json);
                        if (!request.is_error())
                            handle_request(request.release_value());
                        return;
                    }
                    for (auto& arg : log.arguments) {
                        if (arg.is_string())
                            warn("{} ", arg.as_string());
                        else if (arg.is_number())
                            arg.as_number().visit([](auto x) { warn("{} ", x); });
                        else if (arg.is_bool())
                            warn("{}", arg.as_bool());
                        else if (arg.is_null())
                            warn("null ");
                        else
                            warn("{}", arg.serialized());
                    }
                    warnln();
                },
                [](WebView::ConsoleError const& error) {
                    warnln("{}", error.message);
                    if (error.inside_promise) {
                        warnln("  inside promise: {}", error.name);
                        for (auto& entry : error.trace)
                            warnln("  at {} in {}:{}", entry.function, entry.file, entry.line);
                    }
                });
        }
    };

    m_system_visibility_state = Web::HTML::VisibilityState::Visible;
}

Application::Application(Badge<WebView::Application>, Main::Arguments&)
{
}

static void respond_to_request(u64 id, JsonValue const& response_value)
{
    auto json_string = response_value.serialized();
    auto js_code = MUST(String::formatted(
        "REPL.servicePromises.get({})?.resolve({});",
        id,
        json_string));
    g_main_web_view->run_javascript(js_code);
}

static void respond_to_request(u64 id, Error error)
{
    auto js_code = MUST(String::formatted(
        "REPL.servicePromises.get({})?.reject({});",
        id,
        error));
    g_main_web_view->run_javascript(js_code);
}

void handle_request(JsonValue const& request_value)
{
    if (!request_value.is_object())
        return;
    auto& request = request_value.as_object();
    auto id = *request.get_u64("id"sv);
    auto type = *request.get_string("type"sv);
    if (type == "exit"sv) {
        s_exit_code = *request.get_i32("code"sv);
        s_keep_running_repl = false;
        Application::the().event_loop().quit(s_exit_code);
        return;
    }
    if (type == "loadINI"sv) {
        auto path = request.get_string("path"sv)->to_byte_string();
        auto maybe_ini = Core::ConfigFile::open(path);
        if (maybe_ini.is_error()) {
            respond_to_request(id, maybe_ini.release_error());
            return;
        }
        auto ini = maybe_ini.release_value();
        JsonObject object;
        for (auto const& group : ini->groups()) {
            JsonObject group_object;
            for (auto const& key : ini->keys(group)) {
                auto entry = ini->read_entry(group, key);
                group_object.set(key, String::from_utf8_with_replacement_character(entry));
            }
            object.set(group, group_object);
        }
        respond_to_request(id, move(object));
        return;
    }
    if (type == "loadJSON"sv) {
        auto path = *request.get_string("path"sv);
        auto file_or_error = Core::File::open(path, Core::File::OpenMode::Read);
        if (file_or_error.is_error()) {
            respond_to_request(id, file_or_error.release_error());
            return;
        }
        auto file_contents_or_error = file_or_error.value()->read_until_eof();
        if (file_contents_or_error.is_error()) {
            respond_to_request(id, file_contents_or_error.release_error());
            return;
        }
        auto json = JsonValue::from_string(file_contents_or_error.value());
        if (json.is_error()) {
            respond_to_request(id, json.release_error());
            return;
        }
        respond_to_request(id, move(json.release_value()));
        return;
    }
    if (type == "save"sv) {
        if (!s_editor) {
            respond_to_request(id, Error::from_string_literal("REPL editor is not initialized"));
            return;
        }

        auto path = *request.get_string("file"sv);
        s_editor->save_history(path.to_byte_string());
        return;
    }
    if (type == "pieceDone") {
        s_piece_done = true;
        return;
    }
}

static size_t s_ctrl_c_hit_count = 0;
[[maybe_unused]] static ErrorOr<String> prompt_for_level(int level)
{
    static StringBuilder prompt_builder;
    prompt_builder.clear();
    if (s_ctrl_c_hit_count > 0)
        prompt_builder.append("(Use Ctrl+C again to exit)\n"sv);
    prompt_builder.append("> "sv);

    for (auto i = 0; i < level; ++i)
        prompt_builder.append("    "sv);

    return prompt_builder.to_string();
}

static ErrorOr<String> read_next_piece()
{
    StringBuilder piece;

    auto line_level_delta_for_next_line { 0 };

    do {
        auto line_result = s_editor->get_line(TRY(prompt_for_level(s_repl_line_level)).to_byte_string());

        s_ctrl_c_hit_count = 0;
        line_level_delta_for_next_line = 0;

        if (line_result.is_error()) {
            s_keep_running_repl = false;
            return String {};
        }

        auto& line = line_result.value();
        s_editor->add_to_history(line);

        piece.append(line);
        piece.append('\n');
        auto lexer = JS::Lexer(line);

        enum {
            NotInLabelOrObjectKey,
            InLabelOrObjectKeyIdentifier,
            InLabelOrObjectKey
        } label_state { NotInLabelOrObjectKey };

        for (JS::Token token = lexer.next(); token.type() != JS::TokenType::Eof; token = lexer.next()) {
            switch (token.type()) {
            case JS::TokenType::BracketOpen:
            case JS::TokenType::CurlyOpen:
            case JS::TokenType::ParenOpen:
                label_state = NotInLabelOrObjectKey;
                s_repl_line_level++;
                break;
            case JS::TokenType::BracketClose:
            case JS::TokenType::CurlyClose:
            case JS::TokenType::ParenClose:
                label_state = NotInLabelOrObjectKey;
                s_repl_line_level--;
                break;

            case JS::TokenType::Identifier:
            case JS::TokenType::StringLiteral:
                if (label_state == NotInLabelOrObjectKey)
                    label_state = InLabelOrObjectKeyIdentifier;
                else
                    label_state = NotInLabelOrObjectKey;
                break;
            case JS::TokenType::Colon:
                if (label_state == InLabelOrObjectKeyIdentifier)
                    label_state = InLabelOrObjectKey;
                else
                    label_state = NotInLabelOrObjectKey;
                break;
            default:
                break;
            }
        }

        if (label_state == InLabelOrObjectKey) {
            // If there's a label or object literal key at the end of this line,
            // prompt for more lines but do not change the line level.
            line_level_delta_for_next_line += 1;
        }
    } while (s_repl_line_level + line_level_delta_for_next_line > 0);

    return piece.to_string();
}

static ErrorOr<void> repl()
{
    if (!s_keep_running_repl)
        return {};

    auto const piece = TRY(read_next_piece());
    if (Utf8View { piece }.trim(JS::whitespace_characters).is_empty())
        return {};

    g_repl_statements.append(piece);
    auto js = MUST(String::formatted("try {{ {}; }} finally {{ REPL.notifyPieceDone(); }}", piece));
    s_piece_done = false;
    g_main_web_view->run_javascript(js, "REPL"_string, g_use_modules);

    Application::the().event_loop().spin_until([] { return s_piece_done; });
    Application::the().event_loop().deferred_invoke([] {
        if (auto result = repl(); result.is_error()) {
            dbgln("Error in REPL: {}", result.error());
            s_keep_running_repl = false;
            Application::the().event_loop().quit(1);
        }
    });
    return {};
}

ErrorOr<int> serenity_main(Main::Arguments arguments)
{
    WebView::platform_init();

    TRY(Core::Environment::set("AK_DISABLE_DEBUG_LOGS"sv, "1"sv, Core::Environment::Overwrite::Yes));

    auto app = Application::create(arguments);
    TRY(app->launch_services());

    AK::set_debug_enabled(false);

    Core::ResourceImplementation::install(make<Core::ResourceImplementationFile>("/dev/null"_string));

    auto theme_path = LexicalPath::join(WebView::s_ladybird_resource_root, "themes"sv, "Default.ini"sv);
    auto theme = TRY(Gfx::load_system_theme(theme_path.string()));

    auto& main_view = app->create_web_view(move(theme), s_pretend_screen_rect.size());
    g_main_web_view = &main_view;

    main_view.load_html(R"~~~(
<script>
class REPL {
    static #serviceRequestInit = "\u{1F6E0}\u{FE0F}req:";
    static servicePromises = new Map();
    static #nextServiceRequestId = 0;
    static #makeServiceRequest(request) {
        const id = REPL.#nextServiceRequestId++;
        request.id = id;
        console.info(`${REPL.#serviceRequestInit}${JSON.stringify(request)}`);
        return id;
    }
    static #responsePromise(id) {
        if (!REPL.servicePromises.has(id)) {
            let resolve, reject;
            let promise = new Promise((res, rej) => {
                resolve = res;
                reject = rej;
            });
            REPL.servicePromises.set(id, { promise, resolve, reject });
        }
        return REPL.servicePromises.get(id).promise;
    }
    static exit(code) { REPL.#makeServiceRequest({ type: "exit", code }); }
    static help() {
        console.log("REPL commands:");
        console.log("  exit(code) - Exit the REPL with the given exit code.");
        console.log("  help() - Show REPL help message.");
        console.log("  async loadINI(path) - Load the given file as INI.");
        console.log("  async loadJSON(path) - Load the given file as JSON.");
        console.log("  print(value) - Pretty-print the given value.");
        console.log("  async save(file) - Save REPL history to the given file.");
    }
    static async loadINI(path) {
        const id = REPL.#makeServiceRequest({ type: "loadINI", path });
        try {
            return await REPL.#responsePromise(id);
        } finally {
            REPL.servicePromises.delete(id);
        }
    }
    static async loadJSON(path) {
        const id = REPL.#makeServiceRequest({ type: "loadJSON", path });
        try {
            return await REPL.#responsePromise(id);
        } finally {
            REPL.servicePromises.delete(id);
        }
    }
    static print(value) { console.log(value); }
    static async printImplicit(promise) {
        const value = await promise;
        if ("undefined" !== typeof value) console.log(value);
    }
    static async save(file) {
        const id = REPL.#makeServiceRequest({ type: "save", file });
        try {
            return await REPL.#responsePromise(id);
        } finally {
            REPL.servicePromises.delete(id);
        }
    }
    static notifyPieceDone() { REPL.#makeServiceRequest({ type: "pieceDone" }); }
};
window.REPL = REPL;
window.print = (value) => REPL.print(value);

REPL.notifyPieceDone();
</script>
)~~~"sv);

    app->event_loop().deferred_invoke([&] {
        app->event_loop().spin_until([] { return s_piece_done; }); // Wait for the initial REPL script to be loaded.

        auto result = [&] -> ErrorOr<void> {
            if (!s_evaluate_script.is_empty())
                main_view.run_javascript(TRY(String::from_utf8(s_evaluate_script)), "REPL"_string, g_use_modules);

            if (!s_script_paths.is_empty()) {
                StringBuilder script_contents_builder;
                Optional<String> module_path;
                for (auto& script_path : s_script_paths) {
                    auto file = TRY(Core::File::open(script_path, Core::File::OpenMode::Read));
                    auto file_contents = TRY(file->read_until_eof());
                    if (!module_path.has_value())
                        module_path = TRY(String::from_byte_string(script_path));
                    script_contents_builder.append(file_contents);
                }
                main_view.run_javascript(TRY(script_contents_builder.to_string()), *module_path, g_use_modules);
            }

            if (!s_evaluate_script.is_empty() || !s_script_paths.is_empty())
                return {};

            s_editor = Line::Editor::construct();
            s_editor->initialize();

            signal(SIGINT, [](int) {
                if (!s_editor->is_editing())
                    Application::the().event_loop().quit(0);
            });

            s_editor->register_key_input_callback(Line::ctrl('C'), [](Line::Editor& editor) -> bool {
                if (editor.buffer_view().length() == 0 || s_ctrl_c_hit_count > 0) {
                    if (++s_ctrl_c_hit_count == 2) {
                        s_keep_running_repl = false;
                        editor.finish_edit();
                        return false;
                    }
                }

                return true;
            });

            s_editor->on_display_refresh = [](Line::Editor& editor) {
                auto stylize = [&](Line::Span span, Line::Style styles) {
                    editor.stylize(span, styles);
                };
                editor.strip_styles();

                size_t open_indents = s_repl_line_level;

                auto line = editor.line();
                JS::Lexer lexer(line);
                bool indenters_starting_line = true;
                for (JS::Token token = lexer.next(); token.type() != JS::TokenType::Eof; token = lexer.next()) {
                    auto length = Utf8View { token.value() }.length();
                    auto start = token.offset();
                    auto end = start + length;
                    if (indenters_starting_line) {
                        if (token.type() != JS::TokenType::ParenClose && token.type() != JS::TokenType::BracketClose && token.type() != JS::TokenType::CurlyClose) {
                            indenters_starting_line = false;
                        } else {
                            --open_indents;
                        }
                    }

                    switch (token.category()) {
                    case JS::TokenCategory::Invalid:
                        stylize({ start, end, Line::Span::CodepointOriented }, { Line::Style::Foreground(Line::Style::XtermColor::Red), Line::Style::Underline });
                        break;
                    case JS::TokenCategory::Number:
                        stylize({ start, end, Line::Span::CodepointOriented }, { Line::Style::Foreground(Line::Style::XtermColor::Magenta) });
                        break;
                    case JS::TokenCategory::String:
                        stylize({ start, end, Line::Span::CodepointOriented }, { Line::Style::Foreground(Line::Style::XtermColor::Green), Line::Style::Bold });
                        break;
                    case JS::TokenCategory::Punctuation:
                        break;
                    case JS::TokenCategory::Operator:
                        break;
                    case JS::TokenCategory::Keyword:
                        switch (token.type()) {
                        case JS::TokenType::BoolLiteral:
                        case JS::TokenType::NullLiteral:
                            stylize({ start, end, Line::Span::CodepointOriented }, { Line::Style::Foreground(Line::Style::XtermColor::Yellow), Line::Style::Bold });
                            break;
                        default:
                            stylize({ start, end, Line::Span::CodepointOriented }, { Line::Style::Foreground(Line::Style::XtermColor::Blue), Line::Style::Bold });
                            break;
                        }
                        break;
                    case JS::TokenCategory::ControlKeyword:
                        stylize({ start, end, Line::Span::CodepointOriented }, { Line::Style::Foreground(Line::Style::XtermColor::Cyan), Line::Style::Italic });
                        break;
                    case JS::TokenCategory::Identifier:
                        stylize({ start, end, Line::Span::CodepointOriented }, { Line::Style::Foreground(Line::Style::XtermColor::White), Line::Style::Bold });
                        break;
                    default:
                        break;
                    }
                }

                editor.set_prompt(prompt_for_level(open_indents).release_value_but_fixme_should_propagate_errors().to_byte_string());
            };

            app->event_loop().deferred_invoke([] {
                if (auto result = repl(); result.is_error()) {
                    dbgln("Error in REPL: {}", result.error());
                    Application::the().event_loop().quit(1);
                }
            });

            return {};
        }();

        if (result.is_error()) {
            warnln("Error: {}", result.error());
            app->event_loop().quit(1);
        }
    });

    return app->execute();
}
