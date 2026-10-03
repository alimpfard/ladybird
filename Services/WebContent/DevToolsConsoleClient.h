/*
 * Copyright (c) 2025, Tim Flynn <trflynn89@ladybird.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Time.h>
#include <LibIPC/Forward.h>
#include <LibJS/Console.h>
#include <LibJS/Forward.h>
#include <LibWeb/Forward.h>
#include <LibWebCommon/WebView/ConsoleOutput.h>
#include <WebContent/Forward.h>
#include <WebContent/WebContentConsoleClient.h>

namespace WebContent {

class DevToolsConsoleClient final : public WebContentConsoleClient {
    GC_CELL(DevToolsConsoleClient, WebContentConsoleClient);
    GC_DECLARE_ALLOCATOR(DevToolsConsoleClient);

public:
    static GC::Ref<DevToolsConsoleClient> create(JS::Realm&, JS::Console&, PageClient&);
    static JsonValue serialize_value(JS::Realm&, JS::Value);
    virtual ~DevToolsConsoleClient() override;

private:
    DevToolsConsoleClient(JS::Console&, PageClient&, ConsoleGlobalEnvironmentExtensions&);

    static String webdriver_console_log_text(GC::RootVector<JS::Value> const& formatted_arguments);
    void emit_webdriver_console_log_entry(JS::Console::LogLevel, GC::RootVector<JS::Value> const& arguments, Optional<String> text = {});
    void emit_webdriver_javascript_log_entry(Utf16View name, Utf16View message, JS::ErrorData const&);

    virtual void handle_result(JS::Value) override;
    virtual void report_exception(Utf16View name, Utf16View message, JS::ErrorData const&, bool) override;
    virtual void end_group() override { }
    virtual void clear() override { }

    virtual JS::ThrowCompletionOr<JS::Value> printer(JS::Console::LogLevel, PrinterArguments) override;

    void send_console_output(WebView::ConsoleOutput);
};

}
