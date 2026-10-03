/*
 * Copyright (c) 2026, Ali Mohammad Pur <mpfard@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/JsonValue.h>
#include <AK/StringView.h>
#include <AK/Utf16String.h>
#include <LibURL/URL.h>
#include <LibWeb/Export.h>
#include <LibWeb/Forward.h>

namespace Web::WebDriver::BiDi {

// https://w3c.github.io/webdriver-bidi/#type-browsingContext-NavigationInfo
// Reports a navigation event with the given method to the page's client.
WEB_API void emit_navigation_event(HTML::Navigable&, StringView method, Utf16String const& navigation_id, URL::URL const& url);

// https://w3c.github.io/webdriver-bidi/#preload-scripts
// The preload scripts of every BiDi session, as the session's script.PreloadScript records with their ids.
WEB_API void set_preload_scripts(JsonValue);
// https://w3c.github.io/webdriver-bidi/#run-webdriver-bidi-preload-scripts
WEB_API void run_preload_scripts(DOM::Document&);

}
