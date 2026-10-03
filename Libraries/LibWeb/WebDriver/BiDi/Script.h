/*
 * Copyright (c) 2026, Ali Mohammad Pur <mpfard@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/JsonObject.h>
#include <LibGC/Function.h>
#include <LibGC/Ptr.h>
#include <LibWeb/Export.h>
#include <LibWeb/Forward.h>
#include <LibWebCommon/WebDriver/Response.h>

namespace Web::WebDriver::BiDi {

// Each command completes with a script.EvaluateResult, or an error.
using OnEvaluateComplete = GC::Function<void(Response)>;

// https://w3c.github.io/webdriver-bidi/#command-script-callFunction
WEB_API void call_function(HTML::BrowsingContext&, JsonObject const& parameters, GC::Ref<OnEvaluateComplete>);

// https://w3c.github.io/webdriver-bidi/#command-script-evaluate
WEB_API void evaluate(HTML::BrowsingContext&, JsonObject const& parameters, GC::Ref<OnEvaluateComplete>);

}
