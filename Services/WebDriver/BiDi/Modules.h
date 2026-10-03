/*
 * Copyright (c) 2026, Ali Mohammad Pur <mpfard@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <WebDriver/BiDi/Commands.h>

namespace WebDriver::BiDi {

// https://w3c.github.io/webdriver-bidi/#module-session
CommandPromise session_status(BiDiConnection&, RefPtr<Session>, JsonObject const& parameters);
CommandPromise session_new(BiDiConnection&, RefPtr<Session>, JsonObject const& parameters);
CommandPromise session_end(BiDiConnection&, RefPtr<Session>, JsonObject const& parameters);
CommandPromise session_subscribe(BiDiConnection&, RefPtr<Session>, JsonObject const& parameters);
CommandPromise session_unsubscribe(BiDiConnection&, RefPtr<Session>, JsonObject const& parameters);

// https://w3c.github.io/webdriver-bidi/#module-browsingContext
CommandPromise browsing_context_close(BiDiConnection&, RefPtr<Session>, JsonObject const& parameters);
CommandPromise browsing_context_create(BiDiConnection&, RefPtr<Session>, JsonObject const& parameters);
CommandPromise browsing_context_get_tree(BiDiConnection&, RefPtr<Session>, JsonObject const& parameters);
CommandPromise browsing_context_handle_user_prompt(BiDiConnection&, RefPtr<Session>, JsonObject const& parameters);
CommandPromise browsing_context_navigate(BiDiConnection&, RefPtr<Session>, JsonObject const& parameters);

// https://w3c.github.io/permissions/#webdriver-bidi-module-permissions
CommandPromise permissions_set_permission(BiDiConnection&, RefPtr<Session>, JsonObject const& parameters);

// https://w3c.github.io/webdriver-bidi/#module-script
CommandPromise script_add_preload_script(BiDiConnection&, RefPtr<Session>, JsonObject const& parameters);
CommandPromise script_call_function(BiDiConnection&, RefPtr<Session>, JsonObject const& parameters);
CommandPromise script_remove_preload_script(BiDiConnection&, RefPtr<Session>, JsonObject const& parameters);
CommandPromise script_evaluate(BiDiConnection&, RefPtr<Session>, JsonObject const& parameters);

}
