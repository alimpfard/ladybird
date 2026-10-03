/*
 * Copyright (c) 2026, Ali Mohammad Pur <mpfard@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/JsonObject.h>
#include <WebDriver/BiDi/Modules.h>
#include <WebDriver/Session.h>

namespace WebDriver::BiDi {

// https://w3c.github.io/permissions/#webdriver-bidi-command-permissions-setPermission
CommandPromise permissions_set_permission(BiDiConnection&, RefPtr<Session> session, JsonObject const& parameters)
{
    // permissions.SetPermissionParameters = {
    //   descriptor: permissions.PermissionDescriptor,
    //   state: permissions.PermissionState,
    //   origin: text,
    //   ? embeddedOrigin: text,
    //   ? userContext: text,
    // }
    // 1. Let descriptor be the value of the descriptor field of command parameters.
    auto descriptor = parameters.get_object("descriptor"sv);
    if (!descriptor.has_value())
        return rejected(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, "Parameter 'descriptor' must be an object"sv));

    // 2. Let permission name be the value of the name field of descriptor representing PermissionDescriptor's name.
    TRY_OR_REJECT(get_required_string(*descriptor, "name"sv));

    // 3. Let state be the value of the state field of command parameters.
    auto state = TRY_OR_REJECT(get_required_string(parameters, "state"sv));

    // 4. Let user context id be the value of the userContext field of command parameters, if present, and default
    //    otherwise.
    if (auto user_context_id = TRY_OR_REJECT(get_optional_string(parameters, "userContext"sv)); user_context_id.has_value() && *user_context_id != "default"sv)
        return rejected(Web::WebDriver::Error { 404, "no such user context"_string, MUST(String::formatted("Unknown user context: {}", *user_context_id)), {} });

    // 5. If state is an inappropriate permission state for any implementation-defined reason, return error with
    //    error code invalid argument.
    if (!state.is_one_of("granted"sv, "denied"sv, "prompt"sv))
        return rejected(Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, "Parameter 'state' must be 'granted', 'denied' or 'prompt'"sv));

    // 7. Let origin be the value of the origin field of command parameters.
    auto origin = TRY_OR_REJECT(get_required_string(parameters, "origin"sv));

    // 8. Let embedded origin be the value of the embeddedOrigin field of command parameters, if present, and origin
    //    otherwise.
    auto embedded_origin = TRY_OR_REJECT(get_optional_string(parameters, "embeddedOrigin"sv)).value_or(origin);

    // 6, 9-11. The browser converts the descriptor, generates the permission key and sets the permission.
    auto promise = Session::WebDriverPromise::construct();
    auto set = session->set_permission(*descriptor, move(state), move(origin), move(embedded_origin));
    promise->add_child(set);
    set->when_resolved([promise](JsonValue&) {
           // 12. Return success with data null.
           promise->resolve(JsonObject {});
       })
        .when_rejected([promise](Web::WebDriver::Error& error) {
            promise->reject(Web::WebDriver::Error(error));
        });
    return promise;
}

}
