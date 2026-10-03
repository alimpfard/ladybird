/*
 * Copyright (c) 2026, Ali Mohammad Pur <mpfard@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/HashMap.h>
#include <AK/JsonObject.h>
#include <AK/JsonValue.h>
#include <AK/Optional.h>
#include <AK/String.h>
#include <LibGC/Ptr.h>
#include <LibJS/Forward.h>
#include <LibJS/Runtime/Value.h>
#include <LibWeb/Export.h>
#include <LibWeb/Forward.h>
#include <LibWebCommon/WebDriver/Error.h>

namespace Web::WebDriver::BiDi {

// https://w3c.github.io/webdriver-bidi/#type-script-ResultOwnership
enum class ResultOwnership {
    None,
    Root,
};

// https://w3c.github.io/webdriver-bidi/#type-script-SerializationOptions
struct SerializationOptions {
    enum class IncludeShadowTree {
        None,
        Open,
        All,
    };

    static ErrorOr<SerializationOptions, Error> deserialize(Optional<JsonObject const&>);

    Optional<u64> max_dom_depth { 0 };
    Optional<u64> max_object_depth {};
    IncludeShadowTree include_shadow_tree { IncludeShadowTree::None };
};

// https://w3c.github.io/webdriver-bidi/#type-script-InternalId
// The serialization internal map of one serialization. The specification assigns an internal id to a remote value
// when the object is met again; a remote value is moved into its parent by then, so the objects reachable more than
// once are found first, and get their ids as they are serialized.
struct SerializationInternalMap {
    HashTable<GC::Ref<JS::Object>> serialized_objects;
    HashMap<GC::Ref<JS::Object>, String> internal_ids;
    bool shared_objects_collected { false };
};

// https://w3c.github.io/webdriver-bidi/#serialize-as-a-remote-value
WEB_API JsonValue serialize_as_a_remote_value(JS::Realm&, JS::Value, SerializationOptions const&, ResultOwnership, SerializationInternalMap&);

// https://w3c.github.io/webdriver-bidi/#deserialize-local-value
WEB_API ErrorOr<JS::Value, Error> deserialize_local_value(JS::Realm&, JsonValue const& local_protocol_value);

// https://w3c.github.io/webdriver-bidi/#type-script-Realm
WEB_API String realm_id(JS::Realm const&);

// https://w3c.github.io/webdriver-bidi/#navigable-id
WEB_API String navigable_id(HTML::Navigable const&);

// https://w3c.github.io/webdriver-bidi/#get-the-source
WEB_API JsonObject get_the_source(JS::Realm&);

// https://w3c.github.io/webdriver-bidi/#current-stack-trace
WEB_API JsonObject current_stack_trace(JS::VM&);

// https://w3c.github.io/webdriver-bidi/#stack-trace-for-an-exception
WEB_API JsonObject stack_trace_for_an_exception(JS::Value exception);
WEB_API JsonObject stack_trace_for_an_exception(JS::ErrorData const&);

// https://w3c.github.io/webdriver-bidi/#get-exception-details
WEB_API JsonObject get_exception_details(JS::Realm&, JS::Value exception, ResultOwnership);

}
