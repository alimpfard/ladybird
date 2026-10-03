/*
 * Copyright (c) 2026, Ali Mohammad Pur <mpfard@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/HashMap.h>
#include <AK/JsonArray.h>
#include <AK/NeverDestroyed.h>
#include <AK/Random.h>
#include <LibGC/Root.h>
#include <LibJS/Runtime/AbstractOperations.h>
#include <LibJS/Runtime/Array.h>
#include <LibJS/Runtime/ArrayBuffer.h>
#include <LibJS/Runtime/AsyncGenerator.h>
#include <LibJS/Runtime/BigInt.h>
#include <LibJS/Runtime/Date.h>
#include <LibJS/Runtime/DateConstructor.h>
#include <LibJS/Runtime/Error.h>
#include <LibJS/Runtime/ExecutionContext.h>
#include <LibJS/Runtime/FunctionObject.h>
#include <LibJS/Runtime/GeneratorObject.h>
#include <LibJS/Runtime/Map.h>
#include <LibJS/Runtime/Promise.h>
#include <LibJS/Runtime/ProxyObject.h>
#include <LibJS/Runtime/Realm.h>
#include <LibJS/Runtime/RegExpConstructor.h>
#include <LibJS/Runtime/RegExpObject.h>
#include <LibJS/Runtime/Set.h>
#include <LibJS/Runtime/TypedArray.h>
#include <LibJS/Runtime/VM.h>
#include <LibJS/Runtime/WeakMap.h>
#include <LibJS/Runtime/WeakSet.h>
#include <LibWeb/Bindings/HTMLCollection.h>
#include <LibWeb/Bindings/NodeList.h>
#include <LibWeb/Bindings/Wrappable.h>
#include <LibWeb/Bindings/WrapperWorld.h>
#include <LibWeb/DOM/Attr.h>
#include <LibWeb/DOM/Document.h>
#include <LibWeb/DOM/Element.h>
#include <LibWeb/DOM/HTMLCollection.h>
#include <LibWeb/DOM/Node.h>
#include <LibWeb/DOM/NodeList.h>
#include <LibWeb/DOM/ParentNode.h>
#include <LibWeb/DOM/ShadowRoot.h>
#include <LibWeb/HTML/LocalNavigable.h>
#include <LibWeb/HTML/LocalTraversableNavigable.h>
#include <LibWeb/HTML/Scripting/Environments.h>
#include <LibWeb/HTML/Window.h>
#include <LibWeb/HTML/WindowProxy.h>
#include <LibWeb/WebDriver/BiDi/RemoteValue.h>
#include <LibWeb/WebDriver/ElementReference.h>

namespace Web::WebDriver::BiDi {

// https://w3c.github.io/webdriver-bidi/#handle-object-map
// Each ECMAScript Realm has a corresponding handle object map. This is a strong map from handle ids to their
// corresponding objects.
// FIXME: Key this by realm, and discard the handles of a realm that is discarded.
static HashMap<String, GC::Root<JS::Object>>& handle_object_map()
{
    static NeverDestroyed<HashMap<String, GC::Root<JS::Object>>> map;
    return *map;
}

ErrorOr<SerializationOptions, Error> SerializationOptions::deserialize(Optional<JsonObject const&> options)
{
    // script.SerializationOptions = {
    //   ? maxDomDepth: (js-uint / null) .default 0,
    //   ? maxObjectDepth: (js-uint / null) .default null,
    //   ? includeShadowTree: ("none" / "open" / "all") .default "none",
    // }
    SerializationOptions result;
    if (!options.has_value())
        return result;

    if (auto max_dom_depth = options->get("maxDomDepth"sv); max_dom_depth.has_value()) {
        if (max_dom_depth->is_null())
            result.max_dom_depth = {};
        else if (max_dom_depth->is_integer<u64>())
            result.max_dom_depth = max_dom_depth->get_integer<u64>();
        else
            return Error::from_code(ErrorCode::InvalidArgument, "Serialization option 'maxDomDepth' must be a non-negative integer or null"sv);
    }

    if (auto max_object_depth = options->get("maxObjectDepth"sv); max_object_depth.has_value()) {
        if (max_object_depth->is_null())
            result.max_object_depth = {};
        else if (max_object_depth->is_integer<u64>())
            result.max_object_depth = max_object_depth->get_integer<u64>();
        else
            return Error::from_code(ErrorCode::InvalidArgument, "Serialization option 'maxObjectDepth' must be a non-negative integer or null"sv);
    }

    if (auto include_shadow_tree = options->get_string("includeShadowTree"sv); include_shadow_tree.has_value() || options->has("includeShadowTree"sv)) {
        if (include_shadow_tree == "none"sv)
            result.include_shadow_tree = IncludeShadowTree::None;
        else if (include_shadow_tree == "open"sv)
            result.include_shadow_tree = IncludeShadowTree::Open;
        else if (include_shadow_tree == "all"sv)
            result.include_shadow_tree = IncludeShadowTree::All;
        else
            return Error::from_code(ErrorCode::InvalidArgument, "Serialization option 'includeShadowTree' must be one of 'none', 'open' or 'all'"sv);
    }

    return result;
}

// https://w3c.github.io/webdriver-bidi/#type-script-Realm
String realm_id(JS::Realm const& realm)
{
    // A realm id is a string uniquely identifying a realm; the environment settings object of a realm has such an id.
    auto& settings = HTML::relevant_settings_object(realm.global_object());
    return settings.id.to_string();
}

// https://w3c.github.io/webdriver-bidi/#navigable-id
String navigable_id(HTML::Navigable const& navigable)
{
    // For navigables with an associated WebDriver window handle the navigable id must be the same as the window handle.
    if (navigable.is_top_level_traversable()) {
        if (auto const* traversable = as_if<HTML::LocalTraversableNavigable>(navigable); traversable && !traversable->window_handle().is_empty())
            return traversable->window_handle().to_utf8();
    }
    // FIXME: A top-level traversable hosted by another process does not know its window handle.
    return MUST(String::formatted("{}", navigable.id()));
}

// The navigable of the document a window realm's settings object is responsible for, if any.
static GC::Ptr<HTML::Navigable> navigable_of_realm(JS::Realm& realm)
{
    auto document = HTML::principal_realm_settings_object(realm).responsible_document();
    if (!document)
        return nullptr;
    return document->navigable();
}

// https://w3c.github.io/webdriver-bidi/#get-the-source
JsonObject get_the_source(JS::Realm& realm)
{
    // 1. Let realm be the realm id for source realm.
    // 2. Let environment settings be the environment settings object whose realm execution context's Realm component
    //    is source realm.
    // 3. If environment settings has a associated Document:
    //    1. Let document be environment settings’ associated Document.
    //    2. Let navigable be document’s node navigable.
    //    3. Let navigable id be the navigable id for navigable if navigable is not null.
    //    4. Let user context id be the user context id of navigable's associated user context.
    //    Otherwise let navigable be null.
    auto navigable = navigable_of_realm(realm);

    // 4. Let source be a map matching the script.Source production with the realm field set to realm, the context
    //    field set to navigable id if navigable is not null, or unset otherwise, and the userContext field set to
    //    user context id if navigable is not null, or unset otherwise.
    JsonObject source;
    source.set("realm"sv, realm_id(realm));
    if (navigable) {
        source.set("context"sv, navigable_id(*navigable));
        source.set("userContext"sv, "default"sv);
    }

    // 5. Return source.
    return source;
}

// https://w3c.github.io/webdriver-bidi/#construct-a-stack-trace
static JsonObject construct_a_stack_trace(JsonArray call_frames)
{
    // 3. Let stack trace be a new map matching the script.StackTrace production, with the callFrames property set to
    //    call frames.
    JsonObject stack_trace;
    stack_trace.set("callFrames"sv, move(call_frames));

    // 4. Return stack trace.
    return stack_trace;
}

static JsonObject stack_frame(Utf16View function_name, Optional<JS::SourceRange const&> source_range)
{
    // 2. Let frame info be a new map matching the script.StackFrame production, with the url field set to url, the
    //    functionName field set to frame's function, the lineNumber field set to frame's line number and the
    //    columnNumber field set to frame's column number.
    JsonObject frame_info;
    frame_info.set("functionName"sv, MUST(function_name.to_utf8()));
    if (source_range.has_value()) {
        frame_info.set("url"sv, source_range->filename().to_utf8());
        // The zero-based line number of the executed code, relative to the top of the resource containing script.
        frame_info.set("lineNumber"sv, source_range->start.line > 0 ? source_range->start.line - 1 : 0);
        // The zero-based column number of the executed code, relative to the start of the line in the resource
        // containing script.
        frame_info.set("columnNumber"sv, source_range->start.column > 0 ? source_range->start.column - 1 : 0);
    } else {
        frame_info.set("url"sv, ""sv);
        frame_info.set("lineNumber"sv, 0);
        frame_info.set("columnNumber"sv, 0);
    }
    return frame_info;
}

// https://w3c.github.io/webdriver-bidi/#current-stack-trace
JsonObject current_stack_trace(JS::VM& vm)
{
    // The current stack trace is the result of construct a stack trace given a list of stack frames representing the
    // callstack of the running execution context.
    JsonArray call_frames;

    // NB: Native functions have no source; only the frames of scripts are stack frames.
    for (auto const& element : vm.stack_trace()) {
        if (!element.source_range.has_value() || element.source_range->filename().is_empty())
            continue;
        auto const* context = element.execution_context;
        auto function_name = (context && context->function) ? context->function->name_for_call_stack() : Utf16String {};
        call_frames.must_append(stack_frame(function_name, *element.source_range));
    }

    return construct_a_stack_trace(move(call_frames));
}

// https://w3c.github.io/webdriver-bidi/#stack-trace-for-an-exception
JsonObject stack_trace_for_an_exception(JS::ErrorData const& error_data)
{
    JsonArray call_frames;

    // 2. Let stack be the list of stack frames corresponding to execution at the point record was created.
    // NB: The native frame of the error's constructor is not a stack frame of a script.
    for (auto const& frame : error_data.traceback()) {
        if (frame.source_range().filename().is_empty())
            continue;
        call_frames.must_append(stack_frame(frame.function_name, frame.source_range()));
    }

    // 3. Return construct a stack trace given stack.
    return construct_a_stack_trace(move(call_frames));
}

JsonObject stack_trace_for_an_exception(JS::Value exception)
{
    // 1. If exception is a value that has been thrown as an exception, let record be the Completion Record created to
    //    throw exception. Otherwise let record be exception.
    if (exception.is_object()) {
        if (auto const* error_data = exception.as_object().error_data())
            return stack_trace_for_an_exception(*error_data);
    }

    // NB: Only error objects carry the stack of their creation.
    return construct_a_stack_trace({});
}

// https://w3c.github.io/webdriver-bidi/#get-exception-details
JsonObject get_exception_details(JS::Realm& realm, JS::Value exception, ResultOwnership ownership_type)
{
    // 2. Let text be an implementation-defined textual description of the error represented by record.
    // NB: Error objects describe themselves as "<name>: <message>"; anything else is described without running script.
    auto text = exception.to_utf16_string_without_side_effects();
    if (exception.is_object() && exception.as_object().error_data()) {
        if (auto description = exception.to_utf16_string(realm.vm()); !description.is_error())
            text = description.release_value();
    }

    // 3. Let serialization options be a map matching the script.SerializationOptions production with the fields set
    //    to their default values.
    SerializationOptions serialization_options;

    // 4. Let exception be the result of serialize as a remote value with record.[[Value]], serialization options,
    //    ownership type, a new map as serialization internal map, realm and session.
    SerializationInternalMap serialization_internal_map;
    auto serialized_exception = serialize_as_a_remote_value(realm, exception, serialization_options, ownership_type, serialization_internal_map);

    // 5. Let stack trace be the stack trace for an exception given record.
    auto stack_trace = stack_trace_for_an_exception(exception);

    // 6. If stack trace has size of 1 or greater, let line number be value of the lineNumber field in stack trace[0],
    //    and let column number be the value of the columnNumber field stack trace[0]. Otherwise let line number and
    //    column number be 0.
    u64 line_number = 0;
    u64 column_number = 0;
    auto const& call_frames = stack_trace.get_array("callFrames"sv).value();
    if (!call_frames.is_empty()) {
        auto const& frame = call_frames[0].as_object();
        line_number = frame.get_integer<u64>("lineNumber"sv).value_or(0);
        column_number = frame.get_integer<u64>("columnNumber"sv).value_or(0);
    }

    // 7. Let exception details be a map matching the script.ExceptionDetails production, with the text field set to
    //    text, the exception field set to exception, the lineNumber field set to line number, the columnNumber field
    //    set to column number, and the stackTrace field set to stack trace.
    JsonObject exception_details;
    exception_details.set("text"sv, text.to_utf8());
    exception_details.set("exception"sv, move(serialized_exception));
    exception_details.set("lineNumber"sv, line_number);
    exception_details.set("columnNumber"sv, column_number);
    exception_details.set("stackTrace"sv, move(stack_trace));

    // 8. Return exception details.
    return exception_details;
}

// https://w3c.github.io/webdriver-bidi/#serialize-primitive-protocol-value
static Optional<JsonObject> serialize_primitive_protocol_value(JS::Value value)
{
    // 1. Let remote value be undefined.
    JsonObject remote_value;

    // 2. In the following list of conditions and associated steps, run the first set of steps for which the
    //    associated condition is true, if any:
    // -> Type(value) is undefined
    if (value.is_undefined()) {
        remote_value.set("type"sv, "undefined"sv);
    }
    // -> Type(value) is Null
    else if (value.is_null()) {
        remote_value.set("type"sv, "null"sv);
    }
    // -> Type(value) is String
    else if (value.is_string()) {
        remote_value.set("type"sv, "string"sv);
        remote_value.set("value"sv, value.as_string().utf16_string().to_utf8());
    }
    // -> Type(value) is Number
    else if (value.is_number()) {
        // 1. Switch on the value of value:
        JsonValue serialized;
        if (value.is_nan())
            serialized = "NaN"sv;
        else if (value.is_negative_zero())
            serialized = "-0"sv;
        else if (value.is_positive_infinity())
            serialized = "Infinity"sv;
        else if (value.is_negative_infinity())
            serialized = "-Infinity"sv;
        else if (value.is_integral_number() && value.as_double() >= -9007199254740991.0 && value.as_double() <= 9007199254740991.0)
            serialized = static_cast<i64>(value.as_double());
        else
            serialized = value.as_double();

        // 2. Let remote value be a map matching the script.NumberValue production in the local end definition, with
        //    the value property set to serialized.
        remote_value.set("type"sv, "number"sv);
        remote_value.set("value"sv, move(serialized));
    }
    // -> Type(value) is Boolean
    else if (value.is_boolean()) {
        remote_value.set("type"sv, "boolean"sv);
        remote_value.set("value"sv, value.as_bool());
    }
    // -> Type(value) is BigInt
    else if (value.is_bigint()) {
        remote_value.set("type"sv, "bigint"sv);
        remote_value.set("value"sv, MUST(value.as_bigint().big_integer().to_base(10)));
    } else {
        return {};
    }

    // 3. Return remote value
    return remote_value;
}

// https://w3c.github.io/webdriver-bidi/#handle-for-an-object
static Optional<String> handle_for_an_object(ResultOwnership ownership_type, JS::Object& object)
{
    // 1. If ownership type is equal "none", return null.
    if (ownership_type == ResultOwnership::None)
        return {};

    // 2. Let handle id be a new, unique, string handle for object.
    auto handle_id = generate_random_uuid();

    // 3. Let handle map be realm's handle object map
    // 4. Set handle map[handle id] to object.
    handle_object_map().set(handle_id, GC::make_root(object));

    // 5. Return handle id as a result.
    return handle_id;
}

// https://w3c.github.io/webdriver-bidi/#get-shared-id-for-a-node
static Optional<String> get_shared_id_for_a_node(DOM::Node const& node)
{
    // 3. Let navigable be node's node navigable.
    auto navigable = node.navigable();

    // 4. If navigable is null, return null.
    if (!navigable)
        return {};

    // 5. Return get or create a node reference with session, navigable and node.
    auto browsing_context = navigable->active_browsing_context();
    if (!browsing_context)
        return {};
    return get_or_create_a_node_reference(*browsing_context, node);
}

static GC::RootVector<JS::Value> array_like_values(JS::Realm&, JS::Object&);

static SerializationOptions child_serialization_options(SerializationOptions const& serialization_options)
{
    // 1. Let child serialization options be a clone of serialization options.
    auto child_serialization_options = serialization_options;

    // 2. If child serialization options["maxObjectDepth"] is not null, set child serialization
    //    options["maxObjectDepth"] to child serialization options["maxObjectDepth"] - 1.
    if (child_serialization_options.max_object_depth.has_value())
        child_serialization_options.max_object_depth = *child_serialization_options.max_object_depth - 1;

    return child_serialization_options;
}

// Finds the objects the serialization of value would meet more than once, following the same containers to the same
// depths as serialize as a remote value, and assigns each of them an internal id.
static void collect_shared_objects(JS::Realm& realm, JS::Value value, SerializationOptions const& serialization_options, HashTable<GC::Ref<JS::Object>>& seen, SerializationInternalMap& serialization_internal_map)
{
    auto& vm = realm.vm();
    if (!value.is_object())
        return;
    auto& object = value.as_object();

    if (seen.contains(object)) {
        // 1. Let internal id be the string representation of a UUID based on truly random, or pseudo-random numbers.
        if (!serialization_internal_map.internal_ids.contains(object))
            serialization_internal_map.internal_ids.set(object, generate_random_uuid());
        return;
    }
    seen.set(object);

    auto child_options = child_serialization_options(serialization_options);
    auto may_descend = serialization_options.max_object_depth != 0u;

    auto visit_list = [&](ReadonlySpan<JS::Value> values) {
        for (auto child : values)
            collect_shared_objects(realm, child, child_options, seen, serialization_internal_map);
    };

    if (auto is_array = value.is_array(vm); !is_array.is_error() && is_array.value()) {
        if (may_descend)
            visit_list(array_like_values(realm, object));
        return;
    }
    if (is<JS::Map>(object)) {
        if (may_descend) {
            for (auto const& entry : as<JS::Map>(object)) {
                collect_shared_objects(realm, entry.key, child_options, seen, serialization_internal_map);
                collect_shared_objects(realm, entry.value, child_options, seen, serialization_internal_map);
            }
        }
        return;
    }
    if (is<JS::Set>(object)) {
        if (may_descend) {
            for (auto entry : as<JS::Set>(object))
                collect_shared_objects(realm, entry, child_options, seen, serialization_internal_map);
        }
        return;
    }
    if (Bindings::impl_from<DOM::NodeList>(&object) || Bindings::impl_from<DOM::HTMLCollection>(&object)) {
        if (may_descend)
            visit_list(array_like_values(realm, object));
        return;
    }
    if (auto* node = Bindings::impl_from<DOM::Node>(&object)) {
        auto const* shadow_root = as_if<DOM::ShadowRoot>(*node);
        bool children_is_null = serialization_options.max_dom_depth == 0u
            || (shadow_root && serialization_options.include_shadow_tree == SerializationOptions::IncludeShadowTree::None)
            || (shadow_root && serialization_options.include_shadow_tree == SerializationOptions::IncludeShadowTree::Open && shadow_root->mode() == Bindings::ShadowRootMode::Closed);
        if (!children_is_null) {
            auto child_dom_options = serialization_options;
            if (child_dom_options.max_dom_depth.has_value())
                child_dom_options.max_dom_depth = *child_dom_options.max_dom_depth - 1;
            node->for_each_child_of_type<DOM::Element>([&](DOM::Element& child) -> IterationDecision {
                collect_shared_objects(realm, JS::Value(Bindings::wrap(Bindings::host_defined_wrapper_world(realm), realm, GC::Ref<Bindings::Wrappable> { child })), child_dom_options, seen, serialization_internal_map);
                return IterationDecision::Continue;
            });
        }
        if (auto* element = as_if<DOM::Element>(*node)) {
            if (auto element_shadow_root = element->shadow_root())
                collect_shared_objects(realm, JS::Value(Bindings::wrap(Bindings::host_defined_wrapper_world(realm), realm, GC::Ref<Bindings::Wrappable> { *element_shadow_root })), serialization_options, seen, serialization_internal_map);
        }
        return;
    }
    if (is<HTML::WindowProxy>(object) || object.is_platform_object() || object.is_function() || is<JS::RegExpObject>(object) || is<JS::Date>(object) || is<JS::WeakMap>(object) || is<JS::WeakSet>(object) || is<JS::GeneratorObject>(object) || is<JS::AsyncGenerator>(object) || object.error_data() || is<JS::ProxyObject>(object) || is<JS::Promise>(object) || is<JS::TypedArrayBase>(object) || is<JS::ArrayBuffer>(object))
        return;

    // A plain object's enumerable own properties.
    if (may_descend) {
        auto entries = object.enumerable_own_property_names(JS::Object::PropertyKind::KeyAndValue);
        if (entries.is_error())
            return;
        for (auto entry : entries.value()) {
            auto& pair = as<JS::Array>(entry.as_object());
            collect_shared_objects(realm, MUST(pair.get(0)), child_options, seen, serialization_internal_map);
            collect_shared_objects(realm, MUST(pair.get(1)), child_options, seen, serialization_internal_map);
        }
    }
}

// https://w3c.github.io/webdriver-bidi/#set-internal-ids-if-needed
static void set_internal_ids_if_needed(SerializationInternalMap& serialization_internal_map, JsonObject& remote_value, JS::Object& object)
{
    // 1. If the serialization internal map does not contain object, set serialization internal map[object] to remote
    //    value.
    serialization_internal_map.serialized_objects.set(object);

    // 2. Otherwise, run the following steps:
    //    1. Let previously serialized remote value be serialization internal map[object].
    //    2. If previously serialized remote value does not have a field internalId, run the following steps:
    //       1. Let internal id be the string representation of a UUID based on truly random, or pseudo-random numbers.
    //       2. Set the internalId field of previously serialized remote value to internal id.
    //    3. Set the internalId field of remote value to a field internalId in previously serialized remote value.
    // NB: Objects met more than once were given their internal id before serialization began.
    if (auto internal_id = serialization_internal_map.internal_ids.get(object); internal_id.has_value())
        remote_value.set("internalId"sv, *internal_id);
}

// https://w3c.github.io/webdriver-bidi/#serialize-as-a-list
static JsonArray serialize_as_a_list(JS::Realm& realm, ReadonlySpan<JS::Value> values, SerializationOptions const& serialization_options, ResultOwnership ownership_type, SerializationInternalMap& serialization_internal_map)
{
    // 1. If serialization options["maxObjectDepth"] is not null, assert: serialization options["maxObjectDepth"] is
    //    greater than 0.
    VERIFY(!serialization_options.max_object_depth.has_value() || *serialization_options.max_object_depth > 0);

    // 2. Let serialized be a new list.
    JsonArray serialized;

    // 3. For each child value in IteratorToList(GetIterator(iterable, sync)):
    for (auto child_value : values) {
        // 3. Let serialized child be the result of serialize as a remote value with child value, child serialization
        //    options, ownership type, serialization internal map, realm, and session.
        // 4. Append serialized child to serialized.
        serialized.must_append(serialize_as_a_remote_value(realm, child_value, child_serialization_options(serialization_options), ownership_type, serialization_internal_map));
    }

    // 4. Return serialized
    return serialized;
}

// https://w3c.github.io/webdriver-bidi/#serialize-as-a-mapping
static JsonArray serialize_as_a_mapping(JS::Realm& realm, ReadonlySpan<JS::Value> entries, SerializationOptions const& serialization_options, ResultOwnership ownership_type, SerializationInternalMap& serialization_internal_map)
{
    // 1. If serialization options["maxObjectDepth"] is not null, assert: serialization options["maxObjectDepth"] is
    //    greater than 0.
    VERIFY(!serialization_options.max_object_depth.has_value() || *serialization_options.max_object_depth > 0);

    // 2. Let serialized be a new list.
    JsonArray serialized;

    // 3. For item in IteratorToList(GetIterator(iterable, sync)):
    for (auto item : entries) {
        // 1. Assert: IsArray(item)
        // 2. Let property be CreateListFromArrayLike(item)
        // 3. Assert: property is a list of size 2
        auto& entry = as<JS::Array>(item.as_object());
        VERIFY(MUST(JS::length_of_array_like(realm.vm(), entry)) == 2);

        // 4. Let key be property[0] and let value be property[1]
        auto key = MUST(entry.get(0));
        auto value = MUST(entry.get(1));

        auto child_options = child_serialization_options(serialization_options);

        // 7. If Type(key) is String, let serialized key be child key, otherwise let serialized key be the result of
        //    serialize as a remote value with child key, child serialization options, ownership type, serialization
        //    internal map, realm, and session.
        JsonValue serialized_key;
        if (key.is_string())
            serialized_key = key.as_string().utf16_string().to_utf8();
        else
            serialized_key = serialize_as_a_remote_value(realm, key, child_options, ownership_type, serialization_internal_map);

        // 8. Let serialized value be the result of serialize as a remote value with value, child serialization
        //    options, ownership type, serialization internal map, realm, and session.
        auto serialized_value = serialize_as_a_remote_value(realm, value, child_options, ownership_type, serialization_internal_map);

        // 9. Let serialized child be («serialized key, serialized value»).
        JsonArray serialized_child;
        serialized_child.must_append(move(serialized_key));
        serialized_child.must_append(move(serialized_value));

        // 10. Append serialized child to serialized.
        serialized.must_append(move(serialized_child));
    }

    // 4. Return serialized
    return serialized;
}

static GC::RootVector<JS::Value> array_like_values(JS::Realm& realm, JS::Object& object)
{
    auto& vm = realm.vm();
    GC::RootVector<JS::Value> values;

    auto length = JS::length_of_array_like(vm, object);
    if (length.is_error())
        return values;

    for (size_t i = 0; i < length.value(); ++i) {
        auto value = object.get(i);
        values.append(value.is_error() ? JS::js_undefined() : value.value());
    }
    return values;
}

// https://w3c.github.io/webdriver-bidi/#serialize-an-array-like
static JsonObject serialize_an_array_like(JS::Realm& realm, StringView production, Optional<String> const& handle_id, bool known_object, JS::Object& value, SerializationOptions const& serialization_options, ResultOwnership ownership_type, SerializationInternalMap& serialization_internal_map)
{
    // 1. Let remote value be a map matching production, with the handle property set to handle id if it's not null, or
    //    omitted otherwise.
    JsonObject remote_value;
    remote_value.set("type"sv, production);
    if (handle_id.has_value())
        remote_value.set("handle"sv, *handle_id);

    // 2. Set internal ids if needed with serialization internal map, remote value and value.
    set_internal_ids_if_needed(serialization_internal_map, remote_value, value);

    // 3. If known object is false, and serialization options["maxObjectDepth"] is not 0:
    if (!known_object && serialization_options.max_object_depth != 0u) {
        // 1. Let serialized be the result of serialize as a list with CreateArrayIterator(value, value),
        //    serialization options, ownership type, serialization internal map, realm, and session.
        auto serialized = serialize_as_a_list(realm, array_like_values(realm, value), serialization_options, ownership_type, serialization_internal_map);

        // 2. If serialized is not null, set field value of remote value to serialized.
        remote_value.set("value"sv, move(serialized));
    }

    // 4. Return remote value
    return remote_value;
}

// https://w3c.github.io/webdriver-bidi/#serialize-as-a-remote-value
JsonValue serialize_as_a_remote_value(JS::Realm& realm, JS::Value value, SerializationOptions const& serialization_options, ResultOwnership ownership_type, SerializationInternalMap& serialization_internal_map)
{
    auto& vm = realm.vm();

    // 1. Let remote value be a result of serialize primitive protocol value given a value.
    // 2. If remote value is not undefined, return remote value.
    if (auto primitive = serialize_primitive_protocol_value(value); primitive.has_value())
        return primitive.release_value();

    if (!serialization_internal_map.shared_objects_collected) {
        serialization_internal_map.shared_objects_collected = true;
        HashTable<GC::Ref<JS::Object>> seen;
        collect_shared_objects(realm, value, serialization_options, seen, serialization_internal_map);
    }

    // -> Type(value) is Symbol
    if (value.is_symbol()) {
        JsonObject remote_value;
        remote_value.set("type"sv, "symbol"sv);
        return remote_value;
    }

    VERIFY(value.is_object());
    auto& object = value.as_object();

    // 3. Let handle id be the handle for an object with realm, ownership type and value.
    auto handle_id = handle_for_an_object(ownership_type, object);

    // 4. Set ownership type to "none".
    ownership_type = ResultOwnership::None;

    // 5. Let known object be true, if value is in the serialization internal map, otherwise false.
    auto known_object = serialization_internal_map.serialized_objects.contains(object);

    auto simple_remote_value = [&](StringView type) {
        JsonObject remote_value;
        remote_value.set("type"sv, type);
        if (handle_id.has_value())
            remote_value.set("handle"sv, *handle_id);
        return remote_value;
    };

    // 6. In the following list of conditions and associated steps, run the first set of steps for which the
    //    associated condition is true:
    // -> IsArray(value)
    if (auto is_array = value.is_array(vm); !is_array.is_error() && is_array.value()) {
        return serialize_an_array_like(realm, "array"sv, handle_id, known_object, object, serialization_options, ownership_type, serialization_internal_map);
    }

    // -> IsRegExp(value)
    if (auto is_regexp = value.is_regexp(vm); !is_regexp.is_error() && is_regexp.value() && is<JS::RegExpObject>(object)) {
        auto& regexp = as<JS::RegExpObject>(object);

        // 3. Let serialized be a map matching the script.RegExpValue production in the local end definition, with the
        //    pattern property set to the pattern and the the flags property set to the flags.
        JsonObject serialized;
        serialized.set("pattern"sv, regexp.pattern().to_utf8());
        serialized.set("flags"sv, regexp.flags().to_utf8());

        auto remote_value = simple_remote_value("regexp"sv);
        remote_value.set("value"sv, move(serialized));
        return remote_value;
    }

    // -> value has a [[DateValue]] internal slot.
    if (is<JS::Date>(object)) {
        // 1. Set serialized to Call(Date.prototype.toISOString, value).
        auto remote_value = simple_remote_value("date"sv);
        remote_value.set("value"sv, as<JS::Date>(object).iso_date_string().to_utf8());
        return remote_value;
    }

    // -> value has a [[MapData]] internal slot
    if (is<JS::Map>(object)) {
        auto& map = as<JS::Map>(object);

        auto remote_value = simple_remote_value("map"sv);
        set_internal_ids_if_needed(serialization_internal_map, remote_value, object);

        // 4. If known object is false, and serialization options["maxObjectDepth"] is not 0, run the following steps:
        if (!known_object && serialization_options.max_object_depth != 0u) {
            GC::RootVector<JS::Value> entries;
            for (auto const& entry : map) {
                auto pair = JS::Array::create_from(realm, { entry.key, entry.value });
                entries.append(pair);
            }
            remote_value.set("value"sv, serialize_as_a_mapping(realm, entries, serialization_options, ownership_type, serialization_internal_map));
        }
        return remote_value;
    }

    // -> value has a [[SetData]] internal slot
    if (is<JS::Set>(object)) {
        auto& set = as<JS::Set>(object);

        auto remote_value = simple_remote_value("set"sv);
        set_internal_ids_if_needed(serialization_internal_map, remote_value, object);

        // 4. If known object is false, and serialization options["maxObjectDepth"] is not 0, run the following steps:
        if (!known_object && serialization_options.max_object_depth != 0u) {
            GC::RootVector<JS::Value> values;
            for (auto entry : set)
                values.append(entry);
            remote_value.set("value"sv, serialize_as_a_list(realm, values, serialization_options, ownership_type, serialization_internal_map));
        }
        return remote_value;
    }

    // -> value has a [[WeakMapData]] internal slot
    if (is<JS::WeakMap>(object))
        return simple_remote_value("weakmap"sv);

    // -> value has a [[WeakSetData]] internal slot
    if (is<JS::WeakSet>(object))
        return simple_remote_value("weakset"sv);

    // -> value has a [[GeneratorState]] internal slot or [[AsyncGeneratorState]] internal slot
    if (is<JS::GeneratorObject>(object) || is<JS::AsyncGenerator>(object))
        return simple_remote_value("generator"sv);

    // -> value has an [[ErrorData]] internal slot
    if (object.error_data())
        return simple_remote_value("error"sv);

    // -> value has a [[ProxyHandler]] internal slot and a [[ProxyTarget]] internal slot
    if (is<JS::ProxyObject>(object))
        return simple_remote_value("proxy"sv);

    // -> IsPromise(value)
    if (is<JS::Promise>(object))
        return simple_remote_value("promise"sv);

    // -> value has a [[TypedArrayName]] internal slot
    if (is<JS::TypedArrayBase>(object))
        return simple_remote_value("typedarray"sv);

    // -> value has an [[ArrayBufferData]] internal slot
    if (is<JS::ArrayBuffer>(object))
        return simple_remote_value("arraybuffer"sv);

    // -> value is a platform object that implements NodeList
    if (Bindings::impl_from<DOM::NodeList>(&object))
        return serialize_an_array_like(realm, "nodelist"sv, handle_id, known_object, object, serialization_options, ownership_type, serialization_internal_map);

    // -> value is a platform object that implements HTMLCollection
    if (Bindings::impl_from<DOM::HTMLCollection>(&object))
        return serialize_an_array_like(realm, "htmlcollection"sv, handle_id, known_object, object, serialization_options, ownership_type, serialization_internal_map);

    // -> value is a platform object that implements Node
    if (auto* node = Bindings::impl_from<DOM::Node>(&object)) {
        // 1. Let shared id be get shared id for a node with value and session.
        auto shared_id = get_shared_id_for_a_node(*node);

        // 2. Let remote value be a map matching the script.NodeRemoteValue production in the local end definition,
        //    with the sharedId property set to shared id if it's not null, or omitted otherwise, and the handle
        //    property set to handle id if it's not null, or omitted otherwise.
        JsonObject remote_value;
        remote_value.set("type"sv, "node"sv);
        if (shared_id.has_value())
            remote_value.set("sharedId"sv, *shared_id);
        if (handle_id.has_value())
            remote_value.set("handle"sv, *handle_id);

        // 3. Set internal ids if needed with serialization internal map, remote value and value.
        set_internal_ids_if_needed(serialization_internal_map, remote_value, object);

        // 5. If known object is false, run the following steps:
        if (!known_object) {
            // 1. Let serialized be a map.
            JsonObject serialized;

            // 2. Set serialized["nodeType"] to Get(value, "nodeType").
            serialized.set("nodeType"sv, node->node_type());

            // 3. Set node value to Get(value, "nodeValue").
            // 4. If node value is not null set serialized["nodeValue"] to node value.
            if (auto node_value = node->node_value(); node_value.has_value())
                serialized.set("nodeValue"sv, node_value->to_utf8());

            // 5. If value implements Element or Attr:
            if (auto const* element = as_if<DOM::Element>(*node)) {
                // 1. Set serialized["localName"] to Get(value, "localName").
                serialized.set("localName"sv, element->local_name().to_utf16_string().to_utf8());
                // 2. Set serialized["namespaceURI"] to Get(value, "namespaceURI")
                if (auto namespace_uri = element->namespace_uri(); namespace_uri.has_value())
                    serialized.set("namespaceURI"sv, namespace_uri->to_utf16_string().to_utf8());
            } else if (auto const* attribute = as_if<DOM::Attr>(*node)) {
                serialized.set("localName"sv, attribute->local_name().to_utf16_string().to_utf8());
                if (auto namespace_uri = attribute->namespace_uri(); namespace_uri.has_value())
                    serialized.set("namespaceURI"sv, namespace_uri->to_utf16_string().to_utf8());
            }

            // 6. Let child node count be the size of value's children.
            // 7. Set serialized["childNodeCount"] to child node count.
            auto const* parent_node = as_if<DOM::ParentNode>(*node);
            serialized.set("childNodeCount"sv, parent_node ? parent_node->child_element_count() : 0);

            // 8. If serialization options["maxDomDepth"] is equal to 0, or if value implements ShadowRoot and
            //    serialization options["includeShadowTree"] is "none", or if serialization options["includeShadowTree"]
            //    is "open" and value's mode is "closed", let children be null.
            auto const* shadow_root = as_if<DOM::ShadowRoot>(*node);
            bool children_is_null = serialization_options.max_dom_depth == 0u
                || (shadow_root && serialization_options.include_shadow_tree == SerializationOptions::IncludeShadowTree::None)
                || (shadow_root && serialization_options.include_shadow_tree == SerializationOptions::IncludeShadowTree::Open && shadow_root->mode() == Bindings::ShadowRootMode::Closed);

            // Otherwise, let children be an empty list and, for each node child in the children of value:
            if (!children_is_null) {
                JsonArray children;
                node->for_each_child_of_type<DOM::Element>([&](DOM::Element& child) -> IterationDecision {
                    // 1. Let child serialization options be a clone of serialization options.
                    auto child_serialization_options = serialization_options;

                    // 2. If child serialization options["maxDomDepth"] is not null, set child serialization
                    //    options["maxDomDepth"] to child serialization options["maxDomDepth"] - 1.
                    if (child_serialization_options.max_dom_depth.has_value())
                        child_serialization_options.max_dom_depth = *child_serialization_options.max_dom_depth - 1;

                    // 3. Let serialized be the result of serialize as a remote value with child, child serialization
                    //    options, ownership type, serialization internal map, realm, and session.
                    auto child_value = JS::Value(Bindings::wrap(Bindings::host_defined_wrapper_world(realm), realm, GC::Ref<Bindings::Wrappable> { child }));

                    // 4. Append serialized to children.
                    children.must_append(serialize_as_a_remote_value(realm, child_value, child_serialization_options, ownership_type, serialization_internal_map));
                    return IterationDecision::Continue;
                });

                // 9. If children is not null, set serialized["children"] to children.
                serialized.set("children"sv, move(children));
            }

            // 10. If value implements Element:
            if (auto* element = as_if<DOM::Element>(*node)) {
                // 1. Let attributes be a new map.
                JsonObject attributes;

                // 2. For each attribute in value's attribute list:
                element->for_each_attribute([&](DOM::Attr const& attribute) {
                    // 1. Let name be attribute's qualified name
                    // 2. Let value be attribute's value.
                    // 3. Set attributes[name] to value
                    attributes.set(attribute.name().to_utf16_string().to_utf8(), attribute.value().to_utf8());
                });

                // 3. Set serialized["attributes"] to attributes.
                serialized.set("attributes"sv, move(attributes));

                // 4. Let shadow root be value's shadow root.
                // 5. If shadow root is null, let serialized shadow be null. Otherwise run the following substeps:
                JsonValue serialized_shadow;
                if (auto element_shadow_root = element->shadow_root()) {
                    // 1. Let serialized shadow be the result of serialize as a remote value with shadow root,
                    //    serialization options, ownership type, serialization internal map, realm, and session.
                    auto shadow_value = JS::Value(Bindings::wrap(Bindings::host_defined_wrapper_world(realm), realm, GC::Ref<Bindings::Wrappable> { *element_shadow_root }));
                    serialized_shadow = serialize_as_a_remote_value(realm, shadow_value, serialization_options, ownership_type, serialization_internal_map);
                }

                // 6. Set serialized["shadowRoot"] to serialized shadow.
                serialized.set("shadowRoot"sv, move(serialized_shadow));
            }

            // 11. If value implements ShadowRoot, set serialized["mode"] to value's mode.
            if (shadow_root)
                serialized.set("mode"sv, shadow_root->mode() == Bindings::ShadowRootMode::Open ? "open"sv : "closed"sv);

            // 6. If serialized is not null, set field value of remote value to serialized.
            remote_value.set("value"sv, move(serialized));
        }

        return remote_value;
    }

    // -> value is a platform object that implements WindowProxy
    if (auto* window_proxy = as_if<HTML::WindowProxy>(object)) {
        // 1. Let window be the value of value's [[WindowProxy]] internal slot.
        // 2. Let navigable be window's navigable.
        // 3. Let navigable id be the navigable id for navigable.
        GC::Ptr<HTML::Navigable> navigable;
        if (auto window = window_proxy->window())
            navigable = window->associated_document().navigable();

        // 4. Let serialized be a map matching the script.WindowProxyProperties production in the local end
        //    definition with the context property set to navigable id.
        JsonObject serialized;
        serialized.set("context"sv, navigable ? navigable_id(*navigable) : String {});

        // 5. Let remote value be a map matching the script.WindowProxyRemoteValue production in the local end
        //    definition, with the handle property set to handle id if it's not null, or omitted otherwise, and the
        //    value property set to serialized.
        auto remote_value = simple_remote_value("window"sv);
        remote_value.set("value"sv, move(serialized));
        return remote_value;
    }

    // -> value is a platform object
    if (object.is_platform_object())
        return simple_remote_value("object"sv);

    // -> IsCallable(value)
    if (object.is_function())
        return simple_remote_value("function"sv);

    // -> Otherwise:
    // 1. Assert: Type(value) is Object
    // 2. Let remote value be a map matching the script.ObjectRemoteValue production in the local end definition, with
    //    the handle property set to handle id if it's not null, or omitted otherwise.
    auto remote_value = simple_remote_value("object"sv);

    // 3. Set internal ids if needed with serialization internal map, remote value and value.
    set_internal_ids_if_needed(serialization_internal_map, remote_value, object);

    // 5. If known object is false, and serialization options["maxObjectDepth"] is not 0, run the following steps:
    if (!known_object && serialization_options.max_object_depth != 0u) {
        // 1. Let serialized be the result of serialize as a mapping with EnumerableOwnPropertyNames(value, key+value),
        //    serialization options, ownership type, serialization internal map, realm, and session.
        auto entries = object.enumerable_own_property_names(JS::Object::PropertyKind::KeyAndValue);
        if (!entries.is_error())
            remote_value.set("value"sv, serialize_as_a_mapping(realm, entries.value(), serialization_options, ownership_type, serialization_internal_map));
    }

    // 7. Return remote value
    return remote_value;
}

// https://w3c.github.io/webdriver-bidi/#deserialize-primitive-protocol-value
static ErrorOr<JS::Value, Error> deserialize_primitive_protocol_value(JS::Realm& realm, JsonObject const& primitive_protocol_value)
{
    auto& vm = realm.vm();

    // 1. Let type be the value of the type field of primitive protocol value.
    auto type = primitive_protocol_value.get_string("type"sv).value();

    // 2. Let value be undefined.
    // 3. If primitive protocol value has field value:
    //    1. Let value be the value of the value field of primitive protocol value.
    auto value = primitive_protocol_value.get("value"sv);

    // 4. In the following list of conditions and associated steps, run the first set of steps for which the
    //    associated condition is true:
    // -> type is the string "undefined"
    if (type == "undefined"sv)
        return JS::js_undefined();

    // -> type is the string "null"
    if (type == "null"sv)
        return JS::js_null();

    // -> type is the string "string"
    if (type == "string"sv) {
        if (!value.has_value() || !value->is_string())
            return Error::from_code(ErrorCode::InvalidArgument, "String value must be a string"sv);
        return JS::PrimitiveString::create(vm, Utf16String::from_utf8(value->as_string()));
    }

    // -> type is the string "number"
    if (type == "number"sv) {
        if (!value.has_value())
            return Error::from_code(ErrorCode::InvalidArgument, "Number value is missing"sv);

        // 1. If Type(value) is Number, return success with data value.
        if (value->is_number())
            return JS::Value(value->get_double_with_precision_loss().value());

        // 2. Assert: Type(value) is String.
        if (!value->is_string())
            return Error::from_code(ErrorCode::InvalidArgument, "Number value must be a number or a string"sv);
        auto const& string = value->as_string();

        // 3. If value is the string "NaN", return success with data NaN.
        if (string == "NaN"sv)
            return JS::js_nan();
        if (string == "-0"sv)
            return JS::Value(-0.0);
        if (string == "Infinity"sv)
            return JS::js_infinity();
        if (string == "-Infinity"sv)
            return JS::js_negative_infinity();

        // 4. Let number_result be StringToNumber(value).
        // 5. If number_result is NaN, return error with error code invalid argument
        // 6. Return success with data number_result.
        return Error::from_code(ErrorCode::InvalidArgument, "Invalid number value"sv);
    }

    // -> type is the string "boolean"
    if (type == "boolean"sv) {
        if (!value.has_value() || !value->is_bool())
            return Error::from_code(ErrorCode::InvalidArgument, "Boolean value must be a boolean"sv);
        return JS::Value(value->as_bool());
    }

    // -> type is the string "bigint"
    if (type == "bigint"sv) {
        if (!value.has_value() || !value->is_string())
            return Error::from_code(ErrorCode::InvalidArgument, "BigInt value must be a string"sv);

        // 1. Let bigint_result be StringToBigInt(value).
        auto bigint_result = JS::Value(JS::PrimitiveString::create(vm, Utf16String::from_utf8(value->as_string()))).to_bigint(vm);

        // 2. If bigint_result is undefined, return error with error code invalid argument
        if (bigint_result.is_error())
            return Error::from_code(ErrorCode::InvalidArgument, "Invalid BigInt value"sv);

        // 3. Return success with data bigint_result.
        return JS::Value(bigint_result.value());
    }

    // 5. Return error with error code invalid argument
    return Error::from_code(ErrorCode::InvalidArgument, "Unknown primitive value type"sv);
}

// https://w3c.github.io/webdriver-bidi/#deserialize-remote-reference
static ErrorOr<JS::Value, Error> deserialize_remote_reference(JS::Realm& realm, JsonObject const& remote_reference)
{
    // 2. If remote reference matches the script.SharedReference production, return deserialize shared reference with
    //    remote reference, realm and session.
    if (auto shared_id = remote_reference.get_string("sharedId"sv); shared_id.has_value()) {
        // https://w3c.github.io/webdriver-bidi/#deserialize-shared-reference
        // 2. Let navigable be get the navigable with realm.
        // 3. If navigable is null, return error with error code no such node.
        auto navigable = navigable_of_realm(realm);
        if (!navigable)
            return Error { 404, "no such node"_string, "Realm is not a window realm"_string, {} };

        // 5. Let node be result of trying to get a node with session, navigable and shared id.
        // 6. If node is null, return error with error code no such node.
        auto node = get_node(*shared_id);
        if (!node)
            return Error { 404, "no such node"_string, "Unknown node reference"_string, {} };

        // 7. Let environment settings be the environment settings object whose realm execution context's Realm
        //    component is realm.
        auto& environment_settings = HTML::relevant_settings_object(realm.global_object());

        // 8. If node's node document's origin is not same origin domain with environment settings's origin then
        //    return error with error code no such node.
        if (!node->document().origin().is_same_origin_domain(environment_settings.origin()))
            return Error { 404, "no such node"_string, "Node belongs to another origin"_string, {} };

        // 10. Return success with data node.
        return JS::Value(Bindings::wrap(Bindings::host_defined_wrapper_world(realm), realm, GC::Ref<Bindings::Wrappable> { *node }));
    }

    // 3. Return deserialize remote object reference with remote reference and realm.
    // https://w3c.github.io/webdriver-bidi/#deserialize-remote-object-reference
    // 1. Let handle id be the value of the handle field of remote object reference.
    auto handle_id = remote_reference.get_string("handle"sv).value();

    // 2. Let handle map be realm's handle object map
    // 3. If handle map does not contain handle id, then return error with error code no such handle.
    auto object = handle_object_map().get(handle_id);
    if (!object.has_value())
        return Error { 404, "no such handle"_string, "Unknown object handle"_string, {} };

    // 4. Return success with data handle map[handle id].
    return JS::Value(object->ptr());
}

// https://w3c.github.io/webdriver-bidi/#deserialize-key-value-list
static ErrorOr<GC::RootVector<JS::Value>, Error> deserialize_key_value_list(JS::Realm& realm, JsonValue const& serialized_key_value_list)
{
    if (!serialized_key_value_list.is_array())
        return Error::from_code(ErrorCode::InvalidArgument, "Mapping value must be a list"sv);

    // 1. Let deserialized key-value list be a new list.
    GC::RootVector<JS::Value> deserialized_key_value_list;

    // 2. For each serialized key-value in the serialized key-value list:
    for (auto const& serialized_key_value : serialized_key_value_list.as_array().values()) {
        // 1. If size of serialized key-value is not 2, return error with error code invalid argument.
        if (!serialized_key_value.is_array() || serialized_key_value.as_array().size() != 2)
            return Error::from_code(ErrorCode::InvalidArgument, "Mapping entry must be a list of two values"sv);

        // 2. Let serialized key be serialized key-value[0].
        auto const& serialized_key = serialized_key_value.as_array()[0];

        // 3. If serialized key is a string, let deserialized key be serialized key.
        // 4. Otherwise let deserialized key be result of trying to given deserialize local value with serialized
        //    key, realm and session.
        JS::Value deserialized_key;
        if (serialized_key.is_string())
            deserialized_key = JS::PrimitiveString::create(realm.vm(), Utf16String::from_utf8(serialized_key.as_string()));
        else
            deserialized_key = TRY(deserialize_local_value(realm, serialized_key));

        // 5. Let serialized value be serialized key-value[1].
        // 6. Let deserialized value be result of trying to deserialize local value given serialized value, realm and
        //    session.
        auto deserialized_value = TRY(deserialize_local_value(realm, serialized_key_value.as_array()[1]));

        // 7. Append CreateArrayFromList(« deserialized key, deserialized value ») to deserialized key-value list.
        deserialized_key_value_list.append(JS::Array::create_from(realm, { deserialized_key, deserialized_value }));
    }

    // 3. Return success with data deserialized key-value list.
    return deserialized_key_value_list;
}

// https://w3c.github.io/webdriver-bidi/#deserialize-value-list
static ErrorOr<GC::RootVector<JS::Value>, Error> deserialize_value_list(JS::Realm& realm, JsonValue const& serialized_value_list)
{
    if (!serialized_value_list.is_array())
        return Error::from_code(ErrorCode::InvalidArgument, "List value must be a list"sv);

    // 1. Let deserialized values be a new list.
    GC::RootVector<JS::Value> deserialized_values;

    // 2. For each serialized value in the serialized value list:
    for (auto const& serialized_value : serialized_value_list.as_array().values()) {
        // 1. Let deserialized value be result of trying to deserialize local value given serialized value, realm and
        //    session.
        // 2. Append deserialized value to deserialized values;
        deserialized_values.append(TRY(deserialize_local_value(realm, serialized_value)));
    }

    // 3. Return success with data deserialized values.
    return deserialized_values;
}

// https://w3c.github.io/webdriver-bidi/#deserialize-local-value
ErrorOr<JS::Value, Error> deserialize_local_value(JS::Realm& realm, JsonValue const& local_protocol_value)
{
    auto& vm = realm.vm();

    if (!local_protocol_value.is_object())
        return Error::from_code(ErrorCode::InvalidArgument, "Local value must be an object"sv);
    auto const& object = local_protocol_value.as_object();

    // 1. If local protocol value matches the script.RemoteReference production, return deserialize remote reference
    //    of given local protocol value, realm and session.
    if (object.has_string("sharedId"sv) || object.has_string("handle"sv))
        return deserialize_remote_reference(realm, object);

    // 4. Let type be the value of the type field of local protocol value or undefined if no such a field.
    auto type = object.get_string("type"sv);
    if (!type.has_value())
        return Error::from_code(ErrorCode::InvalidArgument, "Local value must have a type"sv);

    // 2. If local protocol value matches the script.PrimitiveProtocolValue production, return deserialize primitive
    //    protocol value with local protocol value.
    if (type->is_one_of("undefined"sv, "null"sv, "string"sv, "number"sv, "boolean"sv, "bigint"sv))
        return deserialize_primitive_protocol_value(realm, object);

    // 3. If local protocol value matches the script.ChannelValue production, return create a channel with session,
    //    realm and local protocol value.
    if (type == "channel"sv)
        return Error::from_code(ErrorCode::UnsupportedOperation, "Channels are not supported"sv);

    // 5. Let value be the value of the value field of local protocol value or undefined if no such a field.
    auto value = object.get("value"sv).value_or(JsonValue {});

    // 6. In the following list of conditions and associated steps, run the first set of steps for which the
    //    associated condition is true:
    // -> type is the string "array"
    if (type == "array"sv) {
        // 1. Let deserialized value list be a result of trying to deserialize value list given value, realm and
        //    session.
        auto deserialized_value_list = TRY(deserialize_value_list(realm, value));

        // 2. Return success with data CreateArrayFromList(deserialized value list).
        return JS::Array::create_from(realm, deserialized_value_list);
    }

    // -> type is the string "date"
    if (type == "date"sv) {
        // 1. If value does not match Date Time String Format, return error with error code invalid argument.
        if (!value.is_string())
            return Error::from_code(ErrorCode::InvalidArgument, "Date value must be a string"sv);

        // 2. Let date result be Construct(Date, value).
        auto date_result = JS::construct(vm, *realm.intrinsics().date_constructor(), JS::PrimitiveString::create(vm, Utf16String::from_utf8(value.as_string())));
        if (date_result.is_error() || isnan(as<JS::Date>(*date_result.value()).date_value()))
            return Error::from_code(ErrorCode::InvalidArgument, "Invalid date value"sv);

        // 3. Return success with data date result.
        return JS::Value(date_result.value());
    }

    // -> type is the string "map"
    if (type == "map"sv) {
        // 1. Let deserialized key-value list be a result of trying to deserialize key-value list with value, realm
        //    and session.
        auto deserialized_key_value_list = TRY(deserialize_key_value_list(realm, value));

        // 2. Let iterable be CreateArrayFromList(deserialized key-value list)
        // 3. Return success with data Map(iterable).
        auto map = JS::Map::create(realm);
        for (auto entry : deserialized_key_value_list) {
            auto& pair = as<JS::Array>(entry.as_object());
            map->map_set(MUST(pair.get(0)), MUST(pair.get(1)));
        }
        return map;
    }

    // -> type is the string "object"
    if (type == "object"sv) {
        // 1. Let deserialized key-value list be a result of trying to deserialize key-value list with value, realm
        //    and session.
        auto deserialized_key_value_list = TRY(deserialize_key_value_list(realm, value));

        // 2. Let iterable be CreateArrayFromList(deserialized key-value list)
        // 3. Return success with data Object.fromEntries(iterable).
        auto result = JS::Object::create(realm, realm.intrinsics().object_prototype());
        for (auto entry : deserialized_key_value_list) {
            auto& pair = as<JS::Array>(entry.as_object());
            auto key = MUST(pair.get(0));
            auto property_key = key.to_property_key(vm);
            if (property_key.is_error())
                return Error::from_code(ErrorCode::InvalidArgument, "Invalid object key"sv);
            MUST(result->create_data_property_or_throw(property_key.value(), MUST(pair.get(1))));
        }
        return result;
    }

    // -> type is the string "regexp"
    if (type == "regexp"sv) {
        if (!value.is_object())
            return Error::from_code(ErrorCode::InvalidArgument, "RegExp value must be an object"sv);

        // 1. Let pattern be the value of the pattern field of local protocol value.
        auto pattern = value.as_object().get_string("pattern"sv);
        if (!pattern.has_value())
            return Error::from_code(ErrorCode::InvalidArgument, "RegExp value must have a pattern"sv);

        // 2. Let flags be the value of the flags field of local protocol value or undefined if no such a field.
        auto flags = value.as_object().get_string("flags"sv);

        // 3. Let regex_result be Regexp(pattern, flags). If this throws exception, return error with error code
        //    invalid argument.
        auto regexp_result = JS::regexp_create(vm, JS::PrimitiveString::create(vm, Utf16String::from_utf8(*pattern)), flags.has_value() ? JS::Value(JS::PrimitiveString::create(vm, Utf16String::from_utf8(*flags))) : JS::js_undefined());
        if (regexp_result.is_error())
            return Error::from_code(ErrorCode::InvalidArgument, "Invalid RegExp value"sv);

        // 4. Return success with data regex_result.
        return regexp_result.value();
    }

    // -> type is the string "set"
    if (type == "set"sv) {
        // 1. Let deserialized value list be a result of trying to deserialize value list given value, realm and
        //    session.
        auto deserialized_value_list = TRY(deserialize_value_list(realm, value));

        // 2. Let iterable be CreateArrayFromList(deserialized key-value list)
        // 3. Return success with data Set object(iterable).
        auto set = JS::Set::create(realm);
        for (auto item : deserialized_value_list)
            set->set_add(item);
        return set;
    }

    // -> otherwise
    // Return error with error code invalid argument.
    return Error::from_code(ErrorCode::InvalidArgument, "Unknown local value type"sv);
}

}
