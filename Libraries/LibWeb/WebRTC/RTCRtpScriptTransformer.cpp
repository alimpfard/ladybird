/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibJS/Runtime/Promise.h>
#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCRtpScriptTransformer.h>
#include <LibWeb/Streams/ReadableStream.h>
#include <LibWeb/Streams/ReadableStreamDefaultController.h>
#include <LibWeb/Streams/ReadableStreamOperations.h>
#include <LibWeb/Streams/WritableStream.h>
#include <LibWeb/Streams/WritableStreamOperations.h>
#include <LibWeb/WebIDL/Promise.h>
#include <LibWeb/WebRTC/RTCRtpScriptTransformer.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCRtpScriptTransformer);

// https://w3c.github.io/webrtc-encoded-transform/#create-an-rtcrtpscripttransformer
WebIDL::ExceptionOr<GC::Ref<RTCRtpScriptTransformer>> RTCRtpScriptTransformer::create(JS::Realm& realm, JS::Value options)
{
    auto transformer = realm.create<RTCRtpScriptTransformer>(realm);

    // 1. Let transformer be a new RTCRtpScriptTransformer with:
    //    [[frameSource]] = undefined (set later via set_write_encoded_data_algorithm)
    //    [[options]] = options
    //    [[readable]] = a new ReadableStream
    //    [[writable]] = a new WritableStream
    //    [[lastReceivedFrameCounter]] = 0
    //    [[lastEnqueuedFrameCounter]] = 0
    transformer->m_options = options;

    // 2. Set up transformer.[[readable]]. The readEncodedData algorithm provides
    //    encoded frames to it. In our model, frames are pushed in via
    //    enqueue_encoded_frame from the upstream [[frameSource]] (the depacketizer
    //    on the parent side, plumbed through IPC), so the pull is a no-op.
    auto start_algorithm = GC::create_function(realm.heap(), []() -> WebIDL::ExceptionOr<JS::Value> {
        return JS::js_undefined();
    });
    auto pull_algorithm = GC::create_function(realm.heap(), [&realm]() -> GC::Ref<WebIDL::Promise> {
        return WebIDL::create_resolved_promise(realm, JS::js_undefined());
    });
    auto cancel_algorithm = GC::create_function(realm.heap(), [&realm](JS::Value) -> GC::Ref<WebIDL::Promise> {
        return WebIDL::create_resolved_promise(realm, JS::js_undefined());
    });
    transformer->m_readable = TRY(Streams::create_readable_stream(realm, start_algorithm, pull_algorithm, cancel_algorithm));

    // 3. Let writeAlgorithm be an action that runs writeEncodedData with this as
    //    parameter and frame as input, given frame.
    // 4. Set up transformer.[[writable]] with its writeAlgorithm set to writeAlgorithm
    //    and its highWaterMark set to Infinity.
    auto writable_start_algorithm = GC::create_function(realm.heap(), []() -> WebIDL::ExceptionOr<JS::Value> {
        return JS::js_undefined();
    });
    GC::Ref<RTCRtpScriptTransformer> transformer_capture = transformer;
    auto write_algorithm = GC::create_function(realm.heap(), [&realm, transformer_capture](JS::Value chunk) -> GC::Ref<WebIDL::Promise> {
        // writeEncodedData step: hand the transformed frame to [[frameSource]] for
        // continued pipeline processing (decode, playback, or send-out for senders).
        if (transformer_capture->m_write_encoded_data)
            transformer_capture->m_write_encoded_data->function()(chunk);
        return WebIDL::create_resolved_promise(realm, JS::js_undefined());
    });
    auto close_algorithm = GC::create_function(realm.heap(), [&realm]() -> GC::Ref<WebIDL::Promise> {
        return WebIDL::create_resolved_promise(realm, JS::js_undefined());
    });
    auto abort_algorithm = GC::create_function(realm.heap(), [&realm](JS::Value) -> GC::Ref<WebIDL::Promise> {
        return WebIDL::create_resolved_promise(realm, JS::js_undefined());
    });
    auto size_algorithm = GC::create_function(realm.heap(), [](JS::Value) -> JS::Completion {
        return JS::Completion { JS::Value(1.0) };
    });
    transformer->m_writable = TRY(Streams::create_writable_stream(realm, writable_start_algorithm, write_algorithm, close_algorithm, abort_algorithm, __builtin_inf(), size_algorithm));

    // 5. Return transformer.
    return transformer;
}

void RTCRtpScriptTransformer::set_write_encoded_data_algorithm(GC::Ptr<WriteEncodedDataAlgorithm> algorithm)
{
    m_write_encoded_data = algorithm;
}

WebIDL::ExceptionOr<void> RTCRtpScriptTransformer::enqueue_encoded_frame(JS::Value frame)
{
    if (!m_readable)
        return {};
    auto& maybe_controller = m_readable->controller();
    if (!maybe_controller.has_value())
        return {};
    auto controller = maybe_controller->get<GC::Ref<Streams::ReadableStreamDefaultController>>();
    ++m_last_received_frame_counter;
    TRY(Streams::readable_stream_default_controller_enqueue(realm(), controller, frame));
    ++m_last_enqueued_frame_counter;
    return {};
}

void RTCRtpScriptTransformer::set_onkeyframerequest(WebIDL::CallbackType*) { }
WebIDL::CallbackType* RTCRtpScriptTransformer::onkeyframerequest() { return nullptr; }

RTCRtpScriptTransformer::RTCRtpScriptTransformer(JS::Realm& realm)
    : DOM::EventTarget()
    , m_realm(realm)
{
}

RTCRtpScriptTransformer::~RTCRtpScriptTransformer() = default;

void RTCRtpScriptTransformer::visit_edges(Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
    visitor.visit(m_options);
    visitor.visit(m_readable);
    visitor.visit(m_writable);
    visitor.visit(m_write_encoded_data);
}

}
