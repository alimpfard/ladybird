/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibJS/Runtime/Realm.h>

#include <LibGC/Function.h>
#include <LibWeb/DOM/EventTarget.h>
#include <LibWeb/Export.h>
#include <LibWeb/Forward.h>
#include <LibWeb/WebIDL/ExceptionOr.h>

namespace Web::WebRTC {

// https://w3c.github.io/webrtc-encoded-transform/#rtcrtpscripttransformer
class WEB_API RTCRtpScriptTransformer final : public DOM::EventTarget {
    WEB_WRAPPABLE(RTCRtpScriptTransformer, DOM::EventTarget);
    GC_DECLARE_ALLOCATOR(RTCRtpScriptTransformer);

public:
    // The "writeEncodedData" algorithm. Spec: the writable's write algorithm runs
    // writeEncodedData(transformer, frame) which "hands the frame to the next stage
    // of the pipeline" — i.e. to [[frameSource]] (the encoder/depacketizer) for
    // continued processing. We model that next-stage as an injected callback so
    // the host (worker process) can route the frame back to the parent over IPC.
    using WriteEncodedDataAlgorithm = GC::Function<void(JS::Value frame)>;

    static WebIDL::ExceptionOr<GC::Ref<RTCRtpScriptTransformer>> create(JS::Realm&, JS::Value options);
    virtual ~RTCRtpScriptTransformer() override;

    GC::Ref<Streams::ReadableStream> readable() const { return *m_readable; }
    GC::Ref<Streams::WritableStream> writable() const { return *m_writable; }
    JS::Value options() const { return m_options; }

    // Configure the action to run when the worker writes a transformed frame to
    // [[writable]]. This represents the [[frameSource]]'s "consume the transformed
    // frame" entry point. Per spec [[frameSource]] is set by the host before the
    // rtctransform event is fired; we set it via this API immediately after construction.
    void set_write_encoded_data_algorithm(GC::Ptr<WriteEncodedDataAlgorithm>);

    // Push an encoded frame into [[readable]] from the upstream [[frameSource]]
    // (e.g. a fresh packet from the depacketizer). Returns an exception if the
    // controller rejects the enqueue.
    WebIDL::ExceptionOr<void> enqueue_encoded_frame(JS::Value frame);

    void set_onkeyframerequest(WebIDL::CallbackType*);
    WebIDL::CallbackType* onkeyframerequest();

public:
    JS::Realm& realm() const { return *m_realm; }
    JS::VM& vm() const { return realm().vm(); }

private:
    GC::Ref<JS::Realm> m_realm;
    explicit RTCRtpScriptTransformer(JS::Realm&);
    virtual void visit_edges(Cell::Visitor&) override;

    // [[frameSource]] — modeled as an indirection to the spec algorithm that
    // "hands the frame to the next pipeline stage". undefined per spec until the
    // host wires it.
    GC::Ptr<WriteEncodedDataAlgorithm> m_write_encoded_data;
    // [[options]]
    JS::Value m_options { JS::js_undefined() };
    // [[readable]]
    GC::Ptr<Streams::ReadableStream> m_readable;
    // [[writable]]
    GC::Ptr<Streams::WritableStream> m_writable;
    // [[lastReceivedFrameCounter]]
    u64 m_last_received_frame_counter { 0 };
    // [[lastEnqueuedFrameCounter]]
    u64 m_last_enqueued_frame_counter { 0 };
};

}
