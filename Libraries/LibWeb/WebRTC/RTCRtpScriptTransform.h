/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibJS/Runtime/Realm.h>

#include <LibJS/Forward.h>
#include <LibWeb/Bindings/RTCRtpScriptTransform.h>
#include <LibWeb/Bindings/Wrappable.h>
#include <LibWeb/Forward.h>
#include <LibWeb/HTML/StructuredSerialize.h>
#include <LibWeb/WebIDL/ExceptionOr.h>

namespace Web::WebRTC {

using WorkerAndParameters = Bindings::WorkerAndParameters;

class RTCRtpScriptTransform final : public Bindings::GCAllocatedWrappable {
    WEB_WRAPPABLE(RTCRtpScriptTransform, Bindings::GCAllocatedWrappable);
    GC_DECLARE_ALLOCATOR(RTCRtpScriptTransform);

public:
    static WebIDL::ExceptionOr<GC::Ref<RTCRtpScriptTransform>> construct_impl(JS::Realm&,
        Variant<GC::Ref<HTML::Worker>, WorkerAndParameters> const& worker_or_parameters,
        Optional<JS::Value> options,
        Optional<GC::RootVector<GC::Ref<JS::Object>>> const& transfer);

    virtual ~RTCRtpScriptTransform() override;

    GC::Ptr<HTML::Worker> worker() const { return m_worker; }
    u64 transform_id() const { return m_transform_id; }

    // Hand the transform an encoded frame straight off the wire. The transform forwards it
    // to the worker via IPC; the worker's onrtctransform handler (if any) reads it from the
    // transformer's readable, optionally mutates it, and writes to writable. The written
    // frame comes back on the parent side via on_frame_written.
    void enqueue_encoded_audio_frame(ByteBuffer payload, u32 ssrc, u8 payload_type, u32 rtp_timestamp, u16 sequence_number);

    using FrameWrittenCallback = AK::Function<void(ByteBuffer payload, u32 ssrc, u8 payload_type, u32 rtp_timestamp, u16 sequence_number)>;
    void set_on_frame_written(FrameWrittenCallback callback) { m_on_frame_written = move(callback); }
    bool has_frame_written_callback() const { return static_cast<bool>(m_on_frame_written); }

public:
    JS::Realm& realm() const { return *m_realm; }
    JS::VM& vm() const { return realm().vm(); }

private:
    GC::Ref<JS::Realm> m_realm;
    explicit RTCRtpScriptTransform(JS::Realm&);
    virtual void visit_edges(Cell::Visitor&) override;

    GC::Ptr<HTML::Worker> m_worker;
    bool m_use_sframe { false };
    u64 m_transform_id { 0 };
    bool m_callback_registered { false };

    FrameWrittenCallback m_on_frame_written;
};

}
