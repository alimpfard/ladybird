/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Optional.h>
#include <AK/String.h>
#include <AK/Vector.h>
#include <LibJS/Runtime/ArrayBuffer.h>
#include <LibWeb/Bindings/PlatformObject.h>
#include <LibWeb/Bindings/RTCEncodedAudioFrame.h>
#include <LibWeb/Bindings/Serializable.h>
#include <LibWeb/Export.h>
#include <LibWeb/WebIDL/Buffers.h>
#include <LibWeb/WebIDL/ExceptionOr.h>

namespace Web::WebRTC {

using Bindings::RTCEncodedAudioFrameMetadata;
using Bindings::RTCEncodedAudioFrameOptions;
using Bindings::RTCEncodedFrameMetadata;

class WEB_API RTCEncodedAudioFrame final
    : public Bindings::PlatformObject
    , public Bindings::Serializable {
    WEB_PLATFORM_OBJECT(RTCEncodedAudioFrame, Bindings::PlatformObject);
    GC_DECLARE_ALLOCATOR(RTCEncodedAudioFrame);

public:
    static WebIDL::ExceptionOr<GC::Ref<RTCEncodedAudioFrame>> construct_impl(JS::Realm&, GC::Ref<RTCEncodedAudioFrame> original_frame, RTCEncodedAudioFrameOptions const& options = {});

    // Internal factory used when an encoded packet arrives off the wire — builds
    // [[data]] from a fresh ByteBuffer and seeds [[metadata]] from RTP header fields.
    static GC::Ref<RTCEncodedAudioFrame> create_from_packet(JS::Realm&, ByteBuffer payload,
        u32 ssrc, u8 payload_type, u32 rtp_timestamp, u16 sequence_number);

    virtual ~RTCEncodedAudioFrame() override;

    GC::Ref<JS::ArrayBuffer> data() const;
    WebIDL::ExceptionOr<void> set_data(GC::Ref<JS::ArrayBuffer>);

    RTCEncodedAudioFrameMetadata get_metadata() const { return m_metadata; }

    // https://w3c.github.io/webrtc-encoded-transform/#RTCEncodedAudioFrame-serialization
    virtual WebIDL::ExceptionOr<void> serialization_steps(HTML::TransferDataEncoder&, bool for_storage, HTML::SerializationMemory&) override;
    virtual WebIDL::ExceptionOr<void> deserialization_steps(HTML::TransferDataDecoder&, HTML::DeserializationMemory&) override;

private:
    explicit RTCEncodedAudioFrame(JS::Realm&);
    virtual void initialize(JS::Realm&) override;
    virtual void visit_edges(JS::Cell::Visitor&) override;

    // [[data]]
    GC::Ptr<JS::ArrayBuffer> m_data;
    // [[metadata]]
    RTCEncodedAudioFrameMetadata m_metadata;
};

}
