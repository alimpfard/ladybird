/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibJS/Runtime/ArrayBuffer.h>
#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCEncodedAudioFrame.h>
#include <LibWeb/HTML/StructuredSerialize.h>
#include <LibWeb/WebIDL/DOMException.h>
#include <LibWeb/WebRTC/RTCEncodedAudioFrame.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCEncodedAudioFrame);

// https://w3c.github.io/webrtc-encoded-transform/#dom-rtcencodedaudioframe-rtcencodedaudioframe
WebIDL::ExceptionOr<GC::Ref<RTCEncodedAudioFrame>> RTCEncodedAudioFrame::construct_impl(JS::Realm& realm, GC::Ref<RTCEncodedAudioFrame> original_frame, RTCEncodedAudioFrameOptions const& options)
{
    auto frame = realm.create<RTCEncodedAudioFrame>(realm);

    // 1. Let this.[[data]] be the result of CloneArrayBuffer(originalFrame.[[data]], 0,
    //    originalFrame.[[data]].[[ArrayBufferByteLength]]).
    auto& original_data = *original_frame->m_data;
    auto* cloned = TRY(JS::clone_array_buffer(realm.vm(), original_data, 0, original_data.byte_length()));
    frame->m_data = cloned;

    // 2. Let [[metadata]] represent the metadata associated with this newly constructed frame.
    //    2.1. Copy each field of originalFrame's [[metadata]] into this.[[metadata]].
    frame->m_metadata = original_frame->m_metadata;
    //    2.2. For each field present in options.metadata, override this.[[metadata]] with a deep copy.
    if (options.metadata.has_value()) {
        auto const& source = options.metadata.value();
        if (source.synchronization_source.has_value())
            frame->m_metadata.synchronization_source = source.synchronization_source;
        if (source.payload_type.has_value())
            frame->m_metadata.payload_type = source.payload_type;
        if (source.contributing_sources.has_value())
            frame->m_metadata.contributing_sources = source.contributing_sources;
        if (source.rtp_timestamp.has_value())
            frame->m_metadata.rtp_timestamp = source.rtp_timestamp;
        if (source.receive_time.has_value())
            frame->m_metadata.receive_time = source.receive_time;
        if (source.capture_time.has_value())
            frame->m_metadata.capture_time = source.capture_time;
        if (source.sender_capture_time_offset.has_value())
            frame->m_metadata.sender_capture_time_offset = source.sender_capture_time_offset;
        if (source.mime_type.has_value())
            frame->m_metadata.mime_type = source.mime_type;
        if (source.sequence_number.has_value())
            frame->m_metadata.sequence_number = source.sequence_number;
        if (source.audio_level.has_value())
            frame->m_metadata.audio_level = source.audio_level;
    }
    return frame;
}

GC::Ref<RTCEncodedAudioFrame> RTCEncodedAudioFrame::create_from_packet(JS::Realm& realm, ByteBuffer payload,
    u32 ssrc, u8 payload_type, u32 rtp_timestamp, u16 sequence_number)
{
    auto frame = realm.create<RTCEncodedAudioFrame>(realm);
    frame->m_data = JS::ArrayBuffer::create(realm, move(payload));
    frame->m_metadata.synchronization_source = ssrc;
    frame->m_metadata.payload_type = payload_type;
    frame->m_metadata.rtp_timestamp = rtp_timestamp;
    // sequenceNumber is signed 16-bit per spec — RTP seq is u16, just bit-cast.
    frame->m_metadata.sequence_number = static_cast<i16>(sequence_number);
    frame->m_metadata.mime_type = "audio/opus"_string;
    return frame;
}

RTCEncodedAudioFrame::RTCEncodedAudioFrame(JS::Realm& realm)
    : Bindings::PlatformObject(realm)
{
}

RTCEncodedAudioFrame::~RTCEncodedAudioFrame() = default;

void RTCEncodedAudioFrame::initialize(JS::Realm& realm)
{
    WEB_SET_PROTOTYPE_FOR_INTERFACE(RTCEncodedAudioFrame);
    Base::initialize(realm);
}

void RTCEncodedAudioFrame::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_data);
}

GC::Ref<JS::ArrayBuffer> RTCEncodedAudioFrame::data() const
{
    return *m_data;
}

WebIDL::ExceptionOr<void> RTCEncodedAudioFrame::set_data(GC::Ref<JS::ArrayBuffer> buffer)
{
    m_data = buffer;
    return {};
}

// https://w3c.github.io/webrtc-encoded-transform/#RTCEncodedAudioFrame-serialization
WebIDL::ExceptionOr<void> RTCEncodedAudioFrame::serialization_steps(HTML::TransferDataEncoder& serialized, bool for_storage, HTML::SerializationMemory& memory)
{
    auto& vm = this->vm();
    // 1. If forStorage is true, then throw a DataCloneError.
    if (for_storage)
        return WebIDL::DataCloneError::create(realm(), "RTCEncodedAudioFrame is not storable"_utf16);

    // 2. Set serialized.[[metadata]] to an internal representation of value's metadata.
    auto encode_optional = [&serialized]<typename T>(Optional<T> const& v) {
        serialized.encode<bool>(v.has_value());
        if (v.has_value())
            serialized.encode(v.value());
    };
    encode_optional(m_metadata.synchronization_source);
    encode_optional(m_metadata.payload_type);
    serialized.encode<bool>(m_metadata.contributing_sources.has_value());
    if (m_metadata.contributing_sources.has_value()) {
        auto const& csrcs = m_metadata.contributing_sources.value();
        serialized.encode<u64>(csrcs.size());
        for (auto csrc : csrcs)
            serialized.encode<u32>(csrc);
    }
    encode_optional(m_metadata.rtp_timestamp);
    encode_optional(m_metadata.receive_time);
    encode_optional(m_metadata.capture_time);
    encode_optional(m_metadata.sender_capture_time_offset);
    encode_optional(m_metadata.mime_type);
    encode_optional(m_metadata.sequence_number);
    encode_optional(m_metadata.audio_level);

    // 3. Set serialized.[[data]] to the sub-serialization of value.[[data]].
    serialized.append(TRY(HTML::structured_serialize_internal(vm, JS::Value(m_data.ptr()), for_storage, memory)));
    return {};
}

WebIDL::ExceptionOr<void> RTCEncodedAudioFrame::deserialization_steps(HTML::TransferDataDecoder& serialized, HTML::DeserializationMemory& memory)
{
    auto& vm = this->vm();
    auto& realm = this->realm();
    // 1. Set value's metadata to the platform object representation of serialized.[[metadata]].
    auto decode_optional = [&serialized]<typename T>(Optional<T>& target) {
        if (serialized.decode<bool>())
            target = serialized.decode<T>();
        else
            target = {};
    };
    decode_optional(m_metadata.synchronization_source);
    decode_optional(m_metadata.payload_type);
    if (serialized.decode<bool>()) {
        Vector<u32> csrcs;
        auto count = serialized.decode<u64>();
        csrcs.ensure_capacity(count);
        for (u64 i = 0; i < count; ++i)
            csrcs.append(serialized.decode<u32>());
        m_metadata.contributing_sources = move(csrcs);
    } else {
        m_metadata.contributing_sources = {};
    }
    decode_optional(m_metadata.rtp_timestamp);
    decode_optional(m_metadata.receive_time);
    decode_optional(m_metadata.capture_time);
    decode_optional(m_metadata.sender_capture_time_offset);
    decode_optional(m_metadata.mime_type);
    decode_optional(m_metadata.sequence_number);
    decode_optional(m_metadata.audio_level);

    // 2. Set value.[[data]] to the sub-deserialization of serialized.[[data]].
    auto deserialized_data = TRY(HTML::structured_deserialize_internal(vm, serialized, realm, memory));
    if (!deserialized_data.is_object() || !is<JS::ArrayBuffer>(deserialized_data.as_object()))
        return WebIDL::DataCloneError::create(realm, "RTCEncodedAudioFrame.[[data]] did not deserialize to an ArrayBuffer"_utf16);
    m_data = static_cast<JS::ArrayBuffer&>(deserialized_data.as_object());
    return {};
}

}
