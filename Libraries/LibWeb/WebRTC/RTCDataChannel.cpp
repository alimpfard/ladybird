/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/ByteBuffer.h>
#include <LibJS/Runtime/ArrayBuffer.h>
#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCDataChannel.h>
#include <LibWeb/FileAPI/Blob.h>
#include <LibWeb/HTML/EventNames.h>
#include <LibWeb/WebIDL/Buffers.h>
#include <LibWeb/WebIDL/DOMException.h>
#include <LibWeb/WebRTC/RTCDataChannel.h>
#include <LibWeb/WebRTC/WebRTCAgent.h>
#include <LibWebRTCClient/Client.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCDataChannel);

GC::Ref<RTCDataChannel> RTCDataChannel::create(JS::Realm& realm) { return realm.create<RTCDataChannel>(realm); }
RTCDataChannel::RTCDataChannel(JS::Realm& realm)
    : DOM::EventTarget()
    , m_realm(realm)
{
}
RTCDataChannel::~RTCDataChannel() = default;

void RTCDataChannel::set_onopen(WebIDL::CallbackType* cb) { set_event_handler_attribute(HTML::EventNames::open, cb); }
WebIDL::CallbackType* RTCDataChannel::onopen() { return event_handler_attribute(HTML::EventNames::open); }
void RTCDataChannel::set_onbufferedamountlow(WebIDL::CallbackType* cb) { set_event_handler_attribute(HTML::EventNames::bufferedamountlow, cb); }
WebIDL::CallbackType* RTCDataChannel::onbufferedamountlow() { return event_handler_attribute(HTML::EventNames::bufferedamountlow); }
void RTCDataChannel::set_onerror(WebIDL::CallbackType* cb) { set_event_handler_attribute(HTML::EventNames::error, cb); }
WebIDL::CallbackType* RTCDataChannel::onerror() { return event_handler_attribute(HTML::EventNames::error); }
void RTCDataChannel::set_onclosing(WebIDL::CallbackType* cb) { set_event_handler_attribute(HTML::EventNames::closing, cb); }
WebIDL::CallbackType* RTCDataChannel::onclosing() { return event_handler_attribute(HTML::EventNames::closing); }
void RTCDataChannel::set_onclose(WebIDL::CallbackType* cb) { set_event_handler_attribute(HTML::EventNames::close, cb); }
WebIDL::CallbackType* RTCDataChannel::onclose() { return event_handler_attribute(HTML::EventNames::close); }
void RTCDataChannel::set_onmessage(WebIDL::CallbackType* cb) { set_event_handler_attribute(HTML::EventNames::message, cb); }
WebIDL::CallbackType* RTCDataChannel::onmessage() { return event_handler_attribute(HTML::EventNames::message); }

// https://www.w3.org/TR/webrtc/#dom-rtcdatachannel-send
WebIDL::ExceptionOr<void> RTCDataChannel::send(FlattenVariant<Variant<Utf16String, GC::Ref<FileAPI::Blob>>, WebIDL::BufferSourceVariant> const& data)
{
    // 1. Let channel be the RTCDataChannel object on which data is to be sent.
    // 2. Set channel.[[IsTransferable]] to false.
    m_is_transferable = false;
    // 3. If channel.[[ReadyState]] is not "open", throw an InvalidStateError.
    if (m_ready_state != Bindings::RTCDataChannelState::Open)
        return WebIDL::InvalidStateError::create("RTCDataChannel is not open"_utf16);

    auto* client = WebRTCAgent::the().client();
    size_t byte_size = 0;

    // 4. Execute the sub step that corresponds to the type of the methods argument:
    data.visit(
        [&](Utf16String const& text) {
            // string object: Let data be a byte buffer that represents the result of encoding the method's argument as UTF-8.
            auto string = text.to_utf8();
            byte_size = string.bytes().size();
            // FIXME: 5. If the byte size of data exceeds the value of maxMessageSize on channel's associated RTCSctpTransport, throw a TypeError.
            // 6. Queue data for transmission on channel's underlying data transport.
            if (client)
                client->async_data_channel_send_text(m_channel_id, string);
        },
        [&](GC::Ref<FileAPI::Blob> const& blob) {
            // Blob object: Let data be the raw data represented by the Blob object.
            auto bytes = blob->raw_bytes();
            byte_size = bytes.size();
            // FIXME: 5. If the byte size of data exceeds the value of maxMessageSize on channel's associated RTCSctpTransport, throw a TypeError.
            // 6. Queue data for transmission on channel's underlying data transport.
            if (client)
                client->async_data_channel_send_binary(m_channel_id, bytes);
        },
        [&](auto const& buffer_source) {
            // ArrayBuffer object: Let data be the data stored in the buffer described by the ArrayBuffer object.
            // ArrayBufferView object: Let data be the data stored in the section of the buffer described by the ArrayBuffer object that the ArrayBufferView object references.
            WebIDL::BufferSource source { WebIDL::BufferSourceVariant { buffer_source } };
            if (auto buffer = source.viewed_array_buffer(); buffer && !buffer->is_detached()) {
                buffer->with_readonly_bytes(source.byte_offset(), source.byte_length(), [&](ReadonlyBytes bytes) {
                    byte_size = bytes.size();
                    if (client)
                        client->async_data_channel_send_binary(m_channel_id, bytes);
                });
            }
        });
    // FIXME: 6. ...If queuing data is not possible because not enough buffer space is available, throw an OperationError.
    // 7. Increase the value of the [[BufferedAmount]] slot by the byte size of data.
    m_buffered_amount += byte_size;
    return {};
}

void RTCDataChannel::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
}

}
