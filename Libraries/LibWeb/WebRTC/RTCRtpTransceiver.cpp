/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCRtpTransceiver.h>
#include <LibWeb/WebIDL/DOMException.h>
#include <LibWeb/WebRTC/RTCPeerConnection.h>
#include <LibWeb/WebRTC/RTCRtpReceiver.h>
#include <LibWeb/WebRTC/RTCRtpSender.h>
#include <LibWeb/WebRTC/RTCRtpTransceiver.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCRtpTransceiver);

GC::Ref<RTCRtpTransceiver> RTCRtpTransceiver::create(JS::Realm& realm, RTCPeerConnection& connection, GC::Ref<RTCRtpSender> sender, GC::Ref<RTCRtpReceiver> receiver, Bindings::RTCRtpTransceiverDirection direction, Bindings::MediaStreamTrackKind kind)
{
    return realm.create<RTCRtpTransceiver>(realm, connection, sender, receiver, direction, kind);
}

RTCRtpTransceiver::RTCRtpTransceiver(JS::Realm& realm, RTCPeerConnection& connection, GC::Ref<RTCRtpSender> sender, GC::Ref<RTCRtpReceiver> receiver, Bindings::RTCRtpTransceiverDirection direction, Bindings::MediaStreamTrackKind kind)
    : Bindings::GCAllocatedWrappable()
    , m_realm(realm)
    , m_connection(connection)
    , m_sender(sender)
    , m_receiver(receiver)
    , m_direction(direction)
    , m_kind(kind)
{
}

RTCRtpTransceiver::~RTCRtpTransceiver() = default;

void RTCRtpTransceiver::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
    visitor.visit(m_connection);
    visitor.visit(m_sender);
    visitor.visit(m_receiver);
}

// https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-stop
WebIDL::ExceptionOr<void> RTCRtpTransceiver::stop_method()
{
    // 1. Let transceiver be the RTCRtpTransceiver object on which the method is invoked.
    // 2. Let connection be the RTCPeerConnection object associated with transceiver.
    auto& connection = *m_connection;
    // 3. If connection.[[IsClosed]] is true, throw an InvalidStateError.
    if (connection.is_closed())
        return WebIDL::InvalidStateError::create("RTCPeerConnection is closed"_utf16);
    // 4. If transceiver.[[Stopping]] is true, abort these steps.
    if (m_stopping)
        return {};
    // 5. Stop sending and receiving with transceiver.
    stop_sending_and_receiving();
    // 6. Update the negotiation-needed flag for connection.
    connection.update_negotiation_needed_flag();
    return {};
}

// https://www.w3.org/TR/webrtc/#stop-sending-and-receiving
void RTCRtpTransceiver::stop_sending_and_receiving(bool disappear)
{
    // 1. Let sender be transceiver.[[Sender]].
    // 2. Let receiver be transceiver.[[Receiver]].
    // FIXME: 3. In parallel, stop sending media with sender, and send an RTCP BYE for each RTP stream that was being sent by sender, as specified in [RFC3550].
    // FIXME: 4. In parallel, stop receiving media with receiver.
    // 5. If disappear is false, execute the steps for receiver.[[ReceiverTrack]] to be ended. This fires an event.
    if (!disappear) {
        // FIXME: end receiver.[[ReceiverTrack]].
    }
    // 6. Set transceiver.[[Direction]] to "inactive".
    m_direction = Bindings::RTCRtpTransceiverDirection::Inactive;
    // 7. Set transceiver.[[Stopping]] to true.
    m_stopping = true;
}

// https://www.w3.org/TR/webrtc/#stop-the-rtcrtptransceiver
void RTCRtpTransceiver::stop(bool disappear)
{
    // 1. If transceiver.[[Stopping]] is false, stop sending and receiving with transceiver and disappear.
    if (!m_stopping)
        stop_sending_and_receiving(disappear);
    // 2. Set transceiver.[[Stopped]] to true.
    m_stopped = true;
    // 3. Set transceiver.[[Receptive]] to false.
    m_receptive = false;
    // 4. Set transceiver.[[CurrentDirection]] to null.
    m_current_direction = {};
}

}
