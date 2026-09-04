/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCTrackEvent.h>
#include <LibWeb/HighResolutionTime/TimeOrigin.h>
#include <LibWeb/MediaCapture/MediaStream.h>
#include <LibWeb/MediaCapture/MediaStreamTrack.h>
#include <LibWeb/WebRTC/RTCRtpReceiver.h>
#include <LibWeb/WebRTC/RTCRtpTransceiver.h>
#include <LibWeb/WebRTC/RTCTrackEvent.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCTrackEvent);

GC::Ref<RTCTrackEvent> RTCTrackEvent::create(JS::Realm& realm, Utf16FlyString const& event_name,
    GC::Ref<RTCRtpReceiver> receiver, GC::Ref<MediaCapture::MediaStreamTrack> track,
    Vector<GC::Ref<MediaCapture::MediaStream>> streams, GC::Ref<RTCRtpTransceiver> transceiver)
{
    return realm.create<RTCTrackEvent>(realm, event_name, receiver, track, move(streams), transceiver);
}

RTCTrackEvent::RTCTrackEvent(JS::Realm& realm, Utf16FlyString const& event_name,
    GC::Ref<RTCRtpReceiver> receiver, GC::Ref<MediaCapture::MediaStreamTrack> track,
    Vector<GC::Ref<MediaCapture::MediaStream>> streams, GC::Ref<RTCRtpTransceiver> transceiver)
    : DOM::Event(event_name, HighResolutionTime::current_high_resolution_time(realm.global_object()))
    , m_realm(realm)
    , m_receiver(receiver)
    , m_track(track)
    , m_streams(move(streams))
    , m_transceiver(transceiver)
{
}

RTCTrackEvent::~RTCTrackEvent() = default;

void RTCTrackEvent::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
    visitor.visit(m_receiver);
    visitor.visit(m_track);
    visitor.visit(m_transceiver);
    for (auto& stream : m_streams)
        visitor.visit(stream);
}

GC::Ref<RTCRtpReceiver> RTCTrackEvent::receiver() const { return m_receiver; }
GC::Ref<RTCRtpTransceiver> RTCTrackEvent::transceiver() const { return m_transceiver; }
GC::Ref<MediaCapture::MediaStreamTrack> RTCTrackEvent::track() const { return m_track; }

}
