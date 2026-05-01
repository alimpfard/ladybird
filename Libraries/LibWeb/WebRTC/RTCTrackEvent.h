/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/DOM/Event.h>
#include <LibWeb/Forward.h>

namespace Web::WebRTC {

class RTCRtpReceiver;
class RTCRtpTransceiver;

class RTCTrackEvent final : public DOM::Event {
    WEB_PLATFORM_OBJECT(RTCTrackEvent, DOM::Event);
    GC_DECLARE_ALLOCATOR(RTCTrackEvent);

public:
    static GC::Ref<RTCTrackEvent> create(JS::Realm&, FlyString const& event_name,
        GC::Ref<RTCRtpReceiver>, GC::Ref<MediaCapture::MediaStreamTrack>,
        Vector<GC::Ref<MediaCapture::MediaStream>> streams,
        GC::Ref<RTCRtpTransceiver>);
    virtual ~RTCTrackEvent() override;

    GC::Ref<RTCRtpReceiver> receiver() const;
    GC::Ref<RTCRtpTransceiver> transceiver() const;
    GC::Ref<MediaCapture::MediaStreamTrack> track() const;
    Vector<GC::Ref<MediaCapture::MediaStream>> streams() const { return m_streams; }

private:
    RTCTrackEvent(JS::Realm&, FlyString const&,
        GC::Ref<RTCRtpReceiver>, GC::Ref<MediaCapture::MediaStreamTrack>,
        Vector<GC::Ref<MediaCapture::MediaStream>> streams,
        GC::Ref<RTCRtpTransceiver>);
    virtual void initialize(JS::Realm&) override;
    virtual void visit_edges(JS::Cell::Visitor&) override;

    GC::Ref<RTCRtpReceiver> m_receiver;
    GC::Ref<MediaCapture::MediaStreamTrack> m_track;
    Vector<GC::Ref<MediaCapture::MediaStream>> m_streams;
    GC::Ref<RTCRtpTransceiver> m_transceiver;
};

}
