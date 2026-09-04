/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/WebIDL/DOMException.h>
#include <LibWeb/WebIDL/ExceptionOr.h>

#include <LibJS/Runtime/Realm.h>

#include <LibWeb/DOM/Event.h>
#include <LibWeb/Forward.h>

namespace Web::WebRTC {

class RTCRtpReceiver;
class RTCRtpTransceiver;

class RTCTrackEvent final : public DOM::Event {
    WEB_WRAPPABLE(RTCTrackEvent, DOM::Event);
    GC_DECLARE_ALLOCATOR(RTCTrackEvent);

public:
    template<typename... Args>
    static WebIDL::ExceptionOr<GC::Ref<RTCTrackEvent>> construct_impl(JS::Realm&, Args const&...)
    {
        return WebIDL::NotSupportedError::create("RTCTrackEvent constructor is not implemented"_utf16);
    }

    static GC::Ref<RTCTrackEvent> create(JS::Realm&, Utf16FlyString const& event_name,
        GC::Ref<RTCRtpReceiver>, GC::Ref<MediaCapture::MediaStreamTrack>,
        Vector<GC::Ref<MediaCapture::MediaStream>> streams,
        GC::Ref<RTCRtpTransceiver>);
    virtual ~RTCTrackEvent() override;

    GC::Ref<RTCRtpReceiver> receiver() const;
    GC::Ref<RTCRtpTransceiver> transceiver() const;
    GC::Ref<MediaCapture::MediaStreamTrack> track() const;
    Vector<GC::Ref<MediaCapture::MediaStream>> streams() const { return m_streams; }

public:
    JS::Realm& realm() const { return *m_realm; }
    JS::VM& vm() const { return realm().vm(); }

private:
    GC::Ref<JS::Realm> m_realm;
    RTCTrackEvent(JS::Realm&, Utf16FlyString const&,
        GC::Ref<RTCRtpReceiver>, GC::Ref<MediaCapture::MediaStreamTrack>,
        Vector<GC::Ref<MediaCapture::MediaStream>> streams,
        GC::Ref<RTCRtpTransceiver>);
    virtual void visit_edges(JS::Cell::Visitor&) override;

    GC::Ref<RTCRtpReceiver> m_receiver;
    GC::Ref<MediaCapture::MediaStreamTrack> m_track;
    Vector<GC::Ref<MediaCapture::MediaStream>> m_streams;
    GC::Ref<RTCRtpTransceiver> m_transceiver;
};

}
