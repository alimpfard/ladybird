/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/Bindings/PlatformObject.h>
#include <LibWeb/Forward.h>
#include <LibWeb/WebRTC/RTCRtpParameters.h>

namespace Web::WebRTC {

using RTCRtpSenderTransform = Variant<GC::Ref<RTCSFrameSenderTransform>, GC::Ref<RTCRtpScriptTransform>, Empty>;

class RTCRtpSender final : public Bindings::PlatformObject {
    WEB_PLATFORM_OBJECT(RTCRtpSender, Bindings::PlatformObject);
    GC_DECLARE_ALLOCATOR(RTCRtpSender);

public:
    static GC::Ref<RTCRtpSender> create(JS::Realm&, GC::Ref<RTCPeerConnection>, u64 sender_id, u32 ssrc);
    virtual ~RTCRtpSender() override;

    GC::Ptr<MediaCapture::MediaStreamTrack> track() const { return m_track; }
    void set_track(GC::Ptr<MediaCapture::MediaStreamTrack> track);

    Vector<String> const& associated_media_stream_ids() const { return m_associated_media_stream_ids; }
    void set_associated_media_stream_ids(Vector<String> ids) { m_associated_media_stream_ids = move(ids); }

    RTCRtpSenderTransform transform() const;
    void set_transform(RTCRtpSenderTransform);
    GC::Ptr<RTCRtpScriptTransform> script_transform();

    GC::Ref<WebIDL::Promise> replace_track(GC::Ptr<MediaCapture::MediaStreamTrack> with_track);
    RTCRtpSendParameters get_parameters();
    GC::Ref<WebIDL::Promise> set_parameters(RTCRtpSendParameters const&, RTCSetParameterOptions const&);

    u64 sender_id() const { return m_sender_id; }
    u32 ssrc() const { return m_ssrc; }
    void set_ssrc(u32 ssrc);
    GC::Ref<RTCPeerConnection> connection() const { return m_connection; }

private:
    explicit RTCRtpSender(JS::Realm&, GC::Ref<RTCPeerConnection>, u64 sender_id, u32 ssrc);
    virtual void initialize(JS::Realm&) override;
    virtual void visit_edges(JS::Cell::Visitor&) override;

    GC::Ref<RTCPeerConnection> m_connection;
    u64 m_sender_id { 0 };
    u32 m_ssrc { 0 };

    // [[SenderTrack]]
    GC::Ptr<MediaCapture::MediaStreamTrack> m_track;
    // [[AssociatedMediaStreamIds]]
    Vector<String> m_associated_media_stream_ids;
    // [[SendEncodings]]
    Vector<RTCRtpEncodingParameters> m_send_encodings;
    // [[LastReturnedParameters]]
    Optional<RTCRtpSendParameters> m_last_returned_parameters;
    GC::Ptr<JS::Object> m_transform;
};

}
