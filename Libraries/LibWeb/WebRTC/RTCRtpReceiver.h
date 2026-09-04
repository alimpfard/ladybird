/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibJS/Runtime/Realm.h>

#include <LibWeb/Bindings/MediaStreamTrack.h>
#include <LibWeb/Bindings/Wrappable.h>
#include <LibWeb/Forward.h>

namespace Web::WebRTC {

using RTCRtpReceiverTransform = Variant<GC::Ref<RTCSFrameReceiverTransform>, GC::Ref<RTCRtpScriptTransform>, Empty>;

class RTCRtpReceiver final : public Bindings::GCAllocatedWrappable {
    WEB_WRAPPABLE(RTCRtpReceiver, Bindings::GCAllocatedWrappable);
    GC_DECLARE_ALLOCATOR(RTCRtpReceiver);

public:
    static GC::Ref<RTCRtpReceiver> create(JS::Realm&, Bindings::MediaStreamTrackKind);
    virtual ~RTCRtpReceiver() override;

    GC::Ref<MediaCapture::MediaStreamTrack> track() const;

    RTCRtpReceiverTransform transform() const;
    void set_transform(RTCRtpReceiverTransform);

    // [[AssociatedRemoteMediaStreams]]
    Vector<GC::Ref<MediaCapture::MediaStream>> const& associated_remote_streams() const { return m_associated_remote_streams; }
    void set_associated_remote_streams(Vector<GC::Ref<MediaCapture::MediaStream>>);

public:
    JS::Realm& realm() const { return *m_realm; }
    JS::VM& vm() const { return realm().vm(); }

private:
    GC::Ref<JS::Realm> m_realm;
    RTCRtpReceiver(JS::Realm&, GC::Ref<MediaCapture::MediaStreamTrack>);
    virtual void visit_edges(JS::Cell::Visitor&) override;

    // [[ReceiverTrack]]
    GC::Ref<MediaCapture::MediaStreamTrack> m_track;
    GC::Ptr<Bindings::Wrappable> m_transform;
    Vector<GC::Ref<MediaCapture::MediaStream>> m_associated_remote_streams;
};

}
