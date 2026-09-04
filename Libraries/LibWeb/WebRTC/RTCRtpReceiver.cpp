/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCRtpReceiver.h>
#include <LibWeb/MediaCapture/MediaStream.h>
#include <LibWeb/MediaCapture/MediaStreamTrack.h>
#include <LibWeb/WebRTC/RTCRtpReceiver.h>
#include <LibWeb/WebRTC/RTCRtpScriptTransform.h>
#include <LibWeb/WebRTC/RTCSFrameReceiverTransform.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCRtpReceiver);

GC::Ref<RTCRtpReceiver> RTCRtpReceiver::create(JS::Realm& realm, Bindings::MediaStreamTrackKind kind)
{
    auto track = MediaCapture::MediaStreamTrack::create(kind);
    return realm.create<RTCRtpReceiver>(realm, track);
}

RTCRtpReceiver::RTCRtpReceiver(JS::Realm& realm, GC::Ref<MediaCapture::MediaStreamTrack> track)
    : Bindings::GCAllocatedWrappable()
    , m_realm(realm)
    , m_track(track)
{
}

RTCRtpReceiver::~RTCRtpReceiver() = default;

GC::Ref<MediaCapture::MediaStreamTrack> RTCRtpReceiver::track() const { return m_track; }

void RTCRtpReceiver::set_associated_remote_streams(Vector<GC::Ref<MediaCapture::MediaStream>> streams)
{
    m_associated_remote_streams = move(streams);
}

void RTCRtpReceiver::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
    visitor.visit(m_track);
    visitor.visit(m_transform);
    for (auto& stream : m_associated_remote_streams)
        visitor.visit(stream);
}

RTCRtpReceiverTransform RTCRtpReceiver::transform() const
{
    if (!m_transform)
        return Empty {};
    if (auto* script_transform = as_if<RTCRtpScriptTransform>(*m_transform))
        return GC::Ref { *script_transform };
    if (auto* sframe_transform = as_if<RTCSFrameReceiverTransform>(*m_transform))
        return GC::Ref { *sframe_transform };
    return Empty {};
}

void RTCRtpReceiver::set_transform(RTCRtpReceiverTransform value)
{
    m_transform = value.visit(
        [](Empty) -> GC::Ptr<Bindings::Wrappable> { return nullptr; },
        [](GC::Ref<RTCSFrameReceiverTransform> const& t) -> GC::Ptr<Bindings::Wrappable> { return t.ptr(); },
        [](GC::Ref<RTCRtpScriptTransform> const& t) -> GC::Ptr<Bindings::Wrappable> { return t.ptr(); });
    dbgln("RTCRtpReceiver::set_transform: transform set, kind={}", m_transform ? "set"sv : "null"sv);
}

}
