/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCEncodedVideoFrame.h>
#include <LibWeb/WebRTC/RTCEncodedVideoFrame.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCEncodedVideoFrame);

GC::Ref<RTCEncodedVideoFrame> RTCEncodedVideoFrame::create(JS::Realm& realm) { return realm.create<RTCEncodedVideoFrame>(realm); }

// FIXME: RTCEncodedVideoFrame is a stub — copy the original frame's data/metadata once they exist.
WebIDL::ExceptionOr<GC::Ref<RTCEncodedVideoFrame>> RTCEncodedVideoFrame::construct_impl(JS::Realm& realm, GC::Ref<RTCEncodedVideoFrame>, Bindings::RTCEncodedVideoFrameOptions const&)
{
    return create(realm);
}

RTCEncodedVideoFrame::RTCEncodedVideoFrame(JS::Realm& realm) : Bindings::PlatformObject(realm) { }
RTCEncodedVideoFrame::~RTCEncodedVideoFrame() = default;
void RTCEncodedVideoFrame::initialize(JS::Realm& realm) { WEB_SET_PROTOTYPE_FOR_INTERFACE(RTCEncodedVideoFrame); Base::initialize(realm); }

}
