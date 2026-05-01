/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCIceCandidate.h>
#include <LibWeb/WebIDL/ExceptionOr.h>
#include <LibWeb/WebRTC/RTCIceCandidate.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCIceCandidate);

GC::Ref<RTCIceCandidate> RTCIceCandidate::create(JS::Realm& realm, RTCIceCandidateInit const&)
{
    return realm.create<RTCIceCandidate>(realm);
}

WebIDL::ExceptionOr<GC::Ref<RTCIceCandidate>> RTCIceCandidate::construct_impl(JS::Realm& realm, RTCIceCandidateInit const& init)
{
    return create(realm, init);
}

RTCIceCandidate::RTCIceCandidate(JS::Realm& realm)
    : Bindings::PlatformObject(realm)
{
}

RTCIceCandidate::~RTCIceCandidate() = default;

void RTCIceCandidate::initialize(JS::Realm& realm)
{
    WEB_SET_PROTOTYPE_FOR_INTERFACE(RTCIceCandidate);
    Base::initialize(realm);
}

}
