/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCPeerConnectionIceEvent.h>
#include <LibWeb/WebRTC/RTCPeerConnectionIceEvent.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCPeerConnectionIceEvent);

GC::Ref<RTCPeerConnectionIceEvent> RTCPeerConnectionIceEvent::create(JS::Realm& realm, FlyString const& event_name)
{
    return realm.create<RTCPeerConnectionIceEvent>(realm, event_name);
}

RTCPeerConnectionIceEvent::RTCPeerConnectionIceEvent(JS::Realm& realm, FlyString const& event_name)
    : DOM::Event(realm, event_name)
{
}

RTCPeerConnectionIceEvent::~RTCPeerConnectionIceEvent() = default;

void RTCPeerConnectionIceEvent::initialize(JS::Realm& realm)
{
    WEB_SET_PROTOTYPE_FOR_INTERFACE(RTCPeerConnectionIceEvent);
    Base::initialize(realm);
}

}
