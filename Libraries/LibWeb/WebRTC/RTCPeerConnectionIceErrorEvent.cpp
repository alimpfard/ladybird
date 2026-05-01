/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCPeerConnectionIceErrorEvent.h>
#include <LibWeb/WebRTC/RTCPeerConnectionIceErrorEvent.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCPeerConnectionIceErrorEvent);

GC::Ref<RTCPeerConnectionIceErrorEvent> RTCPeerConnectionIceErrorEvent::create(JS::Realm& realm, FlyString const& event_name)
{
    return realm.create<RTCPeerConnectionIceErrorEvent>(realm, event_name);
}

RTCPeerConnectionIceErrorEvent::RTCPeerConnectionIceErrorEvent(JS::Realm& realm, FlyString const& event_name) : DOM::Event(realm, event_name) { }
RTCPeerConnectionIceErrorEvent::~RTCPeerConnectionIceErrorEvent() = default;
void RTCPeerConnectionIceErrorEvent::initialize(JS::Realm& realm) { WEB_SET_PROTOTYPE_FOR_INTERFACE(RTCPeerConnectionIceErrorEvent); Base::initialize(realm); }

}
