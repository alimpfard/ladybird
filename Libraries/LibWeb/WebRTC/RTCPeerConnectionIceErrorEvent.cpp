/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCPeerConnectionIceErrorEvent.h>
#include <LibWeb/HighResolutionTime/TimeOrigin.h>
#include <LibWeb/WebRTC/RTCPeerConnectionIceErrorEvent.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCPeerConnectionIceErrorEvent);

GC::Ref<RTCPeerConnectionIceErrorEvent> RTCPeerConnectionIceErrorEvent::create(JS::Realm& realm, Utf16FlyString const& event_name)
{
    return realm.create<RTCPeerConnectionIceErrorEvent>(realm, event_name);
}

RTCPeerConnectionIceErrorEvent::RTCPeerConnectionIceErrorEvent(JS::Realm& realm, Utf16FlyString const& event_name)
    : DOM::Event(event_name, HighResolutionTime::current_high_resolution_time(realm.global_object()))
    , m_realm(realm)
{
}
RTCPeerConnectionIceErrorEvent::~RTCPeerConnectionIceErrorEvent() = default;

void RTCPeerConnectionIceErrorEvent::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
}

}
