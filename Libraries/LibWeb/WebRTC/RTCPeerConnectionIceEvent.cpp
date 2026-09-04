/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCPeerConnectionIceEvent.h>
#include <LibWeb/HighResolutionTime/TimeOrigin.h>
#include <LibWeb/WebRTC/RTCPeerConnectionIceEvent.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCPeerConnectionIceEvent);

GC::Ref<RTCPeerConnectionIceEvent> RTCPeerConnectionIceEvent::create(JS::Realm& realm, Utf16FlyString const& event_name)
{
    return realm.create<RTCPeerConnectionIceEvent>(realm, event_name);
}

RTCPeerConnectionIceEvent::RTCPeerConnectionIceEvent(JS::Realm& realm, Utf16FlyString const& event_name)
    : DOM::Event(event_name, HighResolutionTime::current_high_resolution_time(realm.global_object()))
    , m_realm(realm)
{
}

RTCPeerConnectionIceEvent::~RTCPeerConnectionIceEvent() = default;

void RTCPeerConnectionIceEvent::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
    visitor.visit(m_candidate);
}

}
