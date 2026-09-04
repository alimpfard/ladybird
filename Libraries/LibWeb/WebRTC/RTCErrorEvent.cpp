/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCErrorEvent.h>
#include <LibWeb/HighResolutionTime/TimeOrigin.h>
#include <LibWeb/WebRTC/RTCErrorEvent.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCErrorEvent);

GC::Ref<RTCErrorEvent> RTCErrorEvent::create(JS::Realm& realm, Utf16FlyString const& event_name)
{
    return realm.create<RTCErrorEvent>(realm, event_name);
}

RTCErrorEvent::RTCErrorEvent(JS::Realm& realm, Utf16FlyString const& event_name)
    : DOM::Event(event_name, HighResolutionTime::current_high_resolution_time(realm.global_object()))
    , m_realm(realm)
{
}
RTCErrorEvent::~RTCErrorEvent() = default;

void RTCErrorEvent::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
}

}
