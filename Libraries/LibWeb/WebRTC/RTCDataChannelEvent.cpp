/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCDataChannelEvent.h>
#include <LibWeb/HighResolutionTime/TimeOrigin.h>
#include <LibWeb/WebRTC/RTCDataChannelEvent.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCDataChannelEvent);

GC::Ref<RTCDataChannelEvent> RTCDataChannelEvent::create(JS::Realm& realm, Utf16FlyString const& event_name)
{
    return realm.create<RTCDataChannelEvent>(realm, event_name);
}

RTCDataChannelEvent::RTCDataChannelEvent(JS::Realm& realm, Utf16FlyString const& event_name)
    : DOM::Event(event_name, HighResolutionTime::current_high_resolution_time(realm.global_object()))
    , m_realm(realm)
{
}
RTCDataChannelEvent::~RTCDataChannelEvent() = default;

void RTCDataChannelEvent::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
    visitor.visit(m_channel);
}

}
