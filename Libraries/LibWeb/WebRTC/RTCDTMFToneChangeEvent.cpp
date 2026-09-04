/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCDTMFToneChangeEvent.h>
#include <LibWeb/HighResolutionTime/TimeOrigin.h>
#include <LibWeb/WebRTC/RTCDTMFToneChangeEvent.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCDTMFToneChangeEvent);

GC::Ref<RTCDTMFToneChangeEvent> RTCDTMFToneChangeEvent::create(JS::Realm& realm, Utf16FlyString const& event_name)
{
    return realm.create<RTCDTMFToneChangeEvent>(realm, event_name);
}

RTCDTMFToneChangeEvent::RTCDTMFToneChangeEvent(JS::Realm& realm, Utf16FlyString const& event_name)
    : DOM::Event(event_name, HighResolutionTime::current_high_resolution_time(realm.global_object()))
    , m_realm(realm)
{
}
RTCDTMFToneChangeEvent::~RTCDTMFToneChangeEvent() = default;

void RTCDTMFToneChangeEvent::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
}

}
