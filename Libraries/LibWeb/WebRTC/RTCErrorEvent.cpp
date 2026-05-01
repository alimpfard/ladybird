/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCErrorEvent.h>
#include <LibWeb/WebRTC/RTCErrorEvent.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCErrorEvent);

GC::Ref<RTCErrorEvent> RTCErrorEvent::create(JS::Realm& realm, FlyString const& event_name)
{
    return realm.create<RTCErrorEvent>(realm, event_name);
}

RTCErrorEvent::RTCErrorEvent(JS::Realm& realm, FlyString const& event_name) : DOM::Event(realm, event_name) { }
RTCErrorEvent::~RTCErrorEvent() = default;
void RTCErrorEvent::initialize(JS::Realm& realm) { WEB_SET_PROTOTYPE_FOR_INTERFACE(RTCErrorEvent); Base::initialize(realm); }

}
