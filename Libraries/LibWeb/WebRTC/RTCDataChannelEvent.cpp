/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCDataChannelEvent.h>
#include <LibWeb/WebRTC/RTCDataChannelEvent.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCDataChannelEvent);

GC::Ref<RTCDataChannelEvent> RTCDataChannelEvent::create(JS::Realm& realm, FlyString const& event_name)
{
    return realm.create<RTCDataChannelEvent>(realm, event_name);
}

RTCDataChannelEvent::RTCDataChannelEvent(JS::Realm& realm, FlyString const& event_name) : DOM::Event(realm, event_name) { }
RTCDataChannelEvent::~RTCDataChannelEvent() = default;
void RTCDataChannelEvent::initialize(JS::Realm& realm) { WEB_SET_PROTOTYPE_FOR_INTERFACE(RTCDataChannelEvent); Base::initialize(realm); }

}
