/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCDTMFToneChangeEvent.h>
#include <LibWeb/WebRTC/RTCDTMFToneChangeEvent.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCDTMFToneChangeEvent);

GC::Ref<RTCDTMFToneChangeEvent> RTCDTMFToneChangeEvent::create(JS::Realm& realm, FlyString const& event_name)
{
    return realm.create<RTCDTMFToneChangeEvent>(realm, event_name);
}

RTCDTMFToneChangeEvent::RTCDTMFToneChangeEvent(JS::Realm& realm, FlyString const& event_name) : DOM::Event(realm, event_name) { }
RTCDTMFToneChangeEvent::~RTCDTMFToneChangeEvent() = default;
void RTCDTMFToneChangeEvent::initialize(JS::Realm& realm) { WEB_SET_PROTOTYPE_FOR_INTERFACE(RTCDTMFToneChangeEvent); Base::initialize(realm); }

}
