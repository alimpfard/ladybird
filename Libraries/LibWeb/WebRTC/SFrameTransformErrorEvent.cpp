/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/SFrameTransformErrorEvent.h>
#include <LibWeb/WebRTC/SFrameTransformErrorEvent.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(SFrameTransformErrorEvent);

GC::Ref<SFrameTransformErrorEvent> SFrameTransformErrorEvent::create(JS::Realm& realm, FlyString const& event_name) { return realm.create<SFrameTransformErrorEvent>(realm, event_name); }
SFrameTransformErrorEvent::SFrameTransformErrorEvent(JS::Realm& realm, FlyString const& event_name) : DOM::Event(realm, event_name) { }
SFrameTransformErrorEvent::~SFrameTransformErrorEvent() = default;
void SFrameTransformErrorEvent::initialize(JS::Realm& realm) { WEB_SET_PROTOTYPE_FOR_INTERFACE(SFrameTransformErrorEvent); Base::initialize(realm); }

}
