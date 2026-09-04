/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/SFrameTransformErrorEvent.h>
#include <LibWeb/HighResolutionTime/TimeOrigin.h>
#include <LibWeb/WebRTC/SFrameTransformErrorEvent.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(SFrameTransformErrorEvent);

GC::Ref<SFrameTransformErrorEvent> SFrameTransformErrorEvent::create(JS::Realm& realm, Utf16FlyString const& event_name) { return realm.create<SFrameTransformErrorEvent>(realm, event_name); }
SFrameTransformErrorEvent::SFrameTransformErrorEvent(JS::Realm& realm, Utf16FlyString const& event_name)
    : DOM::Event(event_name, HighResolutionTime::current_high_resolution_time(realm.global_object()))
    , m_realm(realm)
{
}
SFrameTransformErrorEvent::~SFrameTransformErrorEvent() = default;

void SFrameTransformErrorEvent::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
}

}
