/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/KeyFrameRequestEvent.h>
#include <LibWeb/HighResolutionTime/TimeOrigin.h>
#include <LibWeb/WebRTC/KeyFrameRequestEvent.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(KeyFrameRequestEvent);

GC::Ref<KeyFrameRequestEvent> KeyFrameRequestEvent::create(JS::Realm& realm, Utf16FlyString const& event_name) { return realm.create<KeyFrameRequestEvent>(realm, event_name); }
KeyFrameRequestEvent::KeyFrameRequestEvent(JS::Realm& realm, Utf16FlyString const& event_name)
    : DOM::Event(event_name, HighResolutionTime::current_high_resolution_time(realm.global_object()))
    , m_realm(realm)
{
}
KeyFrameRequestEvent::~KeyFrameRequestEvent() = default;

void KeyFrameRequestEvent::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
}

}
