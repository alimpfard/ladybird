/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/KeyFrameRequestEvent.h>
#include <LibWeb/WebRTC/KeyFrameRequestEvent.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(KeyFrameRequestEvent);

GC::Ref<KeyFrameRequestEvent> KeyFrameRequestEvent::create(JS::Realm& realm, FlyString const& event_name) { return realm.create<KeyFrameRequestEvent>(realm, event_name); }

// FIXME: KeyFrameRequestEvent is a stub — store the rid once the attribute is implemented.
GC::Ref<KeyFrameRequestEvent> KeyFrameRequestEvent::construct_impl(JS::Realm& realm, String const& type, Optional<String> const&)
{
    return create(realm, type);
}
KeyFrameRequestEvent::KeyFrameRequestEvent(JS::Realm& realm, FlyString const& event_name) : DOM::Event(realm, event_name) { }
KeyFrameRequestEvent::~KeyFrameRequestEvent() = default;
void KeyFrameRequestEvent::initialize(JS::Realm& realm) { WEB_SET_PROTOTYPE_FOR_INTERFACE(KeyFrameRequestEvent); Base::initialize(realm); }

}
