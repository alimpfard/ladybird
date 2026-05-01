/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCTransformEvent.h>
#include <LibWeb/WebRTC/RTCRtpScriptTransformer.h>
#include <LibWeb/WebRTC/RTCTransformEvent.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCTransformEvent);

GC::Ref<RTCTransformEvent> RTCTransformEvent::create(JS::Realm& realm, FlyString const& event_name, GC::Ref<RTCRtpScriptTransformer> transformer)
{
    return realm.create<RTCTransformEvent>(realm, event_name, transformer);
}

RTCTransformEvent::RTCTransformEvent(JS::Realm& realm, FlyString const& event_name, GC::Ref<RTCRtpScriptTransformer> transformer)
    : DOM::Event(realm, event_name)
    , m_transformer(transformer)
{
}

RTCTransformEvent::~RTCTransformEvent() = default;

void RTCTransformEvent::initialize(JS::Realm& realm)
{
    WEB_SET_PROTOTYPE_FOR_INTERFACE(RTCTransformEvent);
    Base::initialize(realm);
}

void RTCTransformEvent::visit_edges(Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_transformer);
}

GC::Ref<RTCRtpScriptTransformer> RTCTransformEvent::transformer() const { return m_transformer; }

}
