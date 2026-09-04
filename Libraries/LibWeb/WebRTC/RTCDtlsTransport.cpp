/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCDtlsTransport.h>
#include <LibWeb/HTML/EventNames.h>
#include <LibWeb/WebRTC/RTCDtlsTransport.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCDtlsTransport);

GC::Ref<RTCDtlsTransport> RTCDtlsTransport::create(JS::Realm& realm) { return realm.create<RTCDtlsTransport>(realm); }
RTCDtlsTransport::RTCDtlsTransport(JS::Realm& realm)
    : DOM::EventTarget()
    , m_realm(realm)
{
}
RTCDtlsTransport::~RTCDtlsTransport() = default;

void RTCDtlsTransport::set_onstatechange(WebIDL::CallbackType* cb) { set_event_handler_attribute(HTML::EventNames::statechange, cb); }
WebIDL::CallbackType* RTCDtlsTransport::onstatechange() { return event_handler_attribute(HTML::EventNames::statechange); }
void RTCDtlsTransport::set_onerror(WebIDL::CallbackType* cb) { set_event_handler_attribute(HTML::EventNames::error, cb); }
WebIDL::CallbackType* RTCDtlsTransport::onerror() { return event_handler_attribute(HTML::EventNames::error); }

void RTCDtlsTransport::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
}

}
