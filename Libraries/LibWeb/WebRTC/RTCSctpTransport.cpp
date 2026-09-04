/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCSctpTransport.h>
#include <LibWeb/HTML/EventNames.h>
#include <LibWeb/WebRTC/RTCSctpTransport.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCSctpTransport);

GC::Ref<RTCSctpTransport> RTCSctpTransport::create(JS::Realm& realm) { return realm.create<RTCSctpTransport>(realm); }
RTCSctpTransport::RTCSctpTransport(JS::Realm& realm)
    : DOM::EventTarget()
    , m_realm(realm)
{
}
RTCSctpTransport::~RTCSctpTransport() = default;

void RTCSctpTransport::set_onstatechange(WebIDL::CallbackType* cb) { set_event_handler_attribute(HTML::EventNames::statechange, cb); }
WebIDL::CallbackType* RTCSctpTransport::onstatechange() { return event_handler_attribute(HTML::EventNames::statechange); }

void RTCSctpTransport::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
}

}
