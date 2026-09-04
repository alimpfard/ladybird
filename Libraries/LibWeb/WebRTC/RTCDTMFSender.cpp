/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCDTMFSender.h>
#include <LibWeb/HTML/EventNames.h>
#include <LibWeb/WebRTC/RTCDTMFSender.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCDTMFSender);

GC::Ref<RTCDTMFSender> RTCDTMFSender::create(JS::Realm& realm) { return realm.create<RTCDTMFSender>(realm); }
RTCDTMFSender::RTCDTMFSender(JS::Realm& realm)
    : DOM::EventTarget()
    , m_realm(realm)
{
}
RTCDTMFSender::~RTCDTMFSender() = default;

void RTCDTMFSender::set_ontonechange(WebIDL::CallbackType* cb) { set_event_handler_attribute(HTML::EventNames::tonechange, cb); }
WebIDL::CallbackType* RTCDTMFSender::ontonechange() { return event_handler_attribute(HTML::EventNames::tonechange); }

void RTCDTMFSender::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
}

}
