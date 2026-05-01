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
RTCSctpTransport::RTCSctpTransport(JS::Realm& realm) : DOM::EventTarget(realm) { }
RTCSctpTransport::~RTCSctpTransport() = default;
void RTCSctpTransport::initialize(JS::Realm& realm) { WEB_SET_PROTOTYPE_FOR_INTERFACE(RTCSctpTransport); Base::initialize(realm); }
void RTCSctpTransport::set_onstatechange(WebIDL::CallbackType* cb) { set_event_handler_attribute(HTML::EventNames::statechange, cb); }
WebIDL::CallbackType* RTCSctpTransport::onstatechange() { return event_handler_attribute(HTML::EventNames::statechange); }

}
