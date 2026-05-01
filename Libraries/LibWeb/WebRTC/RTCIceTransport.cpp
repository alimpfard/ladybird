/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCIceTransport.h>
#include <LibWeb/HTML/EventNames.h>
#include <LibWeb/WebRTC/RTCIceTransport.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCIceTransport);

GC::Ref<RTCIceTransport> RTCIceTransport::create(JS::Realm& realm) { return realm.create<RTCIceTransport>(realm); }
RTCIceTransport::RTCIceTransport(JS::Realm& realm) : DOM::EventTarget(realm) { }
RTCIceTransport::~RTCIceTransport() = default;
void RTCIceTransport::initialize(JS::Realm& realm) { WEB_SET_PROTOTYPE_FOR_INTERFACE(RTCIceTransport); Base::initialize(realm); }
void RTCIceTransport::set_onstatechange(WebIDL::CallbackType* cb) { set_event_handler_attribute(HTML::EventNames::statechange, cb); }
WebIDL::CallbackType* RTCIceTransport::onstatechange() { return event_handler_attribute(HTML::EventNames::statechange); }
void RTCIceTransport::set_ongatheringstatechange(WebIDL::CallbackType* cb) { set_event_handler_attribute(HTML::EventNames::gatheringstatechange, cb); }
WebIDL::CallbackType* RTCIceTransport::ongatheringstatechange() { return event_handler_attribute(HTML::EventNames::gatheringstatechange); }
void RTCIceTransport::set_onselectedcandidatepairchange(WebIDL::CallbackType* cb) { set_event_handler_attribute(HTML::EventNames::selectedcandidatepairchange, cb); }
WebIDL::CallbackType* RTCIceTransport::onselectedcandidatepairchange() { return event_handler_attribute(HTML::EventNames::selectedcandidatepairchange); }

}
