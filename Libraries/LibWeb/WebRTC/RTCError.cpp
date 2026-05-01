/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCError.h>
#include <LibWeb/WebIDL/ExceptionOr.h>
#include <LibWeb/WebRTC/RTCError.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCError);

GC::Ref<RTCError> RTCError::create(JS::Realm& realm) { return realm.create<RTCError>(realm); }

// FIXME: RTCError is a stub — populate errorDetail/sdpLineNumber/etc. from init and use the message.
WebIDL::ExceptionOr<GC::Ref<RTCError>> RTCError::construct_impl(JS::Realm& realm, Bindings::RTCErrorInit const&, String const&)
{
    return create(realm);
}
RTCError::RTCError(JS::Realm& realm) : WebIDL::DOMException(realm, "OperationError"_string, {}) { }
RTCError::~RTCError() = default;
void RTCError::initialize(JS::Realm& realm) { WEB_SET_PROTOTYPE_FOR_INTERFACE(RTCError); Base::initialize(realm); }

}
