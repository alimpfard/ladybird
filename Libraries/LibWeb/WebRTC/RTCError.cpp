/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCError.h>
#include <LibWeb/WebRTC/RTCError.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCError);

GC::Ref<RTCError> RTCError::create(JS::Realm& realm) { return realm.create<RTCError>(realm); }
RTCError::RTCError(JS::Realm& realm)
    : WebIDL::DOMException("OperationError"_utf16_fly_string, {})
    , m_realm(realm)
{
}
RTCError::~RTCError() = default;

void RTCError::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
}

}
