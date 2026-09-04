/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCSessionDescription.h>
#include <LibWeb/WebIDL/ExceptionOr.h>
#include <LibWeb/WebRTC/RTCSessionDescription.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCSessionDescription);

GC::Ref<RTCSessionDescription> RTCSessionDescription::create(JS::Realm& realm, RTCSessionDescriptionInit const& init)
{
    return realm.create<RTCSessionDescription>(realm, init.type, init.sdp);
}

WebIDL::ExceptionOr<GC::Ref<RTCSessionDescription>> RTCSessionDescription::construct_impl(JS::Realm& realm, RTCSessionDescriptionInit const& init)
{
    return create(realm, init);
}

RTCSessionDescription::RTCSessionDescription(JS::Realm& realm, Bindings::RTCSdpType type, Utf16String sdp)
    : Bindings::GCAllocatedWrappable()
    , m_realm(realm)
    , m_type(type)
    , m_sdp(move(sdp))
{
}

RTCSessionDescription::~RTCSessionDescription() = default;

void RTCSessionDescription::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
}

}
