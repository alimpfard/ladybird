/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCIceCandidate.h>
#include <LibWeb/WebIDL/ExceptionOr.h>
#include <LibWeb/WebRTC/RTCIceCandidate.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCIceCandidate);

GC::Ref<RTCIceCandidate> RTCIceCandidate::create(JS::Realm& realm, RTCIceCandidateInit const& init)
{
    auto candidate = realm.create<RTCIceCandidate>(realm);
    candidate->m_init = init;
    return candidate;
}

WebIDL::ExceptionOr<GC::Ref<RTCIceCandidate>> RTCIceCandidate::construct_impl(JS::Realm& realm, RTCIceCandidateInit const& init)
{
    return create(realm, init);
}

RTCIceCandidate::RTCIceCandidate(JS::Realm& realm)
    : Bindings::GCAllocatedWrappable()
    , m_realm(realm)
{
}

RTCIceCandidate::~RTCIceCandidate() = default;

void RTCIceCandidate::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
}

}
