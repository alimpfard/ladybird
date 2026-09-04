/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibGC/Heap.h>
#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCCertificate.h>
#include <LibWeb/WebRTC/RTCCertificate.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCCertificate);

GC::Ref<RTCCertificate> RTCCertificate::create() { return GC::Heap::the().allocate<RTCCertificate>(); }
RTCCertificate::RTCCertificate()
    : Bindings::GCAllocatedWrappable()
{
}
RTCCertificate::~RTCCertificate() = default;

void RTCCertificate::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
}

}
