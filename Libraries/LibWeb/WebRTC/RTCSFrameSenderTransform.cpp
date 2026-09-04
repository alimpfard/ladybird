/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCSFrameSenderTransform.h>
#include <LibWeb/WebRTC/RTCSFrameSenderTransform.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCSFrameSenderTransform);

GC::Ref<RTCSFrameSenderTransform> RTCSFrameSenderTransform::create(JS::Realm& realm) { return realm.create<RTCSFrameSenderTransform>(realm); }
RTCSFrameSenderTransform::RTCSFrameSenderTransform(JS::Realm& realm)
    : Bindings::GCAllocatedWrappable()
    , m_realm(realm)
{
}
RTCSFrameSenderTransform::~RTCSFrameSenderTransform() = default;

void RTCSFrameSenderTransform::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
}

}
