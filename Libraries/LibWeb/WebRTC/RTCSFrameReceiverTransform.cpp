/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCSFrameReceiverTransform.h>
#include <LibWeb/WebRTC/RTCSFrameReceiverTransform.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCSFrameReceiverTransform);

GC::Ref<RTCSFrameReceiverTransform> RTCSFrameReceiverTransform::create(JS::Realm& realm) { return realm.create<RTCSFrameReceiverTransform>(realm); }
RTCSFrameReceiverTransform::RTCSFrameReceiverTransform(JS::Realm& realm)
    : DOM::EventTarget()
    , m_realm(realm)
{
}
RTCSFrameReceiverTransform::~RTCSFrameReceiverTransform() = default;

void RTCSFrameReceiverTransform::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
}

}
