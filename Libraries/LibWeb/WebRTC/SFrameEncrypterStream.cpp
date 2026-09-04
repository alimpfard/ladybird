/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/SFrameEncrypterStream.h>
#include <LibWeb/WebRTC/SFrameEncrypterStream.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(SFrameEncrypterStream);

GC::Ref<SFrameEncrypterStream> SFrameEncrypterStream::create(JS::Realm& realm) { return realm.create<SFrameEncrypterStream>(realm); }
SFrameEncrypterStream::SFrameEncrypterStream(JS::Realm& realm)
    : DOM::EventTarget()
    , m_realm(realm)
{
}
SFrameEncrypterStream::~SFrameEncrypterStream() = default;

void SFrameEncrypterStream::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
}

}
