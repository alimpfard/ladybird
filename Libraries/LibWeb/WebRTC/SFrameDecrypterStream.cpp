/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/SFrameDecrypterStream.h>
#include <LibWeb/WebRTC/SFrameDecrypterStream.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(SFrameDecrypterStream);

GC::Ref<SFrameDecrypterStream> SFrameDecrypterStream::create(JS::Realm& realm) { return realm.create<SFrameDecrypterStream>(realm); }
SFrameDecrypterStream::SFrameDecrypterStream(JS::Realm& realm)
    : DOM::EventTarget()
    , m_realm(realm)
{
}
SFrameDecrypterStream::~SFrameDecrypterStream() = default;

void SFrameDecrypterStream::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
}

}
