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

// FIXME: SFrameDecrypterStream is a stub — wire up the options once SFrame transforms are implemented.
WebIDL::ExceptionOr<GC::Ref<SFrameDecrypterStream>> SFrameDecrypterStream::construct_impl(JS::Realm& realm, Bindings::SFrameTransformOptions const&)
{
    return create(realm);
}
SFrameDecrypterStream::SFrameDecrypterStream(JS::Realm& realm) : DOM::EventTarget(realm) { }
SFrameDecrypterStream::~SFrameDecrypterStream() = default;
void SFrameDecrypterStream::initialize(JS::Realm& realm) { WEB_SET_PROTOTYPE_FOR_INTERFACE(SFrameDecrypterStream); Base::initialize(realm); }

}
