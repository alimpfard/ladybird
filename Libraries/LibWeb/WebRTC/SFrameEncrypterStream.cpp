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

// FIXME: SFrameEncrypterStream is a stub — wire up the options once SFrame transforms are implemented.
WebIDL::ExceptionOr<GC::Ref<SFrameEncrypterStream>> SFrameEncrypterStream::construct_impl(JS::Realm& realm, Bindings::SFrameTransformOptions const&)
{
    return create(realm);
}
SFrameEncrypterStream::SFrameEncrypterStream(JS::Realm& realm) : DOM::EventTarget(realm) { }
SFrameEncrypterStream::~SFrameEncrypterStream() = default;
void SFrameEncrypterStream::initialize(JS::Realm& realm) { WEB_SET_PROTOTYPE_FOR_INTERFACE(SFrameEncrypterStream); Base::initialize(realm); }

}
