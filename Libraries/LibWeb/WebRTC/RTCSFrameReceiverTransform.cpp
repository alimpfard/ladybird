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

// FIXME: RTCSFrameReceiverTransform is a stub — wire up the options once SFrame transforms are implemented.
WebIDL::ExceptionOr<GC::Ref<RTCSFrameReceiverTransform>> RTCSFrameReceiverTransform::construct_impl(JS::Realm& realm, Bindings::SFrameTransformOptions const&)
{
    return create(realm);
}
RTCSFrameReceiverTransform::RTCSFrameReceiverTransform(JS::Realm& realm) : DOM::EventTarget(realm) { }
RTCSFrameReceiverTransform::~RTCSFrameReceiverTransform() = default;
void RTCSFrameReceiverTransform::initialize(JS::Realm& realm) { WEB_SET_PROTOTYPE_FOR_INTERFACE(RTCSFrameReceiverTransform); Base::initialize(realm); }

}
