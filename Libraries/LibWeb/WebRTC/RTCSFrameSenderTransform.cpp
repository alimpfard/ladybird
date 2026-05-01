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

// FIXME: RTCSFrameSenderTransform is a stub — wire up the options once SFrame transforms are implemented.
WebIDL::ExceptionOr<GC::Ref<RTCSFrameSenderTransform>> RTCSFrameSenderTransform::construct_impl(JS::Realm& realm, Bindings::RTCSFrameSenderTransformOptions const&)
{
    return create(realm);
}
RTCSFrameSenderTransform::RTCSFrameSenderTransform(JS::Realm& realm) : Bindings::PlatformObject(realm) { }
RTCSFrameSenderTransform::~RTCSFrameSenderTransform() = default;
void RTCSFrameSenderTransform::initialize(JS::Realm& realm) { WEB_SET_PROTOTYPE_FOR_INTERFACE(RTCSFrameSenderTransform); Base::initialize(realm); }

}
