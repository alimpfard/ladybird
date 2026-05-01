/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCCertificate.h>
#include <LibWeb/WebRTC/RTCCertificate.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCCertificate);

GC::Ref<RTCCertificate> RTCCertificate::create(JS::Realm& realm) { return realm.create<RTCCertificate>(realm); }
RTCCertificate::RTCCertificate(JS::Realm& realm) : Bindings::PlatformObject(realm) { }
RTCCertificate::~RTCCertificate() = default;
void RTCCertificate::initialize(JS::Realm& realm) { WEB_SET_PROTOTYPE_FOR_INTERFACE(RTCCertificate); Base::initialize(realm); }

}
