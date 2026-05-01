/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCStatsReport.h>
#include <LibWeb/WebRTC/RTCStatsReport.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCStatsReport);

GC::Ref<RTCStatsReport> RTCStatsReport::create(JS::Realm& realm)
{
    return realm.create<RTCStatsReport>(realm);
}

RTCStatsReport::RTCStatsReport(JS::Realm& realm)
    : Bindings::PlatformObject(realm)
{
}

RTCStatsReport::~RTCStatsReport() = default;

void RTCStatsReport::initialize(JS::Realm& realm)
{
    WEB_SET_PROTOTYPE_FOR_INTERFACE(RTCStatsReport);
    Base::initialize(realm);
}

}
