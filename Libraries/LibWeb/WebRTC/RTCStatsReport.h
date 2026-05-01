/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/Bindings/PlatformObject.h>

namespace Web::WebRTC {

// https://w3c.github.io/webrtc-pc/#rtcstatsreport-object
class RTCStatsReport final : public Bindings::PlatformObject {
    WEB_PLATFORM_OBJECT(RTCStatsReport, Bindings::PlatformObject);
    GC_DECLARE_ALLOCATOR(RTCStatsReport);

public:
    static GC::Ref<RTCStatsReport> create(JS::Realm&);

    virtual ~RTCStatsReport() override;

private:
    explicit RTCStatsReport(JS::Realm&);

    virtual void initialize(JS::Realm&) override;
};

}
