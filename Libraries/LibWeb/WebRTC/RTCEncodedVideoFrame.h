/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/Bindings/PlatformObject.h>
#include <LibWeb/Bindings/RTCEncodedVideoFrame.h>
#include <LibWeb/WebIDL/ExceptionOr.h>

namespace Web::WebRTC {

class RTCEncodedVideoFrame final : public Bindings::PlatformObject {
    WEB_PLATFORM_OBJECT(RTCEncodedVideoFrame, Bindings::PlatformObject);
    GC_DECLARE_ALLOCATOR(RTCEncodedVideoFrame);

public:
    static GC::Ref<RTCEncodedVideoFrame> create(JS::Realm&);
    static WebIDL::ExceptionOr<GC::Ref<RTCEncodedVideoFrame>> construct_impl(JS::Realm&, GC::Ref<RTCEncodedVideoFrame> original_frame, Bindings::RTCEncodedVideoFrameOptions const& = {});
    virtual ~RTCEncodedVideoFrame() override;

private:
    explicit RTCEncodedVideoFrame(JS::Realm&);
    virtual void initialize(JS::Realm&) override;
};

}
