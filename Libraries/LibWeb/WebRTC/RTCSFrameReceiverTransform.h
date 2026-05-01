/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/Bindings/Forward.h>
#include <LibWeb/DOM/EventTarget.h>
#include <LibWeb/WebIDL/ExceptionOr.h>

namespace Web::WebRTC {

class RTCSFrameReceiverTransform final : public DOM::EventTarget {
    WEB_PLATFORM_OBJECT(RTCSFrameReceiverTransform, DOM::EventTarget);
    GC_DECLARE_ALLOCATOR(RTCSFrameReceiverTransform);

public:
    static GC::Ref<RTCSFrameReceiverTransform> create(JS::Realm&);
    static WebIDL::ExceptionOr<GC::Ref<RTCSFrameReceiverTransform>> construct_impl(JS::Realm&, Bindings::SFrameTransformOptions const&);
    virtual ~RTCSFrameReceiverTransform() override;

private:
    explicit RTCSFrameReceiverTransform(JS::Realm&);
    virtual void initialize(JS::Realm&) override;
};

}
