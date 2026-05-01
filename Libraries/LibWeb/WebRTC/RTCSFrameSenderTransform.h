/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/Bindings/Forward.h>
#include <LibWeb/Bindings/PlatformObject.h>
#include <LibWeb/WebIDL/ExceptionOr.h>

namespace Web::WebRTC {

class RTCSFrameSenderTransform final : public Bindings::PlatformObject {
    WEB_PLATFORM_OBJECT(RTCSFrameSenderTransform, Bindings::PlatformObject);
    GC_DECLARE_ALLOCATOR(RTCSFrameSenderTransform);

public:
    static GC::Ref<RTCSFrameSenderTransform> create(JS::Realm&);
    static WebIDL::ExceptionOr<GC::Ref<RTCSFrameSenderTransform>> construct_impl(JS::Realm&, Bindings::RTCSFrameSenderTransformOptions const&);
    virtual ~RTCSFrameSenderTransform() override;

private:
    explicit RTCSFrameSenderTransform(JS::Realm&);
    virtual void initialize(JS::Realm&) override;
};

}
