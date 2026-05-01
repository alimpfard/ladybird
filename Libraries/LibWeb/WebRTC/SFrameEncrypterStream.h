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

class SFrameEncrypterStream final : public DOM::EventTarget {
    WEB_PLATFORM_OBJECT(SFrameEncrypterStream, DOM::EventTarget);
    GC_DECLARE_ALLOCATOR(SFrameEncrypterStream);

public:
    static GC::Ref<SFrameEncrypterStream> create(JS::Realm&);
    static WebIDL::ExceptionOr<GC::Ref<SFrameEncrypterStream>> construct_impl(JS::Realm&, Bindings::SFrameTransformOptions const&);
    virtual ~SFrameEncrypterStream() override;

private:
    explicit SFrameEncrypterStream(JS::Realm&);
    virtual void initialize(JS::Realm&) override;
};

}
