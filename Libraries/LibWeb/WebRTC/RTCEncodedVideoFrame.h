/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/WebIDL/DOMException.h>
#include <LibWeb/WebIDL/ExceptionOr.h>

#include <LibJS/Runtime/Realm.h>

#include <LibWeb/Bindings/Wrappable.h>

namespace Web::WebRTC {

class RTCEncodedVideoFrame final : public Bindings::GCAllocatedWrappable {
    WEB_WRAPPABLE(RTCEncodedVideoFrame, Bindings::GCAllocatedWrappable);
    GC_DECLARE_ALLOCATOR(RTCEncodedVideoFrame);

public:
    template<typename... Args>
    static WebIDL::ExceptionOr<GC::Ref<RTCEncodedVideoFrame>> construct_impl(JS::Realm&, Args const&...)
    {
        return WebIDL::NotSupportedError::create("RTCEncodedVideoFrame constructor is not implemented"_utf16);
    }

    static GC::Ref<RTCEncodedVideoFrame> create();
    virtual ~RTCEncodedVideoFrame() override;

public:
private:
    virtual void visit_edges(JS::Cell::Visitor&) override;
    explicit RTCEncodedVideoFrame();
};

}
