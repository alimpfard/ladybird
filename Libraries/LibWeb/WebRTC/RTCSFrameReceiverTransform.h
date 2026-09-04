/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/WebIDL/DOMException.h>
#include <LibWeb/WebIDL/ExceptionOr.h>

#include <LibJS/Runtime/Realm.h>

#include <LibWeb/DOM/EventTarget.h>

namespace Web::WebRTC {

class RTCSFrameReceiverTransform final : public DOM::EventTarget {
    WEB_WRAPPABLE(RTCSFrameReceiverTransform, DOM::EventTarget);
    GC_DECLARE_ALLOCATOR(RTCSFrameReceiverTransform);

public:
    template<typename... Args>
    static WebIDL::ExceptionOr<GC::Ref<RTCSFrameReceiverTransform>> construct_impl(JS::Realm&, Args const&...)
    {
        return WebIDL::NotSupportedError::create("RTCSFrameReceiverTransform constructor is not implemented"_utf16);
    }

    static GC::Ref<RTCSFrameReceiverTransform> create(JS::Realm&);
    virtual ~RTCSFrameReceiverTransform() override;

public:
    JS::Realm& realm() const { return *m_realm; }
    JS::VM& vm() const { return realm().vm(); }

private:
    GC::Ref<JS::Realm> m_realm;
    virtual void visit_edges(JS::Cell::Visitor&) override;
    explicit RTCSFrameReceiverTransform(JS::Realm&);
};

}
