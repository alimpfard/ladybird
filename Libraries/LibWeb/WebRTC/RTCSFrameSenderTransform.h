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

class RTCSFrameSenderTransform final : public Bindings::GCAllocatedWrappable {
    WEB_WRAPPABLE(RTCSFrameSenderTransform, Bindings::GCAllocatedWrappable);
    GC_DECLARE_ALLOCATOR(RTCSFrameSenderTransform);

public:
    template<typename... Args>
    static WebIDL::ExceptionOr<GC::Ref<RTCSFrameSenderTransform>> construct_impl(JS::Realm&, Args const&...)
    {
        return WebIDL::NotSupportedError::create("RTCSFrameSenderTransform constructor is not implemented"_utf16);
    }

    static GC::Ref<RTCSFrameSenderTransform> create(JS::Realm&);
    virtual ~RTCSFrameSenderTransform() override;

public:
    JS::Realm& realm() const { return *m_realm; }
    JS::VM& vm() const { return realm().vm(); }

private:
    GC::Ref<JS::Realm> m_realm;
    virtual void visit_edges(JS::Cell::Visitor&) override;
    explicit RTCSFrameSenderTransform(JS::Realm&);
};

}
