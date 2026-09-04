/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/WebIDL/DOMException.h>
#include <LibWeb/WebIDL/ExceptionOr.h>

#include <LibJS/Runtime/Realm.h>

namespace Web::WebRTC {

class RTCError final : public WebIDL::DOMException {
    WEB_WRAPPABLE(RTCError, WebIDL::DOMException);
    GC_DECLARE_ALLOCATOR(RTCError);

public:
    template<typename... Args>
    static WebIDL::ExceptionOr<GC::Ref<RTCError>> construct_impl(JS::Realm&, Args const&...)
    {
        return WebIDL::NotSupportedError::create("RTCError constructor is not implemented"_utf16);
    }

    static GC::Ref<RTCError> create(JS::Realm&);
    virtual ~RTCError() override;

public:
    JS::Realm& realm() const { return *m_realm; }
    JS::VM& vm() const { return realm().vm(); }

private:
    GC::Ref<JS::Realm> m_realm;
    virtual void visit_edges(JS::Cell::Visitor&) override;
    explicit RTCError(JS::Realm&);
};

}
