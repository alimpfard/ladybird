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

class SFrameEncrypterStream final : public DOM::EventTarget {
    WEB_WRAPPABLE(SFrameEncrypterStream, DOM::EventTarget);
    GC_DECLARE_ALLOCATOR(SFrameEncrypterStream);

public:
    template<typename... Args>
    static WebIDL::ExceptionOr<GC::Ref<SFrameEncrypterStream>> construct_impl(JS::Realm&, Args const&...)
    {
        return WebIDL::NotSupportedError::create("SFrameEncrypterStream constructor is not implemented"_utf16);
    }

    static GC::Ref<SFrameEncrypterStream> create(JS::Realm&);
    virtual ~SFrameEncrypterStream() override;

public:
    JS::Realm& realm() const { return *m_realm; }
    JS::VM& vm() const { return realm().vm(); }

private:
    GC::Ref<JS::Realm> m_realm;
    virtual void visit_edges(JS::Cell::Visitor&) override;
    explicit SFrameEncrypterStream(JS::Realm&);
};

}
