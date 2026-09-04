/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibJS/Runtime/Realm.h>

#include <LibWeb/DOM/EventTarget.h>

namespace Web::WebRTC {

class RTCDtlsTransport final : public DOM::EventTarget {
    WEB_WRAPPABLE(RTCDtlsTransport, DOM::EventTarget);
    GC_DECLARE_ALLOCATOR(RTCDtlsTransport);

public:
    static GC::Ref<RTCDtlsTransport> create(JS::Realm&);
    virtual ~RTCDtlsTransport() override;

    void set_onstatechange(WebIDL::CallbackType*);
    WebIDL::CallbackType* onstatechange();
    void set_onerror(WebIDL::CallbackType*);
    WebIDL::CallbackType* onerror();

public:
    JS::Realm& realm() const { return *m_realm; }
    JS::VM& vm() const { return realm().vm(); }

private:
    GC::Ref<JS::Realm> m_realm;
    virtual void visit_edges(JS::Cell::Visitor&) override;
    explicit RTCDtlsTransport(JS::Realm&);
};

}
