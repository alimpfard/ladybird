/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibJS/Runtime/Realm.h>

#include <LibWeb/DOM/EventTarget.h>

namespace Web::WebRTC {

class RTCIceTransport final : public DOM::EventTarget {
    WEB_WRAPPABLE(RTCIceTransport, DOM::EventTarget);
    GC_DECLARE_ALLOCATOR(RTCIceTransport);

public:
    static GC::Ref<RTCIceTransport> create(JS::Realm&);
    virtual ~RTCIceTransport() override;

    void set_onstatechange(WebIDL::CallbackType*);
    WebIDL::CallbackType* onstatechange();
    void set_ongatheringstatechange(WebIDL::CallbackType*);
    WebIDL::CallbackType* ongatheringstatechange();
    void set_onselectedcandidatepairchange(WebIDL::CallbackType*);
    WebIDL::CallbackType* onselectedcandidatepairchange();

public:
    JS::Realm& realm() const { return *m_realm; }
    JS::VM& vm() const { return realm().vm(); }

private:
    GC::Ref<JS::Realm> m_realm;
    virtual void visit_edges(JS::Cell::Visitor&) override;
    explicit RTCIceTransport(JS::Realm&);
};

}
