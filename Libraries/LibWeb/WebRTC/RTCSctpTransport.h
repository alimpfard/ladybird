/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibJS/Runtime/Realm.h>

#include <LibWeb/DOM/EventTarget.h>

namespace Web::WebRTC {

class RTCSctpTransport final : public DOM::EventTarget {
    WEB_WRAPPABLE(RTCSctpTransport, DOM::EventTarget);
    GC_DECLARE_ALLOCATOR(RTCSctpTransport);

public:
    static GC::Ref<RTCSctpTransport> create(JS::Realm&);
    virtual ~RTCSctpTransport() override;

    void set_onstatechange(WebIDL::CallbackType*);
    WebIDL::CallbackType* onstatechange();

public:
    JS::Realm& realm() const { return *m_realm; }
    JS::VM& vm() const { return realm().vm(); }

private:
    GC::Ref<JS::Realm> m_realm;
    virtual void visit_edges(JS::Cell::Visitor&) override;
    explicit RTCSctpTransport(JS::Realm&);
};

}
