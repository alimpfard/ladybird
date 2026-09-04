/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibJS/Runtime/Realm.h>

#include <LibWeb/DOM/EventTarget.h>

namespace Web::WebRTC {

class RTCDTMFSender final : public DOM::EventTarget {
    WEB_WRAPPABLE(RTCDTMFSender, DOM::EventTarget);
    GC_DECLARE_ALLOCATOR(RTCDTMFSender);

public:
    static GC::Ref<RTCDTMFSender> create(JS::Realm&);
    virtual ~RTCDTMFSender() override;

    void set_ontonechange(WebIDL::CallbackType*);
    WebIDL::CallbackType* ontonechange();

public:
    JS::Realm& realm() const { return *m_realm; }
    JS::VM& vm() const { return realm().vm(); }

private:
    GC::Ref<JS::Realm> m_realm;
    virtual void visit_edges(JS::Cell::Visitor&) override;
    explicit RTCDTMFSender(JS::Realm&);
};

}
