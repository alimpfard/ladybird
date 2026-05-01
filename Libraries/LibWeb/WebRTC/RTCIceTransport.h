/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/DOM/EventTarget.h>

namespace Web::WebRTC {

class RTCIceTransport final : public DOM::EventTarget {
    WEB_PLATFORM_OBJECT(RTCIceTransport, DOM::EventTarget);
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

private:
    explicit RTCIceTransport(JS::Realm&);
    virtual void initialize(JS::Realm&) override;
};

}
