/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/DOM/EventTarget.h>

namespace Web::WebRTC {

class RTCSctpTransport final : public DOM::EventTarget {
    WEB_PLATFORM_OBJECT(RTCSctpTransport, DOM::EventTarget);
    GC_DECLARE_ALLOCATOR(RTCSctpTransport);

public:
    static GC::Ref<RTCSctpTransport> create(JS::Realm&);
    virtual ~RTCSctpTransport() override;

    void set_onstatechange(WebIDL::CallbackType*);
    WebIDL::CallbackType* onstatechange();

private:
    explicit RTCSctpTransport(JS::Realm&);
    virtual void initialize(JS::Realm&) override;
};

}
