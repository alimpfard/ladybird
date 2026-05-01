/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/DOM/EventTarget.h>

namespace Web::WebRTC {

class RTCDTMFSender final : public DOM::EventTarget {
    WEB_PLATFORM_OBJECT(RTCDTMFSender, DOM::EventTarget);
    GC_DECLARE_ALLOCATOR(RTCDTMFSender);

public:
    static GC::Ref<RTCDTMFSender> create(JS::Realm&);
    virtual ~RTCDTMFSender() override;

    void set_ontonechange(WebIDL::CallbackType*);
    WebIDL::CallbackType* ontonechange();

private:
    explicit RTCDTMFSender(JS::Realm&);
    virtual void initialize(JS::Realm&) override;
};

}
