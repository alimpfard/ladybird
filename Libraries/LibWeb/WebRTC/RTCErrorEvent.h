/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/DOM/Event.h>

namespace Web::WebRTC {

class RTCErrorEvent final : public DOM::Event {
    WEB_PLATFORM_OBJECT(RTCErrorEvent, DOM::Event);
    GC_DECLARE_ALLOCATOR(RTCErrorEvent);

public:
    static GC::Ref<RTCErrorEvent> create(JS::Realm&, FlyString const& event_name);
    virtual ~RTCErrorEvent() override;

private:
    RTCErrorEvent(JS::Realm&, FlyString const&);
    virtual void initialize(JS::Realm&) override;
};

}
