/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/DOM/Event.h>

namespace Web::WebRTC {

class RTCDTMFToneChangeEvent final : public DOM::Event {
    WEB_PLATFORM_OBJECT(RTCDTMFToneChangeEvent, DOM::Event);
    GC_DECLARE_ALLOCATOR(RTCDTMFToneChangeEvent);

public:
    static GC::Ref<RTCDTMFToneChangeEvent> create(JS::Realm&, FlyString const& event_name);
    virtual ~RTCDTMFToneChangeEvent() override;

private:
    RTCDTMFToneChangeEvent(JS::Realm&, FlyString const&);
    virtual void initialize(JS::Realm&) override;
};

}
