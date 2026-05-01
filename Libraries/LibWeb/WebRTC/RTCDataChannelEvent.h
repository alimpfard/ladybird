/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/DOM/Event.h>

namespace Web::WebRTC {

class RTCDataChannelEvent final : public DOM::Event {
    WEB_PLATFORM_OBJECT(RTCDataChannelEvent, DOM::Event);
    GC_DECLARE_ALLOCATOR(RTCDataChannelEvent);

public:
    static GC::Ref<RTCDataChannelEvent> create(JS::Realm&, FlyString const& event_name);
    virtual ~RTCDataChannelEvent() override;

private:
    RTCDataChannelEvent(JS::Realm&, FlyString const&);
    virtual void initialize(JS::Realm&) override;
};

}
