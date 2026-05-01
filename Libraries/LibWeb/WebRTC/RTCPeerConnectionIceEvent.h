/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/DOM/Event.h>

namespace Web::WebRTC {

class RTCPeerConnectionIceEvent final : public DOM::Event {
    WEB_PLATFORM_OBJECT(RTCPeerConnectionIceEvent, DOM::Event);
    GC_DECLARE_ALLOCATOR(RTCPeerConnectionIceEvent);

public:
    static GC::Ref<RTCPeerConnectionIceEvent> create(JS::Realm&, FlyString const& event_name);
    virtual ~RTCPeerConnectionIceEvent() override;

private:
    RTCPeerConnectionIceEvent(JS::Realm&, FlyString const&);
    virtual void initialize(JS::Realm&) override;
};

}
