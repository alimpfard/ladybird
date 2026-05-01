/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/DOM/Event.h>

namespace Web::WebRTC {

class RTCPeerConnectionIceErrorEvent final : public DOM::Event {
    WEB_PLATFORM_OBJECT(RTCPeerConnectionIceErrorEvent, DOM::Event);
    GC_DECLARE_ALLOCATOR(RTCPeerConnectionIceErrorEvent);

public:
    static GC::Ref<RTCPeerConnectionIceErrorEvent> create(JS::Realm&, FlyString const& event_name);
    virtual ~RTCPeerConnectionIceErrorEvent() override;

private:
    RTCPeerConnectionIceErrorEvent(JS::Realm&, FlyString const&);
    virtual void initialize(JS::Realm&) override;
};

}
