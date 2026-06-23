/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibJS/Forward.h>
#include <LibWeb/Bindings/RTCPeerConnectionIceEvent.h>
#include <LibWeb/DOM/Event.h>

namespace Web::WebRTC {

using RTCPeerConnectionIceEventInit = Bindings::RTCPeerConnectionIceEventInit;

class RTCPeerConnectionIceEvent final : public DOM::Event {
    WEB_WRAPPABLE(RTCPeerConnectionIceEvent, DOM::Event);
    GC_DECLARE_ALLOCATOR(RTCPeerConnectionIceEvent);

public:
    [[nodiscard]] static GC::Ref<RTCPeerConnectionIceEvent> create(Utf16FlyString const& event_name, RTCPeerConnectionIceEventInit const&, HighResolutionTime::DOMHighResTimeStamp);
    virtual ~RTCPeerConnectionIceEvent() override;

private:
    RTCPeerConnectionIceEvent(Utf16FlyString const& event_name, RTCPeerConnectionIceEventInit const&, HighResolutionTime::DOMHighResTimeStamp);
};

}
