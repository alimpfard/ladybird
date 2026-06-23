/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibJS/Forward.h>
#include <LibWeb/Bindings/RTCDataChannelEvent.h>
#include <LibWeb/DOM/Event.h>

namespace Web::WebRTC {

using RTCDataChannelEventInit = Bindings::RTCDataChannelEventInit;

class RTCDataChannelEvent final : public DOM::Event {
    WEB_WRAPPABLE(RTCDataChannelEvent, DOM::Event);
    GC_DECLARE_ALLOCATOR(RTCDataChannelEvent);

public:
    [[nodiscard]] static GC::Ref<RTCDataChannelEvent> create(Utf16FlyString const& event_name, RTCDataChannelEventInit const&, HighResolutionTime::DOMHighResTimeStamp);
    virtual ~RTCDataChannelEvent() override;

private:
    RTCDataChannelEvent(Utf16FlyString const& event_name, RTCDataChannelEventInit const&, HighResolutionTime::DOMHighResTimeStamp);
};

}
