/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/DOM/Event.h>

namespace Web::WebRTC {

class SFrameTransformErrorEvent final : public DOM::Event {
    WEB_PLATFORM_OBJECT(SFrameTransformErrorEvent, DOM::Event);
    GC_DECLARE_ALLOCATOR(SFrameTransformErrorEvent);

public:
    static GC::Ref<SFrameTransformErrorEvent> create(JS::Realm&, FlyString const& event_name);
    virtual ~SFrameTransformErrorEvent() override;

private:
    SFrameTransformErrorEvent(JS::Realm&, FlyString const&);
    virtual void initialize(JS::Realm&) override;
};

}
