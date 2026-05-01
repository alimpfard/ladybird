/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/DOM/Event.h>

namespace Web::WebRTC {

class KeyFrameRequestEvent final : public DOM::Event {
    WEB_PLATFORM_OBJECT(KeyFrameRequestEvent, DOM::Event);
    GC_DECLARE_ALLOCATOR(KeyFrameRequestEvent);

public:
    static GC::Ref<KeyFrameRequestEvent> create(JS::Realm&, FlyString const& event_name);
    static GC::Ref<KeyFrameRequestEvent> construct_impl(JS::Realm&, String const& type, Optional<String> const& rid);
    virtual ~KeyFrameRequestEvent() override;

private:
    KeyFrameRequestEvent(JS::Realm&, FlyString const&);
    virtual void initialize(JS::Realm&) override;
};

}
