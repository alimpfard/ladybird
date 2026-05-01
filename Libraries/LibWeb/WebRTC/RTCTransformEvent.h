/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/DOM/Event.h>
#include <LibWeb/Export.h>
#include <LibWeb/Forward.h>

namespace Web::WebRTC {

class RTCRtpScriptTransformer;

class WEB_API RTCTransformEvent final : public DOM::Event {
    WEB_PLATFORM_OBJECT(RTCTransformEvent, DOM::Event);
    GC_DECLARE_ALLOCATOR(RTCTransformEvent);

public:
    static GC::Ref<RTCTransformEvent> create(JS::Realm&, FlyString const& event_name, GC::Ref<RTCRtpScriptTransformer>);
    virtual ~RTCTransformEvent() override;

    GC::Ref<RTCRtpScriptTransformer> transformer() const;

private:
    RTCTransformEvent(JS::Realm&, FlyString const&, GC::Ref<RTCRtpScriptTransformer>);
    virtual void initialize(JS::Realm&) override;
    virtual void visit_edges(Cell::Visitor&) override;

    GC::Ref<RTCRtpScriptTransformer> m_transformer;
};

}
