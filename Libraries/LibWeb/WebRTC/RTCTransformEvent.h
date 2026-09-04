/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibJS/Runtime/Realm.h>

#include <LibWeb/DOM/Event.h>
#include <LibWeb/Export.h>
#include <LibWeb/Forward.h>

namespace Web::WebRTC {

class RTCRtpScriptTransformer;

class WEB_API RTCTransformEvent final : public DOM::Event {
    WEB_WRAPPABLE(RTCTransformEvent, DOM::Event);
    GC_DECLARE_ALLOCATOR(RTCTransformEvent);

public:
    static GC::Ref<RTCTransformEvent> create(JS::Realm&, Utf16FlyString const& event_name, GC::Ref<RTCRtpScriptTransformer>);
    virtual ~RTCTransformEvent() override;

    GC::Ref<RTCRtpScriptTransformer> transformer() const;

public:
    JS::Realm& realm() const { return *m_realm; }
    JS::VM& vm() const { return realm().vm(); }

private:
    GC::Ref<JS::Realm> m_realm;
    RTCTransformEvent(JS::Realm&, Utf16FlyString const&, GC::Ref<RTCRtpScriptTransformer>);
    virtual void visit_edges(Cell::Visitor&) override;

    GC::Ref<RTCRtpScriptTransformer> m_transformer;
};

}
