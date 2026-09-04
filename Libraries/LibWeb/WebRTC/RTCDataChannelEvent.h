/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/WebIDL/DOMException.h>
#include <LibWeb/WebIDL/ExceptionOr.h>

#include <LibJS/Runtime/Realm.h>

#include <LibWeb/DOM/Event.h>
#include <LibWeb/WebRTC/RTCDataChannel.h>

namespace Web::WebRTC {

class RTCDataChannelEvent final : public DOM::Event {
    WEB_WRAPPABLE(RTCDataChannelEvent, DOM::Event);
    GC_DECLARE_ALLOCATOR(RTCDataChannelEvent);

public:
    template<typename... Args>
    static WebIDL::ExceptionOr<GC::Ref<RTCDataChannelEvent>> construct_impl(JS::Realm&, Args const&...)
    {
        return WebIDL::NotSupportedError::create("RTCDataChannelEvent constructor is not implemented"_utf16);
    }

    static GC::Ref<RTCDataChannelEvent> create(JS::Realm&, Utf16FlyString const& event_name);
    GC::Ref<RTCDataChannel> channel() const { return *m_channel; }
    void set_channel(GC::Ptr<RTCDataChannel> value) { m_channel = value; }
    virtual ~RTCDataChannelEvent() override;

public:
    JS::Realm& realm() const { return *m_realm; }
    JS::VM& vm() const { return realm().vm(); }

private:
    GC::Ptr<RTCDataChannel> m_channel;
    GC::Ref<JS::Realm> m_realm;
    virtual void visit_edges(JS::Cell::Visitor&) override;
    RTCDataChannelEvent(JS::Realm&, Utf16FlyString const&);
};

}
