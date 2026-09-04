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
#include <LibWeb/WebRTC/RTCIceCandidate.h>

namespace Web::WebRTC {

class RTCPeerConnectionIceEvent final : public DOM::Event {
    WEB_WRAPPABLE(RTCPeerConnectionIceEvent, DOM::Event);
    GC_DECLARE_ALLOCATOR(RTCPeerConnectionIceEvent);

public:
    template<typename... Args>
    static WebIDL::ExceptionOr<GC::Ref<RTCPeerConnectionIceEvent>> construct_impl(JS::Realm&, Args const&...)
    {
        return WebIDL::NotSupportedError::create("RTCPeerConnectionIceEvent constructor is not implemented"_utf16);
    }

    static GC::Ref<RTCPeerConnectionIceEvent> create(JS::Realm&, Utf16FlyString const& event_name);
    GC::Ptr<RTCIceCandidate> candidate() const { return m_candidate; }
    void set_candidate(GC::Ptr<RTCIceCandidate> value) { m_candidate = value; }
    virtual ~RTCPeerConnectionIceEvent() override;

public:
    JS::Realm& realm() const { return *m_realm; }
    JS::VM& vm() const { return realm().vm(); }

private:
    GC::Ptr<RTCIceCandidate> m_candidate;
    GC::Ref<JS::Realm> m_realm;
    virtual void visit_edges(JS::Cell::Visitor&) override;
    RTCPeerConnectionIceEvent(JS::Realm&, Utf16FlyString const&);
};

}
