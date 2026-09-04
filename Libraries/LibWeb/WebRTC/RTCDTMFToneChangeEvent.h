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

namespace Web::WebRTC {

class RTCDTMFToneChangeEvent final : public DOM::Event {
    WEB_WRAPPABLE(RTCDTMFToneChangeEvent, DOM::Event);
    GC_DECLARE_ALLOCATOR(RTCDTMFToneChangeEvent);

public:
    template<typename... Args>
    static WebIDL::ExceptionOr<GC::Ref<RTCDTMFToneChangeEvent>> construct_impl(JS::Realm&, Args const&...)
    {
        return WebIDL::NotSupportedError::create("RTCDTMFToneChangeEvent constructor is not implemented"_utf16);
    }

    static GC::Ref<RTCDTMFToneChangeEvent> create(JS::Realm&, Utf16FlyString const& event_name);
    virtual ~RTCDTMFToneChangeEvent() override;

public:
    JS::Realm& realm() const { return *m_realm; }
    JS::VM& vm() const { return realm().vm(); }

private:
    GC::Ref<JS::Realm> m_realm;
    virtual void visit_edges(JS::Cell::Visitor&) override;
    RTCDTMFToneChangeEvent(JS::Realm&, Utf16FlyString const&);
};

}
