/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibJS/Runtime/Realm.h>

#include <LibWeb/Bindings/RTCSessionDescription.h>
#include <LibWeb/Bindings/Wrappable.h>

namespace Web::WebRTC {

using RTCSessionDescriptionInit = Bindings::RTCSessionDescriptionInit;

using RTCLocalSessionDescriptionInit = Bindings::RTCLocalSessionDescriptionInit;

class RTCSessionDescription final : public Bindings::GCAllocatedWrappable {
    WEB_WRAPPABLE(RTCSessionDescription, Bindings::GCAllocatedWrappable);
    GC_DECLARE_ALLOCATOR(RTCSessionDescription);

public:
    static GC::Ref<RTCSessionDescription> create(JS::Realm&, RTCSessionDescriptionInit const&);
    static WebIDL::ExceptionOr<GC::Ref<RTCSessionDescription>> construct_impl(JS::Realm&, RTCSessionDescriptionInit const&);

    virtual ~RTCSessionDescription() override;

    Bindings::RTCSdpType type() const { return m_type; }
    Utf16String const& sdp() const { return m_sdp; }
    RTCSessionDescriptionInit to_json() const { return { .sdp = m_sdp, .type = m_type }; }

public:
    JS::Realm& realm() const { return *m_realm; }
    JS::VM& vm() const { return realm().vm(); }

private:
    GC::Ref<JS::Realm> m_realm;
    virtual void visit_edges(JS::Cell::Visitor&) override;
    RTCSessionDescription(JS::Realm&, Bindings::RTCSdpType, Utf16String);

    Bindings::RTCSdpType m_type {};
    Utf16String m_sdp;
};

}
