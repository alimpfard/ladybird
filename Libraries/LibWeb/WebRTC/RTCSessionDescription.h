/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/Bindings/PlatformObject.h>
#include <LibWeb/Bindings/RTCSessionDescription.h>

namespace Web::WebRTC {

using Bindings::RTCLocalSessionDescriptionInit;
using Bindings::RTCSessionDescriptionInit;

class RTCSessionDescription final : public Bindings::PlatformObject {
    WEB_PLATFORM_OBJECT(RTCSessionDescription, Bindings::PlatformObject);
    GC_DECLARE_ALLOCATOR(RTCSessionDescription);

public:
    static GC::Ref<RTCSessionDescription> create(JS::Realm&, RTCSessionDescriptionInit const&);
    static WebIDL::ExceptionOr<GC::Ref<RTCSessionDescription>> construct_impl(JS::Realm&, RTCSessionDescriptionInit const&);

    virtual ~RTCSessionDescription() override;

    Bindings::RTCSdpType type() const { return m_type; }
    String const& sdp() const { return m_sdp; }
    RTCSessionDescriptionInit to_json() const { return { .sdp = m_sdp, .type = m_type }; }

private:
    RTCSessionDescription(JS::Realm&, Bindings::RTCSdpType, String);

    virtual void initialize(JS::Realm&) override;

    Bindings::RTCSdpType m_type {};
    String m_sdp;
};

}
