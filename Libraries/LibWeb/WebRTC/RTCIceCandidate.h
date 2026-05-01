/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/Bindings/PlatformObject.h>
#include <LibWeb/Bindings/RTCIceCandidate.h>

namespace Web::WebRTC {

using Bindings::RTCIceCandidateInit;

class RTCIceCandidate final : public Bindings::PlatformObject {
    WEB_PLATFORM_OBJECT(RTCIceCandidate, Bindings::PlatformObject);
    GC_DECLARE_ALLOCATOR(RTCIceCandidate);

public:
    static GC::Ref<RTCIceCandidate> create(JS::Realm&, RTCIceCandidateInit const& = {});
    static WebIDL::ExceptionOr<GC::Ref<RTCIceCandidate>> construct_impl(JS::Realm&, RTCIceCandidateInit const& = {});

    virtual ~RTCIceCandidate() override;

    Optional<String> foundation() const { return {}; }
    Optional<Bindings::RTCIceServerTransportProtocol> relay_protocol() const { return {}; }

private:
    explicit RTCIceCandidate(JS::Realm&);

    virtual void initialize(JS::Realm&) override;
};

}
