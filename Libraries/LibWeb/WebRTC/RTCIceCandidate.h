/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibJS/Runtime/Realm.h>

#include <LibWeb/Bindings/RTCIceCandidate.h>
#include <LibWeb/Bindings/Wrappable.h>

namespace Web::WebRTC {

using RTCIceCandidateInit = Bindings::RTCIceCandidateInit;

class RTCIceCandidate final : public Bindings::GCAllocatedWrappable {
    WEB_WRAPPABLE(RTCIceCandidate, Bindings::GCAllocatedWrappable);
    GC_DECLARE_ALLOCATOR(RTCIceCandidate);

public:
    static GC::Ref<RTCIceCandidate> create(JS::Realm&, RTCIceCandidateInit const& = {});
    static WebIDL::ExceptionOr<GC::Ref<RTCIceCandidate>> construct_impl(JS::Realm&, RTCIceCandidateInit const& = {});

    virtual ~RTCIceCandidate() override;

    Utf16String const& candidate() const { return m_init.candidate; }
    Optional<Utf16String> const& sdp_mid() const { return m_init.sdp_mid; }
    Optional<u16> sdp_m_line_index() const { return m_init.sdp_m_line_index; }
    Optional<Utf16String> const& username_fragment() const { return m_init.username_fragment; }
    RTCIceCandidateInit to_json() const { return m_init; }

    Optional<String> foundation() const { return {}; }
    Optional<Bindings::RTCIceServerTransportProtocol> relay_protocol() const { return {}; }

public:
    JS::Realm& realm() const { return *m_realm; }
    JS::VM& vm() const { return realm().vm(); }

private:
    RTCIceCandidateInit m_init;
    GC::Ref<JS::Realm> m_realm;
    virtual void visit_edges(JS::Cell::Visitor&) override;
    explicit RTCIceCandidate(JS::Realm&);
};

}
