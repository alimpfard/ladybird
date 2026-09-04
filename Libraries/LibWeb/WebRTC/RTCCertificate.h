/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibJS/Runtime/Realm.h>

#include <LibWeb/Bindings/Wrappable.h>

namespace Web::WebRTC {

class RTCCertificate final : public Bindings::GCAllocatedWrappable {
    WEB_WRAPPABLE(RTCCertificate, Bindings::GCAllocatedWrappable);
    GC_DECLARE_ALLOCATOR(RTCCertificate);

public:
    static GC::Ref<RTCCertificate> create();
    virtual ~RTCCertificate() override;

public:
private:
    virtual void visit_edges(JS::Cell::Visitor&) override;
    explicit RTCCertificate();
};

}
