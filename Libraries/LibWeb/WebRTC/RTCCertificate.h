/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/Bindings/PlatformObject.h>

namespace Web::WebRTC {

class RTCCertificate final : public Bindings::PlatformObject {
    WEB_PLATFORM_OBJECT(RTCCertificate, Bindings::PlatformObject);
    GC_DECLARE_ALLOCATOR(RTCCertificate);

public:
    static GC::Ref<RTCCertificate> create(JS::Realm&);
    virtual ~RTCCertificate() override;

private:
    explicit RTCCertificate(JS::Realm&);
    virtual void initialize(JS::Realm&) override;
};

}
