/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibJS/Runtime/Realm.h>

#include <LibWeb/Bindings/Wrappable.h>

namespace Web::WebRTC {

// https://w3c.github.io/webrtc-pc/#rtcstatsreport-object
class RTCStatsReport final : public Bindings::GCAllocatedWrappable {
    WEB_WRAPPABLE(RTCStatsReport, Bindings::GCAllocatedWrappable);
    GC_DECLARE_ALLOCATOR(RTCStatsReport);

public:
    static GC::Ref<RTCStatsReport> create(JS::Realm&);

    virtual ~RTCStatsReport() override;

public:
    JS::Realm& realm() const { return *m_realm; }
    JS::VM& vm() const { return realm().vm(); }

private:
    GC::Ref<JS::Realm> m_realm;
    virtual void visit_edges(JS::Cell::Visitor&) override;
    explicit RTCStatsReport(JS::Realm&);
};

}
