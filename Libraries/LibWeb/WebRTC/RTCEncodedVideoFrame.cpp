/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibGC/Heap.h>
#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCEncodedVideoFrame.h>
#include <LibWeb/WebRTC/RTCEncodedVideoFrame.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCEncodedVideoFrame);

GC::Ref<RTCEncodedVideoFrame> RTCEncodedVideoFrame::create() { return GC::Heap::the().allocate<RTCEncodedVideoFrame>(); }
RTCEncodedVideoFrame::RTCEncodedVideoFrame()
    : Bindings::GCAllocatedWrappable()
{
}
RTCEncodedVideoFrame::~RTCEncodedVideoFrame() = default;

void RTCEncodedVideoFrame::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
}

}
