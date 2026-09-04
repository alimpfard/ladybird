/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibJS/Runtime/Realm.h>

#include <LibWeb/Bindings/RTCDataChannel.h>
#include <LibWeb/DOM/EventTarget.h>
#include <LibWeb/Forward.h>
#include <LibWeb/WebIDL/Buffers.h>
#include <LibWeb/WebIDL/ExceptionOr.h>
#include <LibWeb/WebIDL/Types.h>

namespace Web::WebRTC {

using RTCDataChannelInit = Bindings::RTCDataChannelInit;

class RTCDataChannel final : public DOM::EventTarget {
    WEB_WRAPPABLE(RTCDataChannel, DOM::EventTarget);
    GC_DECLARE_ALLOCATOR(RTCDataChannel);

public:
    static GC::Ref<RTCDataChannel> create(JS::Realm&);
    virtual ~RTCDataChannel() override;

    void set_label(String label) { m_label = move(label); }
    void set_max_packet_life_time(Optional<u16> v) { m_max_packet_life_time = v; }
    void set_max_retransmits(Optional<u16> v) { m_max_retransmits = v; }
    void set_ordered(bool v) { m_ordered = v; }
    void set_protocol(String v) { m_protocol = move(v); }
    void set_negotiated(bool v) { m_negotiated = v; }
    void set_id(Optional<u16> v) { m_id = v; }
    void set_channel_id(u64 v) { m_channel_id = v; }
    void set_ready_state(Bindings::RTCDataChannelState v) { m_ready_state = v; }

    Bindings::RTCDataChannelState ready_state() const { return m_ready_state; }
    WebIDL::UnsignedLong buffered_amount() const { return m_buffered_amount; }
    WebIDL::UnsignedLong buffered_amount_low_threshold() const { return m_buffered_amount_low_threshold; }
    void set_buffered_amount_low_threshold(WebIDL::UnsignedLong v) { m_buffered_amount_low_threshold = v; }

    WebIDL::ExceptionOr<void> send(FlattenVariant<Variant<Utf16String, GC::Ref<FileAPI::Blob>>, WebIDL::BufferSourceVariant> const&);

    void set_onopen(WebIDL::CallbackType*);
    WebIDL::CallbackType* onopen();
    void set_onbufferedamountlow(WebIDL::CallbackType*);
    WebIDL::CallbackType* onbufferedamountlow();
    void set_onerror(WebIDL::CallbackType*);
    WebIDL::CallbackType* onerror();
    void set_onclosing(WebIDL::CallbackType*);
    WebIDL::CallbackType* onclosing();
    void set_onclose(WebIDL::CallbackType*);
    WebIDL::CallbackType* onclose();
    void set_onmessage(WebIDL::CallbackType*);
    WebIDL::CallbackType* onmessage();

public:
    JS::Realm& realm() const { return *m_realm; }
    JS::VM& vm() const { return realm().vm(); }

private:
    GC::Ref<JS::Realm> m_realm;
    virtual void visit_edges(JS::Cell::Visitor&) override;
    explicit RTCDataChannel(JS::Realm&);

    // [[DataChannelLabel]]
    String m_label;
    // [[MaxPacketLifeTime]]
    Optional<u16> m_max_packet_life_time;
    // [[MaxRetransmits]]
    Optional<u16> m_max_retransmits;
    // [[Ordered]]
    bool m_ordered { true };
    // [[DataChannelProtocol]]
    String m_protocol;
    // [[Negotiated]]
    bool m_negotiated { false };
    // [[DataChannelId]]
    Optional<u16> m_id;
    // [[ReadyState]]
    Bindings::RTCDataChannelState m_ready_state { Bindings::RTCDataChannelState::Connecting };
    // [[BufferedAmount]]
    WebIDL::UnsignedLong m_buffered_amount { 0 };
    WebIDL::UnsignedLong m_buffered_amount_low_threshold { 0 };
    // [[IsTransferable]]
    bool m_is_transferable { true };
    u64 m_channel_id { 0 };
};

}
