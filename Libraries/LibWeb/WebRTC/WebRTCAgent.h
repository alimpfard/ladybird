/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/HashMap.h>
#include <AK/RefPtr.h>
#include <LibGC/Heap.h>
#include <LibGC/Ptr.h>
#include <LibGC/Root.h>
#include <LibWebRTCClient/Client.h>

namespace Web::WebRTC {

class RTCDataChannel;
class RTCPeerConnection;

class WEB_API WebRTCAgent {
    AK_MAKE_NONCOPYABLE(WebRTCAgent);
    AK_MAKE_NONMOVABLE(WebRTCAgent);

public:
    static WebRTCAgent& the();

    void initialize(NonnullOwnPtr<IPC::Transport>);
    bool is_ready();
    WebRTCClient::Client* client();

    u64 next_pc_id() { return ++m_next_pc_id; }
    u64 next_request_id() { return ++m_next_request_id; }
    u64 next_sender_id() { return ++m_next_sender_id; }
    u64 next_channel_id() { return ++m_next_channel_id; }
    // Allocate a 32-bit SSRC for an outgoing sender. Starts well above the small
    // values rust-side webrtc tends to mint so we don't accidentally collide.
    u32 next_ssrc() { return ++m_next_ssrc; }

    void register_peer_connection(u64 pc_id, GC::Ref<RTCPeerConnection>);
    void unregister_peer_connection(u64 pc_id);

    void register_data_channel(u64 channel_id, GC::Ref<RTCDataChannel>);
    void unregister_data_channel(u64 channel_id);

private:
    WebRTCAgent() = default;

    void wire_event_handlers();

    RefPtr<WebRTCClient::Client> m_client;

    HashMap<u64, GC::Root<RTCPeerConnection>> m_peer_connections;
    HashMap<u64, GC::Root<RTCDataChannel>> m_data_channels;

    u64 m_next_pc_id { 0 };
    u64 m_next_request_id { 0 };
    u64 m_next_sender_id { 0 };
    u64 m_next_channel_id { 0 };
    u32 m_next_ssrc { 0xa0000000 };
};

}
