/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Format.h>
#include <LibIPC/Transport.h>
#include <LibJS/Runtime/ArrayBuffer.h>
#include <LibJS/Runtime/PrimitiveString.h>
#include <LibWeb/DOM/Event.h>
#include <LibWeb/HTML/EventNames.h>
#include <LibWeb/HTML/MessageEvent.h>
#include <LibWeb/HTML/Scripting/TemporaryExecutionContext.h>
#include <LibWeb/WebRTC/RTCDataChannel.h>
#include <LibWeb/WebRTC/RTCPeerConnection.h>
#include <LibWeb/WebRTC/WebRTCAgent.h>

namespace Web::WebRTC {

WebRTCAgent& WebRTCAgent::the()
{
    static auto* s_agent = new WebRTCAgent;
    return *s_agent;
}

bool WebRTCAgent::is_ready()
{
    return m_client;
}

WebRTCClient::Client* WebRTCAgent::client()
{
    return m_client.ptr();
}

void WebRTCAgent::register_peer_connection(u64 pc_id, GC::Ref<RTCPeerConnection> pc)
{
    m_peer_connections.set(pc_id, pc);
}

void WebRTCAgent::unregister_peer_connection(u64 pc_id)
{
    m_peer_connections.remove(pc_id);
}

void WebRTCAgent::register_data_channel(u64 channel_id, GC::Ref<RTCDataChannel> channel)
{
    m_data_channels.set(channel_id, channel);
}

void WebRTCAgent::unregister_data_channel(u64 channel_id)
{
    m_data_channels.remove(channel_id);
}

void WebRTCAgent::initialize(NonnullOwnPtr<IPC::Transport> transport)
{
    m_client = adopt_ref(*new WebRTCClient::Client(move(transport)));
    wire_event_handlers();
}

#define ROUTE_PC_EVENT(slot, method)                                 \
    m_client->slot = [this](u64 pc_id, auto&&... args) {             \
        if (auto pc = m_peer_connections.get(pc_id); pc.has_value()) \
            (*pc)->method(forward<decltype(args)>(args)...);         \
    };

void WebRTCAgent::wire_event_handlers()
{
    ROUTE_PC_EVENT(on_signaling_state_change, on_signaling_state_event);
    ROUTE_PC_EVENT(on_connection_state_change, on_connection_state_event);
    ROUTE_PC_EVENT(on_ice_gathering_state_change, on_ice_gathering_state_event);
    ROUTE_PC_EVENT(on_ice_connection_state_change, on_ice_connection_state_event);
    ROUTE_PC_EVENT(on_ice_candidate_event, on_ice_candidate_received);
    ROUTE_PC_EVENT(on_ice_candidate_error_event, on_ice_candidate_error_received);
    ROUTE_PC_EVENT(on_negotiation_needed_event, on_negotiation_needed_received);
    ROUTE_PC_EVENT(on_track_event, on_remote_track_added);
    ROUTE_PC_EVENT(on_track_ended_event, on_remote_track_ended);
    ROUTE_PC_EVENT(on_encoded_audio_frame_event, on_encoded_audio_frame_received);
    ROUTE_PC_EVENT(on_audio_track_added_event, on_audio_track_ssrc_assigned);
    ROUTE_PC_EVENT(on_create_offer_completion, on_create_offer_result_received);
    ROUTE_PC_EVENT(on_create_answer_completion, on_create_answer_result_received);
    ROUTE_PC_EVENT(on_set_local_description_completion, on_set_local_description_result_received);
    ROUTE_PC_EVENT(on_set_remote_description_completion, on_set_remote_description_result_received);
    ROUTE_PC_EVENT(on_add_ice_candidate_completion, on_add_ice_candidate_result_received);
    ROUTE_PC_EVENT(on_data_channel_event, on_remote_data_channel_received);

    m_client->on_data_channel_open_event = [this](u64 channel_id) {
        if (auto channel = m_data_channels.get(channel_id); channel.has_value()) {
            HTML::TemporaryExecutionContext context((*channel)->realm());
            (*channel)->set_ready_state(Bindings::RTCDataChannelState::Open);
            (*channel)->dispatch_event(DOM::Event::create((*channel)->realm().global_object(), HTML::EventNames::open));
        }
    };
    m_client->on_data_channel_closing_event = [this](u64 channel_id) {
        if (auto channel = m_data_channels.get(channel_id); channel.has_value()) {
            HTML::TemporaryExecutionContext context((*channel)->realm());
            (*channel)->set_ready_state(Bindings::RTCDataChannelState::Closing);
            (*channel)->dispatch_event(DOM::Event::create((*channel)->realm().global_object(), HTML::EventNames::closing));
        }
    };
    m_client->on_data_channel_closed_event = [this](u64 channel_id) {
        if (auto channel = m_data_channels.get(channel_id); channel.has_value()) {
            HTML::TemporaryExecutionContext context((*channel)->realm());
            (*channel)->set_ready_state(Bindings::RTCDataChannelState::Closed);
            (*channel)->dispatch_event(DOM::Event::create((*channel)->realm().global_object(), HTML::EventNames::close));
        }
        m_data_channels.remove(channel_id);
    };
    m_client->on_data_channel_error_event = [this](u64 channel_id, String) {
        if (auto channel = m_data_channels.get(channel_id); channel.has_value()) {
            HTML::TemporaryExecutionContext context((*channel)->realm());
            // FIXME: dispatch RTCErrorEvent("error") with the error detail; bare Event for now.
            (*channel)->dispatch_event(DOM::Event::create((*channel)->realm().global_object(), HTML::EventNames::error));
        }
    };
    m_client->on_data_channel_buffered_amount_low_event = [this](u64 channel_id) {
        if (auto channel = m_data_channels.get(channel_id); channel.has_value()) {
            HTML::TemporaryExecutionContext context((*channel)->realm());
            (*channel)->dispatch_event(DOM::Event::create((*channel)->realm().global_object(), HTML::EventNames::bufferedamountlow));
        }
    };
    m_client->on_data_channel_message_text_event = [this](u64 channel_id, String text) {
        if (auto channel = m_data_channels.get(channel_id); channel.has_value()) {
            HTML::TemporaryExecutionContext context((*channel)->realm());
            HTML::MessageEventInit init;
            init.data = JS::PrimitiveString::create((*channel)->vm(), Utf16String::from_utf8(text));
            (*channel)->dispatch_event(HTML::MessageEvent::create((*channel)->realm().global_object(), HTML::EventNames::message, init));
        }
    };
    m_client->on_data_channel_message_binary_event = [this](u64 channel_id, ByteBuffer bytes) {
        if (auto channel = m_data_channels.get(channel_id); channel.has_value()) {
            HTML::TemporaryExecutionContext context((*channel)->realm());
            HTML::MessageEventInit init;
            init.data = JS::ArrayBuffer::create((*channel)->realm(), move(bytes));
            (*channel)->dispatch_event(HTML::MessageEvent::create((*channel)->realm().global_object(), HTML::EventNames::message, init));
        }
    };
}

#undef ROUTE_PC_EVENT

}
