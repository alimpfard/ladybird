/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Format.h>
#include <AK/LexicalPath.h>
#include <LibCore/Environment.h>
#include <LibCore/Process.h>
#include <LibCore/Socket.h>
#include <LibCore/System.h>
#include <LibFileSystem/FileSystem.h>
#include <LibIPC/Transport.h>
#include <LibWeb/DOM/Event.h>
#include <LibWeb/HTML/EventNames.h>
#include <LibWeb/HTML/Scripting/TemporaryExecutionContext.h>
#include <LibWeb/WebRTC/AudioCaptureSession.h>
#include <LibWeb/WebRTC/RTCDataChannel.h>
#include <LibWeb/WebRTC/RTCPeerConnection.h>
#include <LibWeb/WebRTC/WebRTCAgent.h>

namespace Web::WebRTC {

WebRTCAgent& WebRTCAgent::the()
{
    static auto& s_agent = *new WebRTCAgent;
    return s_agent;
}

bool WebRTCAgent::is_ready()
{
    ensure_client();
    return m_client;
}

WebRTCClient::Client* WebRTCAgent::client()
{
    ensure_client();
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

void WebRTCAgent::register_audio_capture_session(u64 sender_id, NonnullOwnPtr<AudioCaptureSession> session)
{
    m_audio_capture_sessions.set(sender_id, move(session));
}

void WebRTCAgent::unregister_audio_capture_session(u64 sender_id)
{
    m_audio_capture_sessions.remove(sender_id);
}

void WebRTCAgent::ensure_client()
{
    if (m_client || m_attempted_to_launch)
        return;
    m_attempted_to_launch = true;

    auto exe_path_result = Core::System::current_executable_path();
    if (exe_path_result.is_error()) {
        dbgln("WebRTCAgent: current_executable_path failed: {}", exe_path_result.error());
        return;
    }
    auto exe_dir = LexicalPath(exe_path_result.value()).parent();
    Vector<ByteString> candidate_paths;
    candidate_paths.append(LexicalPath::join(exe_dir.string(), "WebRTCClient"sv).string());
    candidate_paths.append(LexicalPath::join(exe_dir.parent().string(), "libexec"sv, "WebRTCClient"sv).string());
    candidate_paths.append(LexicalPath::join(exe_dir.parent().string(), "bin"sv, "WebRTCClient"sv).string());

    int socket_fds[2] {};
    if (auto rc = Core::System::socketpair(AF_LOCAL, SOCK_STREAM, 0, socket_fds); rc.is_error()) {
        dbgln("WebRTCAgent: socketpair failed: {}", rc.error());
        return;
    }

    if (auto rc = Core::System::set_close_on_exec(socket_fds[0], true); rc.is_error()) {
        (void)Core::System::close(socket_fds[0]);
        (void)Core::System::close(socket_fds[1]);
        dbgln("WebRTCAgent: set_close_on_exec failed: {}", rc.error());
        return;
    }

    auto takeover_string = MUST(String::formatted("WebRTCClient:{}", socket_fds[1]));
    if (auto rc = Core::Environment::set("SOCKET_TAKEOVER"sv, takeover_string, Core::Environment::Overwrite::Yes); rc.is_error()) {
        (void)Core::System::close(socket_fds[0]);
        (void)Core::System::close(socket_fds[1]);
        dbgln("WebRTCAgent: setenv failed: {}", rc.error());
        return;
    }

    Vector<ByteString> arguments;
    Optional<Core::Process> spawned;
    for (auto const& path : candidate_paths) {
        if (!FileSystem::exists(path))
            continue;
        Core::ProcessSpawnOptions options { .name = "WebRTCClient"sv, .executable = path, .arguments = arguments };
        auto result = Core::Process::spawn(options);
        if (!result.is_error()) {
            spawned = result.release_value();
            break;
        }
    }
    if (!spawned.has_value()) {
        (void)Core::System::close(socket_fds[0]);
        (void)Core::System::close(socket_fds[1]);
        dbgln("WebRTCAgent: failed to spawn WebRTCClient binary");
        return;
    }

    (void)Core::System::close(socket_fds[1]);

    auto ipc_socket = Core::LocalSocket::adopt_fd(socket_fds[0]);
    if (ipc_socket.is_error()) {
        dbgln("WebRTCAgent: adopt_fd failed: {}", ipc_socket.error());
        return;
    }
    if (auto rc = ipc_socket.value()->set_blocking(true); rc.is_error()) {
        dbgln("WebRTCAgent: set_blocking failed: {}", rc.error());
        return;
    }

    auto transport = make<IPC::Transport>(ipc_socket.release_value());
    m_client = adopt_ref(*new WebRTCClient::Client(move(transport)));
    wire_event_handlers();
}

#define ROUTE_PC_EVENT(slot, method)                                            \
    m_client->slot = [this](u64 pc_id, auto&&... args) {                        \
        if (auto pc = m_peer_connections.get(pc_id); pc.has_value())            \
            (*pc)->method(forward<decltype(args)>(args)...);                    \
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
            (*channel)->dispatch_event(DOM::Event::create((*channel)->realm(), HTML::EventNames::open));
        }
    };
    m_client->on_data_channel_closing_event = [this](u64 channel_id) {
        if (auto channel = m_data_channels.get(channel_id); channel.has_value()) {
            HTML::TemporaryExecutionContext context((*channel)->realm());
            (*channel)->set_ready_state(Bindings::RTCDataChannelState::Closing);
            (*channel)->dispatch_event(DOM::Event::create((*channel)->realm(), HTML::EventNames::closing));
        }
    };
    m_client->on_data_channel_closed_event = [this](u64 channel_id) {
        if (auto channel = m_data_channels.get(channel_id); channel.has_value()) {
            HTML::TemporaryExecutionContext context((*channel)->realm());
            (*channel)->set_ready_state(Bindings::RTCDataChannelState::Closed);
            (*channel)->dispatch_event(DOM::Event::create((*channel)->realm(), HTML::EventNames::close));
        }
        m_data_channels.remove(channel_id);
    };
    m_client->on_data_channel_error_event = [this](u64 channel_id, String) {
        if (auto channel = m_data_channels.get(channel_id); channel.has_value()) {
            HTML::TemporaryExecutionContext context((*channel)->realm());
            // FIXME: dispatch RTCErrorEvent("error") with the error detail; bare Event for now.
            (*channel)->dispatch_event(DOM::Event::create((*channel)->realm(), HTML::EventNames::error));
        }
    };
    m_client->on_data_channel_buffered_amount_low_event = [this](u64 channel_id) {
        if (auto channel = m_data_channels.get(channel_id); channel.has_value()) {
            HTML::TemporaryExecutionContext context((*channel)->realm());
            (*channel)->dispatch_event(DOM::Event::create((*channel)->realm(), HTML::EventNames::bufferedamountlow));
        }
    };
    m_client->on_data_channel_message_text_event = [this](u64 channel_id, String) {
        if (auto channel = m_data_channels.get(channel_id); channel.has_value()) {
            HTML::TemporaryExecutionContext context((*channel)->realm());
            // FIXME: dispatch a MessageEvent("message") carrying the string payload; bare Event for now.
            (*channel)->dispatch_event(DOM::Event::create((*channel)->realm(), HTML::EventNames::message));
        }
    };
    m_client->on_data_channel_message_binary_event = [this](u64 channel_id, ByteBuffer) {
        if (auto channel = m_data_channels.get(channel_id); channel.has_value()) {
            HTML::TemporaryExecutionContext context((*channel)->realm());
            // FIXME: dispatch a MessageEvent("message") carrying an ArrayBuffer/Blob payload; bare Event for now.
            (*channel)->dispatch_event(DOM::Event::create((*channel)->realm(), HTML::EventNames::message));
        }
    };
}

#undef ROUTE_PC_EVENT

}
