/*
 * Copyright (c) 2026, Ali Mohammad Pur <mpfard@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/JsonValue.h>
#include <AK/NonnullOwnPtr.h>
#include <AK/RefCounted.h>
#include <AK/RefPtr.h>
#include <LibCore/Socket.h>
#include <LibWebCommon/WebDriver/Error.h>
#include <WebDriver/Forward.h>
#include <WebDriver/WebSocketConnection.h>

namespace WebDriver {

// https://w3c.github.io/webdriver-bidi/#transport
// Whether a WebSocket opening handshake for the given resource name is to be accepted.
bool is_websocket_resource_available(StringView resource_name);

// A WebSocket connection, either one of a BiDi session's "session WebSocket connections" or one of the remote end's
// "WebSocket connections not associated with a session" until a session.new command associates it.
class BiDiConnection final : public RefCounted<BiDiConnection> {
public:
    // Runs the steps of the transport section for an accepted connection with the given resource name.
    static void accept(StringView resource_name, NonnullOwnPtr<Core::BufferedTCPSocket>);
    ~BiDiConnection();

    Session* session() { return m_session; }
    void associate_with_session(Session&);

    // https://w3c.github.io/webdriver-bidi/#emit-an-event
    void send_event(JsonValue const& body);

    // https://w3c.github.io/webdriver-bidi/#close-the-websocket-connections
    void close();

private:
    BiDiConnection(NonnullOwnPtr<Core::BufferedTCPSocket>, RefPtr<Session>);

    void handle_an_incoming_message(ByteString const& data);
    void handle_a_connection_closing();

    void send_message(JsonValue const& message);
    void send_command_response(JsonValue const& command_id, JsonValue result);
    void send_error_response(JsonValue const& command_id, Web::WebDriver::Error const&);

    NonnullOwnPtr<WebSocketConnection> m_websocket;
    RefPtr<Session> m_session;
};

}
