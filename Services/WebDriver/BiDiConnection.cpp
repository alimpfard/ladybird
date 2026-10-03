/*
 * Copyright (c) 2026, Ali Mohammad Pur <mpfard@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Debug.h>
#include <AK/HashTable.h>
#include <AK/JsonObject.h>
#include <AK/NeverDestroyed.h>
#include <LibCore/EventLoop.h>
#include <WebDriver/BiDi/Commands.h>
#include <WebDriver/BiDiConnection.h>
#include <WebDriver/Session.h>

namespace WebDriver {

// Every live connection, whether or not a session is associated with it. A connection removes itself once its
// WebSocket is closed.
static HashTable<NonnullRefPtr<BiDiConnection>>& all_connections()
{
    static NeverDestroyed<HashTable<NonnullRefPtr<BiDiConnection>>> connections;
    return *connections;
}

// https://w3c.github.io/webdriver-bidi/#get-a-session-id-for-a-websocket-resource
static Optional<StringView> get_a_session_id_for_a_websocket_resource(StringView resource_name)
{
    // 1. If resource name doesn't begin with the byte string "/session/", return null.
    if (!resource_name.starts_with("/session/"sv))
        return {};

    // 2. Let session id be the bytes in resource name following the "/session/" prefix.
    auto session_id = resource_name.substring_view("/session/"sv.length());

    // 3. If session id is not the string representation of a UUID, return null.
    // NB: Session IDs are UUIDs, so any ID naming an active session is one; the lookup below covers this.
    if (session_id.is_empty() || session_id.contains('/'))
        return {};

    // 4. Return session id.
    return session_id;
}

// https://w3c.github.io/webdriver-bidi/#transport
bool is_websocket_resource_available(StringView resource_name)
{
    // 2. If resource name is the byte string "/session", and the implementation supports BiDi-only sessions:
    if (resource_name == "/session"sv)
        return true;

    // 3. Get a session ID for a WebSocket resource with resource name and let session id be that value. If session
    //    id is null then stop running these steps and act as if the requested service is not available.
    auto session_id = get_a_session_id_for_a_websocket_resource(resource_name);
    if (!session_id.has_value())
        return false;

    // 4. If there is a session in the list of active sessions with session id as its session ID then let session be
    //    that session. Otherwise stop running these steps and act as if the requested service is not available.
    return !Session::find_session(*session_id, Web::WebDriver::SessionFlags::Default, Session::AllowInvalidWindowHandle::Yes).is_error();
}

void BiDiConnection::accept(StringView resource_name, NonnullOwnPtr<Core::BufferedTCPSocket> socket)
{
    RefPtr<Session> session;

    if (resource_name != "/session"sv) {
        auto session_id = get_a_session_id_for_a_websocket_resource(resource_name);
        VERIFY(session_id.has_value());

        auto found_session = Session::find_session(*session_id, Web::WebDriver::SessionFlags::Default, Session::AllowInvalidWindowHandle::Yes);
        VERIFY(!found_session.is_error());
        session = found_session.release_value();
    }

    auto connection = adopt_ref(*new BiDiConnection(move(socket), nullptr));
    all_connections().set(connection);

    // 2.2. Add the connection to WebSocket connections not associated with a session.
    // 6. Otherwise append connection to session's session WebSocket connections, and proceed with the WebSocket
    //    server-side requirements when a server chooses to accept an incoming connection.
    if (session)
        connection->associate_with_session(*session);
}

BiDiConnection::BiDiConnection(NonnullOwnPtr<Core::BufferedTCPSocket> socket, RefPtr<Session> session)
    : m_websocket(make<WebSocketConnection>(move(socket)))
    , m_session(move(session))
{
    dbgln_if(WEBDRIVER_DEBUG, "BiDi: WebSocket connection established");

    // When a WebSocket message has been received for a WebSocket connection connection with type type and data data,
    // a remote end must handle an incoming message given connection, type and data.
    m_websocket->on_text_message = [this](ByteString data) {
        handle_an_incoming_message(data);
    };
    m_websocket->on_binary_message = [this](ByteBuffer) {
        // https://w3c.github.io/webdriver-bidi/#handle-an-incoming-message
        // 1. If type is not text, send an error response given connection, null, and invalid argument, and finally
        //    return.
        send_error_response(JsonValue {}, Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, "Binary messages are not supported"sv));
    };

    // When the WebSocket closing handshake is started or when the WebSocket connection is closed for a WebSocket
    // connection connection, a remote end must handle a connection closing given connection.
    m_websocket->on_close = [this] {
        handle_a_connection_closing();
    };
}

BiDiConnection::~BiDiConnection() = default;

void BiDiConnection::associate_with_session(Session& session)
{
    VERIFY(!m_session);
    m_session = session;
    session.add_websocket_connection({}, *this);
}

// https://w3c.github.io/webdriver-bidi/#handle-an-incoming-message
void BiDiConnection::handle_an_incoming_message(ByteString const& data)
{
    dbgln_if(WEBDRIVER_DEBUG, "BiDi: <- {}", data);

    // 3. If there is a BiDi Session associated with connection connection, let session be that session. Otherwise if
    //    connection is in WebSocket connections not associated with a session, let session be null. Otherwise, return.
    auto session = m_session;

    // 4. Let parsed be the result of parsing JSON into Infra values given data. If this throws an exception, then send
    //    an error response given connection, null, and invalid argument, and finally return.
    auto parsed = JsonValue::from_string(data);
    if (parsed.is_error()) {
        send_error_response(JsonValue {}, Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, "Message is not valid JSON"sv));
        return;
    }

    // 5. If session is not null and not in active sessions then return.
    if (session && !Session::is_active(*session))
        return;

    // 6. Match parsed against the remote end definition. If this results in a match:
    auto matched = BiDi::match_command(parsed.value());
    if (matched.has_value()) {
        // 3. Let command id be matched["id"].
        auto command_id = matched->command_id;

        // 5. Let command be the command with command name method.
        auto const& command = matched->command;

        // 6. If session is null and command is not a static command, then send an error response given connection,
        //    command id, and invalid session id, and return.
        if (!session && !command.is_static) {
            send_error_response(command_id, Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidSessionId, "This connection is not associated with a session"sv));
            return;
        }

        // 7. Run the following steps in parallel:
        //    1. Let result be the result of running the remote end steps for command given session and command
        //       parameters matched["params"]
        auto result = command.handler(*this, session, matched->parameters);

        auto this_ref = NonnullRefPtr { *this };
        result->when_resolved([this_ref, command_id, method = matched->command.name](JsonValue& value) {
                  // 4. If method is "session.new", let session be the entry in the list of active sessions whose
                  //    session ID is equal to the "sessionId" property of value, append connection to session's session
                  //    WebSocket connections, and remove connection from the WebSocket connections not associated with
                  //    a session.
                  if (method == "session.new"sv && !this_ref->m_session) {
                      auto session_id = value.as_object().get_string("sessionId"sv).value();
                      if (auto session = Session::find_session(session_id, Web::WebDriver::SessionFlags::Default, Session::AllowInvalidWindowHandle::Yes); !session.is_error())
                          this_ref->associate_with_session(session.value());
                  }

                  // 5. Let response be a new map matching the CommandResponse production in the local end definition
                  //    with the id field set to command id and the value field set to value.
                  // 6. Let serialized be the result of serialize an infra value to JSON bytes given response.
                  // 7. Send a WebSocket message comprised of serialized over connection.
                  this_ref->send_command_response(command_id, move(value));

                  // https://w3c.github.io/webdriver-bidi/#command-session-end
                  // 2. Return success with data null, and in parallel run the following steps:
                  //    1. Wait until the Send a WebSocket message steps have been called with the response to this
                  //       command.
                  //    2. Cleanup the session with session.
                  if (method == "session.end"sv && this_ref->m_session)
                      this_ref->m_session->close();
              })
            .when_rejected([this_ref, command_id](Web::WebDriver::Error& error) {
                // 2. If result is an error, then send an error response given connection, command id, and result's
                //    error code, and finally return.
                this_ref->send_error_response(command_id, error);
            });
        return;
    }

    // 7. Otherwise:
    //    1. Let command id be null.
    JsonValue command_id;

    //    2. If parsed is a map and parsed["id"] exists and is an integer greater than or equal to zero, set command id
    //       to that integer.
    if (parsed.value().is_object()) {
        if (auto id = parsed.value().as_object().get_integer<u64>("id"sv); id.has_value())
            command_id = *id;
    }

    //    3. Let error code be invalid argument.
    auto error_code = Web::WebDriver::ErrorCode::InvalidArgument;
    auto message = "Message does not match the remote end definition"sv;

    //    4. If parsed is a map and parsed["method"] exists and is a string, but parsed["method"] is not in the set of
    //       all command names, set error code to unknown command.
    if (parsed.value().is_object()) {
        if (auto method = parsed.value().as_object().get_string("method"sv); method.has_value() && !BiDi::is_command_name(*method)) {
            error_code = Web::WebDriver::ErrorCode::UnknownCommand;
            message = "Unknown command"sv;
        }
    }

    //    5. Send an error response given connection, command id, and error code.
    send_error_response(command_id, Web::WebDriver::Error::from_code(error_code, message));
}

// https://w3c.github.io/webdriver-bidi/#handle-a-connection-closing
void BiDiConnection::handle_a_connection_closing()
{
    dbgln_if(WEBDRIVER_DEBUG, "BiDi: WebSocket connection closed");

    // Keep this connection alive while it is removed from every table holding it.
    auto protector = NonnullRefPtr { *this };

    // 1. If there is a BiDi session associated with connection connection:
    if (m_session) {
        // 1. Let session be the BiDi session associated with connection connection.
        // 2. Remove connection from session's session WebSocket connections.
        m_session->remove_websocket_connection({}, *this);
        m_session = nullptr;
    }

    // 2. Otherwise, if WebSocket connections not associated with a session contains connection, remove connection
    //    from that set.
    all_connections().remove(*this);
}

void BiDiConnection::send_message(JsonValue const& message)
{
    auto serialized = message.serialized();
    dbgln_if(WEBDRIVER_DEBUG, "BiDi: -> {}", serialized);

    if (auto result = m_websocket->send_text(serialized); result.is_error())
        dbgln("Unable to send WebDriver BiDi message: {}", result.error());
}

void BiDiConnection::send_command_response(JsonValue const& command_id, JsonValue result)
{
    JsonObject response;
    response.set("type"sv, "success"sv);
    response.set("id"sv, command_id);
    response.set("result"sv, move(result));
    send_message(response);
}

// https://w3c.github.io/webdriver-bidi/#send-an-error-response
void BiDiConnection::send_error_response(JsonValue const& command_id, Web::WebDriver::Error const& error)
{
    // 1. Let error data be a new map matching the ErrorResponse production in the local end definition, with the id
    //    field set to command id, the error field set to error code, the message field set to an implementation-defined
    //    string containing a human-readable definition of the error that occurred and the stacktrace field optionally
    //    set to an implementation-defined string containing a stack trace report of the active stack frames at the
    //    time when the error occurred.
    JsonObject error_data;
    error_data.set("type"sv, "error"sv);
    // Note: command id can be null, in which case the id field will also be set to null, not omitted from response.
    error_data.set("id"sv, command_id);
    error_data.set("error"sv, error.error);
    error_data.set("message"sv, error.message);

    // 2. Let response be the result of serialize an infra value to JSON bytes given error data.
    // 3. Send a WebSocket message comprised of response over connection.
    send_message(error_data);
}

// https://w3c.github.io/webdriver-bidi/#emit-an-event
void BiDiConnection::send_event(JsonValue const& body)
{
    // 2. Let serialized be the result of serialize an infra value to JSON bytes given body.
    // 3. For each connection in session's session WebSocket connections:
    //    1. Send a WebSocket message comprised of serialized over connection.
    send_message(body);
}

void BiDiConnection::close()
{
    // 1. Start the WebSocket closing handshake with connection.
    m_websocket->close(WebSocketConnection::CloseStatusCode::Normal);
}

}
