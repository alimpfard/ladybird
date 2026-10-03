/*
 * Copyright (c) 2026, Ali Mohammad Pur <mpfard@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/ByteReader.h>
#include <AK/Debug.h>
#include <AK/Endian.h>
#include <AK/NumericLimits.h>
#include <AK/Utf8View.h>
#include <LibCore/EventLoop.h>
#include <WebDriver/WebSocketConnection.h>

namespace WebDriver {

// The longest message we accept, in one frame or across the fragments of one message.
static constexpr size_t MAXIMUM_MESSAGE_SIZE = 128 * MiB;

WebSocketConnection::WebSocketConnection(NonnullOwnPtr<Core::BufferedTCPSocket> socket)
    : m_socket(move(socket))
{
    m_socket->on_ready_to_read = [this] {
        read_available_data();
    };
}

WebSocketConnection::~WebSocketConnection()
{
    m_socket->on_ready_to_read = nullptr;
    m_socket->close();
}

void WebSocketConnection::read_available_data()
{
    if (m_state == State::Closed)
        return;

    auto buffer_or_error = ByteBuffer::create_uninitialized(m_socket->buffer_size());
    if (buffer_or_error.is_error()) {
        connection_closed();
        return;
    }
    auto buffer = buffer_or_error.release_value();

    for (;;) {
        auto can_read = m_socket->can_read_without_blocking();
        if (can_read.is_error() || !can_read.value())
            break;

        auto data = m_socket->read_some(buffer);
        if (data.is_error()) {
            connection_closed();
            return;
        }

        if (m_unparsed_bytes.try_append(data.value()).is_error()) {
            fail_the_connection(CloseStatusCode::MessageTooBig, "Out of memory"sv);
            return;
        }

        if (m_socket->is_eof()) {
            // https://datatracker.ietf.org/doc/html/rfc6455#section-7.1.4
            // The WebSocket connection is closed when the underlying TCP connection is closed.
            connection_closed();
            return;
        }
    }

    if (auto result = process_buffered_frames(); result.is_error())
        fail_the_connection(CloseStatusCode::ProtocolError, result.error().string_literal());
}

// https://datatracker.ietf.org/doc/html/rfc6455#section-5.2
ErrorOr<void> WebSocketConnection::process_buffered_frames()
{
    for (;;) {
        if (m_state != State::Open)
            return {};

        auto bytes = m_unparsed_bytes.bytes();
        if (bytes.size() < 2)
            return {};

        // FIN: 1 bit. Indicates that this is the final fragment in a message.
        bool is_final = (bytes[0] & 0x80) != 0;

        // RSV1, RSV2, RSV3: 1 bit each. MUST be 0 unless an extension is negotiated that defines meanings for
        // non-zero values. If a nonzero value is received and none of the negotiated extensions defines the meaning
        // of such a nonzero value, the receiving endpoint MUST _Fail the WebSocket Connection_.
        if ((bytes[0] & 0x70) != 0)
            return Error::from_string_literal("Received frame with reserved bits set");

        // Opcode: 4 bits. Defines the interpretation of the "Payload data".
        auto opcode = static_cast<OpCode>(bytes[0] & 0x0F);
        switch (opcode) {
        case OpCode::Continuation:
        case OpCode::Text:
        case OpCode::Binary:
        case OpCode::ConnectionClose:
        case OpCode::Ping:
        case OpCode::Pong:
            break;
        default:
            // If an unknown opcode is received, the receiving endpoint MUST _Fail the WebSocket Connection_.
            return Error::from_string_literal("Received frame with unknown opcode");
        }

        // Mask: 1 bit. Defines whether the "Payload data" is masked. All frames sent from client to server have this
        // bit set to 1.
        bool is_masked = (bytes[1] & 0x80) != 0;
        if (!is_masked)
            return Error::from_string_literal("Received unmasked frame from client");

        // Payload length: 7 bits, 7+16 bits, or 7+64 bits.
        u64 payload_length = bytes[1] & 0x7F;
        size_t header_length = 2;

        if (payload_length == 126) {
            if (bytes.size() < 4)
                return {};
            payload_length = AK::convert_between_host_and_network_endian(ByteReader::load16(bytes.offset(2)));
            header_length = 4;
        } else if (payload_length == 127) {
            if (bytes.size() < 10)
                return {};
            payload_length = AK::convert_between_host_and_network_endian(ByteReader::load64(bytes.offset(2)));
            // The most significant bit MUST be 0.
            if (payload_length & (1ull << 63))
                return Error::from_string_literal("Received frame with invalid payload length");
            header_length = 10;
        }

        if (payload_length > MAXIMUM_MESSAGE_SIZE) {
            fail_the_connection(CloseStatusCode::MessageTooBig, "Frame too large"sv);
            return {};
        }

        // Masking-key: 0 or 4 bytes.
        if (bytes.size() < header_length + 4)
            return {};
        auto masking_key = bytes.slice(header_length, 4);
        header_length += 4;

        auto frame_length = header_length + payload_length;
        if (bytes.size() < frame_length)
            return {};

        // https://datatracker.ietf.org/doc/html/rfc6455#section-5.3
        // Octet i of the transformed data ("transformed-octet-i") is the XOR of octet i of the original data
        // ("original-octet-i") with octet at index i modulo 4 of the masking key ("masking-key-octet-j").
        auto payload = TRY(ByteBuffer::copy(bytes.slice(header_length, payload_length)));
        for (size_t i = 0; i < payload.size(); ++i)
            payload[i] ^= masking_key[i % 4];

        // The frame is consumed before it is handled, so that a handler closing the connection leaves nothing behind.
        auto remaining = TRY(ByteBuffer::copy(bytes.slice(frame_length)));
        m_unparsed_bytes = move(remaining);

        TRY(handle_frame(opcode, is_final, payload));
    }
}

ErrorOr<void> WebSocketConnection::handle_frame(OpCode opcode, bool is_final, ReadonlyBytes payload)
{
    // https://datatracker.ietf.org/doc/html/rfc6455#section-5.5
    // Control frames are identified by opcodes where the most significant bit of the opcode is 1. All control frames
    // MUST have a payload length of 125 bytes or less and MUST NOT be fragmented.
    if (to_underlying(opcode) & 0x8) {
        if (payload.size() > 125 || !is_final)
            return Error::from_string_literal("Received invalid control frame");

        switch (opcode) {
        case OpCode::ConnectionClose: {
            // https://datatracker.ietf.org/doc/html/rfc6455#section-5.5.1
            // If an endpoint receives a Close frame and did not previously send a Close frame, the endpoint MUST send
            // a Close frame in response. It SHOULD do so as soon as practical.
            if (payload.size() == 1)
                return Error::from_string_literal("Received close frame with a one byte payload");
            if (payload.size() >= 2 && !Utf8View { StringView { payload.slice(2) } }.validate())
                return Error::from_string_literal("Received close frame with an invalid reason");

            dbgln_if(WEBDRIVER_DEBUG, "WebSocket: Client started the closing handshake");
            if (m_state == State::Open) {
                m_state = State::Closing;
                (void)send_frame(OpCode::ConnectionClose, payload);
            }
            connection_closed();
            return {};
        }
        case OpCode::Ping:
            // https://datatracker.ietf.org/doc/html/rfc6455#section-5.5.2
            // Upon receipt of a Ping frame, an endpoint MUST send a Pong frame in response, unless it already received
            // a Close frame. It SHOULD respond with Pong frame as soon as is practical.
            return send_frame(OpCode::Pong, payload);
        case OpCode::Pong:
            // https://datatracker.ietf.org/doc/html/rfc6455#section-5.5.3
            // A response to an unsolicited Pong frame is not expected.
            return {};
        default:
            VERIFY_NOT_REACHED();
        }
    }

    // https://datatracker.ietf.org/doc/html/rfc6455#section-5.4
    if (opcode == OpCode::Continuation) {
        if (!m_fragmented_message_opcode.has_value())
            return Error::from_string_literal("Received continuation frame outside of a fragmented message");
    } else {
        if (m_fragmented_message_opcode.has_value())
            return Error::from_string_literal("Received new data frame inside of a fragmented message");
        m_fragmented_message_opcode = opcode;
    }

    if (m_fragmented_message_payload.size() + payload.size() > MAXIMUM_MESSAGE_SIZE) {
        fail_the_connection(CloseStatusCode::MessageTooBig, "Message too large"sv);
        return {};
    }
    TRY(m_fragmented_message_payload.try_append(payload));

    if (!is_final)
        return {};

    auto message_opcode = m_fragmented_message_opcode.release_value();
    auto message = move(m_fragmented_message_payload);
    m_fragmented_message_payload = {};

    if (message_opcode == OpCode::Text) {
        // https://datatracker.ietf.org/doc/html/rfc6455#section-8.1
        // When an endpoint is to interpret a byte stream as UTF-8 but finds that the byte stream is not, in fact, a
        // valid UTF-8 stream, that endpoint MUST _Fail the WebSocket Connection_.
        if (!Utf8View { StringView { message } }.validate()) {
            fail_the_connection(CloseStatusCode::InvalidPayload, "Received text message with invalid UTF-8"sv);
            return {};
        }
        if (on_text_message)
            on_text_message(ByteString { StringView { message } });
        return {};
    }

    if (on_binary_message)
        on_binary_message(move(message));
    return {};
}

// https://datatracker.ietf.org/doc/html/rfc6455#section-5.2
ErrorOr<void> WebSocketConnection::send_frame(OpCode opcode, ReadonlyBytes payload)
{
    if (m_state == State::Closed)
        return Error::from_string_literal("WebSocket connection is closed");

    ByteBuffer frame;
    // Every frame we send is a complete message, so FIN is always set.
    TRY(frame.try_append(static_cast<u8>(0x80 | to_underlying(opcode))));

    // https://datatracker.ietf.org/doc/html/rfc6455#section-5.1
    // A server MUST NOT mask any frames that it sends to the client.
    if (payload.size() <= 125) {
        TRY(frame.try_append(static_cast<u8>(payload.size())));
    } else if (payload.size() <= NumericLimits<u16>::max()) {
        TRY(frame.try_append(static_cast<u8>(126)));
        auto length = AK::convert_between_host_and_network_endian(static_cast<u16>(payload.size()));
        TRY(frame.try_append({ &length, sizeof(length) }));
    } else {
        TRY(frame.try_append(static_cast<u8>(127)));
        auto length = AK::convert_between_host_and_network_endian(static_cast<u64>(payload.size()));
        TRY(frame.try_append({ &length, sizeof(length) }));
    }

    TRY(frame.try_append(payload));
    return m_socket->write_until_depleted(frame);
}

ErrorOr<void> WebSocketConnection::send_text(StringView message)
{
    if (m_state != State::Open)
        return Error::from_string_literal("WebSocket connection is not open");
    return send_frame(OpCode::Text, message.bytes());
}

// https://datatracker.ietf.org/doc/html/rfc6455#section-7.1.2
void WebSocketConnection::close(CloseStatusCode status_code, StringView reason)
{
    if (m_state != State::Open)
        return;
    m_state = State::Closing;

    // https://datatracker.ietf.org/doc/html/rfc6455#section-5.5.1
    // If there is a body, the first two bytes of the body MUST be a 2-byte unsigned integer (in network byte order)
    // representing a status code with value /code/ defined in Section 7.4. Following the 2-byte integer, the body MAY
    // contain UTF-8-encoded data with value /reason/.
    ByteBuffer payload;
    auto code = AK::convert_between_host_and_network_endian(to_underlying(status_code));
    payload.append({ &code, sizeof(code) });
    payload.append(reason.bytes().trim(123));
    (void)send_frame(OpCode::ConnectionClose, payload);

    // https://datatracker.ietf.org/doc/html/rfc6455#section-7.1.1
    // In abnormal cases (such as not having received a TCP Close from the server after a reasonable amount of time) a
    // client MAY initiate the TCP Close. As such, when a server is instructed to _Close the WebSocket Connection_ it
    // SHOULD initiate a TCP Close immediately.
    connection_closed();
}

// https://datatracker.ietf.org/doc/html/rfc6455#section-7.1.7
void WebSocketConnection::fail_the_connection(CloseStatusCode status_code, StringView reason)
{
    dbgln_if(WEBDRIVER_DEBUG, "WebSocket: Failing the connection: {}", reason);
    close(status_code, reason);
}

void WebSocketConnection::connection_closed()
{
    if (m_state == State::Closed)
        return;
    m_state = State::Closed;

    m_socket->on_ready_to_read = nullptr;
    m_socket->close();

    // The owner is likely to destroy this connection in response, which cannot happen from within the socket's
    // notification we may be running in.
    // The owner may destroy this connection from the callback, so the callback is run detached from it.
    Core::deferred_invoke([weak_this = make_weak_ptr()] {
        auto* self = weak_this.ptr();
        if (!self || !self->on_close)
            return;
        auto on_close = move(self->on_close);
        on_close();
    });
}

}
