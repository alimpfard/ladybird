/*
 * Copyright (c) 2026, Ali Mohammad Pur <mpfard@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/ByteBuffer.h>
#include <AK/ByteString.h>
#include <AK/Function.h>
#include <AK/NonnullOwnPtr.h>
#include <AK/Optional.h>
#include <AK/WeakPtr.h>
#include <AK/Weakable.h>
#include <LibCore/Socket.h>

namespace WebDriver {

// The server side of a WebSocket connection whose opening handshake has already been completed over HTTP.
// https://datatracker.ietf.org/doc/html/rfc6455
class WebSocketConnection : public Weakable<WebSocketConnection> {
    AK_ALLOC_WITH_KMALLOC;
    AK_MAKE_NONCOPYABLE(WebSocketConnection);
    AK_MAKE_NONMOVABLE(WebSocketConnection);

public:
    explicit WebSocketConnection(NonnullOwnPtr<Core::BufferedTCPSocket>);
    ~WebSocketConnection();

    // https://datatracker.ietf.org/doc/html/rfc6455#section-7.4.1
    enum class CloseStatusCode : u16 {
        Normal = 1000,
        GoingAway = 1001,
        ProtocolError = 1002,
        UnsupportedData = 1003,
        InvalidPayload = 1007,
        MessageTooBig = 1009,
    };

    // Each callback is given the data of one complete (possibly fragmented) message.
    Function<void(ByteString)> on_text_message;
    Function<void(ByteBuffer)> on_binary_message;
    // Invoked once, when the closing handshake has been started by either side or the connection is lost.
    Function<void()> on_close;

    bool is_open() const { return m_state == State::Open; }

    ErrorOr<void> send_text(StringView);
    void close(CloseStatusCode = CloseStatusCode::Normal, StringView reason = {});

private:
    // https://datatracker.ietf.org/doc/html/rfc6455#section-5.2
    enum class OpCode : u8 {
        Continuation = 0x0,
        Text = 0x1,
        Binary = 0x2,
        ConnectionClose = 0x8,
        Ping = 0x9,
        Pong = 0xA,
    };

    enum class State {
        Open,
        Closing,
        Closed,
    };

    void read_available_data();
    ErrorOr<void> process_buffered_frames();
    ErrorOr<void> handle_frame(OpCode, bool is_final, ReadonlyBytes payload);
    ErrorOr<void> send_frame(OpCode, ReadonlyBytes payload);
    void fail_the_connection(CloseStatusCode, StringView reason);
    void connection_closed();

    NonnullOwnPtr<Core::BufferedTCPSocket> m_socket;
    State m_state { State::Open };

    ByteBuffer m_unparsed_bytes;

    // https://datatracker.ietf.org/doc/html/rfc6455#section-5.4
    Optional<OpCode> m_fragmented_message_opcode;
    ByteBuffer m_fragmented_message_payload;
};

}
