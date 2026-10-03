#!/usr/bin/env python3
#
# Copyright (c) 2026-present, the Ladybird developers.
#
# SPDX-License-Identifier: BSD-2-Clause

# Exercises the WebDriver BiDi transport of the WebDriver service: the WebSocket upgrade of an HTTP session, the
# session, browsingContext and script modules, and event subscriptions.

import argparse
import base64
import importlib
import json
import os
import socket
import struct
import subprocess
import time

webdriver_helpers = importlib.import_module("test-webdriver-delete-session")


class WebSocket:
    """A minimal RFC 6455 client, enough to talk to the WebDriver service."""

    def __init__(self, url):
        _, _, rest = url.partition("://")
        host_port, _, path = rest.partition("/")
        host, _, port = host_port.partition(":")
        self.socket = socket.create_connection((host, int(port)), timeout=webdriver_helpers.EVENT_TIMEOUT_SECONDS)
        key = base64.b64encode(os.urandom(16)).decode()
        self.socket.sendall(
            f"GET /{path} HTTP/1.1\r\nHost: {host_port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode()
        )
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = self.socket.recv(4096)
            assert chunk, "Connection closed during the WebSocket handshake"
            response += chunk
        status_line = response.split(b"\r\n", 1)[0].decode()
        assert status_line.startswith("HTTP/1.1 101"), status_line
        self.buffer = response.split(b"\r\n\r\n", 1)[1]

    def send(self, text):
        payload = text.encode()
        header = bytearray([0x81])
        if len(payload) < 126:
            header.append(0x80 | len(payload))
        elif len(payload) < 65536:
            header.append(0x80 | 126)
            header += struct.pack("!H", len(payload))
        else:
            header.append(0x80 | 127)
            header += struct.pack("!Q", len(payload))
        mask = os.urandom(4)
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.socket.sendall(bytes(header) + mask + masked)

    def _read_exactly(self, length):
        while len(self.buffer) < length:
            chunk = self.socket.recv(65536)
            assert chunk, "Connection closed while reading a WebSocket frame"
            self.buffer += chunk
        data, self.buffer = self.buffer[:length], self.buffer[length:]
        return data

    def receive(self):
        """Returns a text message, or None once the server has closed the connection."""
        while True:
            first, second = self._read_exactly(2)
            opcode = first & 0x0F
            length = second & 0x7F
            if length == 126:
                (length,) = struct.unpack("!H", self._read_exactly(2))
            elif length == 127:
                (length,) = struct.unpack("!Q", self._read_exactly(8))
            assert not (second & 0x80), "Server frames must not be masked"
            payload = self._read_exactly(length)
            if opcode == 0x1:
                return payload.decode()
            if opcode == 0x8:
                return None
            if opcode == 0x9:
                self.socket.sendall(bytes([0x8A, 0x80]) + b"\x00\x00\x00\x00")

    def close(self):
        self.socket.close()


class BiDiSession:
    def __init__(self, url):
        self.websocket = WebSocket(url)
        self.next_id = 1
        self.events = []

    def send(self, method, params):
        command_id = self.next_id
        self.next_id += 1
        self.websocket.send(json.dumps({"id": command_id, "method": method, "params": params}))
        while True:
            message = self.receive()
            assert message is not None, "Connection closed while waiting for a command response"
            if message.get("type") == "event":
                self.events.append(message)
                continue
            assert message.get("id") == command_id, message
            return message

    def receive(self):
        message = self.websocket.receive()
        return json.loads(message) if message is not None else None

    def wait_for_event(self, method):
        deadline = time.monotonic() + webdriver_helpers.EVENT_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            for event in self.events:
                if event["method"] == method:
                    self.events.remove(event)
                    return event
            message = self.receive()
            assert message is not None, f"Connection closed while waiting for {method}"
            if message.get("type") == "event":
                self.events.append(message)
        raise AssertionError(f"Timed out waiting for {method}")


def run_test(webdriver_binary):
    port = webdriver_helpers.unused_port()
    webdriver = subprocess.Popen([webdriver_binary, "--headless", "-l", "127.0.0.1", "-p", str(port)])
    try:
        webdriver_helpers.wait_for_port(port)

        # A session created over HTTP with the webSocketUrl capability is reachable over WebSocket.
        status, payload, body = webdriver_helpers.request(
            port,
            "POST",
            "/session",
            {"capabilities": {"alwaysMatch": {"ladybird:headless": True, "webSocketUrl": True}}},
        )
        assert status == 200, body
        session_id = payload["value"]["sessionId"]
        websocket_url = payload["value"]["capabilities"]["webSocketUrl"]
        assert websocket_url == f"ws://127.0.0.1:{port}/session/{session_id}", websocket_url

        status, payload, body = webdriver_helpers.request(port, "GET", f"/session/{session_id}/window")
        assert status == 200, body
        window_handle = payload["value"]

        status, _, body = webdriver_helpers.request(
            port,
            "POST",
            f"/session/{session_id}/url",
            {"url": "data:text/html,<title>BiDi</title><iframe src='about:blank'></iframe>"},
        )
        assert status == 200, body

        bidi = BiDiSession(websocket_url)

        # Malformed messages are answered with an error naming no command.
        bidi.websocket.send("not json")
        response = bidi.receive()
        assert response == {"type": "error", "id": None, "error": "invalid argument", "message": response["message"]}, response
        response = bidi.send("no.such.command", {})
        assert response["type"] == "error" and response["error"] == "unknown command", response

        # The browsing context tree names the window by its handle and includes the frame.
        response = bidi.send("browsingContext.getTree", {})
        assert response["type"] == "success", response
        contexts = response["result"]["contexts"]
        assert [context["context"] for context in contexts] == [window_handle], contexts
        assert contexts[0]["parent"] is None and len(contexts[0]["children"]) == 1, contexts
        frame = contexts[0]["children"][0]["context"]
        response = bidi.send("browsingContext.getTree", {"root": frame})
        assert response["result"]["contexts"][0]["parent"] == window_handle, response

        response = bidi.send("session.subscribe", {"events": ["log.entryAdded", "browsingContext.userPromptOpened"]})
        assert response["type"] == "success", response
        subscription = response["result"]["subscription"]

        # script.callFunction deserializes arguments, awaits promises and serializes the result.
        response = bidi.send(
            "script.callFunction",
            {
                "functionDeclaration": "(a, b) => { console.log('hello', a); return Promise.resolve({ sum: a + b, title: document.title }); }",
                "awaitPromise": True,
                "target": {"context": window_handle},
                "arguments": [{"type": "number", "value": 1}, {"type": "number", "value": 2}],
            },
        )
        assert response["type"] == "success", response
        assert response["result"]["type"] == "success", response
        assert response["result"]["result"] == {
            "type": "object",
            "value": [["sum", {"type": "number", "value": 3}], ["title", {"type": "string", "value": "BiDi"}]],
        }, response

        event = bidi.wait_for_event("log.entryAdded")
        assert event["params"]["type"] == "console" and event["params"]["method"] == "log", event
        assert event["params"]["args"][0] == {"type": "string", "value": "hello"}, event
        assert event["params"]["source"]["context"] == window_handle, event

        # script.evaluate reports exceptions as results rather than errors.
        response = bidi.send(
            "script.evaluate",
            {"expression": "throw new TypeError('boom')", "awaitPromise": False, "target": {"context": window_handle}},
        )
        assert response["result"]["type"] == "exception", response
        assert response["result"]["exceptionDetails"]["text"] == "TypeError: boom", response
        assert response["result"]["exceptionDetails"]["exception"]["type"] == "error", response

        response = bidi.send(
            "script.evaluate",
            {"expression": "window", "awaitPromise": False, "target": {"context": window_handle}},
        )
        assert response["result"]["result"] == {"type": "window", "value": {"context": window_handle}}, response

        response = bidi.send(
            "script.evaluate",
            {"expression": "window", "awaitPromise": False, "target": {"context": "no-such-context"}},
        )
        assert response["type"] == "error" and response["error"] == "no such frame", response

        # A user prompt is reported, and can be handled over BiDi.
        response = bidi.send(
            "script.evaluate",
            {"expression": "setTimeout(() => alert('yo'), 0)", "awaitPromise": False, "target": {"context": window_handle}},
        )
        assert response["result"]["type"] == "success", response
        event = bidi.wait_for_event("browsingContext.userPromptOpened")
        assert event["params"]["context"] == window_handle, event
        assert event["params"]["type"] == "alert" and event["params"]["message"] == "yo", event
        response = bidi.send("browsingContext.handleUserPrompt", {"context": window_handle, "accept": True})
        assert response["type"] == "success", response
        response = bidi.send("browsingContext.handleUserPrompt", {"context": window_handle})
        assert response["type"] == "error" and response["error"] == "no such alert", response

        response = bidi.send("session.unsubscribe", {"subscriptions": [subscription]})
        assert response["type"] == "success", response
        response = bidi.send("session.unsubscribe", {"subscriptions": [subscription]})
        assert response["type"] == "error" and response["error"] == "invalid argument", response

        # Subscribing to context events reports the existing contexts; creating and closing a tab reports it too.
        response = bidi.send("session.subscribe", {"events": ["browsingContext.contextCreated", "browsingContext.contextDestroyed"]})
        assert response["type"] == "success", response
        event = bidi.wait_for_event("browsingContext.contextCreated")
        assert event["params"]["context"] == window_handle and event["params"]["children"] is None, event
        event = bidi.wait_for_event("browsingContext.contextCreated")
        assert event["params"]["context"] == frame and event["params"]["parent"] == window_handle, event
        response = bidi.send("browsingContext.create", {"type": "tab", "referenceContext": window_handle})
        assert response["type"] == "success", response
        new_tab = response["result"]["context"]
        assert new_tab != window_handle and response["result"]["userContext"] == "default", response
        event = bidi.wait_for_event("browsingContext.contextCreated")
        assert event["params"]["context"] == new_tab and event["params"]["hasPlannedNavigation"] is False, event
        response = bidi.send("browsingContext.getTree", {})
        assert {context["context"] for context in response["result"]["contexts"]} == {window_handle, new_tab}, response
        response = bidi.send("browsingContext.navigate", {"context": new_tab, "url": "data:text/html,<title>tab</title>", "wait": "complete"})
        assert response["type"] == "success" and response["result"]["url"] == "data:text/html,<title>tab</title>", response
        response = bidi.send("browsingContext.getTree", {"root": new_tab})
        assert response["result"]["contexts"][0]["url"] == "data:text/html,<title>tab</title>", response
        response = bidi.send("browsingContext.navigate", {"context": new_tab, "url": "not a url"})
        assert response["type"] == "error" and response["error"] == "invalid argument", response
        response = bidi.send("browsingContext.close", {"context": frame})
        assert response["type"] == "error" and response["error"] == "invalid argument", response
        response = bidi.send("browsingContext.close", {"context": new_tab})
        assert response["type"] == "success", response
        event = bidi.wait_for_event("browsingContext.contextDestroyed")
        assert event["params"]["context"] == new_tab, event
        response = bidi.send("browsingContext.close", {"context": new_tab})
        assert response["type"] == "error" and response["error"] == "no such frame", response

        # permissions.setPermission changes what the Permissions API reports.
        response = bidi.send(
            "permissions.setPermission",
            {"descriptor": {"name": "geolocation"}, "state": "denied", "origin": "https://example.com"},
        )
        assert response["type"] == "success", response
        response = bidi.send(
            "permissions.setPermission",
            {"descriptor": {"name": "no-such-permission"}, "state": "denied", "origin": "https://example.com"},
        )
        assert response["type"] == "success", response
        response = bidi.send(
            "permissions.setPermission",
            {"descriptor": {"name": "geolocation"}, "state": "maybe", "origin": "https://example.com"},
        )
        assert response["type"] == "error" and response["error"] == "invalid argument", response

        # Ending the session over BiDi answers the command, closes the connection, and frees the HTTP session.
        response = bidi.send("session.end", {})
        assert response["type"] == "success", response
        assert bidi.receive() is None, "The server did not close the WebSocket connection"
        bidi.websocket.close()

        status, payload, body = webdriver_helpers.request(port, "GET", "/status")
        assert status == 200 and payload["value"]["ready"] is True, body

        # A BiDi-only session is created over a connection to /session.
        bidi = BiDiSession(f"ws://127.0.0.1:{port}/session")
        response = bidi.send("session.status", {})
        assert response["type"] == "success" and response["result"]["ready"] is True, response
        response = bidi.send("session.subscribe", {"events": ["log.entryAdded"]})
        assert response["type"] == "error" and response["error"] == "invalid session id", response
        response = bidi.send("session.new", {"capabilities": {"alwaysMatch": {"ladybird:headless": True}}})
        assert response["type"] == "success", response
        assert "webSocketUrl" not in response["result"]["capabilities"], response
        response = bidi.send("browsingContext.getTree", {})
        assert response["type"] == "success" and len(response["result"]["contexts"]) == 1, response
        response = bidi.send("session.end", {})
        assert response["type"] == "success", response
        assert bidi.receive() is None, "The server did not close the WebSocket connection"
        bidi.websocket.close()
    finally:
        webdriver.terminate()
        webdriver.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("webdriver_binary")
    arguments = parser.parse_args()
    run_test(arguments.webdriver_binary)


if __name__ == "__main__":
    main()
