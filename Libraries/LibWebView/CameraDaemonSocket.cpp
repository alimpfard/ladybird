/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/LexicalPath.h>
#include <LibCore/Environment.h>
#include <LibWebView/CameraDaemonSocket.h>

namespace WebView {

ErrorOr<ByteString> camera_daemon_socket_path()
{
    // PIPEWIRE_REMOTE names the socket, or says where it is outright; the name is looked for in PipeWire's runtime
    // directory, which is the user's unless PIPEWIRE_RUNTIME_DIR says otherwise.
    auto name = Core::Environment::get("PIPEWIRE_REMOTE"sv).value_or("pipewire-0"sv);
    if (name.is_empty())
        name = "pipewire-0"sv;
    if (name.starts_with('/'))
        return ByteString { name };

    auto directory = Core::Environment::get("PIPEWIRE_RUNTIME_DIR"sv);
    if (!directory.has_value() || directory->is_empty())
        directory = Core::Environment::get("XDG_RUNTIME_DIR"sv);
    if (!directory.has_value() || directory->is_empty())
        return Error::from_string_literal("There is no runtime directory to look for PipeWire in");
    return LexicalPath::join(*directory, name).string();
}

}
