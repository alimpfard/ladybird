/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Function.h>
#include <AK/HashMap.h>
#include <AK/Vector.h>
#include <LibCamera/DeviceInfo.h>

namespace Camera {

// The process's view of the cameras, kept current by the CameraServer from the first time somebody wants to know. Until
// the Browser says the tab may capture, the server tells only whether there is a camera, as one device with no name.
class Devices {
public:
    static Devices& the();

    // Starts asking the server, which the Browser launches for it. Nothing is asked before somebody calls this, so a
    // page that never looks for a camera costs no server.
    void ensure_watching();

    bool has_device_list() const { return m_has_device_list; }
    Vector<DeviceInfo> const& devices() const { return m_devices; }

    // Has the server report its list again. False when there is no server to ask, so no report will come.
    bool request_fresh_device_list();

    using ListenerId = u64;
    ListenerId add_devices_changed_listener(Function<void()>);
    void remove_devices_changed_listener(ListenerId);

private:
    void report(Vector<DeviceInfo>);

    Vector<DeviceInfo> m_devices;
    bool m_watching { false };
    bool m_has_device_list { false };

    ListenerId m_next_listener_id { 1 };
    HashMap<ListenerId, Function<void()>> m_listeners;
};

}
