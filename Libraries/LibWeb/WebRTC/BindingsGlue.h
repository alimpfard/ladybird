/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/FlyString.h>
#include <AK/Optional.h>
#include <LibGC/Forward.h>
#include <LibJS/Forward.h>
#include <LibJS/Runtime/Value.h>
#include <LibWeb/Export.h>
#include <LibWeb/Forward.h>

namespace Web::WebRTC {

class RTCStatsReport;

}

namespace Web::Bindings {

WEB_API GC::Ref<JS::Map> map_entries(JS::Realm&, WebRTC::RTCStatsReport&);
WEB_API Optional<JS::Value> map_get(JS::Realm&, WebRTC::RTCStatsReport&, FlyString const& key);
WEB_API bool map_has(WebRTC::RTCStatsReport&, FlyString const& key);

}
