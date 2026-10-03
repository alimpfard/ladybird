/*
 * Copyright (c) 2026, Niccolo Antonelli-Dziri <niccolo.antonelli-dziri@protonmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/JsonObject.h>
#include <AK/Optional.h>
#include <AK/String.h>
#include <AK/Types.h>
#include <LibURL/Origin.h>
#include <LibWeb/Bindings/PermissionStatus.h>
#include <LibWeb/Bindings/Permissions.h>
#include <LibWeb/Bindings/Wrappable.h>
#include <LibWeb/Export.h>
#include <LibWeb/Forward.h>
#include <LibWebCommon/WebDriver/Error.h>

namespace Web::PermissionsAPI {

using PermissionDescriptor = Bindings::PermissionDescriptor;
using PermissionState = Bindings::PermissionState;

bool is_permission_supported(Utf16View);

PermissionState permission_state(PermissionDescriptor descriptor, Optional<HTML::EnvironmentSettingsObject&> settings = {});

PermissionState get_current_permission_state(Utf16String const& name, Optional<HTML::EnvironmentSettingsObject&> settings = {});

PermissionState request_permission(PermissionDescriptor const& descriptor);

// https://w3c.github.io/permissions/#dfn-set-a-permission
// Sets the permission a WebDriver command describes as JSON for the key generated from the given origins.
WEB_API ErrorOr<void, WebDriver::Error> set_permission_for_webdriver(JsonObject const& descriptor, StringView state, URL::Origin const& top_level_origin, URL::Origin const& origin);

class WEB_API Permissions : public Bindings::GCAllocatedWrappable {
    WEB_WRAPPABLE(Permissions, Bindings::GCAllocatedWrappable);
    GC_DECLARE_ALLOCATOR(Permissions);

public:
    static GC::Ref<Permissions> create();

    void query(GC::Ref<JS::Object> permission_desc, GC::Ref<WebIDL::Promise>);

private:
    Permissions();
};

void permission_query_algorithm(PermissionDescriptor const&, PermissionStatus&);

}
