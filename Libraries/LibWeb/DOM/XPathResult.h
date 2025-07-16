/*
 * Copyright (c) 2025, Ali Mohammad Pur <mpfard@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/Bindings/PlatformObject.h>

namespace Web::DOM {

class XPathResult : public Bindings::PlatformObject {
    WEB_PLATFORM_OBJECT(XPathResult, PlatformObject);
    GC_DECLARE_ALLOCATOR(XPathResult);

public:
    virtual ~XPathResult() override = default;

protected:
    virtual void initialize(JS::Realm&) override;
    virtual void visit_edges(Cell::Visitor&) override;

private:
};

}
