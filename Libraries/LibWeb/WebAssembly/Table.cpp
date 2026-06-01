/*
 * Copyright (c) 2021, Ali Mohammad Pur <mpfard@serenityos.org>
 * Copyright (c) 2023, Tim Flynn <trflynn89@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibCrypto/BigInt/SignedBigInteger.h>
#include <LibCrypto/BigInt/UnsignedBigInteger.h>
#include <LibJS/Runtime/BigInt.h>
#include <LibJS/Runtime/Realm.h>
#include <LibJS/Runtime/VM.h>
#include <LibJS/Runtime/Value.h>
#include <LibWasm/Types.h>
#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/Table.h>
#include <LibWeb/WebAssembly/Table.h>
#include <LibWeb/WebAssembly/WebAssembly.h>

namespace Web::WebAssembly {

GC_DEFINE_ALLOCATOR(Table);

static Wasm::ValueType table_kind_to_value_type(Bindings::TableKind kind)
{
    switch (kind) {
    case Bindings::TableKind::Externref:
        return Wasm::ValueType { Wasm::ValueType::ExternReference };
    case Bindings::TableKind::Anyfunc:
        return Wasm::ValueType { Wasm::ValueType::FunctionReference };
    }

    VERIFY_NOT_REACHED();
}

static WebIDL::ExceptionOr<u64> table_limit_from_js_value(JS::VM& vm, JS::Value value, Wasm::AddressType address_type)
{
    if (value.is_bigint()) {
        if (value.as_bigint().big_integer().is_negative())
            return vm.throw_completion<JS::TypeError>("Table size must be non-negative"sv);

        auto string = TRY_OR_THROW_OOM(vm, value.as_bigint().big_integer().to_base(10));
        auto number = string.to_number<u64>();
        if (!number.has_value())
            return vm.throw_completion<JS::RangeError>("Table size is too large"sv);
        if (address_type == Wasm::AddressType::I32 && *number > NumericLimits<u32>::max())
            return vm.throw_completion<JS::RangeError>("Table size is too large"sv);
        return *number;
    }

    auto number_value = TRY(value.to_number(vm));
    if (!number_value.is_integral_number() || number_value.as_double() < 0)
        return vm.throw_completion<JS::TypeError>("Table size must be a non-negative integer"sv);
    auto number = number_value.as_double();
    if (number > static_cast<double>(NumericLimits<u64>::max()))
        return vm.throw_completion<JS::RangeError>("Table size is too large"sv);
    if (address_type == Wasm::AddressType::I32 && number > static_cast<double>(NumericLimits<u32>::max()))
        return vm.throw_completion<JS::RangeError>("Table size is too large"sv);
    return static_cast<u64>(number);
}

static JS::Value table_limit_to_js_value(JS::VM& vm, u64 value, Wasm::AddressType address_type)
{
    if (address_type == Wasm::AddressType::I64)
        return JS::BigInt::create(vm, ::Crypto::SignedBigInteger { ::Crypto::UnsignedBigInteger { value } });
    return JS::Value { static_cast<u32>(value) };
}

WebIDL::ExceptionOr<GC::Ref<Table>> Table::construct_impl(JS::Realm& realm, Bindings::TableDescriptor& descriptor, Optional<JS::Value> value)
{
    auto& vm = realm.vm();

    auto reference_type = table_kind_to_value_type(descriptor.element);
    auto address_type = descriptor.address == Bindings::AddressType::I64 ? Wasm::AddressType::I64 : Wasm::AddressType::I32;

    auto initial = TRY(table_limit_from_js_value(vm, descriptor.initial, address_type));
    auto maximum = descriptor.maximum.has_value()
        ? Optional<u64> { TRY(table_limit_from_js_value(vm, descriptor.maximum.value(), address_type)) }
        : Optional<u64> {};

    if (maximum.has_value() && maximum.value() < initial)
        return vm.throw_completion<JS::RangeError>("Maximum should not be less than initial in table type"sv);

    auto reference_value = !value.has_value()
        ? Detail::default_webassembly_value(vm, reference_type)
        : TRY(Detail::to_webassembly_value(vm, *value, reference_type));

    Wasm::Limits limits { address_type, initial, maximum };
    Wasm::TableType table_type { reference_type, move(limits) };

    auto& cache = Detail::get_cache(realm);
    auto address = cache.abstract_machine().store().allocate(table_type);
    if (!address.has_value())
        return vm.throw_completion<JS::TypeError>("Wasm Table allocation failed"sv);

    auto const& reference = reference_value.to<Wasm::Reference>();
    auto& table = *cache.abstract_machine().store().get(*address);
    for (auto& element : table.elements())
        element = reference;

    return realm.create<Table>(realm, *address);
}

Table::Table(JS::Realm& realm, Wasm::TableAddress address)
    : Bindings::PlatformObject(realm)
    , m_address(address)
{
}

void Table::initialize(JS::Realm& realm)
{
    WEB_SET_PROTOTYPE_FOR_INTERFACE_WITH_CUSTOM_NAME(Table, WebAssembly.Table);
    Base::initialize(realm);
}

// https://webassembly.github.io/spec/js-api/#dom-table-grow
WebIDL::ExceptionOr<JS::Value> Table::grow(JS::Value delta_value, Optional<JS::Value> value)
{
    auto& vm = this->vm();

    auto& cache = Detail::get_cache(realm());
    auto* table = cache.abstract_machine().store().get(address());
    if (!table)
        return vm.throw_completion<JS::RangeError>("Could not find the memory table to grow"sv);

    auto delta = TRY(table_limit_from_js_value(vm, delta_value, table->type().limits().address_type()));
    auto initial_size = table->elements().size();

    auto reference_value = !value.has_value()
        ? Detail::default_webassembly_value(vm, table->type().element_type())
        : TRY(Detail::to_webassembly_value(vm, *value, table->type().element_type()));
    auto const& reference = reference_value.to<Wasm::Reference>();

    if (!table->grow(delta, reference))
        return vm.throw_completion<JS::RangeError>("Failed to grow table"sv);

    return table_limit_to_js_value(vm, initial_size, table->type().limits().address_type());
}

// https://webassembly.github.io/spec/js-api/#dom-table-get
WebIDL::ExceptionOr<JS::Value> Table::get(JS::Value index_value) const
{
    auto& vm = this->vm();

    auto& cache = Detail::get_cache(realm());
    auto* table = cache.abstract_machine().store().get(address());
    if (!table)
        return vm.throw_completion<JS::RangeError>("Could not find the memory table"sv);

    auto index = TRY(table_limit_from_js_value(vm, index_value, table->type().limits().address_type()));
    if (table->elements().size() <= index)
        return vm.throw_completion<JS::RangeError>("Table element index out of range"sv);

    auto& ref = table->elements()[index];

    Wasm::Value wasm_value { ref };
    return Detail::to_js_value(vm, wasm_value, table->type().element_type());
}

// https://webassembly.github.io/spec/js-api/#dom-table-set
WebIDL::ExceptionOr<void> Table::set(JS::Value index_value, Optional<JS::Value> value)
{
    auto& vm = this->vm();

    auto& cache = Detail::get_cache(realm());
    auto* table = cache.abstract_machine().store().get(address());
    if (!table)
        return vm.throw_completion<JS::RangeError>("Could not find the memory table"sv);

    auto index = TRY(table_limit_from_js_value(vm, index_value, table->type().limits().address_type()));
    if (table->elements().size() <= index)
        return vm.throw_completion<JS::RangeError>("Table element index out of range"sv);

    auto reference_value = !value.has_value()
        ? Detail::default_webassembly_value(vm, table->type().element_type())
        : TRY(Detail::to_webassembly_value(vm, *value, table->type().element_type()));
    auto const& reference = reference_value.to<Wasm::Reference>();

    table->elements()[index] = reference;

    return {};
}

// https://webassembly.github.io/spec/js-api/#dom-table-length
WebIDL::ExceptionOr<JS::Value> Table::length() const
{
    auto& vm = this->vm();

    auto& cache = Detail::get_cache(realm());
    auto* table = cache.abstract_machine().store().get(address());
    if (!table)
        return vm.throw_completion<JS::RangeError>("Could not find the memory table"sv);

    return table_limit_to_js_value(vm, table->elements().size(), table->type().limits().address_type());
}

}
