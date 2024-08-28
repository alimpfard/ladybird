/*
 * Copyright (c) 2024, Ali Mohammad Pur <mpfard@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/AtomicRefCounted.h>
#include <AK/HashTable.h>
#include <AK/MemoryStream.h>
#include <AK/Random.h>
#include <AK/StringView.h>
#include <LibCore/Promise.h>
#include <LibCore/SocketAddress.h>
#include <LibDNS/Message.h>
#include <LibThreading/MutexProtected.h>
#include <LibThreading/RWLockProtected.h>
#include <AK/TemporaryChange.h>

namespace DNS {
class Resolver;

class LookupResult : public AtomicRefCounted<LookupResult>
    , public Weakable<LookupResult> {
public:
    LookupResult() = default;

    Vector<Variant<IPv4Address, IPv6Address>> cached_addresses() const
    {
        Vector<Variant<IPv4Address, IPv6Address>> result;
        for (auto& record : m_cached_records) {
            record.record.visit(
                [&](Messages::Records::A const& a) { result.append(a.address); },
                [&](Messages::Records::AAAA const& aaaa) { result.append(aaaa.address); },
                [](auto&) {});
        }
        return result;
    }

    void add_record(Messages::ResourceRecord record)
    {
        m_valid = true;
        m_cached_records.append(move(record));
    }

    Vector<Messages::ResourceRecord> const& records() const { return m_cached_records; }

    void set_id(u16 id) { m_id = id; }
    u16 id() { return m_id; }

    bool is_valid() const { return m_valid; }

private:
    bool m_valid { false };
    Vector<Messages::ResourceRecord> m_cached_records;
    u16 m_id { 0 };
};

class Resolver {
public:
    enum class ConnectionMode {
        TCP,
        UDP,
    };

    struct SocketResult {
        MaybeOwned<Core::Socket> socket;
        ConnectionMode mode;
    };

    Resolver(Function<ErrorOr<SocketResult>()> create_socket)
        : m_pending_lookups(make<RedBlackTree<u16, PendingLookup>>())
        , m_create_socket(move(create_socket))
    {
    }

    NonnullRefPtr<Core::Promise<Empty>> when_socket_ready()
    {
        auto promise = Core::Promise<Empty>::construct();
        m_socket_ready_promises.append(promise);
        if (has_connection(false)) {
            promise->resolve({});
            return promise;
        }

        if (!has_connection())
            promise->reject(Error::from_string_literal("Failed to create socket"));

        return promise;
    }

    NonnullRefPtr<LookupResult const> expect_cached(StringView name, Messages::Class class_ = Messages::Class::IN)
    {
        return expect_cached(name, class_, Array { Messages::ResourceType::A, Messages::ResourceType::AAAA });
    }

    NonnullRefPtr<LookupResult const> expect_cached(StringView name, Messages::Class class_, Span<Messages::ResourceType const> desired_types)
    {
        auto result = lookup_in_cache(name, class_, desired_types);
        VERIFY(!result.is_null());
        dbgln("DNS::expect({}) -> OK", name);
        return *result;
    }

    RefPtr<LookupResult const> lookup_in_cache(StringView name, Messages::Class class_ = Messages::Class::IN)
    {
        return lookup_in_cache(name, class_, Array { Messages::ResourceType::A, Messages::ResourceType::AAAA });
    }

    RefPtr<LookupResult const> lookup_in_cache(StringView name, Messages::Class, Span<Messages::ResourceType const>)
    {
        return m_cache.with_read_locked([&](auto& cache) -> RefPtr<LookupResult const> {
            auto it = cache.find(name);
            if (it == cache.end())
                return {};
            return *it->value;
        });
    }

    NonnullRefPtr<Core::Promise<NonnullRefPtr<LookupResult const>>> lookup(ByteString name, Messages::Class class_ = Messages::Class::IN)
    {
        return lookup(move(name), class_, Array { Messages::ResourceType::A, Messages::ResourceType::AAAA });
    }

    NonnullRefPtr<Core::Promise<NonnullRefPtr<LookupResult const>>> lookup(ByteString name, Messages::Class class_, Span<Messages::ResourceType const> desired_types)
    {
        auto promise = Core::Promise<NonnullRefPtr<LookupResult const>>::construct();

        if (auto result = lookup_in_cache(name, class_, desired_types)) {
            promise->resolve(result.release_nonnull());
            return promise;
        }

        if (!has_connection()) {
            // Use system resolver
            // FIXME: Use an underlying resolver instead.
            dbgln("Not ready to resolve, using system resolver and skipping cache for {}", name);
            auto record_or_error = Core::Socket::resolve_host(name, Core::Socket::SocketType::Stream);
            if (record_or_error.is_error()) {
                promise->reject(record_or_error.release_error());
                return promise;
            }
            auto result = make_ref_counted<LookupResult>();
            auto record = record_or_error.release_value();
            record.visit(
                [&](IPv4Address const& address) {
                    result->add_record({ .name = {}, .type = Messages::ResourceType::A, .class_ = Messages::Class::IN, .ttl = 0, .record = Messages::Records::A { address } });
                },
                [&](IPv6Address const& address) {
                    result->add_record({ .name = {}, .type = Messages::ResourceType::AAAA, .class_ = Messages::Class::IN, .ttl = 0, .record = Messages::Records::AAAA { address } });
                });
            promise->resolve(result);
            return promise;
        }

        auto already_in_cache = false;
        auto result = m_cache.with_write_locked([&](auto& cache) -> RefPtr<LookupResult> {
            if (cache.contains(name)) {
                already_in_cache = true;
                return *cache.get(name);
            }

            auto ptr = make_ref_counted<LookupResult>();
            cache.set(name, ptr);
            return ptr;
        });

        if (already_in_cache) {
            auto id = result->id();
            auto existing_promise = m_pending_lookups.with_write_locked([&](auto& lookups) -> RefPtr<Core::Promise<NonnullRefPtr<LookupResult const>>> {
                if (auto* lookup = lookups->find(id))
                    return lookup->promise;
                return nullptr;
            });
            if (existing_promise)
                return existing_promise.release_nonnull();

            promise->resolve(*result);
            return promise;
        }

        Messages::Message query;
        m_pending_lookups.with_read_locked([&](auto& lookups) {
            do
                fill_with_random({ &query.header.id, sizeof(query.header.id) });
            while (lookups->find(query.header.id) != nullptr);
        });
        query.header.question_count = max(1u, desired_types.size());
        query.header.options.set_recursion_desired(true);
        query.header.options.set_op_code(Messages::OpCode::Query);
        for (auto const& type : desired_types) {
            query.questions.append(Messages::Question {
                .name = Messages::DomainName::from_string(name),
                .type = type,
                .class_ = class_,
            });
        }

        if (query.questions.is_empty()) {
            query.questions.append(Messages::Question {
                .name = Messages::DomainName::from_string(name),
                .type = Messages::ResourceType::A,
                .class_ = class_,
            });
        }

        result->set_id(query.header.id);

        m_pending_lookups.with_write_locked([&](auto& pending_lookups) {
            pending_lookups->insert(query.header.id, { query.header.id, result->make_weak_ptr(), promise });
        });

        ByteBuffer query_bytes;
        MUST(query.to_raw(query_bytes));

        if (m_mode == ConnectionMode::TCP) {
            auto original_query_bytes = query_bytes;
            query_bytes = MUST(ByteBuffer::create_uninitialized(query_bytes.size() + sizeof(u16)));
            NetworkOrdered<u16> size = original_query_bytes.size();
            query_bytes.overwrite(0, &size, sizeof(size));
            query_bytes.overwrite(sizeof(size), original_query_bytes.data(), original_query_bytes.size());
        }

        auto write_result = m_socket.with_write_locked([&](auto& socket) {
            return (*socket)->write_until_depleted(query_bytes.bytes());
        });
        if (write_result.is_error()) {
            promise->reject(write_result.release_error());
            return promise;
        }

        return promise;
    }

private:
    ErrorOr<Messages::Message> parse_one_message()
    {
        if (m_mode == ConnectionMode::UDP)
            return m_socket.with_write_locked([&](auto& socket) { return Messages::Message::from_raw(**socket); });

        return m_socket.with_write_locked([&](auto& socket) -> ErrorOr<Messages::Message> {
            if (!TRY((*socket)->can_read_without_blocking()))
                return Error::from_errno(EAGAIN);

            auto size = TRY((*socket)->template read_value<NetworkOrdered<u16>>());
            auto buffer = TRY(ByteBuffer::create_uninitialized(size));
            TRY((*socket)->read_until_filled(buffer));
            FixedMemoryStream stream { static_cast<ReadonlyBytes>(buffer) };
            return Messages::Message::from_raw(stream);
        });
    }

    void process_incoming_messages()
    {
        while (true) {
            auto message_or_err = parse_one_message();
            if (message_or_err.is_error()) {
                if (!message_or_err.error().is_errno() || message_or_err.error().code() != EAGAIN)
                    dbgln("Failed to receive message: {}", message_or_err.error());
                break;
            }

            auto message = message_or_err.release_value();
            auto result = m_pending_lookups.with_write_locked([&](auto& lookups) -> ErrorOr<void> {
                auto* lookup = lookups->find(message.header.id);
                if (!lookup)
                    return Error::from_string_literal("No pending lookup found for this message");

                auto result = lookup->result.strong_ref();
                for (auto& record : message.answers)
                    result->add_record(move(record));

                lookup->promise->resolve(*result);
                lookups->remove(message.header.id);
                return {};
            });
            if (result.is_error()) {
                dbgln("Received a message with no pending lookup: {}", result.error());
                continue;
            }
        }
    }

    bool has_connection(bool attempt_restart = true)
    {
        auto result = m_socket.with_read_locked(
            [&](auto& socket) { return socket.has_value() && (*socket)->is_open(); });

        if (attempt_restart && !result && !m_attempting_restart) {
            TemporaryChange change(m_attempting_restart, true);
            auto create_result = m_create_socket();
            if (create_result.is_error()) {
                dbgln("Failed to create socket: {}", create_result.error());
                return false;
            }

            auto [socket, mode] = MUST(move(create_result));
            set_socket(move(socket), mode);
            result = true;
        }

        return result;
    }

    void set_socket(MaybeOwned<Core::Socket> socket, ConnectionMode mode = ConnectionMode::UDP)
    {
        m_mode = mode;
        m_socket.with_write_locked([&](auto& s) {
            s = move(socket);
            (*s)->on_ready_to_read = [this] {
                process_incoming_messages();
            };
            (*s)->set_notifications_enabled(true);
        });

        for (auto& promise : m_socket_ready_promises)
            promise->resolve({});

        m_socket_ready_promises.clear();
    }

    struct PendingLookup {
        u16 id { 0 };
        WeakPtr<LookupResult> result;
        NonnullRefPtr<Core::Promise<NonnullRefPtr<LookupResult const>>> promise;
    };
    Threading::RWLockProtected<HashMap<ByteString, NonnullRefPtr<LookupResult>>> m_cache;
    Threading::RWLockProtected<NonnullOwnPtr<RedBlackTree<u16, PendingLookup>>> m_pending_lookups;
    Threading::RWLockProtected<Optional<MaybeOwned<Core::Socket>>> m_socket;
    Function<ErrorOr<SocketResult>()> m_create_socket;
    bool m_attempting_restart { false };
    ConnectionMode m_mode { ConnectionMode::UDP };
    Vector<NonnullRefPtr<Core::Promise<Empty>>> m_socket_ready_promises;
};

}
