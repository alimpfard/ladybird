/*
 * Copyright (c) 2023, Andrew Kaster <akaster@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibCore/EventLoop.h>
#include <LibCore/Process.h>
#include <LibCore/System.h>
#include <LibGC/Function.h>
#include <LibGfx/Font/FontDatabase.h>
#include <LibGfx/Font/SharedFontProvider.h>
#include <LibJS/Runtime/ArrayBuffer.h>
#include <LibWeb/Bindings/WrapperWorld.h>
#include <LibWeb/HTML/BroadcastChannel.h>
#include <LibWeb/HTML/EventLoop/EventLoop.h>
#include <LibWeb/HTML/EventLoop/Task.h>
#include <LibWeb/HTML/EventNames.h>
#include <LibWeb/HTML/Scripting/TemporaryExecutionContext.h>
#include <LibWeb/HTML/WorkerAgentParent.h>
#include <LibWeb/HTML/WorkerGlobalScope.h>
#include <LibWeb/Platform/FontPlugin.h>
#include <LibWeb/WebRTC/RTCEncodedAudioFrame.h>
#include <LibWeb/WebRTC/RTCRtpScriptTransformer.h>
#include <LibWeb/WebRTC/RTCTransformEvent.h>
#include <LibWebView/CompositorConnection.h>
#include <WebWorker/ConnectionFromClient.h>
#include <WebWorker/PageHost.h>
#include <WebWorker/WorkerHost.h>

namespace WebWorker {

Messages::WebWorkerServer::InitTransportResponse ConnectionFromClient::init_transport([[maybe_unused]] int peer_pid)
{
#ifdef AK_OS_WINDOWS
    m_transport->set_peer_pid(peer_pid);
    return Core::System::getpid();
#endif
    VERIFY_NOT_REACHED();
}

void ConnectionFromClient::connect_to_request_server(IPC::TransportHandle handle)
{
    if (on_request_server_connection)
        on_request_server_connection(handle);

    // A real connection loss defers this callback. Exercise the case where the replacement connection arrives before
    // that deferred callback runs.
    if (auto request_server_died_callback = move(m_request_server_died_callback_for_testing))
        request_server_died_callback();
}

void ConnectionFromClient::simulate_request_server_connection_loss_and_reconnect_for_testing(IPC::TransportHandle replacement_handle)
{
    auto disconnected_client = move(Web::ResourceLoader::the().request_client());
    m_request_server_died_callback_for_testing = move(disconnected_client->on_request_server_died);
    disconnected_client = nullptr;

    connect_to_request_server(move(replacement_handle));
}

void ConnectionFromClient::connect_to_image_decoder(IPC::TransportHandle handle)
{
    if (on_image_decoder_connection)
        on_image_decoder_connection(handle);
}

void ConnectionFromClient::connect_to_wasm_compiler([[maybe_unused]] IPC::TransportHandle handle)
{
#if defined(HAVE_WASM_COMPILER_SERVICE)
    if (on_wasm_compiler_connection)
        on_wasm_compiler_connection(move(handle));
#endif
}

void ConnectionFromClient::connect_to_compositor(IPC::TransportHandle handle)
{
    auto transport = MUST(handle.create_transport());
    m_compositor_connection = adopt_ref(*new WebView::CompositorConnection(move(transport)));
    m_compositor_connection->on_compositor_lost = [this] {
        m_page_host->compositor_process_lost();
    };

#ifdef AK_OS_WINDOWS
    if constexpr (requires { m_compositor_connection->transport().set_peer_pid(0); }) {
        auto response = m_compositor_connection->send_sync<Messages::CompositorWebContentServer::InitTransport>(Core::System::getpid());
        m_compositor_connection->transport().set_peer_pid(response->compositor_pid());
    }
#endif
}

WebView::CompositorConnection* ConnectionFromClient::compositor_process_connection() const
{
    if (!m_compositor_connection || !m_compositor_connection->is_open())
        return nullptr;
    return m_compositor_connection.ptr();
}

void ConnectionFromClient::set_system_font_family(String family)
{
    Web::Platform::FontPlugin::the().set_system_font_family(FlyString { family });
}

void ConnectionFromClient::set_site_compatibility_data(JsonValue data)
{
    auto parsed_data = Web::SiteCompatibilityData::from_json(data);
    if (parsed_data.is_error()) {
        warnln("Ignoring invalid site compatibility data: {}", parsed_data.error());
        return;
    }
    Web::ResourceLoader::the().set_site_compatibility_data(parsed_data.release_value());
}

void ConnectionFromClient::close_worker()
{
    async_did_close_worker();

    // FIXME: Invoke a worker shutdown operation that implements the spec
    m_worker_host = nullptr;

    die();
}

void ConnectionFromClient::die()
{
    // FIXME: When handling multiple workers in the same process,
    //     this logic needs to be smarter (only when all workers are dead, etc).
    Core::Process::terminate_immediately(0);
}

void ConnectionFromClient::request_file(Web::FileRequest request)
{
    auto request_id = ++last_id;

    auto path = request.path();
    m_requested_files.set(request_id, move(request));
    async_did_request_file(path, request_id);
}

ConnectionFromClient::ConnectionFromClient(NonnullOwnPtr<IPC::Transport> transport)
    : IPC::ConnectionFromClient<WebWorkerClientEndpoint, WebWorkerServerEndpoint>(*this, move(transport), 1)
    , m_page_host(PageHost::create(*this))
{
}

ConnectionFromClient::~ConnectionFromClient() = default;

void ConnectionFromClient::set_font_catalog(IPC::File file, u64 size, u64 generation)
{
    if (m_font_provider) {
        if (auto result = m_font_provider->replace_catalog(move(file), size, generation); result.is_error())
            dbgln("WebWorker: Unable to replace font catalog: {}", result.error());
        else
            Web::Platform::FontPlugin::the().update_generic_fonts();
        return;
    }

    Gfx::SharedFontProviderCallbacks callbacks;
    callbacks.open_font = [this](u64 requested_generation, u64 face_id) {
        auto response = send_sync_but_allow_failure<Messages::WebWorkerClient::OpenSystemFont>(requested_generation, face_id);
        if (!response || response->format() > to_underlying(Gfx::FontFileFormat::WOFF))
            return Gfx::BrokeredFont {};
        return Gfx::BrokeredFont {
            .face_id = response->matched_face_id(),
            .ttc_index = response->ttc_index(),
            .format = static_cast<Gfx::FontFileFormat>(response->format()),
            .file = response->take_file(),
        };
    };
    callbacks.match_font = [this](String const& family, u16 weight, u16 width, u8 slope) {
        auto response = send_sync_but_allow_failure<Messages::WebWorkerClient::MatchSystemFont>(family, weight, width, slope);
        if (!response || response->format() > to_underlying(Gfx::FontFileFormat::WOFF))
            return Gfx::BrokeredFont {};
        return Gfx::BrokeredFont {
            .face_id = response->face_id(),
            .ttc_index = response->ttc_index(),
            .format = static_cast<Gfx::FontFileFormat>(response->format()),
            .file = response->take_file(),
        };
    };
    callbacks.match_font_for_code_point = [this](u32 code_point, u16 weight, u16 width, u8 slope, bool prefer_color_emoji) {
        auto response = send_sync_but_allow_failure<Messages::WebWorkerClient::MatchSystemFontForCodePoint>(code_point, weight, width, slope, prefer_color_emoji);
        if (!response || response->format() > to_underlying(Gfx::FontFileFormat::WOFF))
            return Gfx::BrokeredFont {};
        return Gfx::BrokeredFont {
            .face_id = response->face_id(),
            .ttc_index = response->ttc_index(),
            .format = static_cast<Gfx::FontFileFormat>(response->format()),
            .file = response->take_file(),
        };
    };
    callbacks.resolve_generic_family = [this](String const& family, u16 weight, u8 slope) -> Optional<FlyString> {
        auto response = send_sync_but_allow_failure<Messages::WebWorkerClient::ResolveGenericFont>(family, weight, slope);
        if (!response)
            return {};
        auto resolved_family = response->take_resolved_family();
        if (!resolved_family.has_value())
            return {};
        return FlyString { resolved_family.release_value() };
    };

    auto provider = Gfx::SharedFontProvider::create_from_catalog_file_or_empty(move(file), size, generation, move(callbacks));
    if (provider.is_error()) {
        dbgln("WebWorker: Unable to install fallback font catalog: {}", provider.error());
        return;
    }
    m_font_provider = provider.value().ptr();
    Gfx::FontDatabase::the().install_system_font_provider(provider.release_value());
    Web::Platform::FontPlugin::install(*new Web::Platform::FontPlugin(false, m_font_provider));
}

Web::Page& ConnectionFromClient::page()
{
    return m_page_host->page();
}

Web::Page const& ConnectionFromClient::page() const
{
    return m_page_host->page();
}

void ConnectionFromClient::start_worker(URL::URL url, Web::HTML::WorkerType type, Web::HTML::RequestCredentials credentials, String name, Web::HTML::TransferDataEncoder implicit_port, Web::HTML::SerializedEnvironmentSettingsObject outside_settings, Web::HTML::AgentType agent_type)
{
    m_worker_host = make_ref_counted<WorkerHost>(move(url), type, move(name));

    bool const is_shared = agent_type == Web::HTML::AgentType::SharedWorker;
    VERIFY(is_shared || agent_type == Web::HTML::AgentType::DedicatedWorker);

    // FIXME: Add an assertion that the agent_type passed here is the same that was passed at process creation to initialize_main_thread_vm()

    m_worker_host->set_on_script_ready([this] {
        auto pending = move(m_pending_transform_inits);
        for (auto& entry : pending)
            run_transform_init(entry.key, move(entry.value));
    });

    m_worker_host->run(page(), move(implicit_port), outside_settings, credentials, is_shared);
}

void ConnectionFromClient::connect_shared_worker(Web::HTML::TransferDataEncoder message_port, Web::HTML::SerializedEnvironmentSettingsObject outside_settings)
{
    if (!m_worker_host)
        return;
    m_worker_host->connect_shared_worker(move(message_port), move(outside_settings));
}

void ConnectionFromClient::handle_file_return(i32 error, Optional<IPC::File> file, i32 request_id)
{
    auto file_request = m_requested_files.take(request_id);

    VERIFY(file_request.has_value());
    VERIFY(file_request.value().on_file_request_finish);

    file_request.value().on_file_request_finish(error != 0 ? Error::from_errno(error) : ErrorOr<i32> { file->take_fd() });
}

void ConnectionFromClient::did_worker_agent_finish_loading_script(Web::HTML::WorkerAgentOwnerToken owner_token)
{
    Web::HTML::WorkerAgentParent::did_finish_loading_worker_script(owner_token);
}

void ConnectionFromClient::did_worker_agent_fail_loading_script(Web::HTML::WorkerAgentOwnerToken owner_token)
{
    Web::HTML::WorkerAgentParent::did_fail_loading_worker_script(owner_token);
}

void ConnectionFromClient::did_worker_agent_report_exception(Web::HTML::WorkerAgentOwnerToken owner_token, Utf16String message, Utf16String filename, u32 lineno, u32 colno)
{
    Web::HTML::WorkerAgentParent::did_report_worker_exception(owner_token, move(message), move(filename), lineno, colno);
}

void ConnectionFromClient::did_worker_agent_close(Web::HTML::WorkerAgentOwnerToken owner_token)
{
    Web::HTML::WorkerAgentParent::did_close_worker(owner_token);
}

void ConnectionFromClient::broadcast_channel_message(Web::HTML::BroadcastChannelMessage message)
{
    Web::HTML::BroadcastChannel::deliver_message_locally(message);
}

void ConnectionFromClient::rtc_transform_init(u64 transform_id, Web::HTML::SerializedTransferRecord options_record)
{
    if (!m_worker_host)
        return;
    if (!m_worker_host->script_has_run()) {
        // Hold the init until discord's worker script has had a chance to install its
        // onrtctransform handler. Otherwise the event fires into a global scope with
        // no listeners and is dropped.
        m_pending_transform_inits.set(transform_id, move(options_record));
        return;
    }
    run_transform_init(transform_id, move(options_record));
}

void ConnectionFromClient::run_transform_init(u64 transform_id, Web::HTML::SerializedTransferRecord options_record)
{
    if (!m_worker_host)
        return;
    auto global_scope = m_worker_host->global_scope();
    if (!global_scope) {
        dbgln("ConnectionFromClient::rtc_transform_init: no worker global scope yet (transform_id={})", transform_id);
        return;
    }
    auto& realm = global_scope->realm();
    Web::HTML::TemporaryExecutionContext context(realm, Web::HTML::TemporaryExecutionContext::CallbacksEnabled::Yes);

    // Spec step 8.1: deserialize serializedOptions in the worker realm.
    auto deserialized_or_err = Web::HTML::structured_deserialize_with_transfer(options_record, realm);
    if (deserialized_or_err.is_exception()) {
        dbgln("ConnectionFromClient::rtc_transform_init: failed to deserialize options for id={}", transform_id);
        return;
    }
    auto options = deserialized_or_err.release_value().deserialized;

    // Spec step 8.2: create an RTCRtpScriptTransformer with the deserialized options.
    auto transformer_or_err = Web::WebRTC::RTCRtpScriptTransformer::create(realm, options);
    if (transformer_or_err.is_exception()) {
        dbgln("ConnectionFromClient::rtc_transform_init: failed to construct transformer for id={}", transform_id);
        return;
    }
    auto transformer = transformer_or_err.release_value();
    m_transformers.set(transform_id, GC::make_root(transformer));

    // Wire transformer.[[frameSource]]'s writeEncodedData entry point: the worker's
    // transformed frames are piped over IPC to the parent process, where the receiver's
    // decode/playback path consumes them. Captured `this` is fine — the connection
    // outlives the transformer (close_worker tears the connection down via die()).
    auto write_encoded_data = GC::create_function(realm.heap(), [this, transform_id](JS::Value chunk) {
        auto* frame = Web::Bindings::impl_from<Web::WebRTC::RTCEncodedAudioFrame>(chunk.is_object() ? &chunk.as_object() : nullptr);
        if (!frame) {
            static size_t logged_non_frame = 0;
            if (logged_non_frame++ < 3)
                dbgln("worker: write algorithm got non-frame value (chunk_is_object={}, class={}) for id={}",
                    chunk.is_object(),
                    chunk.is_object() ? chunk.as_object().class_name() : "n/a"sv,
                    transform_id);
            return;
        }
        static size_t logged_writes = 0;
        if (logged_writes++ < 3)
            dbgln("worker: write algorithm received frame id={}", transform_id);
        auto data = frame->data();
        auto bytes = MUST(ByteBuffer::create_uninitialized(data->byte_length()));
        data->copy_to(0, bytes);
        auto metadata = frame->get_metadata();
        u32 ssrc = metadata.synchronization_source.value_or(0);
        u8 payload_type = metadata.payload_type.value_or(0);
        u32 rtp_timestamp = metadata.rtp_timestamp.value_or(0);
        u16 sequence_number = static_cast<u16>(metadata.sequence_number.value_or(0));
        async_rtc_transform_encoded_audio_frame_written(transform_id, bytes.bytes(), ssrc, payload_type, rtp_timestamp, sequence_number);
    });
    transformer->set_write_encoded_data_algorithm(write_encoded_data);

    // Spec step 8: queue a global task on the DOM manipulation task source so the
    // event fires on the worker's own event loop, after any pending script setup
    // (e.g. `self.onrtctransform = ...`) has had a chance to run.
    Web::HTML::queue_global_task(Web::HTML::Task::Source::DOMManipulation, realm.global_object(),
        GC::create_function(realm.heap(), [global_scope, transformer, &realm, transform_id] {
            Web::HTML::TemporaryExecutionContext context(realm, Web::HTML::TemporaryExecutionContext::CallbacksEnabled::Yes);
            auto event = Web::WebRTC::RTCTransformEvent::create(realm, Web::HTML::EventNames::rtctransform, transformer);
            auto handler_attr = global_scope->event_handler_attribute(Web::HTML::EventNames::rtctransform);
            auto has_listeners = global_scope->has_event_listener(Web::HTML::EventNames::rtctransform);
            dbgln("worker: dispatching rtctransform id={} attr_present={} addEventListener_present={}", transform_id, handler_attr != nullptr, has_listeners);
            global_scope->dispatch_event(event);
        }));
}

void ConnectionFromClient::rtc_transform_encoded_audio_frame(u64 transform_id, ByteBuffer payload, u32 ssrc, u8 payload_type, u32 rtp_timestamp, u16 sequence_number)
{
    auto entry = m_transformers.get(transform_id);
    if (!entry.has_value()) {
        static size_t logged_miss = 0;
        if (logged_miss++ < 3)
            dbgln("worker: rtc_transform_encoded_audio_frame for unknown id={} (have {} transformers)", transform_id, m_transformers.size());
        return;
    }
    auto transformer = *entry;
    static size_t logged_hit = 0;
    if (logged_hit++ < 3)
        dbgln("worker: rtc_transform_encoded_audio_frame id={} ssrc={} seq={} len={}", transform_id, ssrc, sequence_number, payload.size());

    if (!m_worker_host || !m_worker_host->global_scope())
        return;
    auto& realm = m_worker_host->global_scope()->realm();
    Web::HTML::TemporaryExecutionContext context(realm, Web::HTML::TemporaryExecutionContext::CallbacksEnabled::Yes);

    auto frame = Web::WebRTC::RTCEncodedAudioFrame::create_from_packet(realm, move(payload), ssrc, payload_type, rtp_timestamp, sequence_number);
    if (auto result = transformer->enqueue_encoded_frame(Web::Bindings::wrap(Web::Bindings::host_defined_wrapper_world(realm), realm, frame)); result.is_exception())
        dbgln("rtc_transform_encoded_audio_frame: enqueue failed for transform_id={}", transform_id);
}

void ConnectionFromClient::rtc_transform_encoded_audio_frame_written(Web::HTML::WorkerAgentOwnerToken owner_token, u64 transform_id, ByteBuffer payload, u32 ssrc, u8 payload_type, u32 rtp_timestamp, u16 sequence_number)
{
    Web::HTML::WorkerAgentParent::rtc_transform_encoded_audio_frame_written(owner_token, transform_id, move(payload), ssrc, payload_type, rtp_timestamp, sequence_number);
}

}
