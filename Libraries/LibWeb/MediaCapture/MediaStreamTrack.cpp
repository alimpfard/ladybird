/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/ByteString.h>
#include <LibAudio/RecordStream.h>
#include <LibAudio/SampleSpecification.h>
#include <LibCore/Timer.h>
#include <LibGC/Heap.h>
#include <LibGC/Weak.h>
#include <LibJS/Runtime/Value.h>
#include <LibWeb/Crypto/Crypto.h>
#include <LibWeb/DOM/Event.h>
#include <LibWeb/HTML/EventNames.h>
#include <LibWeb/HTML/Window.h>
#include <LibWeb/HighResolutionTime/TimeOrigin.h>
#include <LibWeb/MediaCapture/MediaDevices.h>
#include <LibWeb/MediaCapture/MediaStreamTrack.h>
#include <LibWeb/MediaCapture/VideoPictureSource.h>
#include <LibWeb/MediaCapture/VideoTrackEncoder.h>
#include <LibWeb/Page/Page.h>
#include <LibWeb/WebIDL/Promise.h>

namespace Web::MediaCapture {

GC_DEFINE_ALLOCATOR(MediaStreamTrack);

Atomic<u64> MediaStreamTrack::s_next_provider_id { 1 };

static constexpr auto VIDEO_REFRESH_INTERVAL = AK::Duration::from_seconds(1);

// A single make-up gain point for audio delivered by this track's source.
// FIXME: This is where the autoGainControl constraint belongs once constraint processing can
//        negotiate it; until then the track source applies unity gain.
static constexpr float TRACK_SOURCE_GAIN = 1.0f;

void AudioFrameFanout::add_sink(NonnullRefPtr<AudioFrameSink> sink)
{
    MutexLocker locker(m_mutex);
    m_sinks.append(move(sink));
}

void AudioFrameFanout::remove_sink(AudioFrameSink const& sink)
{
    sink.deactivate();
    MutexLocker locker(m_mutex);
    m_sinks.remove_first_matching([&](auto const& existing) { return existing.ptr() == &sink; });
}

void AudioFrameFanout::deliver(float const* samples, size_t frame_count, u8 channel_count, u32 sample_rate)
{
    if (frame_count == 0 || channel_count == 0)
        return;

    // Snapshot the sinks so a slow consumer never holds up add/remove on other threads.
    Vector<NonnullRefPtr<AudioFrameSink>> sinks;
    {
        MutexLocker locker(m_mutex);
        sinks = m_sinks;
    }
    if (sinks.is_empty())
        return;

    auto sample_count = frame_count * channel_count;
    if (m_silenced.load(AK::MemoryOrder::memory_order_relaxed)) {
        // A muted or disabled track delivers silence in the same shape as the live signal,
        // so consumers keep observing the track's timing and format.
        // https://w3c.github.io/mediacapture-main/#dfn-enabled
        m_scratch.resize(sample_count);
        m_scratch.span().fill(0.f);
        samples = m_scratch.data();
    } else if constexpr (TRACK_SOURCE_GAIN != 1.0f) {
        m_scratch.resize(sample_count);
        for (size_t sample_index = 0; sample_index < sample_count; ++sample_index)
            m_scratch[sample_index] = samples[sample_index] * TRACK_SOURCE_GAIN;
        samples = m_scratch.data();
    }

    // AudioBlock consumers accept at most 1024 frames per delivery.
    for (size_t offset = 0; offset < frame_count; offset += 1024) {
        auto frames = min(static_cast<size_t>(1024), frame_count - offset);
        for (auto const& sink : sinks)
            sink->deliver(samples + offset * channel_count, frames, channel_count, sample_rate);
    }
}

MediaStreamTrack::MediaStreamTrack()
    : DOM::EventTarget()
    , m_audio_fanout(adopt_ref(*new AudioFrameFanout))
{
}

MediaStreamTrack::~MediaStreamTrack() = default;

// https://w3c.github.io/mediacapture-main/#mediastreamtrack
GC::Ref<MediaStreamTrack> MediaStreamTrack::create(MediaStreamTrackKind kind, Optional<Utf16String> label, bool muted)
{
    // https://w3c.github.io/mediacapture-main/#dfn-create-a-mediastreamtrack
    // 1. Let track be a new object of type source's MediaStreamTrack source type.
    auto track = GC::Heap::the().allocate<MediaStreamTrack>();
    track->initialize_track(kind, move(label), muted);

    // FIXME: 2. If mediaDevicesToTieSourceTo is not null, tie track source to MediaDevices with source and mediaDevicesToTieSourceTo.
    // FIXME: 3. Run source's MediaStreamTrack source-specific construction steps with track as parameter.

    // 4. Return track.
    return track;
}

void MediaStreamTrack::initialize_track(MediaStreamTrackKind kind, Optional<Utf16String> label, bool muted)
{
    // Initialize track with the following internal slots.
    // NB: [[Source]], initialized to source, is set by whoever makes the track, for the sources that are objects.

    // [[Id]]: See MediaStream.id attribute for guidelines on how to generate such an identifier.
    m_id = Utf16String::from_utf8(Crypto::generate_random_uuid());

    // [[Kind]]: "audio" if source is an audio source, or "video" if source is a video source.
    m_kind = kind;

    // [[Label]]: source label or empty string.
    m_label = label.value_or({});

    // [[ReadyState]]: "live".
    m_state = MediaStreamTrackState::Live;

    // [[Enabled]]: true.
    m_enabled = true;

    // [[Muted]]: true if source is muted, false otherwise.
    m_muted = muted;
    update_audio_silence_state();

    // [[Capabilities]], [[Constraints]], and [[Settings]], all initialized as specified in the ConstrainablePattern.
    // [[Restrictable]], initialized to false.
    m_provider_id = s_next_provider_id.fetch_add(1, AK::MemoryOrder::memory_order_relaxed);
}

GC::Ref<MediaStreamTrack> MediaStreamTrack::allocate_clone() const
{
    return GC::Heap::the().allocate<MediaStreamTrack>();
}

void MediaStreamTrack::set_settings(MediaTrackSettings settings)
{
    m_settings = move(settings);
}

// https://w3c.github.io/mediacapture-main/#dom-mediastreamtrack-enabled
void MediaStreamTrack::set_enabled(bool enabled)
{
    // On setting, it must be set to the new value.
    m_enabled = enabled;

    // If a track is disabled, meaning enabled is false, the track's source only provides
    // silence (for audio) or black frames (for video). The source itself keeps running so
    // that re-enabling the track is cheap.
    update_audio_silence_state();
}

// https://w3c.github.io/mediacapture-main/#dom-mediastreamtrack-stop
void MediaStreamTrack::stop()
{
    // 1. Let track be the current MediaStreamTrack object.
    // 2. If track's [[ReadyState]] is "ended", then abort these steps.
    if (m_state == MediaStreamTrackState::Ended)
        return;

    // 3. Notify track's source that track is ended.
    // NB: Every track of a device holds a stream of it, and the process keeps the device's capture open while any does.
    stop_audio_capture();
    stop_video_encoders();
    m_last_video_picture = nullptr;
    if (auto source = move(m_video_picture_source))
        source->remove_track(*this);

    // 4. Set track's [[ReadyState]] to "ended".
    m_state = MediaStreamTrackState::Ended;

    update_audio_silence_state();
}

// https://w3c.github.io/mediacapture-main/#set-track-muted
void MediaStreamTrack::set_muted(bool muted)
{
    // 1. If track.[[Muted]] is already newState, then abort these steps.
    if (m_muted == muted)
        return;

    // 2. Set track.[[Muted]] to newState.
    m_muted = muted;
    update_audio_silence_state();

    // 3. If newState is true let eventName be mute, otherwise unmute.
    // 4. Fire an event named eventName on track.
    dispatch_event(DOM::Event::create(muted ? HTML::EventNames::mute : HTML::EventNames::unmute,
        HighResolutionTime::current_high_resolution_time(HTML::current_global_object())));
}

void MediaStreamTrack::set_onmute(WebIDL::CallbackType* callback)
{
    set_event_handler_attribute(HTML::EventNames::mute, callback);
}

WebIDL::CallbackType* MediaStreamTrack::onmute()
{
    return event_handler_attribute(HTML::EventNames::mute);
}

void MediaStreamTrack::set_onunmute(WebIDL::CallbackType* callback)
{
    set_event_handler_attribute(HTML::EventNames::unmute, callback);
}

WebIDL::CallbackType* MediaStreamTrack::onunmute()
{
    return event_handler_attribute(HTML::EventNames::unmute);
}

void MediaStreamTrack::set_onended(WebIDL::CallbackType* callback)
{
    set_event_handler_attribute(HTML::EventNames::ended, callback);
}

WebIDL::CallbackType* MediaStreamTrack::onended()
{
    return event_handler_attribute(HTML::EventNames::ended);
}

void MediaStreamTrack::end()
{
    if (m_state == MediaStreamTrackState::Ended)
        return;
    stop();
    dispatch_event(DOM::Event::create(HTML::EventNames::ended,
        HighResolutionTime::current_high_resolution_time(HTML::current_global_object())));
}

// https://w3c.github.io/mediacapture-main/#dom-mediastreamtrack-clone
GC::Ref<MediaStreamTrack> MediaStreamTrack::clone() const
{
    // When the clone() method is invoked, the User Agent MUST return the result of clone a track with this.
    // https://w3c.github.io/mediacapture-main/#clone-a-track
    // 1. Let track be the MediaStreamTrack object to be cloned.
    //
    // 2. Let source be track's [[Source]].
    // NB: Only the sources of pictures are objects. The clone is given this track's further down.

    // 3. Let trackClone be the result of creating a MediaStreamTrack with source and null.
    auto track_clone = allocate_clone();
    track_clone->initialize_track(m_kind, m_label, m_muted);

    // 4. Set trackClone's [[ReadyState]] to track's [[ReadyState]] value.
    track_clone->m_state = m_state;
    // 5. FIXME: Set trackClone's [[Capabilities]] to a clone of track's [[Capabilities]].
    // 6. Set trackClone's [[Constraints]] to a clone of track's [[Constraints]].
    track_clone->m_constraints = m_constraints;
    // 7. Set trackClone's [[Settings]] to a clone of track's [[Settings]].
    track_clone->m_settings = m_settings;

    // Initialize the remaining internal slots to match the source track.
    track_clone->m_enabled = m_enabled;
    track_clone->update_audio_silence_state();
    track_clone->m_provider_id = s_next_provider_id.fetch_add(1, AK::MemoryOrder::memory_order_relaxed);

    // 8. Run source MediaStreamTrack source-specific clone steps with track and trackClone as parameters.
    // NB: The one source Ladybird captures from is the microphone, whose tracks end when the permission is taken away;
    //     the clone of such a track ends with it.
    if (auto media_devices = m_media_devices.ptr()) {
        media_devices->track_was_cloned({}, track_clone);
        track_clone->m_media_devices = m_media_devices;
    }
    if (track_clone->m_state == MediaStreamTrackState::Live && is_audio() && device_id().has_value())
        track_clone->start_audio_capture();
    if (track_clone->m_state == MediaStreamTrackState::Live && m_video_picture_source) {
        track_clone->set_video_picture_source(*m_video_picture_source);
        // The clone shows what this track is showing, without waiting for the source to have something new.
        track_clone->m_last_video_picture = m_last_video_picture;
    }

    // 9. Return trackClone.
    return track_clone;
}

void MediaStreamTrack::set_media_devices(Badge<MediaDevices>, MediaDevices& media_devices)
{
    m_media_devices = media_devices;
}

bool MediaStreamTrack::is_audio() const
{
    return m_kind == MediaStreamTrackKind::Audio;
}

bool MediaStreamTrack::is_video() const
{
    return m_kind == MediaStreamTrackKind::Video;
}

Optional<Utf16String> MediaStreamTrack::device_id() const
{
    return m_settings.device_id;
}

u32 MediaStreamTrack::sample_rate_hz() const
{
    if (m_settings.sample_rate.has_value())
        return *m_settings.sample_rate;
    return 0;
}

u32 MediaStreamTrack::channel_count() const
{
    if (m_settings.channel_count.has_value())
        return *m_settings.channel_count;
    return 0;
}

// https://w3c.github.io/mediacapture-main/#dom-mediastreamtrack-getconstraints
MediaTrackConstraints const& MediaStreamTrack::get_constraints() const
{
    return m_constraints;
}

// https://w3c.github.io/mediacapture-main/#dom-mediastreamtrack-getsettings
MediaTrackSettings const& MediaStreamTrack::get_settings() const
{
    return m_settings;
}

// https://w3c.github.io/mediacapture-main/#dom-mediastreamtrack-applyconstraints
GC::Ref<WebIDL::Promise> MediaStreamTrack::apply_constraints(JS::Object const& relevant_global_object, Optional<MediaTrackConstraints> constraints)
{
    apply_constraints_impl(move(constraints));
    return WebIDL::create_resolved_promise_for(relevant_global_object, JS::js_undefined());
}

// https://w3c.github.io/mediacapture-main/#dom-mediastreamtrack-applyconstraints
void MediaStreamTrack::apply_constraints_impl(Optional<MediaTrackConstraints> constraints)
{
    if (constraints.has_value())
        m_constraints = constraints.release_value();

    // FIXME: Apply constraints to the underlying source and update settings.
}

void MediaStreamTrack::add_audio_sink(NonnullRefPtr<AudioFrameSink> sink)
{
    m_audio_fanout->add_sink(move(sink));
}

void MediaStreamTrack::remove_audio_sink(AudioFrameSink const& sink)
{
    m_audio_fanout->remove_sink(sink);
}

void MediaStreamTrack::deliver_audio_frames(float const* samples, size_t frame_count, u8 channel_count, u32 sample_rate)
{
    m_audio_fanout->deliver(samples, frame_count, channel_count, sample_rate);
}

void MediaStreamTrack::add_video_sink(NonnullRefPtr<VideoFrameSink> sink)
{
    sink->needs_key_frame = true;
    m_video_sinks.append(move(sink));
    request_video_key_frame();
}

void MediaStreamTrack::remove_video_sink(VideoFrameSink const& sink)
{
    m_video_sinks.remove_first_matching([&](auto const& existing) { return existing.ptr() == &sink; });
    stop_unwanted_video_encoders();
}

void MediaStreamTrack::deliver_video_frame(EncodedVideoFrame const& frame)
{
    // FIXME: A muted or disabled track should render black frames rather than nothing.
    //        https://w3c.github.io/mediacapture-main/#dfn-enabled
    auto is_rendering = m_enabled && !m_muted && m_state == MediaStreamTrackState::Live;

    auto key_frame_is_needed = false;
    // A sink may remove itself, or add another, while it is given the frame.
    auto sinks = m_video_sinks;
    for (auto const& sink : sinks) {
        if (!is_rendering) {
            sink->needs_key_frame = true;
            continue;
        }
        if (sink->needs_key_frame && !frame.is_key_frame) {
            key_frame_is_needed = true;
            continue;
        }
        sink->needs_key_frame = false;
        if (sink->on_frame)
            sink->on_frame(frame);
    }
    if (key_frame_is_needed)
        request_video_key_frame();
}

void MediaStreamTrack::request_video_key_frame()
{
    if (m_video_picture_source) {
        for (auto& [_, encoder] : m_video_encoders)
            encoder->request_key_frame();
        // The source may not have another picture for a while: a canvas has one when it is next drawn to.
        encode_last_video_picture();
        return;
    }
    if (on_video_key_frame_requested)
        on_video_key_frame_requested();
}

void MediaStreamTrack::set_video_picture_source(NonnullRefPtr<VideoPictureSource> source)
{
    VERIFY(is_video());
    VERIFY(!m_video_picture_source);
    m_video_picture_source = source;
    source->add_track(*this);
}

void MediaStreamTrack::deliver_video_picture(NonnullRefPtr<Media::I420Picture> picture)
{
    if (m_state != MediaStreamTrackState::Live)
        return;
    m_last_video_picture = move(picture);
    encode_last_video_picture();
}

// The codec a sink gets a track's pictures in when it doesn't ask for one.
static Media::CodecID codec_for(VideoFrameSink const& sink)
{
    return sink.codec.value_or(VideoTrackEncoder::supported_codecs().first());
}

// Everything that takes a track's video takes it encoded: an element plays it through a pipeline in another process,
// which decodes what it is sent, and a sender sends it. A sender says which codec it sends.
// FIXME: A sender should encode for itself, at the bitrate that was negotiated for it and that the network allows.
void MediaStreamTrack::encode_last_video_picture()
{
    if (!m_last_video_picture || m_video_sinks.is_empty())
        return;
    // FIXME: A muted or disabled track should render black frames rather than nothing.
    //        https://w3c.github.io/mediacapture-main/#dfn-enabled
    if (!m_enabled || m_muted)
        return;

    auto now = MonotonicTime::now();
    if (!m_first_video_picture_time.has_value())
        m_first_video_picture_time = now;
    m_last_video_encode_time = now;

    for (auto const& sink : m_video_sinks) {
        auto codec = codec_for(sink);
        if (m_video_encoders.contains(codec))
            continue;
        m_video_encoders.set(codec, VideoTrackEncoder::create(codec, [weak_track = GC::Weak { *this }](Media::CodecID codec_id, bool is_key_frame, AK::Duration timestamp, ByteBuffer data) {
            if (auto track = weak_track.ptr())
                track->deliver_encoded_video_picture({ .codec_id = codec_id, .is_key_frame = is_key_frame, .timestamp = timestamp, .data = data.bytes() });
        }));
    }
    for (auto& [_, encoder] : m_video_encoders)
        encoder->encode(*m_last_video_picture, now - *m_first_video_picture_time);

    // Repeat the last picture of an idle source so receivers can distinguish it from a lost stream and detect gaps.
    if (!m_video_refresh_timer) {
        m_video_refresh_timer = Core::Timer::create_repeating(VIDEO_REFRESH_INTERVAL, [weak_track = GC::Weak { *this }] {
            auto track = weak_track.ptr();
            if (track && MonotonicTime::now() - track->m_last_video_encode_time >= VIDEO_REFRESH_INTERVAL)
                track->encode_last_video_picture();
        });
        m_video_refresh_timer->start();
    }
}

void MediaStreamTrack::deliver_encoded_video_picture(EncodedVideoFrame const& frame)
{
    auto is_rendering = m_enabled && !m_muted && m_state == MediaStreamTrackState::Live;
    auto key_frame_is_needed = false;
    // A sink may remove itself, or add another, while it is given the frame.
    auto sinks = m_video_sinks;
    for (auto const& sink : sinks) {
        if (codec_for(sink) != frame.codec_id)
            continue;
        if (!is_rendering) {
            sink->needs_key_frame = true;
            continue;
        }
        if (sink->needs_key_frame && !frame.is_key_frame) {
            key_frame_is_needed = true;
            continue;
        }
        sink->needs_key_frame = false;
        if (sink->on_frame)
            sink->on_frame(frame);
    }
    if (!key_frame_is_needed)
        return;
    // NB: The encoder has the picture this frame was made from, so it isn't given another to make the key frame from
    //     unless the source has stopped giving them; the refresh sees to that.
    if (auto encoder = m_video_encoders.get(frame.codec_id); encoder.has_value())
        (*encoder)->request_key_frame();
}

void MediaStreamTrack::stop_unwanted_video_encoders()
{
    Vector<Media::CodecID> unwanted;
    for (auto& [codec, _] : m_video_encoders) {
        if (!m_video_sinks.contains([&](auto const& sink) { return codec_for(sink) == codec; }))
            unwanted.append(codec);
    }
    for (auto codec : unwanted) {
        if (auto encoder = m_video_encoders.take(codec); encoder.has_value())
            (*encoder)->stop();
    }
    if (m_video_encoders.is_empty())
        m_video_refresh_timer = nullptr;
}

void MediaStreamTrack::stop_video_encoders()
{
    m_video_refresh_timer = nullptr;
    for (auto& [_, encoder] : m_video_encoders)
        encoder->stop();
    m_video_encoders.clear();
}

void MediaStreamTrack::start_audio_capture(GC::Ptr<GC::Function<void(ErrorOr<void>)>> on_started)
{
    if (m_audio_capture_stream || m_audio_capture_start_pending)
        return;

    // A device-backed track is tied to the mediaDevices that made it, and captures for its window's page. Another realm
    // can keep the track once that window is gone, as after its iframe is removed, and then it has no page to capture for.
    auto media_devices = m_media_devices.ptr();
    if (!media_devices) {
        if (on_started)
            on_started->function()(Error::from_errno(EIO));
        else
            stop();
        return;
    }

    m_audio_capture_start_pending = true;
    auto capture_request_id = ++m_audio_capture_request_id;

    ByteString device_id_string;
    if (auto id = device_id(); id.has_value())
        device_id_string = id->to_byte_string();

    auto stream_promise = media_devices->window().page().client().create_audio_record_stream(device_id_string,
        [fanout = m_audio_fanout](ReadonlyBytes data, Audio::SampleSpecification const& stream_specification) {
            // Runs on the audio backend's capture thread. Only the ref-counted fan-out is
            // captured here: the GC may reap the track while a callback is in flight, so the
            // callback must never reference the track itself.
            auto channel_count = stream_specification.channel_count();
            if (channel_count == 0)
                return;
            // RecordStream fragments contain complete interleaved stream frames.
            auto bytes_per_frame = sizeof(float) * channel_count;
            if (data.size() % bytes_per_frame != 0) {
                dbgln("MediaStreamTrack: Dropping unaligned audio capture fragment ({} bytes for {} channels)", data.size(), channel_count);
                return;
            }
            auto frame_count = data.size() / bytes_per_frame;
            if (frame_count == 0)
                return;
            fanout->deliver(reinterpret_cast<float const*>(data.data()), frame_count, channel_count, stream_specification.sample_rate());
        });
    // The promise's callbacks don't keep the track alive, so a track nothing else holds can be collected while its
    // capture start is pending, and then there's nothing left to start.
    stream_promise->when_resolved([weak_track = GC::Weak<MediaStreamTrack>(*this), capture_request_id, on_started = GC::Root(on_started)](NonnullRefPtr<Audio::RecordStream>& stream) {
        auto track = weak_track.ptr();
        if (!track || track->m_audio_capture_request_id != capture_request_id)
            return;
        track->m_audio_capture_start_pending = false;
        if (track->m_state != MediaStreamTrackState::Live)
            return;
        track->m_audio_capture_stream = stream;
        // The backend behind the stream is gone for good; a fresh stream picks the capture up again.
        stream->on_capture_lost = [weak_track = GC::Weak<MediaStreamTrack>(*track), capture_request_id] {
            auto track = weak_track.ptr();
            if (!track || track->m_audio_capture_request_id != capture_request_id)
                return;
            track->m_audio_capture_stream = nullptr;
            track->start_audio_capture();
        };
        stream->on_capture_revoked = [weak_track = GC::Weak<MediaStreamTrack>(*track), capture_request_id] {
            auto track = weak_track.ptr();
            if (!track || track->m_audio_capture_request_id != capture_request_id)
                return;
            track->audio_source_ended();
        };
        if (on_started)
            on_started->function()({});
    });
    stream_promise->when_rejected([weak_track = GC::Weak<MediaStreamTrack>(*this), capture_request_id, on_started = GC::Root(on_started)](Error& error) {
        auto track = weak_track.ptr();
        if (!track || track->m_audio_capture_request_id != capture_request_id)
            return;
        track->m_audio_capture_start_pending = false;
        if (on_started) {
            on_started->function()(Error::copy(error));
            return;
        }
        // A device the track can't capture from again has permanently ended production of live samples.
        track->audio_source_ended();
    });
}

void MediaStreamTrack::audio_source_ended()
{
    if (auto media_devices = m_media_devices.ptr())
        media_devices->track_source_ended({}, *this);
}

void MediaStreamTrack::video_source_ended()
{
    // A track that some MediaDevices made ends in a task, with its ended event; any other has nobody to tell.
    if (auto media_devices = m_media_devices.ptr())
        media_devices->track_source_ended({}, *this);
    else
        end();
}

void MediaStreamTrack::stop_audio_capture()
{
    m_audio_capture_start_pending = false;
    ++m_audio_capture_request_id;
    m_audio_capture_stream = nullptr;
}

void MediaStreamTrack::finalize()
{
    Base::finalize();

    // Tearing the capture stream down here cannot race a capture callback into freed memory:
    // the callback only references the atomically ref-counted fan-out, never this GC-managed
    // track.
    stop_audio_capture();
    stop_video_encoders();
    if (auto source = move(m_video_picture_source))
        source->remove_track(*this);
}

}
