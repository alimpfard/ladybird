/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/ByteBuffer.h>
#include <AK/Math.h>
#include <AK/OwnPtr.h>
#include <LibMedia/Audio/PulseAudioWrappers.h>
#include <LibWeb/WebRTC/AudioCaptureSession.h>

namespace Web::WebRTC {

static constexpr u32 SAMPLE_RATE_HZ = 48000;
static constexpr u8 CHANNEL_COUNT = 2;
static constexpr size_t FRAME_SAMPLES_PER_CHANNEL = 960; // 20 ms @ 48 kHz
static constexpr size_t FRAME_INTERLEAVED_SAMPLES = FRAME_SAMPLES_PER_CHANNEL * CHANNEL_COUNT;

OwnPtr<AudioCaptureSession> AudioCaptureSession::start(FrameCallback callback)
{
    auto context_or_err = Audio::PulseAudioContext::the();
    if (context_or_err.is_error()) {
        dbgln("AudioCaptureSession: PulseAudioContext::the() failed: {}", context_or_err.error());
        return {};
    }
    auto context = context_or_err.release_value();

    Audio::SampleSpecification spec(SAMPLE_RATE_HZ, Audio::ChannelMap::stereo());
    constexpr u32 fragment_size_bytes = FRAME_INTERLEAVED_SAMPLES * sizeof(float);

    auto session = adopt_own(*new AudioCaptureSession(move(callback)));
    auto* session_ptr = session.ptr();
    auto stream_or_err = context->create_record_stream(spec, fragment_size_bytes, /* default device */ nullptr,
        [session_ptr](ReadonlyBytes data, Audio::SampleSpecification const& sample_spec) {
            session_ptr->on_pulse_audio_data(data, sample_spec.channel_count());
        });
    if (stream_or_err.is_error()) {
        dbgln("AudioCaptureSession: create_record_stream failed: {}", stream_or_err.error());
        return {};
    }
    session->m_record_stream = stream_or_err.release_value();
    dbgln("AudioCaptureSession: started, format=float32 48kHz stereo, frame_size=20ms");
    return session;
}

AudioCaptureSession::AudioCaptureSession(FrameCallback callback)
    : m_on_frame(move(callback))
{
}

AudioCaptureSession::~AudioCaptureSession() = default;

void AudioCaptureSession::on_pulse_audio_data(ReadonlyBytes data, size_t channel_count)
{
    // Convert PA's float32 LE samples to interleaved s16. PA gives us the channel
    // count from the stream's spec (= 2 in our setup).
    if (channel_count == 0)
        return;
    auto float_count = data.size() / sizeof(float);
    if (float_count == 0)
        return;
    auto const* floats = reinterpret_cast<float const*>(data.data());
    auto previous_size = m_accumulator.size();
    m_accumulator.resize(previous_size + float_count);
    // FIXME: ad-hoc input gain. PulseAudio's mic level on this hardware tops out
    // around -42 dBFS even at full speech, so we boost on the way to opus.
    // Once we expose a proper input-gain control via getUserMedia constraints
    // (or wire pavucontrol's stream volume), this constant should go away.
    constexpr float CAPTURE_GAIN = 50.0f;
    for (size_t i = 0; i < float_count; ++i) {
        auto sample = AK::clamp(floats[i] * CAPTURE_GAIN, -1.0f, 1.0f);
        m_accumulator[previous_size + i] = static_cast<i16>(sample * 32767.0f);
    }

    while (m_accumulator.size() >= FRAME_INTERLEAVED_SAMPLES) {
        ReadonlyBytes frame_bytes { reinterpret_cast<u8 const*>(m_accumulator.data()), FRAME_INTERLEAVED_SAMPLES * sizeof(i16) };
        if (m_on_frame)
            m_on_frame(frame_bytes);
        m_accumulator.remove(0, FRAME_INTERLEAVED_SAMPLES);
    }
}

}
