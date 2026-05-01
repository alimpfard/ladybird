/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Function.h>
#include <AK/NonnullOwnPtr.h>
#include <AK/NonnullRefPtr.h>
#include <AK/Vector.h>

namespace Audio {
class PulseAudioRecordStream;
}

namespace Web::WebRTC {

// Captures interleaved 48 kHz stereo s16 from the system default recording device,
// frames at 20 ms (960 samples per channel), and hands each frame to the configured
// callback. Backed by libmedia's PulseAudio wrapper. The callback runs on the PA
// main-loop thread, so the receiver should either be thread-safe or repost the
// frame to its own thread.
class AudioCaptureSession {
    AK_MAKE_NONCOPYABLE(AudioCaptureSession);
    AK_MAKE_NONMOVABLE(AudioCaptureSession);

public:
    using FrameCallback = Function<void(ReadonlyBytes /* interleaved s16 48k stereo, exactly 20 ms */)>;

    static OwnPtr<AudioCaptureSession> start(FrameCallback);
    ~AudioCaptureSession();

private:
    explicit AudioCaptureSession(FrameCallback);
    void on_pulse_audio_data(ReadonlyBytes /* float32 LE interleaved */, size_t channel_count);

    FrameCallback m_on_frame;
    RefPtr<Audio::PulseAudioRecordStream> m_record_stream;
    Vector<i16> m_accumulator;
};

}
