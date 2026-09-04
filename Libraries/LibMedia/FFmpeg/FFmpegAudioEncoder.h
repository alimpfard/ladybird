/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/ByteBuffer.h>
#include <AK/NonnullOwnPtr.h>
#include <AK/Time.h>
#include <LibMedia/AudioBlock.h>
#include <LibMedia/CodecID.h>
#include <LibMedia/DecoderError.h>
#include <LibMedia/Export.h>
#include <LibMedia/FFmpeg/FFmpegForward.h>

namespace Media::FFmpeg {

// Encodes interleaved float PCM into a codec stream (currently used for opus).
// Mirrors the shape of FFmpegAudioDecoder: feed PCM via receive_pcm_data, then
// drain encoded packets via write_next_packet until it reports NeedsMoreInput.
class MEDIA_API FFmpegAudioEncoder final {
public:
    struct Packet {
        ByteBuffer data;
        AK::Duration timestamp;
        AK::Duration duration;
    };

    static DecoderErrorOr<NonnullOwnPtr<FFmpegAudioEncoder>> try_create(CodecID, Audio::SampleSpecification const&, int bitrate);
    FFmpegAudioEncoder(AVCodecContext*, AVPacket*, AVFrame*);
    ~FFmpegAudioEncoder();

    int frame_size() const;

    DecoderErrorOr<void> receive_pcm_data(AK::Duration timestamp, AudioBlock const& block);
    DecoderErrorOr<bool> write_next_packet(Packet& out);
    void signal_end_of_stream();
    void flush();

private:
    AVCodecContext* m_codec_context;
    AVPacket* m_packet;
    AVFrame* m_frame;
};

}
