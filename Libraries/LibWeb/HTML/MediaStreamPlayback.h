/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Function.h>
#include <AK/NonnullOwnPtr.h>
#include <AK/NonnullRefPtr.h>
#include <AK/Optional.h>
#include <AK/RefPtr.h>
#include <AK/Vector.h>
#include <LibGC/Ptr.h>
#include <LibGC/Weak.h>
#include <LibMedia/Track.h>
#include <LibMediaClient/Forward.h>
#include <LibWeb/Forward.h>
#include <LibWeb/MediaCapture/MediaStream.h>
#include <LibWeb/MediaCapture/MediaStreamTrack.h>

namespace Web::HTML {

// Feeds srcObject tracks into the element's playback as live sources, keeping them synchronized and subject to
// the element's controls.
// https://w3c.github.io/mediacapture-main/#mediastreams-in-media-elements
class MediaStreamPlayback final : public MediaCapture::MediaStream::Observer {
    AK_MAKE_NONCOPYABLE(MediaStreamPlayback);
    AK_MAKE_NONMOVABLE(MediaStreamPlayback);
    AK_ALLOC_WITH_KMALLOC;

public:
    // The playback manager must outlive this.
    static NonnullOwnPtr<MediaStreamPlayback> create(MediaClient::RemotePlaybackManager&, MediaCapture::MediaStream&);
    virtual ~MediaStreamPlayback() override;

    // Called once the playback knows a track of the stream, with what it knows it as.
    Function<void(Media::Track const&)> on_track_added;

    // Stops feeding the playback. This must happen before the garbage collector may have collected the stream.
    void stop();

    struct AudioInput;

private:
    MediaStreamPlayback(MediaClient::RemotePlaybackManager&, MediaCapture::MediaStream&);

    virtual void media_stream_tracks_changed() override;

    struct Subscription {
        GC::Weak<MediaCapture::MediaStreamTrack> track;
        // Unset while the track has given nothing to play.
        Optional<u64> live_source_id;
        RefPtr<MediaCapture::AudioFrameSink> audio_sink;
        RefPtr<AudioInput> audio_input;
        RefPtr<MediaCapture::VideoFrameSink> video_sink;
    };

    void update_subscriptions();
    void subscribe(MediaCapture::MediaStreamTrack&);
    void unsubscribe(Subscription&);
    void announce_live_source(MediaClient::RemotePlaybackManager::LiveSource const&);
    Subscription* find_subscription_for_live_source(u64 live_source_id);

    MediaClient::RemotePlaybackManager& m_playback_manager;
    GC::Weak<MediaCapture::MediaStream> m_stream;
    Vector<Subscription> m_subscriptions;
};

}
