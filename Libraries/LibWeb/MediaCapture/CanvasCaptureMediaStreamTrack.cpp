/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibCore/Timer.h>
#include <LibGC/Heap.h>
#include <LibGfx/DecodedImageFrame.h>
#include <LibWeb/HTML/HTMLCanvasElement.h>
#include <LibWeb/MediaCapture/CanvasCaptureMediaStreamTrack.h>

namespace Web::MediaCapture {

GC_DEFINE_ALLOCATOR(CanvasCaptureMediaStreamTrack);

// A canvas that is drawn to more often than this is captured this often, unless the page asked for less.
static constexpr double MAXIMUM_FRAME_RATE = 60;

NonnullRefPtr<CanvasCaptureSource> CanvasCaptureSource::create(HTML::HTMLCanvasElement& canvas, Optional<double> frame_request_rate)
{
    return adopt_ref(*new CanvasCaptureSource(canvas, frame_request_rate));
}

CanvasCaptureSource::CanvasCaptureSource(HTML::HTMLCanvasElement& canvas, Optional<double> frame_request_rate)
    : m_canvas(canvas)
    , m_frame_request_rate(frame_request_rate)
{
}

CanvasCaptureSource::~CanvasCaptureSource() = default;

// https://w3c.github.io/mediacapture-fromelement/#dom-htmlcanvaselement-capturestream
void CanvasCaptureSource::canvas_content_changed()
{
    // If frameRequestRate is not set, a new frame is captured each time the canvas changes. If it is set, it is an
    // upper bound on the rate at which frames are captured. If it is 0, frames are not captured automatically, and
    // are only captured when requestFrame() is called.
    if (m_frame_request_rate == 0.0)
        return;
    schedule_capture();
}

void CanvasCaptureSource::request_frame()
{
    m_last_capture_time = {};
    schedule_capture();
}

void CanvasCaptureSource::schedule_capture()
{
    if (m_timer || !has_tracks())
        return;

    // NB: Capture in a separate task to include all drawing from the current script.
    auto frame_rate = MAXIMUM_FRAME_RATE;
    if (m_frame_request_rate.has_value() && *m_frame_request_rate > 0)
        frame_rate = min(frame_rate, *m_frame_request_rate);
    auto interval = AK::Duration::from_microseconds(static_cast<i64>(1'000'000 / frame_rate));
    auto delay = AK::Duration::zero();
    if (m_last_capture_time.has_value())
        delay = max(delay, interval - (MonotonicTime::now() - *m_last_capture_time));

    m_timer = Core::Timer::create_single_shot(delay, [this] {
        m_timer = nullptr;
        capture();
    });
    m_timer->start();
}

void CanvasCaptureSource::capture()
{
    auto canvas = m_canvas.ptr();
    if (!canvas || !has_tracks())
        return;

    // A captured stream MUST immediately cease to capture content when the origin-clean flag of the source canvas
    // becomes false after the stream is created by captureStream().
    if (!canvas->is_origin_clean())
        return;

    m_last_capture_time = MonotonicTime::now();

    auto size = canvas->bitmap_size_for_canvas();
    if (size.is_empty())
        return;

    ErrorOr<NonnullRefPtr<Media::I420Picture>> picture = Error::from_string_literal("Canvas has no bitmap");
    if (auto frame = canvas->get_srgb_frame_from_surface(); frame.has_value()) {
        if (!canvas->is_origin_clean())
            return;
        auto width = static_cast<u32>(frame->width());
        auto height = static_cast<u32>(frame->height());
        switch (frame->format()) {
        case Gfx::BitmapFormat::BGRx8888:
        case Gfx::BitmapFormat::BGRA8888:
            picture = Media::I420Picture::from_bgra(frame->pixels(), width, height, frame->pitch());
            break;
        case Gfx::BitmapFormat::RGBx8888:
        case Gfx::BitmapFormat::RGBA8888:
            picture = Media::I420Picture::from_rgba(frame->pixels(), width, height, frame->pitch());
            break;
        case Gfx::BitmapFormat::Invalid:
            break;
        }
    } else {
        // A canvas that has had nothing drawn to it is transparent black, which a video shows as black.
        picture = Media::I420Picture::create(static_cast<u32>(size.width()), static_cast<u32>(size.height()));
        if (!picture.is_error()) {
            picture.value()->y().fill(16);
            picture.value()->u().fill(128);
            picture.value()->v().fill(128);
        }
    }
    if (picture.is_error())
        return;

    // Delivering the picture can stop the last of the tracks that keep this source going.
    NonnullRefPtr protector { *this };
    deliver(picture.release_value());
}

GC::Ref<CanvasCaptureMediaStreamTrack> CanvasCaptureMediaStreamTrack::create(HTML::HTMLCanvasElement& canvas, NonnullRefPtr<CanvasCaptureSource> source)
{
    auto track = GC::Heap::the().allocate<CanvasCaptureMediaStreamTrack>(canvas, source);
    track->initialize_track(MediaStreamTrackKind::Video, {}, false);
    track->set_video_picture_source(move(source));
    return track;
}

CanvasCaptureMediaStreamTrack::CanvasCaptureMediaStreamTrack(HTML::HTMLCanvasElement& canvas, NonnullRefPtr<CanvasCaptureSource> source)
    : m_canvas(canvas)
    , m_source(move(source))
{
}

CanvasCaptureMediaStreamTrack::~CanvasCaptureMediaStreamTrack() = default;

// https://w3c.github.io/mediacapture-fromelement/#dom-canvascapturemediastreamtrack-requestframe
void CanvasCaptureMediaStreamTrack::request_frame()
{
    // Applications that depend on tight control over the rendering of content to the media stream can use this
    // method to control when frames from the canvas are captured.
    if (track_ready_state() == MediaStreamTrackState::Live)
        m_source->request_frame();
}

GC::Ref<MediaStreamTrack> CanvasCaptureMediaStreamTrack::allocate_clone() const
{
    return GC::Heap::the().allocate<CanvasCaptureMediaStreamTrack>(*m_canvas, m_source);
}

void CanvasCaptureMediaStreamTrack::visit_edges(Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_canvas);
}

}
