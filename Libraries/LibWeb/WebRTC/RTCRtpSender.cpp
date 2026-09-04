/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCRtpSender.h>
#include <LibWeb/HTML/EventLoop/EventLoop.h>
#include <LibWeb/HTML/Scripting/TemporaryExecutionContext.h>
#include <LibWeb/MediaCapture/MediaStreamTrack.h>
#include <LibWeb/WebIDL/Promise.h>
#include <LibWeb/WebRTC/RTCPeerConnection.h>
#include <LibWeb/WebRTC/RTCRtpScriptTransform.h>
#include <LibWeb/WebRTC/RTCRtpSender.h>
#include <LibWeb/WebRTC/RTCSFrameSenderTransform.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCRtpSender);

GC::Ref<RTCRtpSender> RTCRtpSender::create(JS::Realm& realm, GC::Ref<RTCPeerConnection> connection, u64 sender_id, u32 ssrc)
{
    return realm.create<RTCRtpSender>(realm, connection, sender_id, ssrc);
}

RTCRtpSender::RTCRtpSender(JS::Realm& realm, GC::Ref<RTCPeerConnection> connection, u64 sender_id, u32 ssrc)
    : Bindings::GCAllocatedWrappable()
    , m_realm(realm)
    , m_connection(connection)
    , m_sender_id(sender_id)
    , m_ssrc(ssrc)
{
    // Seed [[SendEncodings]] with a single encoding mirroring the wire-side SSRC. This is what consumers like
    // Discord's EncryptionWorker read out of `getParameters().encodings[0].ssrc` to register their userId mapping.
    RTCRtpEncodingParameters encoding;
    encoding.ssrc = m_ssrc;
    m_send_encodings.append(move(encoding));
}

void RTCRtpSender::set_ssrc(u32 ssrc)
{
    m_ssrc = ssrc;
    if (m_send_encodings.is_empty())
        m_send_encodings.append({});
    m_send_encodings[0].ssrc = m_ssrc;
    // [[LastReturnedParameters]] is now stale; clear it so the next getParameters() rebuilds.
    m_last_returned_parameters = {};
}

RTCRtpSender::~RTCRtpSender() = default;

void RTCRtpSender::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
    visitor.visit(m_connection);
    visitor.visit(m_track);
    visitor.visit(m_transform);
}

void RTCRtpSender::set_track(GC::Ptr<MediaCapture::MediaStreamTrack> track)
{
    m_track = track;
    m_connection->on_sender_track_changed(*this);
}

RTCRtpSenderTransform RTCRtpSender::transform() const
{
    if (!m_transform)
        return Empty {};
    if (auto* script_transform = as_if<RTCRtpScriptTransform>(*m_transform))
        return GC::Ref { *script_transform };
    if (auto* sframe_transform = as_if<RTCSFrameSenderTransform>(*m_transform))
        return GC::Ref { *sframe_transform };
    return Empty {};
}

GC::Ptr<RTCRtpScriptTransform> RTCRtpSender::script_transform()
{
    if (!m_transform)
        return nullptr;
    return as_if<RTCRtpScriptTransform>(*m_transform);
}

void RTCRtpSender::set_transform(RTCRtpSenderTransform value)
{
    m_transform = value.visit(
        [](Empty) -> GC::Ptr<Bindings::Wrappable> { return nullptr; },
        [](GC::Ref<RTCSFrameSenderTransform> const& t) -> GC::Ptr<Bindings::Wrappable> { return t.ptr(); },
        [](GC::Ref<RTCRtpScriptTransform> const& t) -> GC::Ptr<Bindings::Wrappable> { return t.ptr(); });
    dbgln("RTCRtpSender::set_transform: transform set, kind={}", m_transform ? "set"sv : "null"sv);
    m_connection->on_sender_transform_changed(*this);
}

GC::Ref<WebIDL::Promise> RTCRtpSender::replace_track(GC::Ptr<MediaCapture::MediaStreamTrack> with_track)
{
    // FIXME: Implement the full spec algorithm. For now, swap the track and resolve.
    set_track(with_track);
    auto promise = WebIDL::create_promise(realm());
    WebIDL::resolve_promise(realm(), promise, JS::js_undefined());
    return promise;
}

// https://w3c.github.io/webrtc-pc/#dom-rtcrtpsender-setparameters
GC::Ref<WebIDL::Promise> RTCRtpSender::set_parameters(RTCRtpSendParameters const& parameters, RTCSetParameterOptions const&)
{
    // 1. Let parameters be the method's first argument.
    // 2. Let sender be the RTCRtpSender object on which setParameters is invoked.

    // FIXME: 3. Let transceiver be the RTCRtpTransceiver object associated with sender (i.e. sender is transceiver.[[Sender]]).
    // FIXME: 4. If transceiver.[[Stopping]] is true, return a promise rejected with a newly created InvalidStateError.

    // FIXME: 5. If sender.[[LastReturnedParameters]] is null, return a promise rejected with a newly created InvalidStateError.
    //        Real browsers strictly require a getParameters() round-trip before each setParameters(); we don't
    //        enforce that yet because some apps (e.g. Discord's setTransceiverEncodingParameters) call
    //        setParameters early in setup before any getParameters.

    // FIXME: 6. Validate parameters by running the following setParameters validation steps:
    //          6.1. Let encodings be parameters.encodings.
    //          6.2. Let codecs be parameters.codecs.
    //          6.3. Let choosableCodecs be codecs.
    //          6.4. If choosableCodecs is an empty list, set choosableCodecs to the list of implemented send codecs for transceiver's kind.
    //          6.5. Let N be the number of RTCRtpEncodingParameters stored in sender.[[SendEncodings]].
    //          6.6. If any of the following conditions are met, return a promise rejected with a newly created InvalidModificationError:
    //                  encodings.length is different from N.
    //                  encodings has been re-ordered.
    //                  Any parameter in parameters is marked as a Read-only parameter (such as RID) and has a value
    //                      that is different from the corresponding parameter value in sender.[[LastReturnedParameters]].
    //                      Note that this also applies to transactionId.
    //                  Any encoding in encodings contains a codec not found in choosableCodecs, using the codec
    //                      dictionary match algorithm with ignoreAsymmetricalParameters set to true.
    //          6.7. If transceiver kind is "audio", remove the scaleResolutionDownBy and maxFramerate members from
    //               all encodings that contain any of them.
    //          6.8. If transceiver kind is "video", then for each encoding in encodings that doesn't contain a
    //               scaleResolutionDownBy member, add a scaleResolutionDownBy member with the value 1.0.
    //          6.9. If transceiver kind is "video", and any encoding in encodings contains a scaleResolutionDownBy
    //               member whose value is less than 1.0, return a promise rejected with a newly created RangeError.
    //          6.10. Verify that each encoding in encodings has a maxFramerate member whose value is greater than
    //                or equal to 0.0. If one of the maxFramerate values does not meet this requirement, return a
    //                promise rejected with a newly created RangeError.
    //          6.11. If the user agent does not support setting the codec for any encoding or mixing different
    //                codec values on the different encodings, return a promise rejected with a newly created OperationError.

    // 7. Let p be a new promise.
    auto p = WebIDL::create_promise(realm());

    // 8. In parallel, configure the media stack to use parameters to transmit sender.[[SenderTrack]].
    //    FIXME: actually wire `parameters` into the media stack (bitrate caps, encoding rid, etc).
    HTML::queue_a_task(HTML::Task::Source::Networking, nullptr, nullptr, GC::create_function(realm().heap(), [this, p, parameters] {
        // Promise resolution calls into JS and needs a running execution context on the VM stack; tasks don't
        // come with one by default.
        HTML::TemporaryExecutionContext context(realm());
        // 8.1. If the media stack is successfully configured with parameters, queue a task to run the following steps:
        //   8.1.1. Set sender.[[LastReturnedParameters]] to null.
        m_last_returned_parameters = {};
        //   8.1.2. Set sender.[[SendEncodings]] to parameters.encodings.
        m_send_encodings = parameters.encodings;
        //   8.1.3. Resolve p with undefined.
        WebIDL::resolve_promise(realm(), p, JS::js_undefined());
        // 8.2. If any error occurred while configuring the media stack, queue a task to run the following steps:
        //   8.2.1. If an error occurred due to hardware resources not being available, reject p with a newly
        //          created RTCError whose errorDetail is set to "hardware-encoder-not-available" and abort
        //          these steps.
        //   8.2.2. If an error occurred due to a hardware encoder not supporting parameters, reject p with a
        //          newly created RTCError whose errorDetail is set to "hardware-encoder-error" and abort these
        //          steps.
        //   8.2.3. For all other errors, reject p with a newly created OperationError.
    }));

    // 9. Return p.
    return p;
}

// https://w3c.github.io/webrtc-pc/#dom-rtcrtpsender-getparameters
RTCRtpSendParameters RTCRtpSender::get_parameters()
{
    // 1. Let sender be the RTCRtpSender object on which the getter was invoked.

    // 2. If sender.[[LastReturnedParameters]] is not null, return sender.[[LastReturnedParameters]], and abort these steps.
    if (m_last_returned_parameters.has_value())
        return m_last_returned_parameters.value();

    // 3. Let result be a new RTCRtpSendParameters dictionary constructed as follows:
    RTCRtpSendParameters result;
    //    transactionId is set to a new unique identifier.
    // FIXME: assign a fresh transaction id.
    //    encodings is set to the value of the [[SendEncodings]] internal slot.
    result.encodings = m_send_encodings;
    //    The headerExtensions sequence is populated based on the header extensions that have been negotiated for sending.
    // FIXME: populate from negotiated header extensions.
    //    codecs is set to the value of the [[SendCodecs]] internal slot.
    // FIXME: populate from [[SendCodecs]].
    //    rtcp.cname is set to the CNAME of the associated RTCPeerConnection. rtcp.reducedSize is set to true if
    //        reduced-size RTCP has been negotiated for sending, and false otherwise.
    // FIXME: populate rtcp.cname and rtcp.reducedSize from the connection.

    // 4. Set sender.[[LastReturnedParameters]] to result.
    m_last_returned_parameters = result;

    // 5. Queue a task that sets sender.[[LastReturnedParameters]] to null.
    HTML::queue_a_task(HTML::Task::Source::Networking, nullptr, nullptr, GC::create_function(realm().heap(), [this] {
        m_last_returned_parameters = {};
    }));

    // 6. Return result.
    return result;
}

}
