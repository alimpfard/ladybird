/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibCore/EventLoop.h>
#include <LibJS/Runtime/Map.h>
#include <LibMedia/Audio/PlaybackStream.h>
#include <LibMedia/AudioBlock.h>
#include <LibMedia/CodecID.h>
#include <LibMedia/CodedFrame.h>
#include <LibMedia/FFmpeg/FFmpegAudioConverter.h>
#include <LibMedia/FFmpeg/FFmpegAudioDecoder.h>
#include <LibMedia/FFmpeg/FFmpegAudioEncoder.h>
#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/RTCPeerConnection.h>
#include <LibWeb/DOM/Event.h>
#include <LibWeb/HTML/EventNames.h>
#include <LibWeb/HTML/Scripting/TemporaryExecutionContext.h>
#include <LibWeb/HighResolutionTime/TimeOrigin.h>
#include <LibWeb/MediaCapture/MediaStream.h>
#include <LibWeb/MediaCapture/MediaStreamTrack.h>
#include <LibWeb/WebIDL/ExceptionOr.h>
#include <LibWeb/WebIDL/Promise.h>
#include <LibWeb/WebRTC/RTCDataChannel.h>
#include <LibWeb/WebRTC/RTCDataChannelEvent.h>
#include <LibWeb/WebRTC/RTCEncodedAudioFrame.h>
#include <LibWeb/WebRTC/RTCIceCandidate.h>
#include <LibWeb/WebRTC/RTCPeerConnection.h>
#include <LibWeb/WebRTC/RTCPeerConnectionIceEvent.h>
#include <LibWeb/WebRTC/RTCRtpReceiver.h>
#include <LibWeb/WebRTC/RTCRtpScriptTransform.h>
#include <LibWeb/WebRTC/RTCRtpSender.h>
#include <LibWeb/WebRTC/RTCRtpTransceiver.h>
#include <LibWeb/WebRTC/RTCSctpTransport.h>
#include <LibWeb/WebRTC/RTCSessionDescription.h>
#include <LibWeb/WebRTC/RTCStatsReport.h>
#include <LibWeb/WebRTC/RTCTrackEvent.h>
#include <LibWeb/WebRTC/WebRTCAgent.h>
#include <LibWebRTCClient/Client.h>

namespace Web::WebRTC {

GC_DEFINE_ALLOCATOR(RTCPeerConnection);

WebIDL::ExceptionOr<GC::Ref<RTCPeerConnection>> RTCPeerConnection::construct_impl(JS::Realm& realm, RTCConfiguration const& configuration)
{
    return realm.create<RTCPeerConnection>(realm, configuration);
}

RTCPeerConnection::RTCPeerConnection(JS::Realm& realm, RTCConfiguration configuration)
    : DOM::EventTarget()
    , m_realm(realm)
    , m_configuration(move(configuration))
{
    auto& agent = WebRTCAgent::the();
    m_pc_id = agent.next_pc_id();
    agent.register_peer_connection(m_pc_id, *this);
    if (auto* client = agent.client())
        client->async_create_peer_connection(m_pc_id);
}

RTCPeerConnection::~RTCPeerConnection()
{
    auto& agent = WebRTCAgent::the();
    if (auto* client = agent.client())
        client->async_close_peer_connection(m_pc_id);
    agent.unregister_peer_connection(m_pc_id);
}

void RTCPeerConnection::visit_edges(JS::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_realm);
    visitor.visit(m_sctp);
    visitor.visit(m_pending_void_requests);
    visitor.visit(m_pending_description_requests);
    visitor.visit(m_transceivers);
    visitor.visit(m_data_channels);
    visitor.visit(m_data_channels_by_id);
    visitor.visit(m_current_local_description);
    visitor.visit(m_pending_local_description);
    visitor.visit(m_current_remote_description);
    visitor.visit(m_pending_remote_description);
    visitor.visit(m_remote_streams);
    visitor.visit(m_remote_receivers_by_id);
    for (auto& [_, pipeline] : m_outgoing_audio_pipelines)
        visitor.visit(pipeline->track);
}

// https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close
void RTCPeerConnection::close()
{
    // When the close method is invoked, the user agent MUST run the following steps:
    // 1. Let connection be the RTCPeerConnection object on which the method was invoked.
    // 2. close the connection with connection and the value false.
    close_the_connection_algorithm(false);
}

// https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close
void RTCPeerConnection::close_the_connection_algorithm(bool disappear)
{
    // The close the connection algorithm given a connection and a disappear boolean, is as follows:
    // 1. If connection.[[IsClosed]] is true, abort these steps.
    if (m_is_closed)
        return;
    // 2.Set connection.[[IsClosed]] to true.
    m_is_closed = true;
    stop_outgoing_audio();
    auto& agent = WebRTCAgent::the();
    if (auto* client = agent.client())
        client->async_close_peer_connection(m_pc_id);
    agent.unregister_peer_connection(m_pc_id);
    for (auto const& entry : m_data_channels_by_id)
        agent.unregister_data_channel(entry.key);
    // 3. Set connection.[[SignalingState]] to "closed". This does not fire any event.
    m_signaling_state = Bindings::RTCSignalingState::Closed;
    // 4. Let transceivers be the result of executing the CollectTransceivers algorithm...
    auto transceivers = collect_transceivers();
    // 4... For every RTCRtpTransceiver transceiver in transceivers, run the following steps:
    for (auto& transceiver : transceivers) {
        // 4.1. If transceiver.[[Stopped]] is true, abort these sub steps.
        if (transceiver->is_stopped())
            break;
        // 4.2. Stop the RTCRtpTransceiver with transceiver and disappear.
        transceiver->stop(disappear);
    }
    // TODO: 5. Set the [[ReadyState]] slot of each of connection's RTCDataChannels to "closed".
    // 6. If connection.[[SctpTransport]] is not null...
    if (m_sctp) {
        // TODO: 6. ...tear down the underlying SCTP association by sending an SCTP ABORT chunk and set the [[SctpTransportState]] to "closed".
    }
    // TODO: 7. Set the [[DtlsTransportState]] slot of each of connection's RTCDtlsTransports to "closed".
    // TODO: 8. Destroy connection's ICE Agent, abruptly ending any active ICE processing and releasing any relevant resources (e.g. TURN permissions).
    // TODO: 9. Set the [[IceTransportState]] slot of each of connection's RTCIceTransports to "closed".
    // 10. Set connection.[[IceConnectionState]] to "closed". This does not fire any event.
    m_ice_connection_state = Bindings::RTCIceConnectionState::Closed;
    // 11. Set connection.[[ConnectionState]] to "closed". This does not fire any event.
    m_connection_state = Bindings::RTCPeerConnectionState::Closed;
}

// https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-createoffer
GC::Ref<WebIDL::Promise> RTCPeerConnection::create_offer(RTCOfferOptions const&)
{
    // 1. Let connection be the RTCPeerConnection object on which the method was invoked.
    auto& realm = this->realm();
    // 2. If connection.[[IsClosed]] is true, return a promise rejected with a newly created InvalidStateError.
    if (m_is_closed) {
        auto promise = WebIDL::create_promise(realm);
        WebIDL::reject_promise(realm, promise, WebIDL::InvalidStateError::create("RTCPeerConnection is closed"_utf16));
        return promise;
    }
    // FIXME: 3. Return the result of chaining the result of creating an offer with connection to connection's operations chain.
    return create_an_offer();
}

// https://www.w3.org/TR/webrtc/#create-an-offer
GC::Ref<WebIDL::Promise> RTCPeerConnection::create_an_offer()
{
    auto& realm = this->realm();
    // 1. If connection.[[SignalingState]] is neither "stable" nor "have-local-offer", return a promise rejected with a newly created InvalidStateError.
    if (m_signaling_state != Bindings::RTCSignalingState::Stable && m_signaling_state != Bindings::RTCSignalingState::HaveLocalOffer) {
        auto rejected = WebIDL::create_promise(realm);
        WebIDL::reject_promise(realm, rejected, WebIDL::InvalidStateError::create("RTCPeerConnection is not in a state to create an offer"_utf16));
        return rejected;
    }
    // 2. Let p be a new promise.
    auto p = WebIDL::create_promise(realm);
    // 3. In parallel, begin the in-parallel steps to create an offer given connection and p.
    //    Service-side equivalents (in parallel + the final-step queued task) are run by the rust
    //    WebRTCClient; result arrives via on_create_offer_result.
    auto& agent = WebRTCAgent::the();
    auto request_id = agent.next_request_id();
    m_pending_description_requests.set(request_id, p);
    if (auto* client = agent.client())
        client->async_create_offer(m_pc_id, request_id);
    // 4. Return p.
    return p;
}

// https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-createanswer
GC::Ref<WebIDL::Promise> RTCPeerConnection::create_answer(RTCAnswerOptions const&)
{
    auto& realm = this->realm();
    // 1. Let connection be the RTCPeerConnection object on which the method was invoked.
    // 2. If connection.[[IsClosed]] is true, return a promise rejected with a newly created InvalidStateError.
    if (m_is_closed) {
        auto rejected = WebIDL::create_promise(realm);
        WebIDL::reject_promise(realm, rejected, WebIDL::InvalidStateError::create("RTCPeerConnection is closed"_utf16));
        return rejected;
    }
    // FIXME: 3. Return the result of chaining the result of creating an answer with connection to connection's operations chain.
    return create_an_answer();
}

// https://www.w3.org/TR/webrtc/#create-an-answer
GC::Ref<WebIDL::Promise> RTCPeerConnection::create_an_answer()
{
    auto& realm = this->realm();
    // 1. If connection.[[SignalingState]] is neither "have-remote-offer" nor "have-local-pranswer", return a promise rejected with a newly created InvalidStateError.
    if (m_signaling_state != Bindings::RTCSignalingState::HaveRemoteOffer && m_signaling_state != Bindings::RTCSignalingState::HaveLocalPranswer) {
        auto rejected = WebIDL::create_promise(realm);
        WebIDL::reject_promise(realm, rejected, WebIDL::InvalidStateError::create("RTCPeerConnection is not in a state to create an answer"_utf16));
        return rejected;
    }
    // 2. Let p be a new promise.
    auto p = WebIDL::create_promise(realm);
    // 3. In parallel, begin the in-parallel steps to create an answer given connection and p.
    //    Service-side equivalents (in parallel + the final-step queued task) are run by the rust
    //    WebRTCClient; result arrives via on_create_answer_result.
    auto& agent = WebRTCAgent::the();
    auto request_id = agent.next_request_id();
    m_pending_description_requests.set(request_id, p);
    if (auto* client = agent.client())
        client->async_create_answer(m_pc_id, request_id);
    // 4. Return p.
    return p;
}

// https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-setlocaldescription
GC::Ref<WebIDL::Promise> RTCPeerConnection::set_local_description(RTCLocalSessionDescriptionInit const& description)
{
    auto& realm = this->realm();
    // 1. Let description be the method's first argument.
    // 2. Let connection be the RTCPeerConnection object on which the method was invoked.
    // 3. Let sdp be description.sdp.
    auto sdp = description.sdp;
    // FIXME: 4. Return the result of chaining the following steps to connection's operations chain:
    // 4.1. Let type be description.type if present, or "offer" if not present and connection.[[SignalingState]] is either "stable", "have-local-offer", or "have-remote-pranswer"; otherwise "answer".
    Bindings::RTCSdpType type;
    if (description.type.has_value()) {
        type = *description.type;
    } else if (m_signaling_state == Bindings::RTCSignalingState::Stable
        || m_signaling_state == Bindings::RTCSignalingState::HaveLocalOffer
        || m_signaling_state == Bindings::RTCSignalingState::HaveRemotePranswer) {
        type = Bindings::RTCSdpType::Offer;
    } else {
        type = Bindings::RTCSdpType::Answer;
    }
    // 4.2. If type is "offer", and sdp is not the empty string and not equal to connection.[[LastCreatedOffer]], then return a promise rejected with a newly created InvalidModificationError and abort these steps.
    if (type == Bindings::RTCSdpType::Offer && !sdp.is_empty() && sdp != m_last_created_offer) {
        auto rejected = WebIDL::create_promise(realm);
        WebIDL::reject_promise(realm, rejected, WebIDL::InvalidModificationError::create("Local description SDP does not match last created offer"_utf16));
        return rejected;
    }
    // 4.3. If type is "answer" or "pranswer", and sdp is not the empty string and not equal to connection.[[LastCreatedAnswer]], then return a promise rejected with a newly created InvalidModificationError and abort these steps.
    if ((type == Bindings::RTCSdpType::Answer || type == Bindings::RTCSdpType::Pranswer) && !sdp.is_empty() && sdp != m_last_created_answer) {
        auto rejected = WebIDL::create_promise(realm);
        WebIDL::reject_promise(realm, rejected, WebIDL::InvalidModificationError::create("Local description SDP does not match last created answer"_utf16));
        return rejected;
    }
    // 4.4. If sdp is the empty string, and type is "offer", then run the following sub steps:
    if (sdp.is_empty() && type == Bindings::RTCSdpType::Offer) {
        // 4.4.1. Set sdp to the value of connection.[[LastCreatedOffer]].
        sdp = m_last_created_offer;
        // FIXME: 4.4.2. If sdp is the empty string, or if it no longer accurately represents the offerer's system state of connection, then let p be the result of creating an offer with connection, and return the result of reacting to p with a fulfillment step that sets the local session description indicated by its first argument.
    }
    // 4.5. If sdp is the empty string, and type is "answer" or "pranswer", then run the following sub steps:
    if (sdp.is_empty() && (type == Bindings::RTCSdpType::Answer || type == Bindings::RTCSdpType::Pranswer)) {
        // 4.5.1. Set sdp to the value of connection.[[LastCreatedAnswer]].
        sdp = m_last_created_answer;
        // FIXME: 4.5.2. If sdp is the empty string, or if it no longer accurately represents the answerer's system state of connection, then let p be the result of creating an answer with connection, and return the result of reacting to p with the following fulfillment steps:
        //   FIXME: 4.5.2.1. Let answer be the first argument to these fulfillment steps.
        //   FIXME: 4.5.2.2. Return the result of setting the local session description indicated by {type, answer.sdp}.
    }
    // 4.6. Return the result of setting the local session description indicated by {type, sdp}.
    return set_a_local_description(type, sdp);
}

// FIXME: https://www.w3.org/TR/webrtc/#set-the-rtcsessiondescription (set the local session description)
GC::Ref<WebIDL::Promise> RTCPeerConnection::set_a_local_description(Bindings::RTCSdpType type, Utf16String const& sdp)
{
    auto& realm = this->realm();
    auto p = WebIDL::create_promise(realm);
    auto& agent = WebRTCAgent::the();
    auto request_id = agent.next_request_id();
    m_pending_void_requests.set(request_id, p);
    m_pending_description_payloads.set(request_id, PendingDescription { type, sdp, true });
    if (auto* client = agent.client())
        client->async_set_local_description(m_pc_id, request_id, idl_enum_to_string(type).to_utf8(), sdp.to_utf8());
    return p;
}

// https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-setremotedescription
GC::Ref<WebIDL::Promise> RTCPeerConnection::set_remote_description(RTCSessionDescriptionInit const& description)
{
    // 1. Let description be the method's first argument.
    // 2. Let connection be the RTCPeerConnection object on which the method was invoked.
    // FIXME: 3. Return the result of chaining the following steps to connection's operations chain:
    // FIXME: 3.1. If description.type is "offer" and is invalid for the current connection.[[SignalingState]] as described in [RFC9429] (section 5.5. and section 5.6.), then run the following sub steps:
    //   FIXME: 3.1.1. Let p be the result of setting the local session description indicated by {type: "rollback"}.
    //   FIXME: 3.1.2. Return the result of reacting to p with a fulfillment step that sets the remote session description description, and abort these steps.
    // 3.2. Return the result of setting the remote session description description.
    return set_a_remote_description(description);
}

// FIXME: https://www.w3.org/TR/webrtc/#set-description (set the remote session description)
GC::Ref<WebIDL::Promise> RTCPeerConnection::set_a_remote_description(RTCSessionDescriptionInit const& description)
{
    auto& realm = this->realm();
    auto p = WebIDL::create_promise(realm);
    auto& agent = WebRTCAgent::the();
    auto request_id = agent.next_request_id();
    m_pending_void_requests.set(request_id, p);
    m_pending_description_payloads.set(request_id, PendingDescription { description.type, description.sdp, false });
    if (auto* client = agent.client())
        client->async_set_remote_description(m_pc_id, request_id, idl_enum_to_string(description.type).to_utf8(), description.sdp.to_utf8());
    return p;
}

// https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-localdescription
GC::Ptr<RTCSessionDescription> RTCPeerConnection::local_description() const
{
    // The localDescription attribute MUST return [[PendingLocalDescription]] if not null and otherwise [[CurrentLocalDescription]].
    if (m_pending_local_description)
        return m_pending_local_description;
    return m_current_local_description;
}

// https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-remotedescription
GC::Ptr<RTCSessionDescription> RTCPeerConnection::remote_description() const
{
    // The remoteDescription attribute MUST return [[PendingRemoteDescription]] if not null and otherwise [[CurrentRemoteDescription]].
    if (m_pending_remote_description)
        return m_pending_remote_description;
    return m_current_remote_description;
}

// https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-getreceivers
Vector<GC::Ref<RTCRtpReceiver>> RTCPeerConnection::get_receivers() const
{
    // 1. Let transceivers be the result of executing the CollectTransceivers algorithm.
    auto transceivers = collect_transceivers();
    // 2. Let receivers be a new empty sequence.
    Vector<GC::Ref<RTCRtpReceiver>> receivers;
    // 3. For each transceiver in transceivers,
    for (auto& transceiver : transceivers) {
        // 3.1. If transceiver.[[Stopped]] is false, add transceiver.[[Receiver]] to receivers.
        if (!transceiver->is_stopped())
            receivers.append(transceiver->receiver());
    }
    // 4. Return receivers.
    return receivers;
}

// https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-addicecandidate
GC::Ref<WebIDL::Promise> RTCPeerConnection::add_ice_candidate(RTCIceCandidateInit const& candidate)
{
    auto& realm = this->realm();
    // 1. Let candidate be the method's argument.
    // 2. Let connection be the RTCPeerConnection object on which the method was invoked.
    // 3. If candidate.candidate is not an empty string and both candidate.sdpMid and candidate.sdpMLineIndex are null, return a promise rejected with a newly created TypeError.
    if (!candidate.candidate.is_empty() && !candidate.sdp_mid.has_value() && !candidate.sdp_m_line_index.has_value()) {
        auto rejected = WebIDL::create_promise(realm);
        WebIDL::reject_promise(realm, rejected, JS::TypeError::create(realm, "addIceCandidate: sdpMid and sdpMLineIndex are both null"_utf16));
        return rejected;
    }
    // FIXME: 4. Return the result of chaining the following steps to connection's operations chain:
    auto p = WebIDL::create_promise(realm);
    // FIXME: 4.1. If remoteDescription is null return a promise rejected with a newly created InvalidStateError.
    //        We don't yet mirror [[CurrentRemoteDescription]]/[[PendingRemoteDescription]] from the
    //        rust service — defer the check there (it'll come back as InvalidStateError via the result event).
    // FIXME: 4.2. If candidate.sdpMid is not null, run the following steps:
    //   FIXME: 4.2.1. If candidate.sdpMid is not equal to the mid of any media description in remoteDescription, return a promise rejected with a newly created OperationError.
    // FIXME: 4.3. Else, if candidate.sdpMLineIndex is not null, run the following steps:
    //   FIXME: 4.3.1. If candidate.sdpMLineIndex is equal to or larger than the number of media descriptions in remoteDescription, return a promise rejected with a newly created OperationError.
    // FIXME: 4.4. If either candidate.sdpMid or candidate.sdpMLineIndex indicate a media description in remoteDescription whose associated transceiver is stopped, return a promise resolved with undefined.
    // FIXME: 4.5. If candidate.usernameFragment is not null, and is not equal to any username fragment present in the corresponding media description of an applied remote description, return a promise rejected with a newly created OperationError.
    // 4.6. Let p be a new promise.
    // 4.7. In parallel, if the candidate is not administratively prohibited, add the ICE candidate
    //      candidate as described in [RFC9429] (section 4.1.19.). The service runs the in-parallel
    //      branch and queues the result task; it lands here via on_add_ice_candidate_result.
    auto& agent = WebRTCAgent::the();
    auto request_id = agent.next_request_id();
    m_pending_void_requests.set(request_id, p);
    if (auto* client = agent.client()) {
        client->async_add_ice_candidate(
            m_pc_id,
            request_id,
            candidate.candidate.to_utf8(),
            candidate.sdp_mid.map([](auto const& value) { return value.to_utf8(); }),
            candidate.sdp_m_line_index.map([](u16 v) { return static_cast<u32>(v); }),
            candidate.username_fragment.map([](auto const& value) { return value.to_utf8(); }));
    }
    // 4.8. Return p.
    return p;
}

// https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-addtrack
WebIDL::ExceptionOr<GC::Ref<RTCRtpSender>> RTCPeerConnection::add_track(GC::Ref<MediaCapture::MediaStreamTrack> track, GC::Ref<MediaCapture::MediaStream> stream)
{
    Vector<GC::Ref<MediaCapture::MediaStream>> streams;
    streams.append(stream);
    return add_track(track, streams);
}

WebIDL::ExceptionOr<GC::Ref<RTCRtpSender>> RTCPeerConnection::add_track(GC::Ref<MediaCapture::MediaStreamTrack> track, Vector<GC::Ref<MediaCapture::MediaStream>> const& streams)
{
    auto& realm = this->realm();
    // 1. Let connection be the RTCPeerConnection object on which this method was invoked.
    // 2. Let track be the MediaStreamTrack object indicated by the method's first argument.
    // 3. Let kind be track.kind.
    auto kind = track->track_kind();
    // 4. Let streams be a list of MediaStream objects constructed from the method's remaining arguments, or an empty list if the method was called with a single argument.
    // 5. If connection.[[IsClosed]] is true, throw an InvalidStateError.
    if (m_is_closed)
        return WebIDL::InvalidStateError::create("RTCPeerConnection is closed"_utf16);
    // 6. Let senders be the result of executing the CollectSenders algorithm. If an RTCRtpSender for track already exists in senders, throw an InvalidAccessError.
    auto senders = collect_senders();
    for (auto const& existing : senders) {
        if (existing->track() == track)
            return WebIDL::InvalidAccessError::create("RTCRtpSender for track already exists"_utf16);
    }
    // 7. ...if any RTCRtpSender object in senders matches all the following criteria, let sender be that object, or null otherwise:
    //    - The sender's track is null.
    //    - The transceiver kind of the RTCRtpTransceiver, associated with the sender, matches kind.
    //    - The [[Stopping]] slot of the RTCRtpTransceiver associated with the sender is false.
    //    - The sender has never been used to send. More precisely, the [[CurrentDirection]] slot of the RTCRtpTransceiver associated with the sender has never had a value of "sendrecv" or "sendonly".
    GC::Ptr<RTCRtpSender> sender;
    GC::Ptr<RTCRtpTransceiver> matching_transceiver;
    for (auto& transceiver : m_transceivers) {
        if (transceiver->sender()->track() != nullptr)
            continue;
        if (transceiver->kind() != kind)
            continue;
        if (transceiver->is_stopping())
            continue;
        // FIXME: track [[CurrentDirection]] history; for now we approximate by checking the current value.
        auto current = transceiver->current_direction();
        if (current.has_value() && (*current == Bindings::RTCRtpTransceiverDirection::Sendrecv || *current == Bindings::RTCRtpTransceiverDirection::Sendonly))
            continue;
        sender = transceiver->sender();
        matching_transceiver = transceiver;
        break;
    }
    // 8. If sender is not null, run the following steps to use that sender:
    if (sender) {
        // 8.1. Set sender.[[SenderTrack]] to track.
        sender->set_track(track);
        // 8.2. Set sender.[[AssociatedMediaStreamIds]] to an empty set.
        Vector<String> ids;
        // 8.3. For each stream in streams, add stream.id to [[AssociatedMediaStreamIds]] if it's not already there.
        for (auto const& stream : streams) {
            auto id = stream->id().to_utf8();
            if (!ids.contains_slow(id))
                ids.append(move(id));
        }
        sender->set_associated_media_stream_ids(move(ids));
        // 8.4. Let transceiver be the RTCRtpTransceiver associated with sender.
        // 8.5. If transceiver.[[Direction]] is "recvonly", set transceiver.[[Direction]] to "sendrecv".
        if (matching_transceiver->direction() == Bindings::RTCRtpTransceiverDirection::Recvonly)
            matching_transceiver->set_direction(Bindings::RTCRtpTransceiverDirection::Sendrecv);
        // 8.6. If transceiver.[[Direction]] is "inactive", set transceiver.[[Direction]] to "sendonly".
        else if (matching_transceiver->direction() == Bindings::RTCRtpTransceiverDirection::Inactive)
            matching_transceiver->set_direction(Bindings::RTCRtpTransceiverDirection::Sendonly);
    }
    auto& agent = WebRTCAgent::the();
    // 9. If sender is null, run the following steps:
    if (!sender) {
        auto sender_id = agent.next_sender_id();
        auto sender_ssrc = agent.next_ssrc();
        // FIXME: 9.1. Create an RTCRtpSender with track, kind and streams, and let sender be the result.
        sender = RTCRtpSender::create(realm, *this, sender_id, sender_ssrc);
        sender->set_track(track);
        Vector<String> ids;
        for (auto const& stream : streams) {
            auto id = stream->id().to_utf8();
            if (!ids.contains_slow(id))
                ids.append(move(id));
        }
        sender->set_associated_media_stream_ids(move(ids));
        // 9.2. Create an RTCRtpReceiver with kind, and let receiver be the result.
        auto receiver = RTCRtpReceiver::create(realm, kind);
        // FIXME: 9.3. Create an RTCRtpTransceiver with sender, receiver and an RTCRtpTransceiverDirection value of "sendrecv", and let transceiver be the result.
        auto transceiver = RTCRtpTransceiver::create(realm, *this, *sender, receiver, Bindings::RTCRtpTransceiverDirection::Sendrecv, kind);
        // 9.4. Add transceiver to connection's set of transceivers.
        m_transceivers.append(transceiver);
    }
    // FIXME: 10. A track could have contents that are inaccessible to the application. ... Silence (audio), black frames (video) or equivalently absent content is sent in place of track content.
    if (auto* client = agent.client()) {
        if (kind == Bindings::MediaStreamTrackKind::Audio) {
            // FIXME: honor the track's [[Source]] device id; for now we capture from the
            //        default recording device. The actual capture pipeline is started by
            //        on_sender_track_changed() below since set_track() drives that hook.
            (void)client;
        }
    }
    // 11. Update the negotiation-needed flag for connection.
    update_negotiation_needed_flag();
    // 12. Return sender.
    return GC::Ref { *sender };
}

// https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-addtransceiver
WebIDL::ExceptionOr<GC::Ref<RTCRtpTransceiver>> RTCPeerConnection::add_transceiver(Variant<GC::Ref<MediaCapture::MediaStreamTrack>, Utf16String> const& track_or_kind, RTCRtpTransceiverInit const& init)
{
    auto& realm = this->realm();
    // 1. Let connection be the RTCPeerConnection object on which the method was invoked.
    // 2. If connection.[[IsClosed]] is true, throw an InvalidStateError.
    if (m_is_closed)
        return WebIDL::InvalidStateError::create("RTCPeerConnection is closed"_utf16);
    // 3. Let init be the method's second argument.
    // 4. Let trackOrKind be the method's first argument.
    // 5. If trackOrKind is a kind, then let kind be trackOrKind, and let track be null.
    //    Otherwise, let kind be trackOrKind.kind and let track be trackOrKind.
    GC::Ptr<MediaCapture::MediaStreamTrack> track;
    Bindings::MediaStreamTrackKind kind;
    if (track_or_kind.has<Utf16String>()) {
        auto const& kind_string = track_or_kind.get<Utf16String>();
        // 6. If kind is not equal to "audio" or "video", throw a TypeError.
        if (kind_string == "audio"sv) {
            kind = Bindings::MediaStreamTrackKind::Audio;
        } else if (kind_string == "video"sv) {
            kind = Bindings::MediaStreamTrackKind::Video;
        } else {
            return WebIDL::SimpleException { WebIDL::SimpleExceptionType::TypeError, "addTransceiver: kind must be \"audio\" or \"video\""_utf16 };
        }
    } else {
        track = *track_or_kind.get<GC::Ref<MediaCapture::MediaStreamTrack>>();
        kind = track->track_kind();
    }
    // FIXME: 7. Verify that each value in init.sendEncodings conforms to the set of "RTCRtpEncodingParameters dictionary" requirements provided in the send encodings parameters section. If one of the values does not meet these requirements, throw a RangeError.
    // FIXME: 8. ...remaining sendEncodings normalization steps from the spec.
    // 9. Let sendEncodings be the value of init.sendEncodings.
    (void)init.send_encodings;
    // 10. Let direction be the value of init.direction.
    auto direction = init.direction;
    // 11. Create an RTCRtpSender, sender, from track, kind, init.streams, and sendEncodings.
    auto sender_id_for_new_sender = WebRTCAgent::the().next_sender_id();
    auto sender_ssrc_for_new_sender = WebRTCAgent::the().next_ssrc();
    auto sender = RTCRtpSender::create(realm, *this, sender_id_for_new_sender, sender_ssrc_for_new_sender);
    sender->set_track(track);
    Vector<String> stream_ids;
    for (auto const& stream : init.streams) {
        auto id = stream->id().to_utf8();
        if (!stream_ids.contains_slow(id))
            stream_ids.append(move(id));
    }
    sender->set_associated_media_stream_ids(move(stream_ids));
    // 12. Create an RTCRtpReceiver, receiver, from kind.
    auto receiver = RTCRtpReceiver::create(realm, kind);
    // 13. Create an RTCRtpTransceiver, transceiver, from sender, receiver, and direction.
    auto transceiver = RTCRtpTransceiver::create(realm, *this, sender, receiver, direction, kind);
    // 14. Add transceiver to connection's set of transceivers.
    m_transceivers.append(transceiver);
    auto& agent = WebRTCAgent::the();
    auto transceiver_id = agent.next_sender_id();
    transceiver->set_transceiver_id(transceiver_id);
    if (auto* client = agent.client()) {
        client->async_add_transceiver(
            m_pc_id,
            transceiver_id,
            kind == Bindings::MediaStreamTrackKind::Audio ? "audio"_string : "video"_string,
            idl_enum_to_string(direction).to_utf8());
    }
    // 15. Update the negotiation-needed flag for connection.
    update_negotiation_needed_flag();
    // 16. Return transceiver.
    return transceiver;
}

// https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-getsenders (CollectSenders)
Vector<GC::Ref<RTCRtpSender>> RTCPeerConnection::collect_senders() const
{
    // 1. Let transceivers be the result of executing the CollectTransceivers algorithm.
    auto transceivers = collect_transceivers();
    // 2. Let senders be a new empty sequence.
    Vector<GC::Ref<RTCRtpSender>> senders;
    // 3. For each transceiver in transceivers,
    for (auto& transceiver : transceivers) {
        // 3.1. If transceiver.[[Stopped]] is false, add transceiver.[[Sender]] to senders.
        if (!transceiver->is_stopped())
            senders.append(transceiver->sender());
    }
    // 4. Return senders.
    return senders;
}

// https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-createdatachannel
WebIDL::ExceptionOr<GC::Ref<RTCDataChannel>> RTCPeerConnection::create_data_channel(Utf16String const& label, RTCDataChannelInit const& options)
{
    auto& realm = this->realm();
    // 1. Let connection be the RTCPeerConnection object on which the method is invoked.
    // 2. If connection.[[IsClosed]] is true, throw an InvalidStateError.
    if (m_is_closed)
        return WebIDL::InvalidStateError::create("RTCPeerConnection is closed"_utf16);
    // 3. Create an RTCDataChannel, channel.
    auto channel = RTCDataChannel::create(realm);
    // 4. Initialize channel.[[DataChannelLabel]] to the value of the first argument.
    channel->set_label(label.to_utf8());
    // 5. If the UTF-8 representation of [[DataChannelLabel]] is longer than 65535 bytes, throw a TypeError.
    if (label.to_utf8().byte_count() > 65535)
        return WebIDL::SimpleException { WebIDL::SimpleExceptionType::TypeError, "RTCDataChannel label exceeds 65535 bytes"_utf16 };
    // 6. Let options be the second argument.
    // 7. Initialize channel.[[MaxPacketLifeTime]] to option.maxPacketLifeTime, if present, otherwise null.
    channel->set_max_packet_life_time(options.max_packet_life_time);
    // 8. Initialize channel.[[MaxRetransmits]] to option.maxRetransmits, if present, otherwise null.
    channel->set_max_retransmits(options.max_retransmits);
    // 9. Initialize channel.[[Ordered]] to option.ordered.
    channel->set_ordered(options.ordered);
    // 10. Initialize channel.[[DataChannelProtocol]] to option.protocol.
    channel->set_protocol(options.protocol.to_utf8());
    // 11. If the UTF-8 representation of [[DataChannelProtocol]] is longer than 65535 bytes, throw a TypeError.
    if (options.protocol.to_utf8().byte_count() > 65535)
        return WebIDL::SimpleException { WebIDL::SimpleExceptionType::TypeError, "RTCDataChannel protocol exceeds 65535 bytes"_utf16 };
    // 12. Initialize channel.[[Negotiated]] to option.negotiated.
    channel->set_negotiated(options.negotiated);
    // 13. Initialize channel.[[DataChannelId]] to the value of option.id, if it is present and [[Negotiated]] is true, otherwise null.
    if (options.id.has_value() && options.negotiated)
        channel->set_id(options.id);
    else
        channel->set_id({});
    // 14. If [[Negotiated]] is true and [[DataChannelId]] is null, throw a TypeError.
    if (options.negotiated && !options.id.has_value())
        return WebIDL::SimpleException { WebIDL::SimpleExceptionType::TypeError, "RTCDataChannel: negotiated=true requires id"_utf16 };
    // 15. If both [[MaxPacketLifeTime]] and [[MaxRetransmits]] attributes are set (not null), throw a TypeError.
    if (options.max_packet_life_time.has_value() && options.max_retransmits.has_value())
        return WebIDL::SimpleException { WebIDL::SimpleExceptionType::TypeError, "RTCDataChannel: maxPacketLifeTime and maxRetransmits are mutually exclusive"_utf16 };
    // FIXME: 16. If a setting, either [[MaxPacketLifeTime]] or [[MaxRetransmits]], has been set to indicate unreliable mode, and that value exceeds the maximum value supported by the user agent, the value MUST be set to the user agents maximum value.
    // 17. If [[DataChannelId]] is equal to 65535, which is greater than the maximum allowed ID of 65534 but still qualifies as an unsigned short, throw a TypeError.
    if (options.id.has_value() && *options.id == 65535)
        return WebIDL::SimpleException { WebIDL::SimpleExceptionType::TypeError, "RTCDataChannel id 65535 is reserved"_utf16 };
    // FIXME: 18. If the [[DataChannelId]] slot is null (due to no ID being passed into createDataChannel, or [[Negotiated]] being false), and the DTLS role of the SCTP transport has already been negotiated, then initialize [[DataChannelId]] to a value generated by the user agent, according to [RFC8832], and skip to the next step. If no available ID could be generated, or if the value of the [[DataChannelId]] slot is being used by an existing RTCDataChannel, throw an OperationError exception.
    // FIXME: 19. Let transport be connection.[[SctpTransport]]. If the [[DataChannelId]] slot is not null, transport is in the "connected" state and [[DataChannelId]] is greater or equal to transport.[[MaxChannels]], throw an OperationError.
    // 20. If channel is the first RTCDataChannel created on connection, update the negotiation-needed flag for connection.
    if (m_data_channels.is_empty())
        update_negotiation_needed_flag();
    // 21. Append channel to connection.[[DataChannels]].
    m_data_channels.append(channel);
    // 22. Return channel and continue the following steps in parallel.
    // 23. Create channel's associated underlying data transport and configure it according to the relevant properties of channel.
    auto& agent = WebRTCAgent::the();
    auto channel_id = agent.next_channel_id();
    channel->set_channel_id(channel_id);
    m_data_channels_by_id.set(channel_id, channel);
    agent.register_data_channel(channel_id, channel);
    if (auto* client = agent.client()) {
        client->async_add_data_channel(
            m_pc_id,
            channel_id,
            label.to_utf8(),
            options.ordered,
            options.max_packet_life_time,
            options.max_retransmits,
            options.protocol.to_utf8(),
            options.negotiated,
            options.id);
    }
    return channel;
}

// https://www.w3.org/TR/webrtc/#collect-transceivers
Vector<GC::Ref<RTCRtpTransceiver>> RTCPeerConnection::collect_transceivers() const
{
    // 1. Let transceivers be a new sequence consisting of all RTCRtpTransceiver objects in this RTCPeerConnection object's set of transceivers, in insertion order.
    // 2. Return transceivers.
    return m_transceivers;
}

// FIXME: https://www.w3.org/TR/webrtc/#update-the-negotiation-needed-flag
void RTCPeerConnection::update_negotiation_needed_flag()
{
}

// https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-getstats
GC::Ref<WebIDL::Promise> RTCPeerConnection::get_stats(GC::Ptr<MediaCapture::MediaStreamTrack>)
{
    auto& realm = this->realm();
    auto& vm = realm.vm();

    // 1. Let selector be the RTCRtpReceiver object on which the method was invoked.
    // FIXME: honor the selector argument.

    // 2. Let p be a new promise, and run the following steps in parallel:
    auto p = WebIDL::create_promise(realm);
    HTML::TemporaryExecutionContext context(realm);

    // 2.1. Gather the stats indicated by selector according to the stats selection algorithm.
    //
    // Stats selection algorithm:
    //     1. Let result be an empty RTCStatsReport.
    //     2. If selector is null, gather stats for the whole connection, add them to result, return result, and abort these steps.
    //     3. If selector is an RTCRtpSender, gather stats for and add the following objects to result:
    //         All RTCOutboundRtpStreamStats objects representing RTP streams being sent by selector.
    //         All stats objects referenced directly or indirectly by the RTCOutboundRtpStreamStats objects added.
    //     4. If selector is an RTCRtpReceiver, gather stats for and add the following objects to result:
    //         All RTCInboundRtpStreamStats objects representing RTP streams being received by selector.
    //         All stats objects referenced directly or indirectly by the RTCInboundRtpStreamStats added.
    //     5. Return result.
    //
    // FIXME: implement the full RTCStatsReport hierarchy. We currently fake just one outbound-rtp entry per
    //        sender (with kind, mediaType, ssrc, timestamp) — enough for consumers like Discord that use the
    //        report to discover their local SSRC for EncryptionWorker registration.
    //
    // FIXME: codegen doesn't yet support maplike with non-sequence values, so RTCStatsReport is an empty
    //        platform interface. We instead resolve with a real `JS::Map` — `.values()`/`.entries()` work as
    //        expected, but `instanceof RTCStatsReport` does not.
    auto map = JS::Map::create(realm);
    auto now = HighResolutionTime::unsafe_shared_current_time();

    auto append_entry = [&](StringView id, StringView type, GC::Ref<JS::Object> entry) {
        MUST(entry->create_data_property("id"_utf16_fly_string, JS::PrimitiveString::create(vm, id)));
        MUST(entry->create_data_property("type"_utf16_fly_string, JS::PrimitiveString::create(vm, type)));
        MUST(entry->create_data_property("timestamp"_utf16_fly_string, JS::Value(now)));
        map->map_set(JS::PrimitiveString::create(vm, id), entry);
    };

    for (auto& transceiver : m_transceivers) {
        auto sender = transceiver->sender();
        auto kind_str = transceiver->kind() == Bindings::MediaStreamTrackKind::Audio ? "audio"sv : "video"sv;
        auto entry = JS::Object::create(realm, realm.intrinsics().object_prototype());
        MUST(entry->create_data_property("ssrc"_utf16_fly_string, JS::Value(static_cast<double>(sender->ssrc()))));
        MUST(entry->create_data_property("kind"_utf16_fly_string, JS::PrimitiveString::create(vm, kind_str)));
        MUST(entry->create_data_property("mediaType"_utf16_fly_string, JS::PrimitiveString::create(vm, kind_str)));
        auto id = MUST(String::formatted("outbound-rtp-{}", sender->ssrc()));
        append_entry(id, "outbound-rtp"sv, entry);
    }

    // 2.2. Queue a global task on the networking task source given the current realm's global object as global to
    //      resolve p with the resulting RTCStatsReport object, containing the gathered stats.
    // FIXME: this should be queued on the networking task source rather than resolving inline.
    WebIDL::resolve_promise(realm, p, map);

    // 3. Return p.
    return p;
}

static Optional<Bindings::RTCSignalingState> parse_signaling_state(StringView s)
{
    if (s == "stable"sv)
        return Bindings::RTCSignalingState::Stable;
    if (s == "have-local-offer"sv || s == "havelocaloffer"sv)
        return Bindings::RTCSignalingState::HaveLocalOffer;
    if (s == "have-remote-offer"sv || s == "haveremoteoffer"sv)
        return Bindings::RTCSignalingState::HaveRemoteOffer;
    if (s == "have-local-pranswer"sv || s == "havelocalpranswer"sv)
        return Bindings::RTCSignalingState::HaveLocalPranswer;
    if (s == "have-remote-pranswer"sv || s == "haveremotepranswer"sv)
        return Bindings::RTCSignalingState::HaveRemotePranswer;
    if (s == "closed"sv)
        return Bindings::RTCSignalingState::Closed;
    return {};
}

static Optional<Bindings::RTCPeerConnectionState> parse_connection_state(StringView s)
{
    if (s == "new"sv)
        return Bindings::RTCPeerConnectionState::New;
    if (s == "connecting"sv)
        return Bindings::RTCPeerConnectionState::Connecting;
    if (s == "connected"sv)
        return Bindings::RTCPeerConnectionState::Connected;
    if (s == "disconnected"sv)
        return Bindings::RTCPeerConnectionState::Disconnected;
    if (s == "failed"sv)
        return Bindings::RTCPeerConnectionState::Failed;
    if (s == "closed"sv)
        return Bindings::RTCPeerConnectionState::Closed;
    return {};
}

static Optional<Bindings::RTCIceGatheringState> parse_ice_gathering(StringView s)
{
    if (s == "new"sv)
        return Bindings::RTCIceGatheringState::New;
    if (s == "gathering"sv)
        return Bindings::RTCIceGatheringState::Gathering;
    if (s == "complete"sv)
        return Bindings::RTCIceGatheringState::Complete;
    return {};
}

static Optional<Bindings::RTCIceConnectionState> parse_ice_connection(StringView s)
{
    if (s == "new"sv)
        return Bindings::RTCIceConnectionState::New;
    if (s == "checking"sv)
        return Bindings::RTCIceConnectionState::Checking;
    if (s == "connected"sv)
        return Bindings::RTCIceConnectionState::Connected;
    if (s == "completed"sv)
        return Bindings::RTCIceConnectionState::Completed;
    if (s == "disconnected"sv)
        return Bindings::RTCIceConnectionState::Disconnected;
    if (s == "failed"sv)
        return Bindings::RTCIceConnectionState::Failed;
    if (s == "closed"sv)
        return Bindings::RTCIceConnectionState::Closed;
    return {};
}

void RTCPeerConnection::on_signaling_state_event(String state)
{
    if (auto parsed = parse_signaling_state(state); parsed.has_value()) {
        m_signaling_state = *parsed;
        HTML::TemporaryExecutionContext context(realm());
        dispatch_event(DOM::Event::create(realm().global_object(), HTML::EventNames::signalingstatechange));
    }
}

void RTCPeerConnection::on_connection_state_event(String state)
{
    if (auto parsed = parse_connection_state(state); parsed.has_value()) {
        m_connection_state = *parsed;
        HTML::TemporaryExecutionContext context(realm());
        dispatch_event(DOM::Event::create(realm().global_object(), HTML::EventNames::connectionstatechange));
    }
}

void RTCPeerConnection::on_ice_gathering_state_event(String state)
{
    if (auto parsed = parse_ice_gathering(state); parsed.has_value()) {
        m_ice_gathering_state = *parsed;
        HTML::TemporaryExecutionContext context(realm());
        dispatch_event(DOM::Event::create(realm().global_object(), HTML::EventNames::icegatheringstatechange));
    }
}

void RTCPeerConnection::on_ice_connection_state_event(String state)
{
    if (auto parsed = parse_ice_connection(state); parsed.has_value()) {
        m_ice_connection_state = *parsed;
        HTML::TemporaryExecutionContext context(realm());
        dispatch_event(DOM::Event::create(realm().global_object(), HTML::EventNames::iceconnectionstatechange));
    }
}

void RTCPeerConnection::on_ice_candidate_received(Optional<String> candidate, Optional<String> mid, Optional<u32> index)
{
    HTML::TemporaryExecutionContext context(realm());
    auto event = RTCPeerConnectionIceEvent::create(realm(), HTML::EventNames::icecandidate);
    if (candidate.has_value()) {
        RTCIceCandidateInit init;
        init.candidate = Utf16String::from_utf8(*candidate);
        init.sdp_mid = mid.map([](auto const& value) { return Utf16String::from_utf8(value); });
        init.sdp_m_line_index = index.map([](u32 value) { return static_cast<u16>(value); });
        event->set_candidate(RTCIceCandidate::create(realm(), init));
    }
    dispatch_event(event);
}

void RTCPeerConnection::on_ice_candidate_error_received(Optional<String>, Optional<u16>, String, u16, String)
{
    // FIXME: dispatch an RTCPeerConnectionIceErrorEvent with the right fields.
    HTML::TemporaryExecutionContext context(realm());
    dispatch_event(DOM::Event::create(realm().global_object(), HTML::EventNames::icecandidateerror));
}

void RTCPeerConnection::on_negotiation_needed_received()
{
    HTML::TemporaryExecutionContext context(realm());
    dispatch_event(DOM::Event::create(realm().global_object(), HTML::EventNames::negotiationneeded));
}

namespace {

struct TrackEventInit {
    GC::Ref<RTCRtpReceiver> receiver;
    GC::Ref<MediaCapture::MediaStreamTrack> track;
    Vector<GC::Ref<MediaCapture::MediaStream>> streams;
    GC::Ref<RTCRtpTransceiver> transceiver;
};

// Spec uses "(stream, track) pairs" in addList/removeList; alias for clarity.
struct StreamTrackPair {
    GC::Ref<MediaCapture::MediaStream> stream;
    GC::Ref<MediaCapture::MediaStreamTrack> track;
};

constexpr bool direction_is_receive(Bindings::RTCRtpTransceiverDirection d)
{
    return d == Bindings::RTCRtpTransceiverDirection::Sendrecv
        || d == Bindings::RTCRtpTransceiverDirection::Recvonly;
}

constexpr bool direction_is_send_only_or_inactive(Bindings::RTCRtpTransceiverDirection d)
{
    return d == Bindings::RTCRtpTransceiverDirection::Sendonly
        || d == Bindings::RTCRtpTransceiverDirection::Inactive;
}

}

// https://www.w3.org/TR/webrtc/#set-associated-remote-streams
static void set_the_associated_remote_streams(RTCPeerConnection& pc, RTCRtpReceiver& receiver,
    Vector<String> const& msids,
    Vector<StreamTrackPair>& add_list,
    Vector<StreamTrackPair>& remove_list)
{
    // 1. Let connection be the RTCPeerConnection object associated with receiver.
    auto& connection = pc;

    // 2. For each MSID in msids, unless a MediaStream object has previously been
    //    created with that id for this connection, create a MediaStream object with
    //    that id.
    // 3. Let streams be a list of the MediaStream objects created for this connection
    //    with the ids corresponding to msids.
    Vector<GC::Ref<MediaCapture::MediaStream>> streams;
    streams.ensure_capacity(msids.size());
    for (auto const& msid : msids) {
        if (auto stream = connection.find_or_create_remote_stream_for_msid(msid))
            streams.append(*stream);
    }

    // 4. Let track be receiver.[[ReceiverTrack]].
    auto track = receiver.track();

    // 5. For each stream in receiver.[[AssociatedRemoteMediaStreams]] that is not
    //    present in streams, add stream and track as a pair to removeList.
    for (auto const& previous : receiver.associated_remote_streams()) {
        bool still_associated = false;
        for (auto const& fresh : streams) {
            if (fresh.ptr() == previous.ptr()) {
                still_associated = true;
                break;
            }
        }
        if (!still_associated)
            remove_list.append({ previous, track });
    }

    // 6. For each stream in streams that is not present in
    //    receiver.[[AssociatedRemoteMediaStreams]], add stream and track as a pair
    //    to addList.
    for (auto const& fresh : streams) {
        bool was_already_associated = false;
        for (auto const& previous : receiver.associated_remote_streams()) {
            if (previous.ptr() == fresh.ptr()) {
                was_already_associated = true;
                break;
            }
        }
        if (!was_already_associated)
            add_list.append({ fresh, track });
    }

    // 7. Set receiver.[[AssociatedRemoteMediaStreams]] to streams.
    receiver.set_associated_remote_streams(streams);
}

// https://www.w3.org/TR/webrtc/#process-the-addition-of-a-remote-track
static void process_addition_of_remote_track(RTCRtpTransceiver& transceiver, Vector<TrackEventInit>& track_event_inits)
{
    // 1. Let receiver be transceiver.[[Receiver]].
    auto receiver = transceiver.receiver();
    // 2. Let track be receiver.[[ReceiverTrack]].
    auto track = receiver->track();
    // 3. Let streams be receiver.[[AssociatedRemoteMediaStreams]].
    auto streams = receiver->associated_remote_streams();
    // 4. Create a new RTCTrackEventInit dictionary with receiver, track, streams and
    //    transceiver as members and add it to trackEventInits.
    track_event_inits.append({ receiver, track, move(streams), GC::Ref { transceiver } });
}

// https://www.w3.org/TR/webrtc/#process-the-removal-of-a-remote-track
static void process_removal_of_remote_track(RTCRtpTransceiver& transceiver, Vector<GC::Ref<MediaCapture::MediaStreamTrack>>& mute_tracks)
{
    // 1. Let receiver be transceiver.[[Receiver]].
    auto receiver = transceiver.receiver();
    // 2. Let track be receiver.[[ReceiverTrack]].
    auto track = receiver->track();
    // 3. If track.muted is false, add track to muteTracks.
    if (!track->muted())
        mute_tracks.append(track);
}

// https://www.w3.org/TR/webrtc/#process-remote-tracks
static void process_remote_tracks(RTCPeerConnection& pc, RTCRtpTransceiver& transceiver,
    Bindings::RTCRtpTransceiverDirection direction, Vector<String> const& msids,
    Vector<StreamTrackPair>& add_list,
    Vector<StreamTrackPair>& remove_list,
    Vector<TrackEventInit>& track_event_inits,
    Vector<GC::Ref<MediaCapture::MediaStreamTrack>>& mute_tracks)
{
    auto add_list_size_before = add_list.size();
    // 1. Set the associated remote streams with transceiver.[[Receiver]], msids,
    //    addList, and removeList.
    set_the_associated_remote_streams(pc, transceiver.receiver(), msids, add_list, remove_list);

    auto fired = transceiver.fired_direction();
    bool fired_was_recv = fired.has_value() && direction_is_receive(fired.value());
    bool add_list_grew = add_list.size() > add_list_size_before;
    // 2. If direction is "sendrecv" or "recvonly" and transceiver.[[FiredDirection]]
    //    is neither "sendrecv" nor "recvonly", or the previous step increased the
    //    length of addList, process the addition of a remote track with transceiver
    //    and trackEventInits.
    if ((direction_is_receive(direction) && !fired_was_recv) || add_list_grew)
        process_addition_of_remote_track(transceiver, track_event_inits);

    // 3. If direction is "sendonly" or "inactive", set transceiver.[[Receptive]] to false.
    if (direction_is_send_only_or_inactive(direction))
        transceiver.set_receptive(false);

    // 4. If direction is "sendonly" or "inactive", and transceiver.[[FiredDirection]]
    //    is either "sendrecv" or "recvonly", process the removal of a remote track
    //    for the media description, with transceiver and muteTracks.
    if (direction_is_send_only_or_inactive(direction) && fired_was_recv)
        process_removal_of_remote_track(transceiver, mute_tracks);

    // 5. Set transceiver.[[FiredDirection]] to direction.
    transceiver.set_fired_direction(direction);
}

void RTCPeerConnection::on_remote_track_added(u64 receiver_id, u64, String kind_string, Vector<String> stream_ids)
{
    auto& realm = this->realm();
    HTML::TemporaryExecutionContext context(realm);

    auto kind = kind_string == "video"sv ? Bindings::MediaStreamTrackKind::Video : Bindings::MediaStreamTrackKind::Audio;

    // Match the SFU-assigned track to a JS-created transceiver of matching kind whose
    // [[FiredDirection]] hasn't already been set to a receive direction. Fall back to
    // synthesizing one if the remote surprised us with a track we never asked for.
    // (Spec: this matching is normally done by "apply a remote description"; we get a
    //  pre-matched track via IPC, so we approximate the same selection here.)
    GC::Ptr<RTCRtpTransceiver> transceiver;
    for (auto& t : m_transceivers) {
        if (t->kind() != kind || t->is_stopped())
            continue;
        if (t->fired_direction().has_value() && direction_is_receive(t->fired_direction().value()))
            continue;
        transceiver = t;
        break;
    }
    if (!transceiver) {
        auto synth_sender_id = WebRTCAgent::the().next_sender_id();
        auto synth_sender_ssrc = WebRTCAgent::the().next_ssrc();
        auto sender = RTCRtpSender::create(realm, *this, synth_sender_id, synth_sender_ssrc);
        auto receiver = RTCRtpReceiver::create(realm, kind);
        auto new_transceiver = RTCRtpTransceiver::create(realm, *this, sender, receiver, Bindings::RTCRtpTransceiverDirection::Recvonly, kind);
        m_transceivers.append(new_transceiver);
        transceiver = new_transceiver;
    }

    auto receiver = transceiver->receiver();
    m_remote_receivers_by_id.set(receiver_id, receiver);

    // Drive the spec's "process remote tracks" algorithm. The IPC only signals new
    // tracks today (no removals), so direction is recvonly.
    Vector<StreamTrackPair> add_list;
    Vector<StreamTrackPair> remove_list;
    Vector<TrackEventInit> track_event_inits;
    Vector<GC::Ref<MediaCapture::MediaStreamTrack>> mute_tracks;
    process_remote_tracks(*this, *transceiver, Bindings::RTCRtpTransceiverDirection::Recvonly,
        stream_ids, add_list, remove_list, track_event_inits, mute_tracks);

    // The apply-remote-description algorithm follows up by:
    //   - Adding each (stream, track) pair from addList to its stream's track set
    //     (which fires "addtrack" on the stream).
    //   - Removing each (stream, track) pair from removeList from its stream's track
    //     set (which fires "removetrack" on the stream).
    //   - Firing one RTCTrackEvent per init.
    //   - Muting each track in muteTracks.
    for (auto& pair : add_list)
        pair.stream->add_track(pair.track);
    for (auto& pair : remove_list)
        pair.stream->remove_track(pair.track);
    for (auto& init : track_event_inits) {
        auto event = RTCTrackEvent::create(realm, HTML::EventNames::track,
            init.receiver, init.track, move(init.streams), init.transceiver);
        dispatch_event(event);
    }
    // FIXME: muteTracks step is "set track.muted to true and fire mute on it";
    //        MediaStreamTrack.muted is a getter so we'd need an internal set_muted.
    (void)mute_tracks;
}

GC::Ptr<MediaCapture::MediaStream> RTCPeerConnection::find_or_create_remote_stream_for_msid(String const& msid)
{
    if (auto existing = m_remote_streams.get(msid); existing.has_value())
        return existing.value();
    auto fresh = MediaCapture::MediaStream::create_with_id(Utf16String::from_utf8(msid));
    m_remote_streams.set(msid, fresh);
    return fresh;
}

void RTCPeerConnection::on_sender_track_changed(RTCRtpSender& sender)
{
    auto track = sender.track();
    if (auto previous = m_outgoing_audio_pipelines.take(sender.sender_id()); previous.has_value()) {
        if ((*previous)->track && (*previous)->sink)
            (*previous)->track->remove_audio_sink(*(*previous)->sink);
    }
    if (m_is_closed || !track || !track->is_audio())
        return;
    if (m_registered_audio_senders.contains(sender.sender_id())) {
        start_outgoing_audio_for_sender(sender);
        return;
    }
    // Tell the rust service to add a sending audio track for this sender. The
    // service will allocate the wire-side SSRC and send it back via
    // `on_audio_track_added` — at that point we update the sender's SSRC and
    // start the encode pipeline. We defer the pipeline start so frames never
    // flow with a stale SSRC (which would make Discord's EncryptionWorker drop
    // them all because the userId mapping is keyed on the wire SSRC).
    if (auto* client = WebRTCAgent::the().client())
        client->async_add_audio_track(m_pc_id, sender.sender_id());
}

void RTCPeerConnection::on_audio_track_ssrc_assigned(u64 sender_id, u32 ssrc)
{
    GC::Ptr<RTCRtpSender> sender;
    for (auto& transceiver : m_transceivers) {
        if (transceiver->sender()->sender_id() == sender_id) {
            sender = transceiver->sender();
            break;
        }
    }
    if (!sender) {
        dbgln("RTCPeerConnection: on_audio_track_ssrc_assigned for unknown sender_id={}", sender_id);
        return;
    }
    if (m_is_closed)
        return;
    sender->set_ssrc(ssrc);
    m_registered_audio_senders.set(sender_id);
    if (m_outgoing_audio_pipelines.contains(sender_id))
        return;
    start_outgoing_audio_for_sender(*sender);
}

void RTCPeerConnection::on_sender_transform_changed(RTCRtpSender& sender)
{
    // The script transform's writeEncodedData hands us the SFrame-encrypted frame
    // back. Wire it now so the path mic→encode→transform→encrypt→wire is complete.
    auto script_transform = sender.script_transform();
    if (!script_transform)
        return;
    auto sender_id = sender.sender_id();
    if (script_transform->has_frame_written_callback())
        return;
    script_transform->set_on_frame_written([self = GC::Weak { *this }, sender_id](ByteBuffer payload, u32, u8 payload_type, u32 rtp_timestamp, u16 sequence_number) {
        if (!self || self->m_is_closed)
            return;
        self->on_outgoing_encrypted_frame(sender_id, move(payload), rtp_timestamp, sequence_number, payload_type);
    });
}

void RTCPeerConnection::start_outgoing_audio_for_sender(GC::Ref<RTCRtpSender> sender)
{
    auto sender_id = sender->sender_id();
    auto track = sender->track();
    if (!track) {
        dbgln("RTCPeerConnection: sender_id={} has no track yet, deferring", sender_id);
        return;
    }
    auto sample_spec = Audio::SampleSpecification(48000, Audio::ChannelMap::stereo());
    constexpr int OPUS_BITRATE_BPS = 64'000;
    auto encoder_or_err = Media::FFmpeg::FFmpegAudioEncoder::try_create(Media::CodecID::Opus, sample_spec, OPUS_BITRATE_BPS);
    if (encoder_or_err.is_error()) {
        dbgln("RTCPeerConnection: opus encoder init failed for sender_id={}: {}", sender_id, encoder_or_err.error().description());
        return;
    }
    auto pipeline = make<OutgoingAudioPipeline>();
    pipeline->encoder = encoder_or_err.release_value();
    pipeline->sender_id = sender_id;
    pipeline->track = track;
    auto ring = adopt_ref(*new Media::SpscAudioFrameRing(8192, 2));
    pipeline->ring = ring;
    auto sink = adopt_ref(*new MediaCapture::AudioFrameSink);
    // Capture only atomically ref-counted storage. A producer callback can outlive the
    // track, sender, or peer connection and must never touch their GC-managed state.
    sink->on_frames = [ring, phase = 0.0, previous = Array<float, 2> {}, previous_rate = u32 { 0 }](float const* samples, size_t frame_count, u8 channels, u32 sample_rate) mutable {
        if (!channels || !sample_rate)
            return;
        if (sample_rate != previous_rate) {
            phase = 0;
            previous_rate = sample_rate;
        }
        auto step = static_cast<double>(sample_rate) / 48000.0;
        for (size_t frame = 0; frame < frame_count; ++frame) {
            Array<float, 2> current { samples[frame * channels], samples[frame * channels + (channels > 1 ? 1 : 0)] };
            while (phase < 1.0) {
                Array<float, 2> output;
                for (size_t channel = 0; channel < 2; ++channel)
                    output[channel] = previous[channel] + static_cast<float>(phase) * (current[channel] - previous[channel]);
                (void)ring->try_push(output);
                phase += step;
            }
            phase -= 1.0;
            previous = current;
        }
    };
    pipeline->sink = sink;
    m_outgoing_audio_pipelines.set(sender_id, move(pipeline));
    track->add_audio_sink(sink);
    if (!m_audio_timer) {
        m_audio_timer = Core::Timer::create_repeating(10, [self = GC::Weak { *this }] {
            if (self)
                self->drain_outgoing_audio();
        });
    }
    m_audio_timer->start();
}

void RTCPeerConnection::stop_outgoing_audio()
{
    if (m_audio_timer)
        m_audio_timer->stop();
    for (auto& entry : m_outgoing_audio_pipelines) {
        auto& pipeline = *entry.value;
        if (pipeline.track && pipeline.sink)
            pipeline.track->remove_audio_sink(*pipeline.sink);
    }
    m_outgoing_audio_pipelines.clear();
    for (auto& entry : m_receiver_audio_playbacks) {
        if (entry.value->playback_stream)
            (void)entry.value->playback_stream->discard_buffer_and_suspend();
    }
    m_receiver_audio_playbacks.clear();
}

void RTCPeerConnection::finalize()
{
    stop_outgoing_audio();
    Base::finalize();
}

void RTCPeerConnection::drain_outgoing_audio()
{
    HTML::TemporaryExecutionContext context(realm());
    for (auto& entry : m_outgoing_audio_pipelines) {
        auto& pipeline = *entry.value;
        while (pipeline.ring->frames_available() >= 960) {
            Array<float, 1920> samples;
            auto frames = pipeline.ring->try_pop(samples);
            VERIFY(frames == 960);
            Media::AudioBlock block;
            block.initialize(Audio::SampleSpecification(48000, Audio::ChannelMap::stereo()), static_cast<i64>(pipeline.next_rtp_timestamp), frames);
            for (size_t channel = 0; channel < 2; ++channel) {
                for (size_t frame = 0; frame < frames; ++frame)
                    block.set_sample(channel, frame, samples[frame * 2 + channel]);
            }
            encode_and_route_outgoing_pcm(entry.key, block);
        }
    }
}

void RTCPeerConnection::encode_and_route_outgoing_pcm(u64 sender_id, Media::AudioBlock const& block)
{
    auto pipeline_iter = m_outgoing_audio_pipelines.find(sender_id);
    if (pipeline_iter == m_outgoing_audio_pipelines.end())
        return;
    auto& pipeline = *pipeline_iter->value;
    if (!pipeline.encoder)
        return;
    constexpr size_t SAMPLES_PER_FRAME = 960;
    auto timestamp = block.media_time_start();

    if (auto rc = pipeline.encoder->receive_pcm_data(timestamp, block); rc.is_error()) {
        static size_t logged = 0;
        if (logged++ < 3)
            dbgln("RTCPeerConnection: opus receive_pcm_data failed: {}", rc.error().description());
        return;
    }
    while (true) {
        Media::FFmpeg::FFmpegAudioEncoder::Packet packet;
        auto got_packet_or_err = pipeline.encoder->write_next_packet(packet);
        if (got_packet_or_err.is_error()) {
            static size_t logged = 0;
            if (logged++ < 3)
                dbgln("RTCPeerConnection: opus write_next_packet failed: {}", got_packet_or_err.error().description());
            return;
        }
        if (!got_packet_or_err.value())
            break;

        // Locate the sender. It may have been GC'd since we kicked off capture, in
        // which case we just drop the frame.
        GC::Ptr<RTCRtpSender> sender;
        for (auto& t : m_transceivers) {
            if (t->sender()->sender_id() == sender_id) {
                sender = t->sender();
                break;
            }
        }
        if (!sender)
            return;

        auto rtp_ts = pipeline.next_rtp_timestamp;
        auto seq = pipeline.next_sequence_number++;
        pipeline.next_rtp_timestamp += SAMPLES_PER_FRAME;

        // Without a script transform we'd need to send straight to rust as raw opus
        // — but discord requires DAVE encryption, so dropping the frame is correct
        // for this MVP. FIXME: for non-DAVE peers we should fall through to a
        // direct-to-rust IPC path.
        auto script_transform = sender->script_transform();
        if (!script_transform) {
            on_outgoing_encrypted_frame(sender_id, move(packet.data), rtp_ts, seq, 111);
            continue;
        }

        script_transform->enqueue_encoded_audio_frame(move(packet.data), sender->ssrc(), 111 /* opus */, rtp_ts, seq);
    }
}

void RTCPeerConnection::on_outgoing_encrypted_frame(u64 sender_id, ByteBuffer payload, u32 rtp_timestamp, u16 sequence_number, u8 payload_type)
{
    (void)rtp_timestamp;
    (void)sequence_number;
    (void)payload_type;
    auto* client = WebRTCAgent::the().client();
    if (!client)
        return;
    constexpr u32 FRAME_DURATION_MICROS = 20'000;
    static size_t logged = 0;
    if (logged++ < 5)
        dbgln("RTCPeerConnection: shipping encoded frame to rust sender_id={} len={}", sender_id, payload.size());
    client->async_audio_track_encoded_frame(sender_id, FRAME_DURATION_MICROS, payload.bytes());
}

void RTCPeerConnection::on_remote_track_ended(u64)
{
    // FIXME: end the corresponding receiver's [[ReceiverTrack]] (fires `ended` on the MediaStreamTrack).
}

void RTCPeerConnection::on_encoded_audio_frame_received(u64 receiver_id, u32 ssrc, u32 rtp_timestamp, u16 sequence_number, u8 payload_type, ByteBuffer payload)
{
    auto receiver_iter = m_remote_receivers_by_id.get(receiver_id);
    if (!receiver_iter.has_value())
        return;
    auto receiver = *receiver_iter;

    auto transform = receiver->transform();
    auto* script_transform_root = transform.get_pointer<GC::Ref<RTCRtpScriptTransform>>();
    if (!script_transform_root) {
        feed_decoded_audio(receiver_id, move(payload), rtp_timestamp);
        return;
    }
    auto& script_transform = **script_transform_root;

    // FIXME: route the worker's transformed frame back into the decode/playback pipeline
    //        instead of dropping it on the floor.
    if (!script_transform.has_frame_written_callback()) {
        script_transform.set_on_frame_written([self = GC::Weak { *this }, receiver_id](ByteBuffer transformed_payload, u32, u8, u32 rtp_timestamp, u16) {
            if (!self || self->m_is_closed)
                return;
            self->feed_decoded_audio(receiver_id, move(transformed_payload), rtp_timestamp);
        });
    }

    script_transform.enqueue_encoded_audio_frame(move(payload), ssrc, payload_type, rtp_timestamp, sequence_number);
}

// Decode one decrypted opus packet and push PCM into the receiver's playback stream.
// FIXME: this is a shortcut around the spec — the right path is for MediaStreamTrack to
//        carry the audio data and HTMLMediaElement.srcObject playback to drain it.
void RTCPeerConnection::feed_decoded_audio(u64 receiver_id, ByteBuffer payload, u32 rtp_timestamp)
{
    auto playback_iter = m_receiver_audio_playbacks.find(receiver_id);
    auto* playback = playback_iter == m_receiver_audio_playbacks.end() ? nullptr : playback_iter->value.ptr();
    if (!playback) {
        dbgln("RTCPeerConnection: setting up audio playback for receiver={}", receiver_id);
        // Lazily set up decoder + playback stream on the first frame for this receiver.
        // Opus is fundamentally 48 kHz; channel count comes out of the first decoded block.
        auto sample_spec = Audio::SampleSpecification(48000, Audio::ChannelMap::stereo());
        auto decoder_or_err = Media::FFmpeg::FFmpegAudioDecoder::try_create(Media::CodecID::Opus, sample_spec, {});
        if (decoder_or_err.is_error()) {
            dbgln("RTCPeerConnection: opus decoder init failed for receiver={}: {}", receiver_id, decoder_or_err.error().description());
            return;
        }
        auto fresh = make<ReceiverAudioPlayback>();
        fresh->decoder = decoder_or_err.release_value();
        auto* fresh_ptr = fresh.ptr();
        m_receiver_audio_playbacks.set(receiver_id, move(fresh));
        playback = fresh_ptr;

        auto data_callback = [pcm = playback->buffer, receiver_id](Span<float> buffer) -> ReadonlySpan<float> {
            Sync::MutexLocker locker(pcm->mutex);
            auto available = pcm->samples.size();
            auto take = AK::min(available, buffer.size());
            memcpy(buffer.data(), pcm->samples.data(), take * sizeof(float));
            pcm->samples.remove(0, take);
            // Pad the rest of the buffer with silence so PulseAudio keeps requesting
            // data — returning a short span makes pa_stream_cancel_write fire and the
            // stream stops being polled, which bricks playback after the first frame.
            if (take < buffer.size())
                memset(buffer.data() + take, 0, (buffer.size() - take) * sizeof(float));
            static size_t logged = 0;
            if (logged++ < 5)
                dbgln("RTCPeerConnection: playback callback receiver={} requested={} available={} taken={}", receiver_id, buffer.size(), available, take);
            return buffer;
        };
        constexpr u32 target_latency_ms = 100;
        auto promise = Audio::PlaybackStream::create_platform_or_null(Audio::OutputState::Suspended, target_latency_ms, move(data_callback));
        promise->when_resolved([self = GC::Weak { *this }, receiver_id](auto& stream) {
            if (!self || self->m_is_closed)
                return;
            auto entry = self->m_receiver_audio_playbacks.find(receiver_id);
            if (entry == self->m_receiver_audio_playbacks.end())
                return;
            auto* playback = entry->value.ptr();
            playback->playback_stream = stream;
            dbgln("RTCPeerConnection: playback stream resolved receiver={} spec={}", receiver_id, stream->sample_specification());
            // Set up the resampler so the decoder's 48 kHz stereo opus matches whatever PA gave us.
            auto converter_or_err = Media::FFmpeg::FFmpegAudioConverter::try_create();
            if (converter_or_err.is_error()) {
                dbgln("RTCPeerConnection: audio converter init failed for receiver={}: {}", receiver_id, converter_or_err.error());
            } else {
                auto converter = converter_or_err.release_value();
                if (auto rc = converter->set_output_sample_specification(stream->sample_specification()); rc.is_error())
                    dbgln("RTCPeerConnection: converter set_output failed for receiver={}: {}", receiver_id, rc.error());
                else
                    playback->converter = move(converter);
            }
            (void)stream->resume();
        });
        promise->when_rejected([receiver_id](auto& error) {
            dbgln("RTCPeerConnection: playback stream init failed for receiver={}: {}", receiver_id, error);
        });
    }

    if (!playback->decoder)
        return;

    auto timestamp = AK::Duration::from_milliseconds(static_cast<i64>(rtp_timestamp / 48));
    Media::CodedFrame coded_frame { Media::CodecID::Opus, timestamp, timestamp, {}, Media::FrameFlags::None, MUST(FixedArray<u8>::create(payload.bytes())) };
    if (auto result = playback->decoder->receive_coded_data(coded_frame); result.is_error()) {
        static size_t logged = 0;
        if (logged++ < 3)
            dbgln("RTCPeerConnection: opus receive_coded_data failed: {}", result.error().description());
        return;
    }
    Media::AudioBlock block;
    if (auto result = playback->decoder->write_next_block(block); result.is_error()) {
        static size_t logged = 0;
        if (logged++ < 3)
            dbgln("RTCPeerConnection: write_next_block failed: {}", result.error().description());
        return;
    }
    if (block.is_empty()) {
        static size_t logged = 0;
        if (logged++ < 3)
            dbgln("RTCPeerConnection: write_next_block produced empty block");
        return;
    }
    if (auto receiver = m_remote_receivers_by_id.get(receiver_id); receiver.has_value()) {
        Array<float, Media::AudioBlock::SAMPLE_CAPACITY> samples;
        auto count = block.copy_to_interleaved(samples.span().trim(block.sample_count()));
        (*receiver)->track()->deliver_audio_frames(samples.data(), count / block.channel_count(), block.channel_count(), block.sample_rate());
    }
    // Drop frames until the playback stream is up — we need its sample-spec to set up the
    // resampler, and feeding mismatched-rate samples in the meantime would just stretch.
    if (!playback->converter)
        return;
    if (auto rc = playback->converter->push_block(block); rc.is_error()) {
        static size_t logged = 0;
        if (logged++ < 3)
            dbgln("RTCPeerConnection: audio convert failed: {}", rc.error());
        return;
    }
    if (auto result = playback->converter->retrieve_block(block); result.is_error() || block.is_empty())
        return;
    {
        Sync::MutexLocker locker(playback->buffer->mutex);
        playback->channel_count = block.channel_count();
        Array<float, Media::AudioBlock::SAMPLE_CAPACITY> samples;
        auto count = block.copy_to_interleaved(samples.span().trim(block.sample_count()));
        playback->buffer->samples.append(samples.data(), count);
        static size_t logged = 0;
        if (logged++ < 5)
            dbgln("RTCPeerConnection: feed_decoded_audio receiver={} samples={} channels={} spec={} buffer_total={}",
                receiver_id, block.sample_count(), block.channel_count(), block.sample_specification(), playback->buffer->samples.size());
    }
}

static Bindings::RTCSdpType parse_sdp_type(StringView s)
{
    if (s == "answer"sv)
        return Bindings::RTCSdpType::Answer;
    if (s == "pranswer"sv)
        return Bindings::RTCSdpType::Pranswer;
    if (s == "rollback"sv)
        return Bindings::RTCSdpType::Rollback;
    return Bindings::RTCSdpType::Offer;
}

void RTCPeerConnection::on_create_offer_result_received(u64 request_id, bool ok, String sdp_type, String sdp, String, String error_message)
{
    auto promise = m_pending_description_requests.take(request_id);
    if (!promise.has_value())
        return;
    auto& realm = this->realm();
    auto& promise_ref = **promise;
    HTML::TemporaryExecutionContext context(realm);
    if (!ok) {
        WebIDL::reject_promise(realm, promise_ref, WebIDL::OperationError::create(Utf16String::from_utf8(error_message)));
        return;
    }
    m_last_created_offer = Utf16String::from_utf8(sdp);
    auto init = JS::Object::create(realm, realm.intrinsics().object_prototype());
    MUST(init->create_data_property("type"_utf16_fly_string, JS::PrimitiveString::create(realm.vm(), idl_enum_to_string(parse_sdp_type(sdp_type)))));
    MUST(init->create_data_property("sdp"_utf16_fly_string, JS::PrimitiveString::create(realm.vm(), Utf16String::from_utf8(sdp))));
    WebIDL::resolve_promise(realm, promise_ref, init);
}

void RTCPeerConnection::on_create_answer_result_received(u64 request_id, bool ok, String sdp_type, String sdp, String, String error_message)
{
    auto promise = m_pending_description_requests.take(request_id);
    if (!promise.has_value())
        return;
    auto& realm = this->realm();
    auto& promise_ref = **promise;
    HTML::TemporaryExecutionContext context(realm);
    if (!ok) {
        WebIDL::reject_promise(realm, promise_ref, WebIDL::OperationError::create(Utf16String::from_utf8(error_message)));
        return;
    }
    m_last_created_answer = Utf16String::from_utf8(sdp);
    auto init = JS::Object::create(realm, realm.intrinsics().object_prototype());
    MUST(init->create_data_property("type"_utf16_fly_string, JS::PrimitiveString::create(realm.vm(), idl_enum_to_string(parse_sdp_type(sdp_type)))));
    MUST(init->create_data_property("sdp"_utf16_fly_string, JS::PrimitiveString::create(realm.vm(), Utf16String::from_utf8(sdp))));
    WebIDL::resolve_promise(realm, promise_ref, init);
}

void RTCPeerConnection::on_set_local_description_result_received(u64 request_id, bool ok, String, String error_message)
{
    auto promise = m_pending_void_requests.take(request_id);
    auto payload = m_pending_description_payloads.take(request_id);
    if (!promise.has_value())
        return;
    auto& realm = this->realm();
    auto& promise_ref = **promise;
    HTML::TemporaryExecutionContext context(realm);
    if (!ok) {
        WebIDL::reject_promise(realm, promise_ref, WebIDL::OperationError::create(Utf16String::from_utf8(error_message)));
        return;
    }
    if (payload.has_value() && payload->is_local) {
        // FIXME: spec splits this between [[CurrentLocalDescription]] and [[PendingLocalDescription]]
        //        based on the answered/pending state. For now stash on [[CurrentLocalDescription]].
        m_current_local_description = RTCSessionDescription::create(realm, RTCSessionDescriptionInit { .sdp = payload->sdp, .type = payload->type });
        m_pending_local_description = nullptr;
    }
    WebIDL::resolve_promise(realm, promise_ref, JS::js_undefined());
}

void RTCPeerConnection::on_set_remote_description_result_received(u64 request_id, bool ok, String, String error_message)
{
    auto promise = m_pending_void_requests.take(request_id);
    auto payload = m_pending_description_payloads.take(request_id);
    if (!promise.has_value())
        return;
    auto& realm = this->realm();
    auto& promise_ref = **promise;
    HTML::TemporaryExecutionContext context(realm);
    if (!ok) {
        WebIDL::reject_promise(realm, promise_ref, WebIDL::OperationError::create(Utf16String::from_utf8(error_message)));
        return;
    }
    if (payload.has_value() && !payload->is_local) {
        // FIXME: spec splits this between [[CurrentRemoteDescription]] and [[PendingRemoteDescription]]
        //        based on the answered/pending state. For now stash on [[CurrentRemoteDescription]].
        m_current_remote_description = RTCSessionDescription::create(realm, RTCSessionDescriptionInit { .sdp = payload->sdp, .type = payload->type });
        m_pending_remote_description = nullptr;
    }
    WebIDL::resolve_promise(realm, promise_ref, JS::js_undefined());
}

void RTCPeerConnection::on_add_ice_candidate_result_received(u64 request_id, bool ok, String, String error_message)
{
    auto promise = m_pending_void_requests.take(request_id);
    if (!promise.has_value())
        return;
    auto& realm = this->realm();
    auto& promise_ref = **promise;
    HTML::TemporaryExecutionContext context(realm);
    if (!ok)
        WebIDL::reject_promise(realm, promise_ref, WebIDL::OperationError::create(Utf16String::from_utf8(error_message)));
    else
        WebIDL::resolve_promise(realm, promise_ref, JS::js_undefined());
}

void RTCPeerConnection::on_remote_data_channel_received(u64 channel_id, String label, bool ordered, Optional<u16> lifetime, Optional<u16> retransmits, String protocol, bool negotiated, Optional<u16> id)
{
    HTML::TemporaryExecutionContext context(realm());
    auto channel = RTCDataChannel::create(realm());
    channel->set_channel_id(channel_id);
    channel->set_label(move(label));
    channel->set_ordered(ordered);
    channel->set_max_packet_life_time(lifetime);
    channel->set_max_retransmits(retransmits);
    channel->set_protocol(move(protocol));
    channel->set_negotiated(negotiated);
    channel->set_id(id);
    m_data_channels.append(channel);
    m_data_channels_by_id.set(channel_id, channel);
    WebRTCAgent::the().register_data_channel(channel_id, channel);
    auto event = RTCDataChannelEvent::create(realm(), HTML::EventNames::datachannel);
    event->set_channel(channel);
    dispatch_event(event);
}

#define EVENT_HANDLER(name, event_name)                                                                                             \
    void RTCPeerConnection::set_##name(WebIDL::CallbackType* cb) { set_event_handler_attribute(HTML::EventNames::event_name, cb); } \
    WebIDL::CallbackType* RTCPeerConnection::name() { return event_handler_attribute(HTML::EventNames::event_name); }

EVENT_HANDLER(onnegotiationneeded, negotiationneeded)
EVENT_HANDLER(onicecandidate, icecandidate)
EVENT_HANDLER(onicecandidateerror, icecandidateerror)
EVENT_HANDLER(onsignalingstatechange, signalingstatechange)
EVENT_HANDLER(oniceconnectionstatechange, iceconnectionstatechange)
EVENT_HANDLER(onicegatheringstatechange, icegatheringstatechange)
EVENT_HANDLER(onconnectionstatechange, connectionstatechange)
EVENT_HANDLER(ontrack, track)
EVENT_HANDLER(ondatachannel, datachannel)

#undef EVENT_HANDLER

}
