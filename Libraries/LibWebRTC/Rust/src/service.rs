/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

//! IPC dispatch loop for the WebRTCClient service.
//!
//! Reads `WebRTCClientServer` messages off a `libipc::TransportSocket`,
//! dispatches each to a handler that drives `webrtc-rs`, and emits
//! `WebRTCClientClient` events (state changes, on_track, ICE candidates,
//! per-request completion replies). Promise-shaped commands carry a
//! `request_id` that the host correlates with a stored promise on its end.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

use anyhow::{Result, anyhow};
use libipc::{Decoder, Encoder, IPCDecode, IPCEncode, IPCMessage, MessageBuffer, TransportSocket};
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use webrtc::data_channel::RTCDataChannel;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;

use crate::peer::build_default_api;

use ipc_webrtcclientclient::WebRTCClientClient as Client;
use ipc_webrtcclientserver::WebRTCClientServer as Server;

type SharedWriter = Arc<std::sync::Mutex<TransportSocket>>;

/// Splits a connected socket into independent read- and write-side
/// `TransportSocket`s by `dup(2)`-ing the underlying fd. Each side becomes
/// its own kernel fd backed by the same socket pair, so the reader can block
/// in `recvmsg` while the writer simultaneously calls `sendmsg` on the dup'd
/// end. With one fd shared via a mutex, every read would have to release the
/// lock before any event could be sent back to the peer — that deadlocks if
/// an event handler runs while the reader is mid-`read_message`.
fn split_transport(transport: TransportSocket) -> std::io::Result<(TransportSocket, TransportSocket)> {
    let handle = transport.into_handle();
    let fd = handle.into_owned_fd();
    let cloned = fd.try_clone()?;
    let reader = TransportSocket::from_owned_fd(fd)?;
    let writer = TransportSocket::from_owned_fd(cloned)?;
    Ok((reader, writer))
}

struct AudioSender {
    pcm_tx: mpsc::UnboundedSender<Vec<i16>>,
    // For senders driven from the host's encoded+encrypted frame pipeline (e.g.
    // Discord's DAVE/SFrame transform), we write the bytes straight onto the
    // wire without going through the rust-side opus encoder.
    track: Arc<TrackLocalStaticSample>,
}

#[derive(Default)]
struct Registry {
    pcs: HashMap<u64, Arc<RTCPeerConnection>>,
    data_channels: HashMap<u64, Arc<RTCDataChannel>>,
    audio_senders: HashMap<u64, AudioSender>,
}

struct State {
    api: webrtc::api::API,
    registry: AsyncMutex<Registry>,
    writer: SharedWriter,
    next_remote_channel_id: std::sync::atomic::AtomicU64,
}

/// Run the dispatch loop on the given transport. Returns when the peer
/// disconnects or an unrecoverable error occurs.
pub fn run(transport: TransportSocket) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>> {
    Box::pin(async move {
        let api = build_default_api()?;
        let (mut reader, writer) = split_transport(transport)?;
        let writer: SharedWriter = Arc::new(std::sync::Mutex::new(writer));
        let state = Arc::new(State {
            api,
            registry: AsyncMutex::new(Registry::default()),
            writer: writer.clone(),
            // Remote-opened channel ids start past the u32 range so they don't collide with
            // host-allocated ids on either side. The host uses the lower range.
            next_remote_channel_id: std::sync::atomic::AtomicU64::new(1u64 << 32),
        });

        let (msg_tx, mut msg_rx) = mpsc::unbounded_channel::<libipc::TransportMessage>();
        std::thread::spawn(move || {
            loop {
                match reader.read_message() {
                    Ok(Some(m)) => {
                        if msg_tx.send(m).is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        log::info!("peer disconnected");
                        break;
                    }
                    Err(e) => {
                        log::error!("read_message: {e}");
                        break;
                    }
                }
            }
        });

        while let Some(msg) = msg_rx.recv().await {
            if let Err(e) = handle_one(&state, msg).await {
                log::warn!("handler error: {e:?}");
            }
        }

        Ok(())
    })
}

async fn handle_one(state: &Arc<State>, msg: libipc::TransportMessage) -> Result<()> {
    let mut decoder = Decoder::new(&msg.bytes, msg.attachments);
    let magic = u32::decode(&mut decoder)?;
    if magic != Server::ENDPOINT_MAGIC {
        return Err(anyhow!(
            "bad endpoint magic: got {magic:#x}, want {:#x}",
            Server::ENDPOINT_MAGIC
        ));
    }
    let id = i32::decode(&mut decoder)?;
    dispatch(state, id, decoder).await
}

async fn dispatch(state: &Arc<State>, id: i32, mut decoder: Decoder<'_>) -> Result<()> {
    use Server::MessageId as M;

    if id == M::InitTransport as i32 {
        let req = Server::InitTransport::decode(&mut decoder)?;
        log::info!("InitTransport: peer_pid={}", req.peer_pid);
        let response = Server::InitTransportResponse {
            peer_pid: std::process::id() as i32,
        };
        send(&state.writer, &response)?;
    } else if id == M::ConnectNewClient as i32 {
        let req = Server::ConnectNewClient::decode(&mut decoder)?;
        let transport = TransportSocket::from_owned_fd(req.handle.into_owned_fd())?;
        tokio::spawn(async move {
            if let Err(error) = run(transport).await {
                log::warn!("WebRTC client disconnected with error: {error:?}");
            }
        });
    } else if id == M::CreatePeerConnection as i32 {
        let req = Server::CreatePeerConnection::decode(&mut decoder)?;
        let pc = state.api.new_peer_connection(RTCConfiguration::default()).await?;
        let pc = Arc::new(pc);
        wire_pc_events(state, req.pc_id, &pc);
        state.registry.lock().await.pcs.insert(req.pc_id, pc);
    } else if id == M::ClosePeerConnection as i32 {
        let req = Server::ClosePeerConnection::decode(&mut decoder)?;
        if let Some(pc) = state.registry.lock().await.pcs.remove(&req.pc_id) {
            let _ = pc.close().await;
        }
    } else if id == M::CreateOffer as i32 {
        let req = Server::CreateOffer::decode(&mut decoder)?;
        let event = match find_pc(state, req.pc_id).await {
            Some(pc) => match pc.create_offer(None).await {
                Ok(d) => Client::OnCreateOfferResult {
                    pc_id: req.pc_id,
                    request_id: req.request_id,
                    ok: true,
                    sdp_type: format!("{:?}", d.sdp_type).to_lowercase(),
                    sdp: d.sdp,
                    error_kind: String::new(),
                    error_message: String::new(),
                },
                Err(e) => Client::OnCreateOfferResult {
                    pc_id: req.pc_id,
                    request_id: req.request_id,
                    ok: false,
                    sdp_type: String::new(),
                    sdp: String::new(),
                    error_kind: "OperationError".to_string(),
                    error_message: format!("{e}"),
                },
            },
            None => Client::OnCreateOfferResult {
                pc_id: req.pc_id,
                request_id: req.request_id,
                ok: false,
                sdp_type: String::new(),
                sdp: String::new(),
                error_kind: "InvalidStateError".to_string(),
                error_message: "unknown pc_id".to_string(),
            },
        };
        send(&state.writer, &event)?;
    } else if id == M::CreateAnswer as i32 {
        let req = Server::CreateAnswer::decode(&mut decoder)?;
        let event = match find_pc(state, req.pc_id).await {
            Some(pc) => match pc.create_answer(None).await {
                Ok(d) => Client::OnCreateAnswerResult {
                    pc_id: req.pc_id,
                    request_id: req.request_id,
                    ok: true,
                    sdp_type: format!("{:?}", d.sdp_type).to_lowercase(),
                    sdp: d.sdp,
                    error_kind: String::new(),
                    error_message: String::new(),
                },
                Err(e) => Client::OnCreateAnswerResult {
                    pc_id: req.pc_id,
                    request_id: req.request_id,
                    ok: false,
                    sdp_type: String::new(),
                    sdp: String::new(),
                    error_kind: "OperationError".to_string(),
                    error_message: format!("{e}"),
                },
            },
            None => Client::OnCreateAnswerResult {
                pc_id: req.pc_id,
                request_id: req.request_id,
                ok: false,
                sdp_type: String::new(),
                sdp: String::new(),
                error_kind: "InvalidStateError".to_string(),
                error_message: "unknown pc_id".to_string(),
            },
        };
        send(&state.writer, &event)?;
    } else if id == M::SetLocalDescription as i32 {
        let req = Server::SetLocalDescription::decode(&mut decoder)?;
        let (ok, error_kind, error_message) = apply_description(state, req.pc_id, &req.sdp_type, req.sdp, true).await;
        send(
            &state.writer,
            &Client::OnSetLocalDescriptionResult {
                pc_id: req.pc_id,
                request_id: req.request_id,
                ok,
                error_kind,
                error_message,
            },
        )?;
    } else if id == M::SetRemoteDescription as i32 {
        let req = Server::SetRemoteDescription::decode(&mut decoder)?;
        let (ok, error_kind, error_message) = apply_description(state, req.pc_id, &req.sdp_type, req.sdp, false).await;
        send(
            &state.writer,
            &Client::OnSetRemoteDescriptionResult {
                pc_id: req.pc_id,
                request_id: req.request_id,
                ok,
                error_kind,
                error_message,
            },
        )?;
    } else if id == M::AddIceCandidate as i32 {
        let req = Server::AddIceCandidate::decode(&mut decoder)?;
        let event = if let Some(pc) = find_pc(state, req.pc_id).await {
            let init = webrtc::ice_transport::ice_candidate::RTCIceCandidateInit {
                candidate: req.candidate,
                sdp_mid: req.sdp_mid,
                sdp_mline_index: req.sdp_mline_index.map(|v| v as u16),
                username_fragment: req.ufrag,
            };
            match pc.add_ice_candidate(init).await {
                Ok(()) => Client::OnAddIceCandidateResult {
                    pc_id: req.pc_id,
                    request_id: req.request_id,
                    ok: true,
                    error_kind: String::new(),
                    error_message: String::new(),
                },
                Err(e) => Client::OnAddIceCandidateResult {
                    pc_id: req.pc_id,
                    request_id: req.request_id,
                    ok: false,
                    error_kind: "OperationError".to_string(),
                    error_message: format!("{e}"),
                },
            }
        } else {
            Client::OnAddIceCandidateResult {
                pc_id: req.pc_id,
                request_id: req.request_id,
                ok: false,
                error_kind: "InvalidStateError".to_string(),
                error_message: "unknown pc_id".to_string(),
            }
        };
        send(&state.writer, &event)?;
    } else if id == M::AddTransceiver as i32 {
        let req = Server::AddTransceiver::decode(&mut decoder)?;
        if let Some(pc) = find_pc(state, req.pc_id).await {
            use webrtc::rtp_transceiver::rtp_codec::RTPCodecType;
            use webrtc::rtp_transceiver::rtp_transceiver_direction::RTCRtpTransceiverDirection;
            let kind = match req.kind.as_str() {
                "audio" => RTPCodecType::Audio,
                "video" => RTPCodecType::Video,
                other => {
                    log::warn!("AddTransceiver: unknown kind {other}");
                    return Ok(());
                }
            };
            let direction = match req.direction.as_str() {
                "sendrecv" => RTCRtpTransceiverDirection::Sendrecv,
                "sendonly" => RTCRtpTransceiverDirection::Sendonly,
                "recvonly" => RTCRtpTransceiverDirection::Recvonly,
                "inactive" => RTCRtpTransceiverDirection::Inactive,
                other => {
                    log::warn!("AddTransceiver: unknown direction {other}");
                    RTCRtpTransceiverDirection::Sendrecv
                }
            };
            let init = webrtc::rtp_transceiver::RTCRtpTransceiverInit {
                direction,
                send_encodings: Vec::new(),
            };
            if let Err(e) = pc.add_transceiver_from_kind(kind, Some(init)).await {
                log::warn!("add_transceiver_from_kind: {e}");
            }
        }
    } else if id == M::AddAudioTrack as i32 {
        let req = Server::AddAudioTrack::decode(&mut decoder)?;
        if let Some(pc) = find_pc(state, req.pc_id).await {
            use webrtc::api::media_engine::MIME_TYPE_OPUS;
            use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability;
            let track = Arc::new(TrackLocalStaticSample::new(
                RTCRtpCodecCapability {
                    mime_type: MIME_TYPE_OPUS.to_owned(),
                    clock_rate: 48000,
                    channels: 2,
                    sdp_fmtp_line: String::new(),
                    rtcp_feedback: vec![],
                },
                format!("audio-{}", req.sender_id),
                format!("ladybird-stream-{}", req.pc_id),
            ));
            match pc.add_track(track.clone()).await {
                Ok(rtp_sender) => {
                    let params = rtp_sender.get_parameters().await;
                    let ssrc = params.encodings.first().map(|e| e.ssrc).unwrap_or(0);
                    // Force the packetizer/sequencer to initialize NOW. webrtc-rs
                    // normally initializes them on the next negotiation cycle via
                    // start_rtp_senders → sender.send → track.bind, but for
                    // tracks added after the initial offer/answer that path can
                    // miss the new sender (the negotiated flag isn't set at the
                    // right point). Without bind(), TrackLocalStaticSample's
                    // write_sample silently no-ops because packetizer is None.
                    if let Err(e) = rtp_sender.send(&params).await {
                        log::warn!("rtp_sender.send (forcing bind): {e}");
                    }
                    let (pcm_tx, pcm_rx) = mpsc::unbounded_channel::<Vec<i16>>();
                    spawn_opus_encoder_task(track.clone(), pcm_rx);
                    state
                        .registry
                        .lock()
                        .await
                        .audio_senders
                        .insert(req.sender_id, AudioSender { pcm_tx, track });
                    log::info!(
                        "AddAudioTrack pc_id={} sender_id={} ssrc={} → host-driven PCM pump ready",
                        req.pc_id,
                        req.sender_id,
                        ssrc
                    );
                    send(
                        &state.writer,
                        &Client::OnAudioTrackAdded {
                            pc_id: req.pc_id,
                            sender_id: req.sender_id,
                            ssrc,
                        },
                    )?;
                }
                Err(e) => log::warn!("pc.add_track: {e}"),
            }
        }
    } else if id == M::AudioTrackPcmFrame as i32 {
        let req = Server::AudioTrackPcmFrame::decode(&mut decoder)?;
        // PCM is interleaved s16le. Cast to Vec<i16> in-place.
        let mut samples = Vec::with_capacity(req.pcm_s16le.len() / 2);
        for chunk in req.pcm_s16le.chunks_exact(2) {
            samples.push(i16::from_le_bytes([chunk[0], chunk[1]]));
        }
        // FIXME: honor sample_rate / channels by resampling. We assume 48 kHz stereo for now.
        let _ = (req.sample_rate, req.channels);
        let registry = state.registry.lock().await;
        if let Some(sender) = registry.audio_senders.get(&req.sender_id) {
            let _ = sender.pcm_tx.send(samples);
        }
    } else if id == M::AudioTrackEncodedFrame as i32 {
        let req = Server::AudioTrackEncodedFrame::decode(&mut decoder)?;
        let registry = state.registry.lock().await;
        if let Some(sender) = registry.audio_senders.get(&req.sender_id) {
            use std::time::Duration;
            use webrtc::media::Sample;
            static AUDIO_FRAME_LOG_COUNTER: AtomicUsize = AtomicUsize::new(0);
            let n = AUDIO_FRAME_LOG_COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
            // Log first few + every 250th frame (~5 seconds at 50 fps) so we can
            // see whether the pipe stays open over time.
            let should_log = n < 5 || n % 250 == 0;
            let sample = Sample {
                data: req.payload.into(),
                duration: Duration::from_micros(req.duration_micros as u64),
                ..Default::default()
            };
            let len = sample.data.len();
            match sender.track.write_sample(&sample).await {
                Ok(()) => {
                    if should_log {
                        log::info!(
                            "audio_track_encoded_frame#{n} sender_id={} duration_us={} len={} write_sample=OK",
                            req.sender_id,
                            req.duration_micros,
                            len
                        );
                    }
                }
                Err(e) => log::warn!("audio_track_encoded_frame#{n} write_sample failed: {e}"),
            }
        } else {
            log::warn!(
                "audio_track_encoded_frame: no AudioSender for sender_id={}",
                req.sender_id
            );
        }
    } else if id == M::RemoveTrack as i32 {
        let req = Server::RemoveTrack::decode(&mut decoder)?;
        // Dropping the pcm_tx ends the encoder task.
        state.registry.lock().await.audio_senders.remove(&req.sender_id);
        log::info!("RemoveTrack pc_id={} sender_id={}", req.pc_id, req.sender_id);
    } else if id == M::AddDataChannel as i32 {
        let req = Server::AddDataChannel::decode(&mut decoder)?;
        if let Some(pc) = find_pc(state, req.pc_id).await {
            let init = RTCDataChannelInit {
                ordered: Some(req.ordered),
                max_packet_life_time: req.max_packet_life_time,
                max_retransmits: req.max_retransmits,
                protocol: Some(req.protocol),
                // webrtc-rs encodes negotiated-ness via a Some(channel_id); host already
                // enforced that `negotiated == true` requires `id` to be set.
                negotiated: if req.negotiated { req.id } else { None },
            };
            match pc.create_data_channel(&req.label, Some(init)).await {
                Ok(dc) => {
                    wire_data_channel_events(state, req.channel_id, &dc).await;
                    state.registry.lock().await.data_channels.insert(req.channel_id, dc);
                }
                Err(e) => log::warn!("create_data_channel: {e}"),
            }
        }
    } else if id == M::DataChannelSendText as i32 {
        let req = Server::DataChannelSendText::decode(&mut decoder)?;
        if let Some(dc) = find_data_channel(state, req.channel_id).await {
            if let Err(e) = dc.send_text(&req.data).await {
                log::warn!("data_channel_send_text: {e}");
            }
        }
    } else if id == M::DataChannelSendBinary as i32 {
        let req = Server::DataChannelSendBinary::decode(&mut decoder)?;
        if let Some(dc) = find_data_channel(state, req.channel_id).await {
            if let Err(e) = dc.send(&bytes::Bytes::from(req.data)).await {
                log::warn!("data_channel_send_binary: {e}");
            }
        }
    } else if id == M::DataChannelClose as i32 {
        let req = Server::DataChannelClose::decode(&mut decoder)?;
        let removed = state.registry.lock().await.data_channels.remove(&req.channel_id);
        if let Some(dc) = removed {
            if let Err(e) = dc.close().await {
                log::warn!("data_channel_close: {e}");
            }
        }
    } else if id == M::SetTrackSinkParams as i32 {
        let _ = Server::SetTrackSinkParams::decode(&mut decoder)?;
    } else {
        log::warn!("unknown message id: {id}");
    }
    Ok(())
}

async fn find_pc(state: &Arc<State>, pc_id: u64) -> Option<Arc<RTCPeerConnection>> {
    state.registry.lock().await.pcs.get(&pc_id).cloned()
}

async fn find_data_channel(state: &Arc<State>, channel_id: u64) -> Option<Arc<RTCDataChannel>> {
    state.registry.lock().await.data_channels.get(&channel_id).cloned()
}

/// Drains a PCM channel (interleaved stereo s16, 48 kHz, 20 ms frames), opus-encodes each
/// frame and writes it to `track`. Ends when the sender side of `pcm_rx` is dropped.
fn spawn_opus_encoder_task(track: Arc<TrackLocalStaticSample>, mut pcm_rx: mpsc::UnboundedReceiver<Vec<i16>>) {
    use audiopus::coder::Encoder;
    use audiopus::{Application, Channels, SampleRate};
    use bytes::Bytes;
    use std::time::Duration;
    use webrtc::media::Sample;

    const FRAME_DURATION: Duration = Duration::from_millis(20);

    tokio::spawn(async move {
        let encoder = match Encoder::new(SampleRate::Hz48000, Channels::Stereo, Application::Voip) {
            Ok(e) => e,
            Err(e) => {
                log::error!("opus encoder: {e}");
                return;
            }
        };
        let mut out = [0u8; 4000];
        while let Some(frame) = pcm_rx.recv().await {
            // FIXME: assumes the host already framed at exactly 20 ms (960 samples per channel).
            //        Buffer/resample inside the service if the host can't guarantee that.
            match encoder.encode(&frame[..], &mut out[..]) {
                Ok(n) => {
                    let sample = Sample {
                        data: Bytes::copy_from_slice(&out[..n]),
                        duration: FRAME_DURATION,
                        ..Default::default()
                    };
                    if let Err(e) = track.write_sample(&sample).await {
                        log::warn!("write_sample: {e}");
                        break;
                    }
                }
                Err(e) => log::warn!("opus encode: {e}"),
            }
        }
    });
}

async fn wire_data_channel_events(state: &Arc<State>, channel_id: u64, dc: &Arc<RTCDataChannel>) {
    let writer = state.writer.clone();
    dc.on_open(Box::new(move || {
        let writer = writer.clone();
        Box::pin(async move {
            let _ = send(&writer, &Client::OnDataChannelOpen { channel_id });
        })
    }));

    let writer = state.writer.clone();
    dc.on_close(Box::new(move || {
        let writer = writer.clone();
        Box::pin(async move {
            let _ = send(&writer, &Client::OnDataChannelClosed { channel_id });
        })
    }));

    let writer = state.writer.clone();
    dc.on_error(Box::new(move |err| {
        let writer = writer.clone();
        Box::pin(async move {
            let _ = send(
                &writer,
                &Client::OnDataChannelError {
                    channel_id,
                    error: format!("{err}"),
                },
            );
        })
    }));

    let writer = state.writer.clone();
    dc.on_message(Box::new(move |msg| {
        let writer = writer.clone();
        Box::pin(async move {
            if msg.is_string {
                let text = String::from_utf8_lossy(&msg.data).into_owned();
                let _ = send(&writer, &Client::OnDataChannelMessageText { channel_id, data: text });
            } else {
                let _ = send(
                    &writer,
                    &Client::OnDataChannelMessageBinary {
                        channel_id,
                        data: msg.data.to_vec(),
                    },
                );
            }
        })
    }));

    let writer = state.writer.clone();
    dc.on_buffered_amount_low(Box::new(move || {
        let writer = writer.clone();
        Box::pin(async move {
            let _ = send(&writer, &Client::OnDataChannelBufferedAmountLow { channel_id });
        })
    }))
    .await;
}

async fn apply_description(
    state: &Arc<State>,
    pc_id: u64,
    sdp_type: &str,
    sdp: String,
    is_local: bool,
) -> (bool, String, String) {
    let Some(pc) = find_pc(state, pc_id).await else {
        return (false, "InvalidStateError".to_string(), "unknown pc_id".to_string());
    };
    // Discord's SDP marks every m= section as `a=inactive`, and webrtc-rs's
    // extract_ice_details skips inactive sections wholesale, so the SDP-embedded
    // candidates never make it into the ICE agent. Pull them out ourselves and
    // trickle them in after set_remote_description.
    let extracted_candidates = if !is_local {
        extract_candidate_lines(&sdp)
    } else {
        Vec::new()
    };

    log_sdp_summary(pc_id, if is_local { "local" } else { sdp_type }, &sdp);
    let parsed = parse_session_description(sdp_type, sdp);
    let Some(desc) = parsed else {
        return (
            false,
            "InvalidAccessError".to_string(),
            "could not parse SDP".to_string(),
        );
    };
    let result = if is_local {
        pc.set_local_description(desc).await
    } else {
        pc.set_remote_description(desc).await
    };
    match result {
        Ok(()) => {
            for candidate in extracted_candidates {
                let init = webrtc::ice_transport::ice_candidate::RTCIceCandidateInit {
                    candidate,
                    sdp_mid: Some("0".to_string()),
                    sdp_mline_index: Some(0),
                    username_fragment: None,
                };
                match pc.add_ice_candidate(init).await {
                    Ok(()) => {}
                    Err(e) => log::warn!("trickle ICE candidate from SDP failed: {e}"),
                }
            }
            (true, String::new(), String::new())
        }
        Err(e) => (false, "OperationError".to_string(), format!("{e}")),
    }
}

fn log_sdp_summary(pc_id: u64, sdp_type: &str, sdp: &str) {
    let mut m_count = 0usize;
    let mut ssrc_count = 0usize;
    let mut extmaps: Vec<String> = Vec::new();
    let mut m_lines: Vec<String> = Vec::new();
    let mut directions: Vec<String> = Vec::new();
    let mut mids: Vec<String> = Vec::new();
    for line in sdp.lines() {
        let line = line.trim();
        if line.starts_with("m=") {
            m_count += 1;
            m_lines.push(line.to_string());
        } else if let Some(rest) = line.strip_prefix("a=") {
            if rest.starts_with("ssrc:") {
                ssrc_count += 1;
            } else if rest.starts_with("extmap:") {
                if !extmaps.contains(&rest.to_string()) {
                    extmaps.push(rest.to_string());
                }
            } else if rest == "sendrecv" || rest == "recvonly" || rest == "sendonly" || rest == "inactive" {
                directions.push(rest.to_string());
            } else if let Some(mid) = rest.strip_prefix("mid:") {
                mids.push(mid.to_string());
            }
        }
    }
    log::info!(
        "{sdp_type} SDP pc_id={pc_id} m_sections={m_count} ssrc_lines={ssrc_count} extmaps={} directions={:?} mids={:?}",
        extmaps.len(),
        directions,
        mids,
    );
    for ext in &extmaps {
        log::info!("  extmap: {ext}");
    }
    for m in m_lines.iter().take(3) {
        log::info!("  m=: {m}");
    }
}

fn extract_candidate_lines(sdp: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in sdp.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("a=") else { continue };
        if !rest.starts_with("candidate:") {
            continue;
        }
        if seen.insert(rest.to_string()) {
            out.push(rest.to_string());
        }
    }
    out
}

fn parse_session_description(sdp_type: &str, sdp: String) -> Option<RTCSessionDescription> {
    let result = match sdp_type.to_ascii_lowercase().as_str() {
        "offer" => RTCSessionDescription::offer(sdp),
        "answer" => RTCSessionDescription::answer(sdp),
        "pranswer" => RTCSessionDescription::pranswer(sdp),
        "rollback" => Ok(RTCSessionDescription::default()),
        other => {
            log::warn!("unknown sdp type: {other}");
            return None;
        }
    };
    match result {
        Ok(d) => Some(d),
        Err(e) => {
            log::warn!("session description parse: {e}");
            None
        }
    }
}

fn wire_pc_events(state: &Arc<State>, pc_id: u64, pc: &Arc<RTCPeerConnection>) {
    let writer = state.writer.clone();
    pc.on_peer_connection_state_change(Box::new(move |s| {
        let writer = writer.clone();
        Box::pin(async move {
            let _ = send(
                &writer,
                &Client::OnConnectionState {
                    pc_id,
                    state: format!("{s:?}").to_lowercase(),
                },
            );
        })
    }));

    let writer = state.writer.clone();
    pc.on_signaling_state_change(Box::new(move |s| {
        let writer = writer.clone();
        Box::pin(async move {
            let _ = send(
                &writer,
                &Client::OnSignalingState {
                    pc_id,
                    state: format!("{s:?}").to_lowercase(),
                },
            );
        })
    }));

    let writer = state.writer.clone();
    pc.on_ice_connection_state_change(Box::new(move |s| {
        let writer = writer.clone();
        Box::pin(async move {
            let _ = send(
                &writer,
                &Client::OnIceConnectionState {
                    pc_id,
                    state: format!("{s:?}").to_lowercase(),
                },
            );
        })
    }));

    let writer = state.writer.clone();
    pc.on_ice_gathering_state_change(Box::new(move |s| {
        let writer = writer.clone();
        Box::pin(async move {
            let _ = send(
                &writer,
                &Client::OnIceGatheringState {
                    pc_id,
                    state: format!("{s:?}").to_lowercase(),
                },
            );
        })
    }));

    let writer = state.writer.clone();
    pc.on_ice_candidate(Box::new(move |c| {
        let writer = writer.clone();
        Box::pin(async move {
            let event = match c.and_then(|c| c.to_json().ok()) {
                Some(json) => Client::OnIceCandidate {
                    pc_id,
                    candidate: Some(json.candidate),
                    sdp_mid: json.sdp_mid,
                    sdp_mline_index: json.sdp_mline_index.map(u32::from),
                },
                None => Client::OnIceCandidate {
                    pc_id,
                    candidate: None,
                    sdp_mid: None,
                    sdp_mline_index: None,
                },
            };
            let _ = send(&writer, &event);
        })
    }));

    let writer = state.writer.clone();
    pc.on_negotiation_needed(Box::new(move || {
        let writer = writer.clone();
        Box::pin(async move {
            let _ = send(&writer, &Client::OnNegotiationNeeded { pc_id });
        })
    }));

    let writer = state.writer.clone();
    pc.on_track(Box::new(move |track, receiver, transceiver| {
        let writer = writer.clone();
        Box::pin(async move {
            // FIXME: hand out monotonic ids and forward audio data through LibMedia plumbing
            //        rather than using ssrc/pointer-derived ids.
            let receiver_id = u64::from(track.ssrc());
            let transceiver_id = Arc::as_ptr(&transceiver) as u64;
            let _ = (receiver,);
            let kind = format!("{}", track.kind());
            let stream_ids = vec![track.stream_id()];
            let track_mid = transceiver.mid();
            let track_rid = track.rid().to_string();
            log::info!(
                "on_track pc_id={pc_id} kind={kind} ssrc={} pt={} id={} stream_id={} mid={:?} rid={}",
                track.ssrc(),
                track.payload_type(),
                track.id(),
                track.stream_id(),
                track_mid,
                track_rid,
            );
            let _ = send(
                &writer,
                &Client::OnTrack {
                    pc_id,
                    receiver_id,
                    transceiver_id,
                    kind: kind.clone(),
                    stream_ids: stream_ids.clone(),
                },
            );
            if kind == "audio" {
                let writer = writer.clone();
                tokio::spawn(async move {
                    let mut pkt_count: u64 = 0;
                    let mut ssrcs_seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
                    loop {
                        match track.read_rtp().await {
                            Ok((packet, _)) => {
                                let ssrc = packet.header.ssrc;
                                let new_ssrc = ssrcs_seen.insert(ssrc);
                                if new_ssrc || pkt_count < 5 || pkt_count % 200 == 0 {
                                    log::info!(
                                        "rtp pc_id={pc_id} track_ssrc={} pkt_ssrc={ssrc} pt={} seq={} ts={} ext={} ext_ids={:?} payload_len={} count={}",
                                        track.ssrc(),
                                        packet.header.payload_type,
                                        packet.header.sequence_number,
                                        packet.header.timestamp,
                                        packet.header.extension,
                                        packet.header.extensions.iter().map(|e| e.id).collect::<Vec<_>>(),
                                        packet.payload.len(),
                                        pkt_count,
                                    );
                                }
                                pkt_count += 1;
                                if packet.payload.is_empty() {
                                    continue;
                                }
                                let _ = send(
                                    &writer,
                                    &Client::OnEncodedAudioFrame {
                                        pc_id,
                                        receiver_id,
                                        ssrc,
                                        rtp_timestamp: packet.header.timestamp,
                                        sequence_number: packet.header.sequence_number,
                                        payload_type: packet.header.payload_type,
                                        payload: packet.payload.to_vec(),
                                    },
                                );
                            }
                            Err(e) => {
                                log::warn!("read_rtp ended pc_id={pc_id} track_ssrc={} after {pkt_count} pkts ssrcs={:?}: {e}", track.ssrc(), ssrcs_seen);
                                break;
                            }
                        }
                    }
                });
            }
        })
    }));

    let state_for_dc = state.clone();
    pc.on_data_channel(Box::new(move |dc| {
        let state_for_dc = state_for_dc.clone();
        Box::pin(async move {
            let channel_id = state_for_dc
                .next_remote_channel_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            // Snapshot channel parameters before registering callbacks (the `on_*`
            // closures move `dc` ownership into webrtc-rs internals).
            let label = dc.label().to_string();
            let protocol = dc.protocol().to_string();
            let ordered = dc.ordered();
            let max_packet_life_time = dc.max_packet_lifetime();
            let max_retransmits = dc.max_retransmits();
            let negotiated = dc.negotiated();
            let id = dc.id();

            let _ = send(
                &state_for_dc.writer,
                &Client::OnDataChannel {
                    pc_id,
                    channel_id,
                    label,
                    ordered,
                    max_packet_life_time,
                    max_retransmits,
                    protocol,
                    negotiated,
                    id: if id == 0 { None } else { Some(id) },
                },
            );

            wire_data_channel_events(&state_for_dc, channel_id, &dc).await;
            state_for_dc.registry.lock().await.data_channels.insert(channel_id, dc);
        })
    }));
}

fn send<M: IPCMessage>(writer: &SharedWriter, msg: &M) -> Result<()> {
    let mut buffer = MessageBuffer::new();
    {
        let mut encoder = Encoder::new(&mut buffer);
        M::ENDPOINT_MAGIC.encode(&mut encoder)?;
        M::MESSAGE_ID.encode(&mut encoder)?;
        msg.encode(&mut encoder)?;
    }
    let mut sock = writer.lock().map_err(|_| anyhow!("writer mutex poisoned"))?;
    sock.post_message(&buffer.data, &mut buffer.attachments)?;
    Ok(())
}
