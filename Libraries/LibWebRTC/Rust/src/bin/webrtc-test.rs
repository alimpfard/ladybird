/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

//! webrtc-test: smoke tests for the WebRTC stack.
//!
//! Modes:
//!   (no args)        - in-process two-peer test: offerer streams 440Hz sine
//!                      to answerer, played through default output device
//!   --role offerer   - read answer from stdin, write offer to stdout, stream
//!                      sine
//!   --role answerer  - read offer from stdin, write answer to stdout, play
//!                      received audio
//!
//! For interop with pion: copy our base64 SDP into pion's example and back.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use tokio::sync::mpsc;

use ladybird_webrtc::media::{play_track, push_sine_to_track};
use ladybird_webrtc::peer::{build_default_api, new_peer_connection};
use ladybird_webrtc::{service, signal};
use libipc::{Decoder, Encoder, IPCDecode, IPCEncode, IPCMessage, MessageBuffer, TransportSocket};
use webrtc::api::media_engine::MIME_TYPE_OPUS;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::rtp_transceiver::RTCRtpTransceiverInit;
use webrtc::rtp_transceiver::rtp_codec::{RTCRtpCodecCapability, RTPCodecType};
use webrtc::rtp_transceiver::rtp_transceiver_direction::RTCRtpTransceiverDirection;
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;

#[derive(Debug)]
enum Mode {
    InProcess,
    Offerer,
    Answerer,
    IpcLoopback,
}

fn parse_mode() -> Result<Mode> {
    let mut args = std::env::args().skip(1);
    let mut role: Option<String> = None;
    let mut ipc_loopback = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--role" => role = args.next(),
            "--ipc-loopback" => ipc_loopback = true,
            "-h" | "--help" => {
                println!(
                    "usage: webrtc-test [--role offerer|answerer | --ipc-loopback]\n  no flag → in-process two-peer test"
                );
                std::process::exit(0);
            }
            other => bail!("unknown arg: {other}"),
        }
    }
    if ipc_loopback {
        return Ok(Mode::IpcLoopback);
    }
    Ok(match role.as_deref() {
        None => Mode::InProcess,
        Some("offerer") => Mode::Offerer,
        Some("answerer") => Mode::Answerer,
        Some(other) => bail!("unknown role: {other}"),
    })
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(env_logger::Target::Stderr)
        .init();
    match parse_mode()? {
        Mode::InProcess => run_in_process().await,
        Mode::Offerer => run_offerer().await,
        Mode::Answerer => run_answerer().await,
        Mode::IpcLoopback => run_ipc_loopback().await,
    }
}

async fn run_ipc_loopback() -> Result<()> {
    use ipc_webrtcclientserver::WebRTCClientServer as Server;

    let (local, handle) = TransportSocket::pair()?;
    let server_socket = TransportSocket::from_owned_fd(handle.into_owned_fd())?;
    tokio::spawn(async move {
        if let Err(e) = service::run(server_socket).await {
            log::warn!("service: {e:?}");
        }
    });

    let mut client = local;

    // 1. InitTransport request
    log::info!("→ InitTransport");
    write_msg(&mut client, &Server::InitTransport { peer_pid: std::process::id() as i32 })?;
    let resp: Server::InitTransportResponse = read_msg(&mut client)?;
    log::info!("← InitTransportResponse peer_pid={}", resp.peer_pid);
    assert!(resp.peer_pid > 0);

    // 2. CreatePeerConnection
    log::info!("→ CreatePeerConnection pc_id=1");
    write_msg(&mut client, &Server::CreatePeerConnection { pc_id: 1 })?;
    let resp: Server::CreatePeerConnectionResponse = read_msg(&mut client)?;
    log::info!("← CreatePeerConnectionResponse ok={}", resp.ok);
    assert!(resp.ok);

    // 3. CreateOffer (no transceivers — just exercise the path)
    log::info!("→ CreateOffer pc_id=1");
    write_msg(&mut client, &Server::CreateOffer { pc_id: 1 })?;
    let resp: Server::CreateOfferResponse = read_msg(&mut client)?;
    log::info!(
        "← CreateOfferResponse ok={} sdp_type={} sdp_len={}",
        resp.ok,
        resp.sdp_type,
        resp.sdp.len()
    );
    assert!(resp.ok);
    assert_eq!(resp.sdp_type, "offer");

    // 4. ClosePeerConnection (no response)
    log::info!("→ ClosePeerConnection pc_id=1");
    write_msg(&mut client, &Server::ClosePeerConnection { pc_id: 1 })?;

    // Drain any state-change events the server emits before tearing down.
    tokio::time::sleep(Duration::from_millis(200)).await;
    log::info!("ipc loopback OK");
    Ok(())
}

fn write_msg<M: IPCMessage>(socket: &mut TransportSocket, msg: &M) -> Result<()> {
    let mut buffer = MessageBuffer::new();
    {
        let mut encoder = Encoder::new(&mut buffer);
        M::ENDPOINT_MAGIC.encode(&mut encoder)?;
        M::MESSAGE_ID.encode(&mut encoder)?;
        msg.encode(&mut encoder)?;
    }
    socket.post_message(&buffer.data, &mut buffer.attachments)?;
    Ok(())
}

fn read_msg<M: IPCMessage>(socket: &mut TransportSocket) -> Result<M> {
    loop {
        let Some(transport_msg) = socket.read_message()? else {
            anyhow::bail!("peer disconnected before response");
        };
        let mut decoder = Decoder::new(&transport_msg.bytes, transport_msg.attachments);
        let _magic = u32::decode(&mut decoder)?;
        let id = i32::decode(&mut decoder)?;
        // Skip events fired by the server while we're waiting for a response.
        if id == M::MESSAGE_ID {
            return Ok(M::decode(&mut decoder)?);
        }
        log::debug!("skipping event id={id} while waiting for {}", M::MESSAGE_ID);
    }
}

fn build_audio_track() -> Arc<TrackLocalStaticSample> {
    Arc::new(TrackLocalStaticSample::new(
        RTCRtpCodecCapability {
            mime_type: MIME_TYPE_OPUS.to_owned(),
            clock_rate: 48000,
            channels: 2,
            ..Default::default()
        },
        "audio".to_owned(),
        "ladybird-mic".to_owned(),
    ))
}

fn forward_state(pc: &Arc<RTCPeerConnection>, who: &'static str, tx: mpsc::UnboundedSender<(&'static str, RTCPeerConnectionState)>) {
    pc.on_peer_connection_state_change(Box::new(move |state| {
        let _ = tx.send((who, state));
        Box::pin(async {})
    }));
}

async fn wait_for_gathering(pc: &Arc<RTCPeerConnection>) {
    let mut gather_complete = pc.gathering_complete_promise().await;
    let _ = gather_complete.recv().await;
}

async fn wait_until_connected(
    rx: &mut mpsc::UnboundedReceiver<(&'static str, RTCPeerConnectionState)>,
    expected: &[&'static str],
) -> Result<()> {
    let mut connected: Vec<&'static str> = Vec::new();
    while connected.len() < expected.len() {
        let Some((who, state)) = rx.recv().await else {
            bail!("state channel closed before all peers connected");
        };
        log::info!("[{who}] {state:?}");
        match state {
            RTCPeerConnectionState::Connected => {
                if expected.contains(&who) && !connected.contains(&who) {
                    connected.push(who);
                }
            }
            RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed => {
                bail!("peer {who} reached terminal state {state:?}");
            }
            _ => {}
        }
    }
    Ok(())
}

async fn run_in_process() -> Result<()> {
    let api = build_default_api()?;
    let config = RTCConfiguration::default();

    let offerer = new_peer_connection(&api, config.clone()).await?;
    let answerer = new_peer_connection(&api, config).await?;

    let (state_tx, mut state_rx) = mpsc::unbounded_channel();
    forward_state(&offerer, "offerer", state_tx.clone());
    forward_state(&answerer, "answerer", state_tx);

    answerer.on_track(Box::new(move |track, _, _| {
        Box::pin(async move {
            log::info!("answerer track: kind={} ssrc={}", track.kind(), track.ssrc());
            if let Err(e) = play_track(track) {
                log::warn!("play_track: {e:?}");
            }
        })
    }));

    let local_track = build_audio_track();
    offerer.add_track(local_track.clone()).await?;

    let offer = offerer.create_offer(None).await?;
    offerer.set_local_description(offer).await?;
    wait_for_gathering(&offerer).await;
    let local_offer = offerer.local_description().await.expect("offerer ldesc");

    answerer.set_remote_description(local_offer).await?;
    let answer = answerer.create_answer(None).await?;
    answerer.set_local_description(answer).await?;
    wait_for_gathering(&answerer).await;
    let local_answer = answerer.local_description().await.expect("answerer ldesc");

    offerer.set_remote_description(local_answer).await?;

    wait_until_connected(&mut state_rx, &["offerer", "answerer"]).await?;
    log::info!("both peers connected — pushing 440Hz sine for 10s");
    push_sine_to_track(local_track, 440.0)?;
    tokio::time::sleep(Duration::from_secs(10)).await;

    log::info!("shutting down");
    offerer.close().await?;
    answerer.close().await?;
    Ok(())
}

async fn run_offerer() -> Result<()> {
    let api = build_default_api()?;
    let pc = new_peer_connection(&api, RTCConfiguration::default()).await?;

    let (state_tx, mut state_rx) = mpsc::unbounded_channel();
    forward_state(&pc, "offerer", state_tx);

    let local_track = build_audio_track();
    pc.add_track(local_track.clone()).await?;

    pc.on_track(Box::new(move |track, _, _| {
        Box::pin(async move {
            log::info!("track: kind={} ssrc={}", track.kind(), track.ssrc());
            if let Err(e) = play_track(track) {
                log::warn!("play_track: {e:?}");
            }
        })
    }));

    let offer = pc.create_offer(None).await?;
    pc.set_local_description(offer).await?;
    wait_for_gathering(&pc).await;
    let local_offer = pc.local_description().await.expect("ldesc");

    log::info!("offer SDP follows on stdout, paste remote answer to stdin then press enter:");
    signal::write_to_stdout(&local_offer)?;

    let remote_answer = tokio::task::spawn_blocking(signal::read_from_stdin).await??;
    pc.set_remote_description(remote_answer).await?;

    wait_until_connected(&mut state_rx, &["offerer"]).await?;
    log::info!("connected — pushing 440Hz sine for 30s");
    push_sine_to_track(local_track, 440.0)?;
    tokio::time::sleep(Duration::from_secs(30)).await;

    pc.close().await?;
    Ok(())
}

async fn run_answerer() -> Result<()> {
    let api = build_default_api()?;
    let pc = new_peer_connection(&api, RTCConfiguration::default()).await?;

    let (state_tx, mut state_rx) = mpsc::unbounded_channel();
    forward_state(&pc, "answerer", state_tx);

    pc.on_track(Box::new(move |track, _, _| {
        Box::pin(async move {
            log::info!("track: kind={} ssrc={}", track.kind(), track.ssrc());
            if let Err(e) = play_track(track) {
                log::warn!("play_track: {e:?}");
            }
        })
    }));

    // recvonly transceiver so we can negotiate audio without a local track
    pc.add_transceiver_from_kind(
        RTPCodecType::Audio,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            send_encodings: vec![],
        }),
    )
    .await?;

    log::info!("paste remote offer to stdin then press enter:");
    let remote_offer = tokio::task::spawn_blocking(signal::read_from_stdin).await??;
    pc.set_remote_description(remote_offer).await?;

    let answer = pc.create_answer(None).await?;
    pc.set_local_description(answer).await?;
    wait_for_gathering(&pc).await;
    let local_answer = pc.local_description().await.expect("ldesc");

    log::info!("answer SDP on stdout:");
    signal::write_to_stdout(&local_answer)?;

    wait_until_connected(&mut state_rx, &["answerer"]).await?;
    log::info!("connected — playing for 30s");
    tokio::time::sleep(Duration::from_secs(30)).await;

    pc.close().await?;
    Ok(())
}
