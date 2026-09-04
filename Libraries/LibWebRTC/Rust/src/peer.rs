/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

//! PeerConnection helpers built on top of the `webrtc` crate.
//!
//! For now this is just a builder that wires up a default `MediaEngine` and
//! returns a fresh `webrtc::api::API` instance ready to spawn peer connections.
//! As the IPC service grows, real wrapper types will live here.

use std::sync::Arc;

use anyhow::Result;
use webrtc::api::API;
use webrtc::api::APIBuilder;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::ice::mdns::MulticastDnsMode;
use webrtc::ice::network_type::NetworkType;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::rtp_transceiver::rtp_codec::{RTCRtpHeaderExtensionCapability, RTPCodecType};

pub fn build_default_api() -> Result<API> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    // Required for routing bundled RTP streams to the right transceiver — without these
    // webrtc-rs falls back to "needs simulcast probing" and drops every speech packet.
    for uri in [
        "urn:ietf:params:rtp-hdrext:sdes:mid",
        "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
        "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
    ] {
        media_engine.register_header_extension(
            RTCRtpHeaderExtensionCapability { uri: uri.to_owned() },
            RTPCodecType::Audio,
            None,
        )?;
        media_engine.register_header_extension(
            RTCRtpHeaderExtensionCapability { uri: uri.to_owned() },
            RTPCodecType::Video,
            None,
        )?;
    }
    let mut setting_engine = SettingEngine::default();
    // Restrict ICE to IPv4. Link-local IPv6 binds need a scope id that webrtc-rs
    // doesn't pass through, so any v6 host candidate fails to bind and we end up
    // with no candidate pairs at all.
    setting_engine.set_network_types(vec![NetworkType::Udp4]);
    // Default mDNS-mode replaces host candidates with `<hash>.local`, which non-
    // browser peers (Discord's media server, in particular) can't resolve, so
    // they get discarded and we end up with no candidate pairs.
    setting_engine.set_ice_multicast_dns_mode(MulticastDnsMode::Disabled);
    Ok(APIBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(setting_engine)
        .build())
}

pub async fn new_peer_connection(api: &API, config: RTCConfiguration) -> Result<Arc<RTCPeerConnection>> {
    let pc = api.new_peer_connection(config).await?;
    Ok(Arc::new(pc))
}
