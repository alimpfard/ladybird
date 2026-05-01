/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

//! LibWebRTC: a thin Ladybird-shaped façade around the `webrtc` crate.
//!
//! Layering:
//!   peer    - PeerConnection wrapper + helpers
//!   media   - audio capture/playback wiring (cpal/pulse) — TODO
//!   service - IPC service surface — TODO

pub mod media;
pub mod peer;
pub mod service;
pub mod signal;

pub use webrtc;
