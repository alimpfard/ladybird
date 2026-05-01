/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

//! WebRTCClient service entrypoint.
//!
//! Owns the entire WebRTC stack via `ladybird_webrtc`. The transport socket fd
//! is inherited from the parent and discovered through the standard Ladybird
//! `SOCKET_TAKEOVER` env var (`Name1:fd1;Name2:fd2;…`).

use std::env;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use anyhow::{Context, Result, anyhow};
use ladybird_webrtc::service;
use libipc::TransportSocket;

const SERVICE_NAME: &str = "WebRTCClient";

fn take_over_socket() -> Result<RawFd> {
    let raw = env::var("SOCKET_TAKEOVER").context("SOCKET_TAKEOVER env var is not set")?;
    for entry in raw.split(';') {
        let mut parts = entry.split(':');
        let name = parts.next().unwrap_or_default();
        let fd_str = parts.next().unwrap_or_default();
        if name == SERVICE_NAME {
            let fd: RawFd = fd_str
                .parse()
                .with_context(|| format!("invalid fd in SOCKET_TAKEOVER entry '{entry}'"))?;
            // Match LibCore's behavior: clear CLOEXEC isn't needed here since we
            // already inherited the fd; we just unset the env var so children
            // don't think we're passing it through.
            unsafe {
                env::remove_var("SOCKET_TAKEOVER");
            }
            return Ok(fd);
        }
    }
    Err(anyhow!(
        "SOCKET_TAKEOVER did not include an entry for {SERVICE_NAME}"
    ))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(env_logger::Target::Stderr)
        .init();

    let fd = take_over_socket()?;
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let transport = TransportSocket::from_owned_fd(owned)?;
    log::info!("WebRTCClient running, transport fd={fd}");
    service::run(transport).await
}
