/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

//! Turns the RTP packets of a received video track into whole encoded frames, which the renderer decodes.

use std::collections::VecDeque;

use bytes::Bytes;
use webrtc::media::io::sample_builder::SampleBuilder;
use webrtc::rtp::codecs::h264::H264Packet;
use webrtc::rtp::codecs::vp8::Vp8Packet;
use webrtc::rtp::codecs::vp9::Vp9Packet;
use webrtc::rtp::packet::Packet;
use webrtc::rtp::packetizer::Depacketizer;

/// Every video codec is carried over RTP with this clock rate.
const VIDEO_CLOCK_RATE: u32 = 90_000;

/// How many packets may arrive after one that is missing before it is given up on. Retransmissions answer the
/// requests made for the missing packet in the meantime.
const MAX_LATE_PACKETS: u16 = 256;

/// The video codecs that are offered to peers, which are the ones whose frames can be put together here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VideoCodec {
    Vp8,
    Vp9,
    H264,
}

impl VideoCodec {
    pub fn from_mime_type(mime_type: &str) -> Option<Self> {
        match mime_type.to_ascii_lowercase().as_str() {
            "video/vp8" => Some(Self::Vp8),
            "video/vp9" => Some(Self::Vp9),
            "video/h264" => Some(Self::H264),
            _ => None,
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        [Self::Vp8, Self::Vp9, Self::H264]
            .into_iter()
            .find(|codec| codec.name() == name)
    }

    /// The name that the renderer knows the codec by.
    pub fn name(self) -> &'static str {
        match self {
            Self::Vp8 => "VP8",
            Self::Vp9 => "VP9",
            Self::H264 => "H264",
        }
    }
}

// https://datatracker.ietf.org/doc/html/rfc6386#section-9.1
fn is_vp8_key_frame(frame: &[u8]) -> bool {
    frame.first().is_some_and(|first| first & 0x01 == 0)
}

// https://datatracker.ietf.org/doc/html/rfc9628#section-4.2
/// What the payload descriptor of a VP9 packet says about the frame the packet belongs to, if the packet is the
/// one that begins the frame: whether the frame is free of inter-picture prediction.
///
/// A VP8 or an H.264 frame says in its own first bytes whether it is a key frame, and end-to-end encryption leaves
/// those bytes readable for that reason. A VP9 frame is encrypted whole, so its packets have to say.
fn vp9_packet_begins_key_frame(payload: &[u8]) -> Option<bool> {
    const INTER_PICTURE_PREDICTED: u8 = 0x40;
    const BEGINNING_OF_FRAME: u8 = 0x08;
    let descriptor = *payload.first()?;
    (descriptor & BEGINNING_OF_FRAME != 0).then_some(descriptor & INTER_PICTURE_PREDICTED == 0)
}

// ITU-T H.264, 7.4.1 NAL unit semantics, for NAL units in the byte stream format of Annex B.
fn is_h264_key_frame(frame: &[u8]) -> bool {
    const NAL_UNIT_TYPE_IDR_SLICE: u8 = 5;
    let mut index = 0;
    while index + 3 < frame.len() {
        if frame[index] == 0 && frame[index + 1] == 0 && frame[index + 2] == 1 {
            if frame[index + 3] & 0x1f == NAL_UNIT_TYPE_IDR_SLICE {
                return true;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    false
}

enum AnyDepacketizer {
    Vp8(Vp8Packet),
    Vp9(Vp9Packet),
    H264(H264Packet),
}

impl Depacketizer for AnyDepacketizer {
    fn depacketize(&mut self, packet: &Bytes) -> Result<Bytes, webrtc::rtp::Error> {
        match self {
            Self::Vp8(depacketizer) => depacketizer.depacketize(packet),
            Self::Vp9(depacketizer) => depacketizer.depacketize(packet),
            Self::H264(depacketizer) => depacketizer.depacketize(packet),
        }
    }

    fn is_partition_head(&self, payload: &Bytes) -> bool {
        match self {
            Self::Vp8(depacketizer) => depacketizer.is_partition_head(payload),
            Self::Vp9(depacketizer) => depacketizer.is_partition_head(payload),
            Self::H264(depacketizer) => depacketizer.is_partition_head(payload),
        }
    }

    fn is_partition_tail(&self, marker: bool, payload: &Bytes) -> bool {
        match self {
            Self::Vp8(depacketizer) => depacketizer.is_partition_tail(marker, payload),
            Self::Vp9(depacketizer) => depacketizer.is_partition_tail(marker, payload),
            Self::H264(depacketizer) => depacketizer.is_partition_tail(marker, payload),
        }
    }
}

pub struct Frame {
    pub data: Bytes,
    pub rtp_timestamp: u32,
    pub is_key_frame: bool,
}

/// Puts frames together from the packets of one codec, and only lets out frames that can be decoded: after a frame
/// is lost, the ones that depend on it are held back until the next key frame.
pub struct FrameAssembler {
    codec: VideoCodec,
    builder: SampleBuilder<AnyDepacketizer>,
    waiting_for_key_frame: bool,
    /// The RTP timestamps of the VP9 frames whose packets are with the builder, and whether each is a key frame.
    vp9_frames: VecDeque<(u32, bool)>,
}

impl FrameAssembler {
    pub fn new(codec: VideoCodec) -> Self {
        let depacketizer = match codec {
            VideoCodec::Vp8 => AnyDepacketizer::Vp8(Vp8Packet::default()),
            VideoCodec::Vp9 => AnyDepacketizer::Vp9(Vp9Packet::default()),
            VideoCodec::H264 => AnyDepacketizer::H264(H264Packet::default()),
        };
        Self {
            codec,
            builder: SampleBuilder::new(MAX_LATE_PACKETS, depacketizer, VIDEO_CLOCK_RATE),
            waiting_for_key_frame: true,
            vp9_frames: VecDeque::new(),
        }
    }

    pub fn codec(&self) -> VideoCodec {
        self.codec
    }

    /// Whether the sender has to be asked for a key frame for any more frames to come out.
    pub fn is_waiting_for_key_frame(&self) -> bool {
        self.waiting_for_key_frame
    }

    /// For when a frame that was let out didn't reach the decoder.
    pub fn wait_for_key_frame(&mut self) {
        self.waiting_for_key_frame = true;
    }

    /// Whether a frame the builder put together can be decoded without any of the frames before it.
    fn is_key_frame(&mut self, frame: &[u8], rtp_timestamp: u32) -> bool {
        match self.codec {
            VideoCodec::Vp8 => is_vp8_key_frame(frame),
            VideoCodec::H264 => is_h264_key_frame(frame),
            VideoCodec::Vp9 => {
                // Frames come out in the order they went in, so the ones noted before this one are gone for good.
                while let Some((noted_timestamp, is_key_frame)) = self.vp9_frames.pop_front() {
                    if noted_timestamp == rtp_timestamp {
                        return is_key_frame;
                    }
                }
                false
            }
        }
    }

    /// Takes a packet, and returns the frames it completed.
    pub fn push(&mut self, packet: Packet) -> Vec<Frame> {
        if self.codec == VideoCodec::Vp9
            && let Some(is_key_frame) = vp9_packet_begins_key_frame(&packet.payload)
            && !self
                .vp9_frames
                .iter()
                .any(|(timestamp, _)| *timestamp == packet.header.timestamp)
        {
            if self.vp9_frames.len() >= usize::from(MAX_LATE_PACKETS) {
                self.vp9_frames.pop_front();
            }
            self.vp9_frames.push_back((packet.header.timestamp, is_key_frame));
        }

        self.builder.push(packet);
        let mut frames = Vec::new();
        while let Some((sample, rtp_timestamp)) = self.builder.pop_with_timestamp() {
            if sample.data.is_empty() {
                continue;
            }
            let is_key_frame = self.is_key_frame(&sample.data, rtp_timestamp);
            if sample.prev_dropped_packets > 0 {
                self.waiting_for_key_frame = true;
            }
            if self.waiting_for_key_frame && !is_key_frame {
                continue;
            }
            self.waiting_for_key_frame = false;
            frames.push(Frame {
                data: sample.data,
                rtp_timestamp,
                is_key_frame,
            });
        }
        frames
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_the_codecs_it_can_assemble() {
        assert_eq!(VideoCodec::from_mime_type("video/VP8"), Some(VideoCodec::Vp8));
        assert_eq!(VideoCodec::from_mime_type("video/vp9"), Some(VideoCodec::Vp9));
        assert_eq!(VideoCodec::from_mime_type("video/H264"), Some(VideoCodec::H264));
        assert_eq!(VideoCodec::from_mime_type("video/AV1"), None);
    }

    #[test]
    fn vp8_key_frames_have_a_clear_first_bit() {
        assert!(is_vp8_key_frame(&[0x10, 0x02, 0x00, 0x9d, 0x01, 0x2a]));
        assert!(!is_vp8_key_frame(&[0x11, 0x02, 0x00]));
        assert!(!is_vp8_key_frame(&[]));
    }

    #[test]
    fn vp9_key_frames_are_read_from_the_payload_descriptor() {
        // The beginning of a frame that isn't predicted from another picture.
        assert_eq!(vp9_packet_begins_key_frame(&[0b0000_1000]), Some(true));
        // The beginning of a frame that is.
        assert_eq!(vp9_packet_begins_key_frame(&[0b0100_1000]), Some(false));
        // A packet from the middle of a frame.
        assert_eq!(vp9_packet_begins_key_frame(&[0b0000_0000]), None);
        assert_eq!(vp9_packet_begins_key_frame(&[]), None);
    }

    fn vp9_packet(sequence_number: u16, timestamp: u32, is_key_frame: bool, first_byte: u8) -> Packet {
        let mut packet = Packet::default();
        packet.header.sequence_number = sequence_number;
        packet.header.timestamp = timestamp;
        packet.header.marker = true;
        // A payload descriptor for a frame that fits in one packet, followed by the frame's bytes.
        let descriptor = 0x08 | 0x04 | if is_key_frame { 0x00 } else { 0x40 };
        packet.payload = Bytes::from(vec![descriptor, first_byte, 0xaa, 0xbb]);
        packet
    }

    #[test]
    fn vp9_key_frames_are_found_whatever_the_frames_contain() {
        // Encrypted end to end, a frame starts with whatever the cipher made of it. These first bytes read as the
        // opposite of what the frames are.
        const LOOKS_LIKE_A_KEY_FRAME: u8 = 0b1000_0010;
        const LOOKS_LIKE_A_DELTA_FRAME: u8 = 0b1000_0110;
        let mut assembler = FrameAssembler::new(VideoCodec::Vp9);
        let frames = push_all(
            &mut assembler,
            vec![
                vp9_packet(1, 3000, false, LOOKS_LIKE_A_KEY_FRAME),
                vp9_packet(2, 6000, true, LOOKS_LIKE_A_DELTA_FRAME),
                vp9_packet(3, 9000, false, LOOKS_LIKE_A_KEY_FRAME),
                vp9_packet(4, 12000, false, LOOKS_LIKE_A_KEY_FRAME),
            ],
        );
        assert!(!frames.is_empty());
        assert!(frames[0].is_key_frame);
        assert_eq!(frames[0].rtp_timestamp, 6000);
        assert!(frames[1..].iter().all(|frame| !frame.is_key_frame));
    }

    #[test]
    fn h264_key_frames_contain_an_idr_slice() {
        let parameter_sets_and_idr = [0, 0, 0, 1, 0x67, 0x42, 0, 0, 0, 1, 0x68, 0xce, 0, 0, 1, 0x65, 0x88];
        assert!(is_h264_key_frame(&parameter_sets_and_idr));
        let non_idr = [0, 0, 0, 1, 0x41, 0x9a, 0x02];
        assert!(!is_h264_key_frame(&non_idr));
        assert!(!is_h264_key_frame(&[0, 0, 1]));
    }

    fn vp8_packet(sequence_number: u16, timestamp: u32, start: bool, marker: bool, first_byte: u8) -> Packet {
        let mut packet = Packet::default();
        packet.header.sequence_number = sequence_number;
        packet.header.timestamp = timestamp;
        packet.header.marker = marker;
        // A payload descriptor with only the start-of-partition bit, followed by the frame's bytes.
        packet.payload = Bytes::from(vec![if start { 0x10 } else { 0x00 }, first_byte, 0xaa, 0xbb]);
        packet
    }

    fn push_all(assembler: &mut FrameAssembler, packets: Vec<Packet>) -> Vec<Frame> {
        packets.into_iter().flat_map(|packet| assembler.push(packet)).collect()
    }

    #[test]
    fn frames_before_the_first_key_frame_are_held_back() {
        let mut assembler = FrameAssembler::new(VideoCodec::Vp8);
        let frames = push_all(
            &mut assembler,
            vec![
                vp8_packet(1, 3000, true, true, 0x01),
                vp8_packet(2, 6000, true, true, 0x00),
                vp8_packet(3, 9000, true, true, 0x01),
                vp8_packet(4, 12000, true, true, 0x01),
            ],
        );
        assert!(!frames.is_empty());
        assert!(frames[0].is_key_frame);
        assert_eq!(frames[0].rtp_timestamp, 6000);
        assert!(frames[1..].iter().all(|frame| !frame.is_key_frame));
        assert!(!assembler.is_waiting_for_key_frame());
    }
}
