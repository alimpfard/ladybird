/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

//! Rust mirror of the LibIPC primitives. Provides Encoder / Decoder traits and
//! impls for the wire-compatible primitive types used by Ladybird IPC.

#[cfg(unix)]
pub mod transport;

#[cfg(unix)]
pub use transport::{TransportHandle, TransportMessage, TransportSocket};

use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    BufferUnderrun,
    SizeTooLarge,
    InvalidUtf8,
    InvalidEnumValue(i64),
    InvalidVariantIndex(u32),
    NoAttachment,
    Custom(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferUnderrun => f.write_str("IPC decode: buffer underrun"),
            Self::SizeTooLarge => f.write_str("IPC: size exceeds maximum allowed"),
            Self::InvalidUtf8 => f.write_str("IPC decode: invalid UTF-8"),
            Self::InvalidEnumValue(v) => write!(f, "IPC decode: invalid enum value {v}"),
            Self::InvalidVariantIndex(i) => write!(f, "IPC decode: invalid variant index {i}"),
            Self::NoAttachment => f.write_str("IPC decode: no attachment available"),
            Self::Custom(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for Error {}

/// Maximum size for decoded containers (strings, buffers, vectors, ...).
/// Mirrors `Decoder::MAX_DECODED_SIZE` in the C++ implementation.
pub const MAX_DECODED_SIZE: usize = 64 * 1024 * 1024;

/// An attachment carried alongside the message bytes — typically a file
/// descriptor (POSIX) or a HANDLE (Windows). The C++ side uses this for
/// `IPC::File`, `Core::AnonymousBuffer`, and `IPC::TransportHandle`.
#[cfg(unix)]
#[derive(Debug)]
pub struct Attachment {
    fd: Option<std::os::fd::OwnedFd>,
}

#[cfg(unix)]
impl Attachment {
    pub fn from_owned_fd(fd: std::os::fd::OwnedFd) -> Self {
        Self { fd: Some(fd) }
    }

    /// Adopt ownership of a raw file descriptor. The attachment will close
    /// the descriptor on drop unless [`Attachment::take`] is called first.
    ///
    /// # Safety
    /// The caller must own `fd` and not use it after this call.
    pub unsafe fn from_raw_fd(fd: std::os::fd::RawFd) -> Self {
        use std::os::fd::FromRawFd;
        Self {
            fd: Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) }),
        }
    }

    pub fn as_raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.fd.as_ref().map_or(-1, std::os::fd::OwnedFd::as_raw_fd)
    }

    pub fn take(&mut self) -> Option<std::os::fd::OwnedFd> {
        self.fd.take()
    }

    pub fn into_owned_fd(self) -> Option<std::os::fd::OwnedFd> {
        self.fd
    }
}

#[cfg(not(unix))]
#[derive(Debug, Default)]
pub struct Attachment;

#[cfg(not(unix))]
impl Attachment {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Default)]
pub struct MessageBuffer {
    pub data: Vec<u8>,
    pub attachments: Vec<Attachment>,
}

impl MessageBuffer {
    pub fn new() -> Self {
        Self::default()
    }
}

pub struct Encoder<'a> {
    buffer: &'a mut MessageBuffer,
}

impl<'a> Encoder<'a> {
    pub fn new(buffer: &'a mut MessageBuffer) -> Self {
        Self { buffer }
    }

    pub fn append(&mut self, bytes: &[u8]) {
        self.buffer.data.extend_from_slice(bytes);
    }

    pub fn append_attachment(&mut self, attachment: Attachment) {
        self.buffer.attachments.push(attachment);
    }

    pub fn encode_size(&mut self, size: usize) -> Result<(), Error> {
        let size = u32::try_from(size).map_err(|_| Error::SizeTooLarge)?;
        size.encode(self)
    }

    pub fn encode<T>(&mut self, value: &T) -> Result<(), Error>
    where
        T: IPCEncode + ?Sized,
    {
        value.encode(self)
    }
}

pub struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
    attachments: VecDeque<Attachment>,
}

impl<'a> Decoder<'a> {
    pub fn new<I>(data: &'a [u8], attachments: I) -> Self
    where
        I: IntoIterator<Item = Attachment>,
    {
        Self {
            data,
            pos: 0,
            attachments: attachments.into_iter().collect(),
        }
    }

    pub fn read(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::BufferUnderrun)?;
        if end > self.data.len() {
            return Err(Error::BufferUnderrun);
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.read(N)?);
        Ok(out)
    }

    pub fn decode_size(&mut self) -> Result<usize, Error> {
        let size = u32::decode(self)? as usize;
        if size > MAX_DECODED_SIZE {
            return Err(Error::SizeTooLarge);
        }
        Ok(size)
    }

    pub fn take_attachment(&mut self) -> Result<Attachment, Error> {
        self.attachments.pop_front().ok_or(Error::NoAttachment)
    }

    pub fn decode<T: IPCDecode>(&mut self) -> Result<T, Error> {
        T::decode(self)
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos == self.data.len()
    }
}

pub trait IPCEncode {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), Error>;
}

pub trait IPCDecode: Sized {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error>;
}

/// Identifies a message within an endpoint. Generated message structs
/// implement this so callers can build full message buffers via
/// [`encode_message`].
pub trait IPCMessage: IPCEncode + IPCDecode {
    const ENDPOINT_MAGIC: u32;
    const MESSAGE_ID: i32;
    const NAME: &'static str;
}

macro_rules! impl_le_arithmetic {
    ($($t:ty),*) => {$(
        impl IPCEncode for $t {
            #[inline]
            fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), Error> {
                encoder.append(&self.to_le_bytes());
                Ok(())
            }
        }
        impl IPCDecode for $t {
            #[inline]
            fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
                Ok(<$t>::from_le_bytes(decoder.read_array()?))
            }
        }
    )*}
}

impl_le_arithmetic!(i8, u8, i16, u16, i32, u32, i64, u64, f32, f64);

impl IPCEncode for bool {
    #[inline]
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), Error> {
        encoder.append(&[u8::from(*self)]);
        Ok(())
    }
}

impl IPCDecode for bool {
    #[inline]
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        Ok(decoder.read_array::<1>()?[0] != 0)
    }
}

impl IPCEncode for str {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), Error> {
        encoder.encode_size(self.len())?;
        encoder.append(self.as_bytes());
        Ok(())
    }
}

impl IPCEncode for String {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), Error> {
        self.as_str().encode(encoder)
    }
}

impl IPCDecode for String {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let len = decoder.decode_size()?;
        let bytes = decoder.read(len)?.to_vec();
        Self::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)
    }
}

/// Mirror of `AK::ByteString` — arbitrary bytes (not necessarily valid UTF-8).
/// Wire format is identical to a String: u32 length followed by the bytes.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ByteString(pub Vec<u8>);

impl ByteString {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<&str> for ByteString {
    fn from(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl From<String> for ByteString {
    fn from(s: String) -> Self {
        Self(s.into_bytes())
    }
}

impl From<Vec<u8>> for ByteString {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl IPCEncode for ByteString {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), Error> {
        encoder.encode_size(self.0.len())?;
        encoder.append(&self.0);
        Ok(())
    }
}

impl IPCDecode for ByteString {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let len = decoder.decode_size()?;
        Ok(Self(decoder.read(len)?.to_vec()))
    }
}

/// Mirror of `AK::Utf16String` — wire format is a 1-byte ASCII flag, a u32
/// length-in-code-units, then either ASCII bytes (if flag is set) or
/// little-endian UTF-16 code units.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Utf16String(pub String);

impl Utf16String {
    pub fn new() -> Self {
        Self(String::new())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Utf16String {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl From<String> for Utf16String {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl IPCEncode for Utf16String {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), Error> {
        if self.0.is_ascii() {
            true.encode(encoder)?;
            encoder.encode_size(self.0.len())?;
            encoder.append(self.0.as_bytes());
        } else {
            false.encode(encoder)?;
            let units: Vec<u16> = self.0.encode_utf16().collect();
            encoder.encode_size(units.len())?;
            for unit in &units {
                unit.encode(encoder)?;
            }
        }
        Ok(())
    }
}

impl IPCDecode for Utf16String {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let is_ascii = bool::decode(decoder)?;
        let len = decoder.decode_size()?;
        if is_ascii {
            let bytes = decoder.read(len)?.to_vec();
            String::from_utf8(bytes).map(Self).map_err(|_| Error::InvalidUtf8)
        } else {
            let mut units = Vec::with_capacity(len);
            for _ in 0..len {
                units.push(u16::decode(decoder)?);
            }
            String::from_utf16(&units).map(Self).map_err(|_| Error::InvalidUtf8)
        }
    }
}

impl<T: IPCEncode> IPCEncode for [T] {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), Error> {
        encoder.encode_size(self.len())?;
        for item in self {
            item.encode(encoder)?;
        }
        Ok(())
    }
}

impl<T: IPCEncode> IPCEncode for Vec<T> {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), Error> {
        self.as_slice().encode(encoder)
    }
}

impl<T: IPCDecode> IPCDecode for Vec<T> {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let len = decoder.decode_size()?;
        let mut out = Self::with_capacity(len);
        for _ in 0..len {
            out.push(T::decode(decoder)?);
        }
        Ok(out)
    }
}

impl<T: IPCEncode> IPCEncode for Option<T> {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), Error> {
        match self {
            Some(value) => {
                true.encode(encoder)?;
                value.encode(encoder)
            }
            None => false.encode(encoder),
        }
    }
}

impl<T: IPCDecode> IPCDecode for Option<T> {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        if bool::decode(decoder)? {
            Ok(Some(T::decode(decoder)?))
        } else {
            Ok(None)
        }
    }
}

impl<K: IPCEncode, V: IPCEncode> IPCEncode for HashMap<K, V> {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), Error> {
        encoder.encode_size(self.len())?;
        for (key, value) in self {
            key.encode(encoder)?;
            value.encode(encoder)?;
        }
        Ok(())
    }
}

impl<K, V> IPCDecode for HashMap<K, V>
where
    K: IPCDecode + std::hash::Hash + Eq,
    V: IPCDecode,
{
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
        let len = decoder.decode_size()?;
        let mut map = Self::with_capacity(len);
        for _ in 0..len {
            let key = K::decode(decoder)?;
            let value = V::decode(decoder)?;
            map.insert(key, value);
        }
        Ok(map)
    }
}

/// Mirror of `IPC::Empty` — encodes to zero bytes. Used for synchronous
/// messages whose response carries no payload.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Empty;

impl IPCEncode for Empty {
    fn encode(&self, _: &mut Encoder<'_>) -> Result<(), Error> {
        Ok(())
    }
}

impl IPCDecode for Empty {
    fn decode(_: &mut Decoder<'_>) -> Result<Self, Error> {
        Ok(Self)
    }
}

/// Build a complete message buffer prefixed with the endpoint magic and the
/// message id, then the message's encoded payload.
pub fn encode_message<M: IPCMessage>(message: &M) -> Result<MessageBuffer, Error> {
    let mut buffer = MessageBuffer::new();
    {
        let mut encoder = Encoder::new(&mut buffer);
        M::ENDPOINT_MAGIC.encode(&mut encoder)?;
        M::MESSAGE_ID.encode(&mut encoder)?;
        message.encode(&mut encoder)?;
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<T: IPCEncode + IPCDecode + std::fmt::Debug + PartialEq>(value: T) {
        let mut buffer = MessageBuffer::new();
        {
            let mut encoder = Encoder::new(&mut buffer);
            value.encode(&mut encoder).unwrap();
        }
        let mut decoder = Decoder::new(&buffer.data, []);
        let decoded = T::decode(&mut decoder).unwrap();
        assert_eq!(value, decoded);
        assert!(decoder.is_empty());
    }

    #[test]
    fn arithmetic_round_trip() {
        round_trip(0u8);
        round_trip(0xffu8);
        round_trip(-1i32);
        round_trip(0xdeadbeefu32);
        round_trip(i64::MIN);
        round_trip(u64::MAX);
        round_trip(std::f32::consts::PI);
        round_trip(std::f64::consts::E);
    }

    #[test]
    fn bool_round_trip() {
        round_trip(true);
        round_trip(false);
    }

    #[test]
    fn string_round_trip() {
        round_trip(String::new());
        round_trip(String::from("hello, world"));
        round_trip(String::from("snowman: \u{2603}"));
    }

    #[test]
    fn byte_string_round_trip() {
        round_trip(ByteString::default());
        round_trip(ByteString::from(vec![0u8, 1, 2, 0xff, 0xfe]));
    }

    #[test]
    fn utf16_round_trip() {
        round_trip(Utf16String::from("ascii fast path"));
        round_trip(Utf16String::from("non-ascii: \u{1F44B}\u{2603}"));
    }

    #[test]
    fn vec_round_trip() {
        round_trip::<Vec<u32>>(vec![]);
        round_trip(vec![1u32, 2, 3, 4]);
        round_trip(vec![String::from("a"), String::from("bb"), String::from("ccc")]);
    }

    #[test]
    fn option_round_trip() {
        round_trip(Option::<u32>::None);
        round_trip(Some(42u32));
        round_trip(Some(String::from("hi")));
    }

    #[test]
    fn hashmap_round_trip() {
        let mut map = HashMap::new();
        map.insert(String::from("a"), 1u32);
        map.insert(String::from("b"), 2u32);
        round_trip(map);
    }

    #[test]
    fn size_too_large_rejected() {
        let mut buffer = MessageBuffer::new();
        {
            let mut encoder = Encoder::new(&mut buffer);
            // u32 size header well above MAX_DECODED_SIZE.
            (MAX_DECODED_SIZE as u32 + 1).encode(&mut encoder).unwrap();
        }
        let mut decoder = Decoder::new(&buffer.data, []);
        let err = String::decode(&mut decoder).unwrap_err();
        assert!(matches!(err, Error::SizeTooLarge));
    }
}
