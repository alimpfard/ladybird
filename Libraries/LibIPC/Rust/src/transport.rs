/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

//! POSIX transport for Ladybird IPC.
//!
//! Wire format mirrors `Libraries/LibIPC/TransportSocket.cpp`:
//!
//! - Each message starts with a 12-byte `MessageHeader` (1-byte type, 3 bytes
//!   of padding, u32 payload size, u32 fd count) followed by `payload_size`
//!   bytes of payload.
//! - File descriptors travel out of band via `SCM_RIGHTS` ancillary data
//!   attached to the same `sendmsg(2)` that carries (the start of) a header.
//! - When a peer receives a payload that carries any fds it sends back a
//!   `FdAck` header so the sender can release the fds it was retaining
//!   (workaround for the macOS premature-GC behavior described in
//!   <https://openradar.me/9477351>).
//!
//! What's intentionally *not* here: the background IO thread, send/receive
//! queues, condvar-driven blocking reads, and the read-available pipe hook
//! from `TransportSocket.cpp`. Those are policy on top of the protocol — pick
//! your own threading model and wrap [`TransportSocket`] with it.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::ptr;

use crate::Attachment;

/// Maximum message payload size — matches `IPC::MAX_MESSAGE_PAYLOAD_SIZE`.
pub const MAX_MESSAGE_PAYLOAD_SIZE: u32 = 64 * 1024 * 1024;

/// Maximum number of file descriptors per message — matches
/// `IPC::MAX_MESSAGE_FD_COUNT`.
pub const MAX_MESSAGE_FD_COUNT: u32 = 128;

/// Cap on file descriptors transferred per `sendmsg(2)`. The C++ side uses
/// `Core::LocalSocket::MAX_TRANSFER_FDS`; 64 is more than enough room and
/// matches typical Linux limits.
const MAX_TRANSFER_FDS: usize = 64;

const SOCKET_BUFFER_SIZE: libc::c_int = 128 * 1024;

const HEADER_TYPE_PAYLOAD: u8 = 0;
const HEADER_TYPE_FD_ACK: u8 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct MessageHeader {
    msg_type: u8,
    _padding: [u8; 3],
    payload_size: u32,
    fd_count: u32,
}

const HEADER_SIZE: usize = mem::size_of::<MessageHeader>();
const _: () = assert!(HEADER_SIZE == 12, "MessageHeader must be 12 bytes for C++ wire compat");

impl MessageHeader {
    fn payload(payload_size: u32, fd_count: u32) -> Self {
        Self {
            msg_type: HEADER_TYPE_PAYLOAD,
            _padding: [0; 3],
            payload_size,
            fd_count,
        }
    }

    fn fd_ack(fd_count: u32) -> Self {
        Self {
            msg_type: HEADER_TYPE_FD_ACK,
            _padding: [0; 3],
            payload_size: 0,
            fd_count,
        }
    }

    fn as_bytes(&self) -> [u8; HEADER_SIZE] {
        // Safety: MessageHeader is `#[repr(C)]` with no padding semantics
        // beyond the explicit `_padding` field; raw bytes are well-defined.
        unsafe { mem::transmute(*self) }
    }

    fn from_bytes(bytes: [u8; HEADER_SIZE]) -> Self {
        // Safety: MessageHeader is plain old data with `#[repr(C)]`; any
        // 12-byte sequence is a valid bit pattern (we validate `msg_type`
        // separately).
        unsafe { mem::transmute(bytes) }
    }
}

/// A handle to a transferable transport endpoint — the file descriptor that
/// would be sent to a child process via `IPC::File`.
#[derive(Debug)]
pub struct TransportHandle {
    fd: OwnedFd,
}

impl TransportHandle {
    pub fn from_owned_fd(fd: OwnedFd) -> Self {
        Self { fd }
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub fn into_owned_fd(self) -> OwnedFd {
        self.fd
    }
}

impl crate::IPCEncode for TransportHandle {
    fn encode(&self, encoder: &mut crate::Encoder<'_>) -> Result<(), crate::Error> {
        let fd = self
            .fd
            .try_clone()
            .map_err(|_| crate::Error::Custom("unable to duplicate transport fd"))?;
        encoder.append_attachment(Attachment::from_owned_fd(fd));
        Ok(())
    }
}

impl crate::IPCDecode for TransportHandle {
    fn decode(decoder: &mut crate::Decoder<'_>) -> Result<Self, crate::Error> {
        let fd = decoder
            .take_attachment()?
            .into_owned_fd()
            .ok_or(crate::Error::NoAttachment)?;
        Ok(Self::from_owned_fd(fd))
    }
}

/// One fully-decoded incoming message.
#[derive(Debug)]
pub struct TransportMessage {
    pub bytes: Vec<u8>,
    pub attachments: Vec<Attachment>,
}

/// A connected POSIX transport. Reads accumulate bytes and fds in internal
/// buffers because `recvmsg(2)` doesn't honor message boundaries — fds may
/// arrive attached to any byte the kernel happens to deliver them with.
pub struct TransportSocket {
    socket: UnixStream,
    unprocessed_bytes: Vec<u8>,
    unprocessed_fds: VecDeque<OwnedFd>,
    peer_eof: bool,
}

impl TransportSocket {
    /// Creates a connected pair of transports backed by `socketpair(2)`.
    /// Returns the local end as a [`TransportSocket`] and the peer end as
    /// a [`TransportHandle`] suitable for sending to another process.
    pub fn pair() -> io::Result<(Self, TransportHandle)> {
        let (local, remote) = UnixStream::pair()?;
        let local = Self::adopt(local);
        let handle = TransportHandle::from_owned_fd(OwnedFd::from(remote));
        Ok((local, handle))
    }

    /// Adopts an existing connected socket.
    pub fn from_owned_fd(fd: OwnedFd) -> io::Result<Self> {
        Ok(Self::adopt(UnixStream::from(fd)))
    }

    fn adopt(socket: UnixStream) -> Self {
        // Match TransportSocket.cpp: bump send/receive buffers to 128 KiB.
        let raw = socket.as_raw_fd();
        let _ = setsockopt_int(raw, libc::SO_SNDBUF, SOCKET_BUFFER_SIZE);
        let _ = setsockopt_int(raw, libc::SO_RCVBUF, SOCKET_BUFFER_SIZE);
        Self {
            socket,
            unprocessed_bytes: Vec::new(),
            unprocessed_fds: VecDeque::new(),
            peer_eof: false,
        }
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    /// Releases the underlying fd so it can be transferred to another
    /// process.
    pub fn into_handle(self) -> TransportHandle {
        TransportHandle::from_owned_fd(OwnedFd::from(self.socket))
    }

    /// Sends one message: header + payload, with file descriptors attached
    /// via `SCM_RIGHTS` to the header send. Drains `attachments` on success.
    pub fn post_message(&mut self, payload: &[u8], attachments: &mut Vec<Attachment>) -> io::Result<()> {
        let payload_size = u32::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "payload exceeds u32::MAX"))?;
        if payload_size > MAX_MESSAGE_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "payload exceeds MAX_MESSAGE_PAYLOAD_SIZE",
            ));
        }
        let fd_count = u32::try_from(attachments.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "fd count exceeds u32::MAX"))?;
        if fd_count > MAX_MESSAGE_FD_COUNT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fd count exceeds MAX_MESSAGE_FD_COUNT",
            ));
        }

        let header = MessageHeader::payload(payload_size, fd_count);
        let raw_fds: Vec<RawFd> = attachments.iter().map(Attachment::as_raw_fd).collect();

        send_all(&self.socket, &header.as_bytes(), &raw_fds)?;
        if !payload.is_empty() {
            self.socket.write_all(payload)?;
        }

        // Kernel has the fds now — drop our copies. (We do not implement the
        // macOS retain-until-acknowledged dance; for that, hold onto the
        // OwnedFds until you receive a matching FdAck.)
        attachments.clear();
        Ok(())
    }

    /// Reads one message, blocking until it's fully available. Returns
    /// `Ok(None)` if the peer closed the connection.
    pub fn read_message(&mut self) -> io::Result<Option<TransportMessage>> {
        loop {
            if let Some(message) = self.try_extract_message()? {
                return Ok(Some(message));
            }
            if self.peer_eof {
                return Ok(None);
            }
            self.fill_buffers(true)?;
        }
    }

    /// Reads any messages already buffered or available without blocking.
    /// Returns `Ok(None)` when there's nothing pending.
    pub fn try_read_message(&mut self) -> io::Result<Option<TransportMessage>> {
        if let Some(message) = self.try_extract_message()? {
            return Ok(Some(message));
        }
        if self.peer_eof {
            return Ok(None);
        }
        match self.fill_buffers(false) {
            Ok(()) => self.try_extract_message(),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn peer_disconnected(&self) -> bool {
        self.peer_eof
    }

    fn fill_buffers(&mut self, blocking: bool) -> io::Result<()> {
        let mut buf = [0u8; 4096];
        let mut fds: Vec<OwnedFd> = Vec::new();
        let flags = if blocking { 0 } else { libc::MSG_DONTWAIT };

        let n = recv_with_fds(self.socket.as_raw_fd(), &mut buf, &mut fds, flags)?;
        if n == 0 && fds.is_empty() {
            self.peer_eof = true;
            return Ok(());
        }
        self.unprocessed_bytes.extend_from_slice(&buf[..n]);
        self.unprocessed_fds.extend(fds);
        Ok(())
    }

    fn try_extract_message(&mut self) -> io::Result<Option<TransportMessage>> {
        loop {
            if self.unprocessed_bytes.len() < HEADER_SIZE {
                return Ok(None);
            }
            let mut header_buf = [0u8; HEADER_SIZE];
            header_buf.copy_from_slice(&self.unprocessed_bytes[..HEADER_SIZE]);
            let header = MessageHeader::from_bytes(header_buf);

            if header.payload_size > MAX_MESSAGE_PAYLOAD_SIZE {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "peer sent oversize payload"));
            }
            if header.fd_count > MAX_MESSAGE_FD_COUNT {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "peer sent oversize fd count",
                ));
            }

            let total_size = HEADER_SIZE
                .checked_add(header.payload_size as usize)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "payload size overflow"))?;
            if self.unprocessed_bytes.len() < total_size {
                return Ok(None);
            }
            if (header.fd_count as usize) > self.unprocessed_fds.len() {
                return Ok(None);
            }

            match header.msg_type {
                HEADER_TYPE_PAYLOAD => {
                    let mut attachments = Vec::with_capacity(header.fd_count as usize);
                    for _ in 0..header.fd_count {
                        let fd = self.unprocessed_fds.pop_front().expect("checked above");
                        attachments.push(Attachment::from_owned_fd(fd));
                    }
                    let payload = self.unprocessed_bytes[HEADER_SIZE..total_size].to_vec();
                    self.unprocessed_bytes.drain(..total_size);

                    if header.fd_count > 0 {
                        // Acknowledge so the peer can release its retained fds.
                        let ack = MessageHeader::fd_ack(header.fd_count);
                        send_all(&self.socket, &ack.as_bytes(), &[])?;
                    }

                    return Ok(Some(TransportMessage {
                        bytes: payload,
                        attachments,
                    }));
                }
                HEADER_TYPE_FD_ACK => {
                    if header.payload_size != 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "FdAck with non-zero payload",
                        ));
                    }
                    self.unprocessed_bytes.drain(..HEADER_SIZE);
                    // We don't track outstanding sent fds for retention, so
                    // this is informational. Loop to look for the next.
                }
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unknown message header type: {other}"),
                    ));
                }
            }
        }
    }
}

fn setsockopt_int(fd: RawFd, name: libc::c_int, value: libc::c_int) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            name,
            ptr::addr_of!(value).cast::<libc::c_void>(),
            mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Writes `bytes` plus, on the first `sendmsg`, the given fds via `SCM_RIGHTS`.
/// Loops until `bytes` is fully written or an error occurs.
fn send_all(socket: &UnixStream, bytes: &[u8], fds: &[RawFd]) -> io::Result<()> {
    let mut sent = 0usize;
    while sent < bytes.len() {
        let attach = if sent == 0 { fds } else { &[] };
        let n = sendmsg_with_fds(socket.as_raw_fd(), &bytes[sent..], attach)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "sendmsg returned 0"));
        }
        sent += n;
    }
    Ok(())
}

fn sendmsg_with_fds(fd: RawFd, bytes: &[u8], fds: &[RawFd]) -> io::Result<usize> {
    let iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };

    let cmsg_space = if fds.is_empty() {
        0
    } else {
        unsafe { libc::CMSG_SPACE((mem::size_of_val(fds)) as libc::c_uint) as usize }
    };
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = ptr::addr_of!(iov) as *mut libc::iovec;
    msg.msg_iovlen = 1;
    if cmsg_space > 0 {
        msg.msg_control = cmsg_buf.as_mut_ptr().cast::<libc::c_void>();
        msg.msg_controllen = cmsg_space as _;

        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN((mem::size_of_val(fds)) as libc::c_uint) as _;
            ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(cmsg).cast::<RawFd>(), fds.len());
        }
    }

    loop {
        let result = unsafe { libc::sendmsg(fd, &raw const msg, 0) };
        if result >= 0 {
            return Ok(result as usize);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(err);
    }
}

fn recv_with_fds(fd: RawFd, buf: &mut [u8], received_fds: &mut Vec<OwnedFd>, flags: libc::c_int) -> io::Result<usize> {
    let iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: buf.len(),
    };

    let cmsg_space = unsafe { libc::CMSG_SPACE((MAX_TRANSFER_FDS * mem::size_of::<RawFd>()) as libc::c_uint) as usize };
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = ptr::addr_of!(iov) as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = cmsg_space as _;

    let result = loop {
        let r = unsafe { libc::recvmsg(fd, &raw mut msg, flags) };
        if r >= 0 {
            break r;
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(err);
    };

    // Walk cmsg headers and pick up SCM_RIGHTS fds. Anything else is ignored.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
    while !cmsg.is_null() {
        unsafe {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let header_len = libc::CMSG_LEN(0) as usize;
                let data_len = (*cmsg).cmsg_len as usize - header_len;
                let count = data_len / mem::size_of::<RawFd>();
                let data = libc::CMSG_DATA(cmsg).cast::<RawFd>();
                for i in 0..count {
                    let raw = ptr::read_unaligned(data.add(i));
                    received_fds.push(OwnedFd::from_raw_fd(raw));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&raw const msg, cmsg);
        }
    }

    if (msg.msg_flags & libc::MSG_CTRUNC) != 0 {
        return Err(io::Error::other("ancillary data truncated (MSG_CTRUNC)"));
    }

    Ok(result as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [-1i32; 2];
        let r = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(r, 0, "pipe(2) failed");
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    #[test]
    fn round_trip_simple_message() {
        let (mut a, handle) = TransportSocket::pair().unwrap();
        let mut b = TransportSocket::from_owned_fd(handle.into_owned_fd()).unwrap();

        let payload = b"hello, transport".to_vec();
        let mut atts = Vec::new();
        a.post_message(&payload, &mut atts).unwrap();

        let received = b.read_message().unwrap().expect("message");
        assert_eq!(received.bytes, payload);
        assert!(received.attachments.is_empty());
    }

    #[test]
    fn round_trip_with_attachment() {
        use std::fs::File;
        use std::io::{Read, Write};
        use std::os::fd::IntoRawFd;

        let (mut a, handle) = TransportSocket::pair().unwrap();
        let mut b = TransportSocket::from_owned_fd(handle.into_owned_fd()).unwrap();

        // Send the write-end of a pipe through the channel. The receiver
        // writes, and we read back through the original read-end to confirm
        // the kernel object is the same.
        let (read_end, write_end) = pipe();

        let mut atts = vec![Attachment::from_owned_fd(write_end)];
        a.post_message(b"with-fd", &mut atts).unwrap();
        assert!(atts.is_empty());

        let mut received = b.read_message().unwrap().expect("message");
        assert_eq!(received.bytes, b"with-fd");
        assert_eq!(received.attachments.len(), 1);

        let received_fd = received.attachments[0].take().unwrap();
        let mut writer = File::from(received_fd);
        writer.write_all(b"y").unwrap();
        drop(writer);

        let mut reader = unsafe { File::from_raw_fd(read_end.into_raw_fd()) };
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"y");
    }

    #[test]
    fn try_read_message_returns_none_when_empty() {
        let (mut a, handle) = TransportSocket::pair().unwrap();
        let mut b = TransportSocket::from_owned_fd(handle.into_owned_fd()).unwrap();

        assert!(b.try_read_message().unwrap().is_none());

        a.post_message(b"queued", &mut Vec::new()).unwrap();
        // We may need a tiny moment for the kernel to deliver; loop a few times.
        let mut received = None;
        for _ in 0..50 {
            if let Some(m) = b.try_read_message().unwrap() {
                received = Some(m);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let received = received.expect("message eventually arrives");
        assert_eq!(received.bytes, b"queued");
    }

    #[test]
    fn peer_close_yields_eof() {
        let (a, handle) = TransportSocket::pair().unwrap();
        let mut b = TransportSocket::from_owned_fd(handle.into_owned_fd()).unwrap();
        drop(a);

        assert!(b.read_message().unwrap().is_none());
        assert!(b.peer_disconnected());
    }

    #[test]
    fn multiple_messages_in_one_recv() {
        let (mut a, handle) = TransportSocket::pair().unwrap();
        let mut b = TransportSocket::from_owned_fd(handle.into_owned_fd()).unwrap();

        a.post_message(b"one", &mut Vec::new()).unwrap();
        a.post_message(b"two", &mut Vec::new()).unwrap();
        a.post_message(b"three", &mut Vec::new()).unwrap();

        assert_eq!(b.read_message().unwrap().unwrap().bytes, b"one");
        assert_eq!(b.read_message().unwrap().unwrap().bytes, b"two");
        assert_eq!(b.read_message().unwrap().unwrap().bytes, b"three");
    }
}
